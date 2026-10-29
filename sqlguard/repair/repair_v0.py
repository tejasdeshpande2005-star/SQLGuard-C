
"""Conservative repair prototype for simple SQL injection patterns.

Supported query assignments:
    query = "SELECT ... username = '" + username + "'"
    query = f"SELECT ... email = '{email}'"
    query = "SELECT ... role = '%s'" % role

Expected execution:
    cursor.execute(query)

The repair replaces the interpolated SQL value with a '?' placeholder
and passes the value separately to execute(). This placeholder style is
appropriate for SQLite. Review database-driver compatibility before use.

This prototype does not execute submitted Python code.
"""

import ast
import os
import tempfile
from pathlib import Path


SQL_WORDS = ("select", "insert", "update", "delete", "where")


def _is_sql_query(query):
    """Return True if the string resembles a supported SQL query."""
    return isinstance(query, str) and any(
        word in query.lower() for word in SQL_WORDS
    )


def _replace_quoted_value(prefix, suffix):
    """Replace the quotes surrounding one interpolated SQL value."""
    if not prefix.rstrip().endswith("'"):
        return None

    if not suffix.lstrip().startswith("'"):
        return None

    query = prefix.rstrip()[:-1] + "?" + suffix.lstrip()[1:]

    if _is_sql_query(query):
        return query

    return None


def _flatten_concat(node):
    """Flatten a + b + c into [a, b, c] for simple string concatenation."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_concat(node.left) + _flatten_concat(node.right)

    return [node]


def _supported_query(value):
    """Return (parameterized_query, parameter_names) for supported patterns."""

    # Pattern 1:
    # "SELECT ... username = '" + username + "'"
    parts = _flatten_concat(value)

    if len(parts) == 3:
        left, variable, right = parts

        if (
            isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and isinstance(variable, ast.Name)
            and isinstance(right, ast.Constant)
            and isinstance(right.value, str)
        ):
            query = _replace_quoted_value(left.value, right.value)

            if query is not None:
                return query, (variable.id,)

    # Pattern 2:
    # f"SELECT ... email = '{email}'"
    if isinstance(value, ast.JoinedStr) and len(value.values) == 3:
        left, middle, right = value.values

        if (
            isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and isinstance(middle, ast.FormattedValue)
            and isinstance(middle.value, ast.Name)
            and middle.conversion in (-1, ord("s"))
            and middle.format_spec is None
            and isinstance(right, ast.Constant)
            and isinstance(right.value, str)
        ):
            query = _replace_quoted_value(left.value, right.value)

            if query is not None:
                return query, (middle.value.id,)

    # Pattern 3:
    # "SELECT ... role = '%s'" % role
    if (
        isinstance(value, ast.BinOp)
        and isinstance(value.op, ast.Mod)
        and isinstance(value.left, ast.Constant)
        and isinstance(value.left.value, str)
        and isinstance(value.right, ast.Name)
    ):
        template = value.left.value

        if template.count("%s") == 1:
            marker = template.find("%s")
            prefix = template[:marker]
            suffix = template[marker + 2:]

            query = _replace_quoted_value(prefix, suffix)

            # Reject extra formatting directives rather than guessing.
            remainder = (prefix + suffix).replace("%%", "")

            if query is not None and "%" not in remainder:
                return query, (value.right.id,)

    return None


class _RepairPlanner(ast.NodeVisitor):
    """Find conservative query assignments and matching execute calls."""

    def __init__(self):
        self.scope = 0
        self.assignments = {}
        self.execute_calls = {}
        self.candidates = {}

    def visit_FunctionDef(self, node):
        previous_scope = self.scope
        self.scope = id(node)

        for statement in node.body:
            self.visit(statement)

        self.scope = previous_scope

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0]
            key = (self.scope, target.id)

            self.assignments.setdefault(key, []).append(node)

            result = _supported_query(node.value)

            if result is not None:
                query, parameters = result

                self.candidates[id(node)] = {
                    "node": node,
                    "scope": self.scope,
                    "query_name": target.id,
                    "query": query,
                    "parameters": parameters,
                }

        self.generic_visit(node)

    def visit_Call(self, node):
        # Match cursor.execute(query) with a simple Name argument.
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            query_name = node.args[0].id
            key = (self.scope, query_name)

            self.execute_calls.setdefault(key, []).append(node)

        self.generic_visit(node)

    def eligible_repairs(self):
        eligible = []

        for candidate in self.candidates.values():
            scope = candidate["scope"]
            query_name = candidate["query_name"]
            parameters = candidate["parameters"]

            query_key = (scope, query_name)
            assignments = self.assignments.get(query_key, [])
            execute_calls = self.execute_calls.get(query_key, [])

            # Require one query assignment and one execute call.
            if len(assignments) != 1 or len(execute_calls) != 1:
                continue

            # Only rewrite calls that currently pass exactly the query.
            call = execute_calls[0]

            if len(call.args) != 1 or call.keywords:
                continue

            # Permit direct input() assignments but reject ambiguous
            # reassignments or derived values.
            safe_parameters = True

            for parameter in parameters:
                parameter_assignments = self.assignments.get(
                    (scope, parameter), []
                )

                for assignment in parameter_assignments:
                    value = assignment.value

                    is_direct_input = (
                        isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id == "input"
                    )

                    if not is_direct_input:
                        safe_parameters = False
                        break

                if not safe_parameters:
                    break

            if not safe_parameters:
                continue

            eligible.append({
                **candidate,
                "call": call,
            })

        return eligible


class _RepairTransformer(ast.NodeTransformer):
    """Apply the query-template and execute-parameter changes."""

    def __init__(self, eligible):
        self.eligible_by_assignment = {
            id(item["node"]): item for item in eligible
        }
        self.eligible_by_call = {
            id(item["call"]): item for item in eligible
        }

    def visit_Assign(self, node):
        info = self.eligible_by_assignment.get(id(node))

        if info is None:
            return self.generic_visit(node)

        node.value = ast.Constant(value=info["query"])
        return ast.copy_location(node, node)

    def visit_Call(self, node):
        info = self.eligible_by_call.get(id(node))

        if info is None:
            return self.generic_visit(node)

        # cursor.execute(query, (username,))
        node.args.append(
            ast.Tuple(
                elts=[
                    ast.Name(id=name, ctx=ast.Load())
                    for name in info["parameters"]
                ],
                ctx=ast.Load(),
            )
        )

        return ast.copy_location(node, node)


def repair_file(input_path, output_path):
    """Generate a repaired candidate without overwriting the input.

    Returns a dictionary containing success, message and output_path.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        return {
            "success": False,
            "message": "Input Python file does not exist.",
        }

    try:
        source = input_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError, UnicodeError) as exc:
        return {
            "success": False,
            "message": f"Could not read or parse input: {exc}",
        }

    planner = _RepairPlanner()
    planner.visit(tree)
    eligible = planner.eligible_repairs()

    if not eligible:
        return {
            "success": False,
            "message": (
                "No unambiguous supported query/execute pair was found. "
                "The original file was not modified."
            ),
        }

    transformed = _RepairTransformer(eligible).visit(tree)
    ast.fix_missing_locations(transformed)

    try:
        repaired_source = ast.unparse(transformed) + "\n"

        # Ensure the generated candidate is syntactically valid.
        ast.parse(repaired_source)

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically to avoid leaving a partially written file.
        fd, temporary_name = tempfile.mkstemp(
            prefix="sqlguard_repair_",
            suffix=".py",
            dir=str(output_path.parent),
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                file.write(repaired_source)

            os.replace(temporary_name, output_path)

        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    except (OSError, ValueError, TypeError) as exc:
        return {
            "success": False,
            "message": f"Could not write repaired candidate: {exc}",
        }

    return {
        "success": True,
        "message": (
            f"Generated candidate with {len(eligible)} repaired "
            "query/execute pair(s). Review and test before use."
        ),
        "output_path": str(output_path),
        "repairs_count": len(eligible),
    }
