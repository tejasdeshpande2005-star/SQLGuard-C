
"""Conservative automatic repair for a narrow SQL injection pattern.

Supported pattern:
    query = "SELECT ... username = '" + username + "'"
    cursor.execute(query)

The repair changes the query to a parameterized template and changes the
execute call to pass the value separately.

This is a prototype, not a general-purpose SQL sanitizer. Unsupported or
ambiguous patterns are rejected. Repaired code must be reviewed and tested.
"""

import ast
from pathlib import Path
from typing import Any


SQL_WORDS = (
    "select ",
    "insert ",
    "update ",
    "delete ",
    "replace ",
    "with ",
    "drop ",
    "alter ",
)


def suggest_repair(finding):
    """Create a human-readable repair recommendation."""
    return {
        "file": finding.file,
        "line": finding.line,
        "action": "manual_parameterization",
        "recommendation": finding.repair,
        "example_sqlite": (
            "cursor.execute("
            "'SELECT * FROM users WHERE username = ?', (username,))"
        ),
        "warning": (
            "Review the query, database driver, placeholder style, and "
            "application behavior before applying a fix."
        ),
    }


def _flatten_concat(node):
    """Flatten a chain of string concatenation into AST parts."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_concat(node.left) + _flatten_concat(node.right)
    return [node]


def _supported_query(value):
    """Return (safe SQL template, parameter name) for a narrow pattern."""
    parts = _flatten_concat(value)

    if len(parts) != 3:
        return None

    left, variable, right = parts

    if not (
        isinstance(left, ast.Constant)
        and isinstance(left.value, str)
        and isinstance(variable, ast.Name)
        and isinstance(right, ast.Constant)
        and isinstance(right.value, str)
    ):
        return None

    prefix = left.value
    suffix = right.value

    # Only support a single-quoted SQL value surrounding the variable.
    if not prefix.rstrip().endswith("'"):
        return None
    if not suffix.lstrip().startswith("'"):
        return None

    query = prefix.rstrip()[:-1] + "?" + suffix.lstrip()[1:]

    if not any(word in query.lower() for word in SQL_WORDS):
        return None

    return query, variable.id


def _target_names(target):
    """Collect names assigned by an assignment target."""
    if isinstance(target, ast.Name):
        return {target.id}

    if isinstance(target, (ast.Tuple, ast.List)):
        names = set()
        for element in target.elts:
            names.update(_target_names(element))
        return names

    return set()


class _RepairPlanner(ast.NodeVisitor):
    """Find candidates that can be repaired without ambiguous rewrites."""

    def __init__(self):
        self.scope_stack = []
        self.candidates = {}
        self.assignments = {}
        self.execute_calls = {}
        self.scope_arguments = {}

    @property
    def scope(self):
        return tuple(self.scope_stack)

    def _record_assignment(self, name, node):
        key = (self.scope, name)
        self.assignments.setdefault(key, []).append(node)

    def _visit_function(self, node):
        # Decorators/default values are evaluated in the enclosing scope.
        for decorator in node.decorator_list:
            self.visit(decorator)

        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        if node.returns is not None:
            self.visit(node.returns)

        scope_id = id(node)
        self.scope_stack.append(scope_id)

        argument_names = {
            arg.arg
            for arg in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
        }
        if node.args.vararg:
            argument_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            argument_names.add(node.args.kwarg.arg)

        self.scope_arguments[self.scope] = argument_names

        for statement in node.body:
            self.visit(statement)

        self.scope_stack.pop()

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node)

    def visit_Lambda(self, node):
        # Do not attempt to repair inside lambdas.
        # Still visit their defaults in the enclosing scope.
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

    def visit_Assign(self, node):
        names = set()
        for target in node.targets:
            names.update(_target_names(target))

        for name in names:
            self._record_assignment(name, node)

        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            result = _supported_query(node.value)
            if result is not None:
                query, parameter = result
                self.candidates[id(node)] = {
                    "node": node,
                    "scope": self.scope,
                    "query_name": node.targets[0].id,
                    "query": query,
                    "parameter": parameter,
                }

        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        for name in _target_names(node.target):
            self._record_assignment(name, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        for name in _target_names(node.target):
            self._record_assignment(name, node)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        for name in _target_names(node.target):
            self._record_assignment(name, node)
        self.generic_visit(node)

    def visit_Delete(self, node):
        for target in node.targets:
            for name in _target_names(target):
                self._record_assignment(name, node)
        self.generic_visit(node)

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            key = (self.scope, node.args[0].id)
            self.execute_calls.setdefault(key, []).append(node)

        self.generic_visit(node)

    def eligible_repairs(self):
        """Return only unambiguous assignment/call pairs."""
        eligible = {}

        for assignment_id, candidate in self.candidates.items():
            scope = candidate["scope"]
            query_name = candidate["query_name"]
            parameter = candidate["parameter"]

            query_key = (scope, query_name)
            parameter_key = (scope, parameter)

            assignments_to_query = self.assignments.get(query_key, [])
            assignments_to_parameter = self.assignments.get(parameter_key, [])
            execute_calls = self.execute_calls.get(query_key, [])

            # The query must have one assignment and one execution.
            if len(assignments_to_query) != 1:
                continue
            if id(assignments_to_query[0]) != assignment_id:
                continue
            if len(execute_calls) != 1:
                continue

            # Do not rewrite executions with existing arguments or keywords.
            call = execute_calls[0]
            if len(call.args) != 1 or call.keywords:
                continue

            # A reassigned parameter could differ from the value used to
            # build the original query. Reject rather than guessing.
            if assignments_to_parameter:
                continue

            # Avoid treating a function's query parameter as the assigned
            # query variable.
            if query_name in self.scope_arguments.get(scope, set()):
                continue

            eligible[assignment_id] = {
                **candidate,
                "call_id": id(call),
            }

        return eligible


class _RepairTransformer(ast.NodeTransformer):
    def __init__(self, eligible):
        self.eligible = eligible
        self.call_repairs = {
            info["call_id"]: info
            for info in eligible.values()
        }
        self.changed = False

    def visit_Assign(self, node):
        # Transform nested expressions first.
        self.generic_visit(node)

        info = self.eligible.get(id(node))
        if info is None:
            return node

        node.value = ast.copy_location(
            ast.Constant(value=info["query"]),
            node.value,
        )
        self.changed = True
        return node

    def visit_Call(self, node):
        self.generic_visit(node)

        info = self.call_repairs.get(id(node))
        if info is None:
            return node

        # The planner guarantees one positional query argument and no
        # keywords. The value is now passed separately as a one-item tuple.
        node.args.append(
            ast.Tuple(
                elts=[
                    ast.Name(
                        id=info["parameter"],
                        ctx=ast.Load(),
                    )
                ],
                ctx=ast.Load(),
            )
        )
        self.changed = True
        return node


def repair_file(input_path, output_path):
    """Write a candidate repair to a different file.

    Returns:
        A dictionary containing success, output (on success), and message.
    """
    source_path = Path(input_path)
    destination = Path(output_path)

    try:
        if source_path.resolve() == destination.resolve():
            return {
                "success": False,
                "message": "Output must be different from the original file.",
            }

        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
        return {"success": False, "message": str(exc)}

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

    transformer = _RepairTransformer(eligible)
    repaired_tree = transformer.visit(tree)

    # A candidate must update both the query assignment and its execute call.
    if not transformer.changed or len(eligible) == 0:
        return {
            "success": False,
            "message": (
                "No complete repair could be generated. "
                "The original file was not modified."
            ),
        }

    ast.fix_missing_locations(repaired_tree)

    try:
        repaired_source = ast.unparse(repaired_tree) + "\n"
        ast.parse(repaired_source, filename=str(destination))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(repaired_source, encoding="utf-8")
    except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
        return {"success": False, "message": str(exc)}

    return {
        "success": True,
        "output": str(destination),
        "message": (
            "Candidate repair generated. Re-analyze and test it before use."
        ),
    }
