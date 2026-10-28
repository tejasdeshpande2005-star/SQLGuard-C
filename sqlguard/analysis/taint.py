
"""Lightweight intraprocedural taint analysis for SQLGuard-C."""

import ast
from dataclasses import dataclass, asdict
from typing import Dict, List, Set


SQL_WORDS = (
    "select ", "insert ", "update ", "delete ",
    "replace ", "with ", "drop ", "alter ",
)


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    message: str
    source: str
    sink: str
    variable: str
    path: List[str]
    repair: str
    start_offset: int = 0
    end_offset: int = 0
    start_line: int = 1
    start_column: int = 0
    end_line: int = 1
    end_column: int = 0
    expression: str = ""
    highlight_ranges: List[dict] = None

    def to_dict(self):
        result = asdict(self)
        result["highlight_ranges"] = self.highlight_ranges or []
        return result


class Analyzer(ast.NodeVisitor):
    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.source = source
        self.lines = source.splitlines(keepends=True)

        self.line_offsets = []
        offset = 0
        for line in self.lines:
            self.line_offsets.append(offset)
            offset += len(line)

        self.tainted: Set[str] = set()
        self.origins: Dict[str, str] = {}
        self.paths: Dict[str, List[str]] = {}
        self.tainted_ranges: Dict[str, List[dict]] = {}

        self.cursor_names: Set[str] = set()
        self.safe_parameterized_queries: Set[str] = set()
        self.safe_placeholder_vars: Set[str] = set()
        self.trusted_dicts: Set[str] = set()
        self.safe_lookup_vars: Set[str] = set()

        self.findings: List[Finding] = []

    def _char_column(self, line_number, byte_column):
        """Convert AST UTF-8 byte columns to Python character columns."""
        if line_number < 1 or line_number > len(self.lines):
            return byte_column

        line = self.lines[line_number - 1].rstrip("\r\n")
        raw = line.encode("utf-8")[:byte_column]
        return len(raw.decode("utf-8", errors="ignore"))

    def _range(self, node):
        """Return editor-compatible offsets and line/column coordinates."""
        if not all(
            hasattr(node, attr)
            for attr in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ):
            return None

        start_line = node.lineno
        end_line = node.end_lineno

        if start_line < 1 or end_line > len(self.lines):
            return None

        start_col = self._char_column(start_line, node.col_offset)
        end_col = self._char_column(end_line, node.end_col_offset)

        start = self.line_offsets[start_line - 1] + start_col
        end = self.line_offsets[end_line - 1] + end_col

        return {
            "start_offset": start,
            "end_offset": end,
            "start_line": start_line,
            "start_column": start_col,
            "end_line": end_line,
            "end_column": end_col,
            "expression": self.source[start:end],
        }

    @staticmethod
    def _is_input_call(node):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "input"
        )

    def expr_taint(self, node):
        """Return whether an expression contains tracked untrusted data."""
        names = []
        is_tainted = False

        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in self.tainted:
                is_tainted = True
                if n.id not in names:
                    names.append(n.id)

            if self._is_input_call(n):
                is_tainted = True
                if "input()" not in names:
                    names.append("input()")

            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in {"get", "get_json"}
                and isinstance(n.func.value, ast.Attribute)
                and n.func.value.attr
                in {"args", "form", "GET", "POST", "query_params"}
            ):
                is_tainted = True
                source_name = ast.unparse(n.func.value)
                if source_name not in names:
                    names.append(source_name)

        return is_tainted, names

    def expr_is_sql(self, node):
        text = ast.unparse(node).lower()
        return any(word in text for word in SQL_WORDS)

    def is_trusted_literal_dict(self, node):
        return (
            isinstance(node, ast.Dict)
            and bool(node.keys)
            and all(
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                for key, value in zip(node.keys, node.values)
            )
        )

    def is_trusted_lookup(self, node):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.trusted_dicts
        )

    def is_generated_placeholder_expression(self, node):
        """Recognize ', '.join(['?'] * len(values))."""
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
            and len(node.args) == 1
        ):
            return False

        repeated = node.args[0]
        return (
            isinstance(repeated, ast.BinOp)
            and isinstance(repeated.op, ast.Mult)
            and isinstance(repeated.left, ast.List)
            and len(repeated.left.elts) == 1
            and isinstance(repeated.left.elts[0], ast.Constant)
            and repeated.left.elts[0].value == "?"
            and isinstance(repeated.right, ast.Call)
            and isinstance(repeated.right.func, ast.Name)
            and repeated.right.func.id == "len"
            and len(repeated.right.args) == 1
        )

    def _unsafe_ranges(self, node):
        """Locate tracked untrusted expressions within a SQL expression."""
        ranges = []

        def visit(current):
            if isinstance(current, ast.Name) and current.id in self.tainted:
                saved = self.tainted_ranges.get(current.id)
                if saved:
                    ranges.extend(saved)
                else:
                    item = self._range(current)
                    if item:
                        ranges.append(item)
                return

            if self._is_input_call(current):
                item = self._range(current)
                if item:
                    ranges.append(item)
                return

            if isinstance(current, ast.FormattedValue):
                visit(current.value)
                return

            if isinstance(current, ast.BinOp):
                visit(current.left)
                visit(current.right)
                return

            if isinstance(current, ast.JoinedStr):
                for value in current.values:
                    if isinstance(value, ast.FormattedValue):
                        visit(value)
                return

            if isinstance(current, ast.Call):
                if (
                    isinstance(current.func, ast.Attribute)
                    and current.func.attr in {"format", "__mod__"}
                ):
                    for arg in current.args:
                        visit(arg)
                    for keyword in current.keywords:
                        visit(keyword.value)
                    return

            if (
                isinstance(current, ast.Call)
                and isinstance(current.func, ast.Attribute)
                and current.func.attr in {"get", "get_json"}
            ):
                item = self._range(current)
                if item:
                    ranges.append(item)
                return

            for child in ast.iter_child_nodes(current):
                visit(child)

        visit(node)

        unique = {}
        for item in ranges:
            unique[(item["start_offset"], item["end_offset"])] = item

        return sorted(
            unique.values(),
            key=lambda item: (item["start_offset"], item["end_offset"]),
        )

    def visit_FunctionDef(self, node):
        old_tainted = set(self.tainted)
        old_origins = dict(self.origins)
        old_paths = {key: list(value) for key, value in self.paths.items()}
        old_ranges = {
            key: list(value) for key, value in self.tainted_ranges.items()
        }

        for arg in node.args.args:
            self.tainted.add(arg.arg)
            self.origins[arg.arg] = f"parameter '{arg.arg}'"
            self.paths[arg.arg] = [
                f"function parameter {arg.arg} at line {node.lineno}"
            ]
            item = self._range(arg)
            self.tainted_ranges[arg.arg] = [item] if item else []

        for stmt in node.body:
            self.visit(stmt)

        self.tainted = old_tainted
        self.origins = old_origins
        self.paths = old_paths
        self.tainted_ranges = old_ranges

    def visit_If(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is False:
            return
        self.generic_visit(node)

    def visit_Assign(self, node):
        value = node.value

        if self.is_trusted_literal_dict(value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.trusted_dicts.add(target.id)

        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "cursor"
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.cursor_names.add(target.id)

        tainted, names = self.expr_taint(value)
        trusted_lookup = self.is_trusted_lookup(value)
        generated_placeholders = self.is_generated_placeholder_expression(value)
        ranges = self._unsafe_ranges(value)

        # If untrusted data is embedded in SQL text during this assignment,
        # highlight the complete SQL-building expression (the RHS), rather
        # than only the original input() call or tainted variable reference.
        # This gives the editor a useful range for concatenations and f-strings.
        if tainted and self.expr_is_sql(value):
            sql_expression_range = self._range(value)
            if sql_expression_range:
                ranges = [sql_expression_range]

        if isinstance(value, ast.Name) and value.id in self.tainted_ranges:
            ranges = list(self.tainted_ranges[value.id])

        text = ast.unparse(value)
        has_placeholder = any(
            isinstance(item, ast.Constant)
            and isinstance(item.value, str)
            and "?" in item.value
            for item in ast.walk(value)
        )

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            name = target.id

            if (
                has_placeholder
                and "?" in text
                and any(word in text.lower() for word in SQL_WORDS)
            ):
                self.safe_parameterized_queries.add(name)
            elif (
                any(
                    isinstance(item, ast.Name)
                    and item.id in self.safe_placeholder_vars
                    for item in ast.walk(value)
                )
                and any(word in text.lower() for word in SQL_WORDS)
            ):
                self.safe_parameterized_queries.add(name)

            if (
                has_placeholder
                and any(
                    isinstance(item, ast.Constant) and item.value == "?"
                    for item in ast.walk(value)
                )
                and not any(
                    isinstance(item, ast.JoinedStr)
                    for item in ast.walk(value)
                )
            ):
                self.safe_placeholder_vars.add(name)
            elif (
                not has_placeholder
                and not any(
                    isinstance(item, ast.Name)
                    and item.id in self.safe_placeholder_vars
                    for item in ast.walk(value)
                )
            ):
                self.safe_placeholder_vars.discard(name)

            if trusted_lookup:
                self.safe_lookup_vars.add(name)
                self.tainted.discard(name)
                self.origins.pop(name, None)
                self.paths.pop(name, None)
                self.tainted_ranges.pop(name, None)
                continue

            if generated_placeholders:
                self.safe_placeholder_vars.add(name)
                self.tainted.discard(name)
                self.origins.pop(name, None)
                self.paths.pop(name, None)
                self.tainted_ranges.pop(name, None)
                continue

            if tainted:
                self.tainted.add(name)

                source = next(
                    (
                        item for item in names
                        if item == "input()" or item not in self.tainted
                    ),
                    names[0] if names else "untrusted input",
                )

                if names and names[0] in self.origins:
                    self.origins[name] = self.origins[names[0]]
                else:
                    self.origins[name] = source

                previous_path = []
                for item in names:
                    previous_path.extend(self.paths.get(item, []))

                self.paths[name] = previous_path + [
                    f"{name} assigned at line {node.lineno}"
                ]
                self.tainted_ranges[name] = ranges
            else:
                self.tainted.discard(name)
                self.origins.pop(name, None)
                self.paths.pop(name, None)
                self.tainted_ranges.pop(name, None)

        self.generic_visit(value)
        for target in node.targets:
            self.visit(target)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            name = node.target.id
            tainted, names = self.expr_taint(node.value)

            if name in self.tainted:
                tainted = True
                names = [name] + names

            if tainted:
                self.tainted.add(name)
                self.paths[name] = self.paths.get(name, []) + [
                    f"{name} updated at line {node.lineno}"
                ]
                self.origins.setdefault(
                    name,
                    self.origins.get(names[0], "untrusted input")
                    if names else "untrusted input",
                )
                self.tainted_ranges[name] = (
                    self.tainted_ranges.get(name, [])
                    + self._unsafe_ranges(node.value)
                )

        self.generic_visit(node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            fake = ast.Assign(targets=[node.target], value=node.value)
            fake.lineno = node.lineno
            self.visit_Assign(fake)

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
        ):
            receiver = node.func.value
            receiver_name = receiver.id if isinstance(receiver, ast.Name) else ""

            looks_cursor = (
                receiver_name in self.cursor_names
                or any(
                    part in receiver_name.lower()
                    for part in ("cursor", "conn", "connection", "db")
                )
            )

            query = node.args[0]
            query_tainted, names = self.expr_taint(query)
            sql_like = self.expr_is_sql(query) or (
                isinstance(query, ast.Name) and query.id in self.tainted
            )

            if looks_cursor and sql_like and query_tainted:
                var = next(
                    (item for item in names if item != "input()"),
                    "input()",
                )
                origin = self.origins.get(
                    var,
                    "input()" if "input()" in names else "untrusted input",
                )

                path = [f"untrusted source: {origin}"]
                path.extend(self.paths.get(var, []))
                path.append(
                    f"SQL execution sink: {ast.unparse(node.func)}(...) "
                    f"at line {node.lineno}"
                )

                ranges = self._unsafe_ranges(query)
                if isinstance(query, ast.Name):
                    ranges = self.tainted_ranges.get(query.id, ranges)

                if not ranges:
                    item = self._range(query)
                    if item:
                        ranges = [item]

                primary = ranges[0] if ranges else {
                    "start_offset": 0,
                    "end_offset": 0,
                    "start_line": node.lineno,
                    "start_column": 0,
                    "end_line": node.lineno,
                    "end_column": 0,
                    "expression": "",
                }

                self.findings.append(
                    Finding(
                        file=self.filename,
                        line=node.lineno,
                        severity="HIGH",
                        message="Untrusted data may reach SQL query text.",
                        source=origin,
                        sink=f"{ast.unparse(node.func)}()",
                        variable=var,
                        path=path,
                        repair=(
                            "Use a parameterized query: keep SQL placeholders "
                            "in the query string and pass user values "
                            "separately to execute()."
                        ),
                        start_offset=primary["start_offset"],
                        end_offset=primary["end_offset"],
                        start_line=primary["start_line"],
                        start_column=primary["start_column"],
                        end_line=primary["end_line"],
                        end_column=primary["end_column"],
                        expression=primary["expression"],
                        highlight_ranges=ranges,
                    )
                )

        self.generic_visit(node)


def analyze_source(source: str, filename: str = "<string>") -> List[Finding]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as error:
        raise ValueError(
            f"Python syntax error at line {error.lineno}: {error.msg}"
        ) from error

    analyzer = Analyzer(filename, source)
    analyzer.visit(tree)

    unique = {}
    for finding in analyzer.findings:
        unique[(finding.line, finding.variable)] = finding

    return list(unique.values())


def analyze_file(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8") as file:
        source = file.read()
    return analyze_source(source, path)
