from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ParseResult:
    ok: bool
    language: str
    error: Optional[str]
    elements: Dict[str, Any]


class _PyAstExtractor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.functions: List[Dict[str, Any]] = []
        self.imports: List[Dict[str, Any]] = []
        self.assignments: List[Dict[str, Any]] = []
        self.string_literals: List[Dict[str, Any]] = []
        self.function_calls: List[Dict[str, Any]] = []

    def _loc(self, node: ast.AST) -> Dict[str, Any]:
        return {
            "line": getattr(node, "lineno", None),
            "col": getattr(node, "col_offset", None),
            "end_line": getattr(node, "end_lineno", None),
            "end_col": getattr(node, "end_col_offset", None),
        }

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.functions.append(
            {
                "name": node.name,
                "args": [a.arg for a in node.args.args],
                "decorators": [ast.unparse(d) if hasattr(ast, "unparse") else type(d).__name__ for d in node.decorator_list],
                **self._loc(node),
            }
        )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.functions.append(
            {
                "name": node.name,
                "args": [a.arg for a in node.args.args],
                "decorators": [ast.unparse(d) if hasattr(ast, "unparse") else type(d).__name__ for d in node.decorator_list],
                "async": True,
                **self._loc(node),
            }
        )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.imports.append({"module": alias.name, "asname": alias.asname, **self._loc(node)})
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(
                {
                    "module": module,
                    "name": alias.name,
                    "asname": alias.asname,
                    "level": node.level,
                    **self._loc(node),
                }
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        try:
            targets = [ast.unparse(t) if hasattr(ast, "unparse") else type(t).__name__ for t in node.targets]
        except Exception:
            targets = [type(t).__name__ for t in node.targets]
        value_repr = None
        try:
            value_repr = ast.unparse(node.value) if hasattr(ast, "unparse") else type(node.value).__name__
        except Exception:
            value_repr = type(node.value).__name__
        self.assignments.append({"targets": targets, "value": value_repr, **self._loc(node)})
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, str):
            self.string_literals.append({"value": node.value, **self._loc(node)})
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> Any:
        # f-strings: keep a placeholder representation
        try:
            s = ast.unparse(node) if hasattr(ast, "unparse") else "<fstring>"
        except Exception:
            s = "<fstring>"
        self.string_literals.append({"value": s, "fstring": True, **self._loc(node)})
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        func_name = None
        try:
            func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else type(node.func).__name__
        except Exception:
            func_name = type(node.func).__name__
        args_repr: List[str] = []
        for a in node.args[:5]:
            try:
                args_repr.append(ast.unparse(a) if hasattr(ast, "unparse") else type(a).__name__)
            except Exception:
                args_repr.append(type(a).__name__)
        self.function_calls.append({"function": func_name, "args_preview": args_repr, **self._loc(node)})
        self.generic_visit(node)


def parse_code(content: str, language: str) -> ParseResult:
    """
    Parse code and extract structured elements.

    - Python: uses builtin `ast` module.
    - JavaScript: lightweight regex extraction (tree-sitter requires external grammar packages).
    """
    language = language.lower()

    if language == "python":
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            return ParseResult(ok=False, language=language, error=str(e), elements={"parse_error": str(e)})
        except Exception as e:
            return ParseResult(ok=False, language=language, error=str(e), elements={"parse_error": str(e)})

        extractor = _PyAstExtractor()
        extractor.visit(tree)
        return ParseResult(
            ok=True,
            language=language,
            error=None,
            elements={
                "functions": extractor.functions,
                "imports": extractor.imports,
                "assignments": extractor.assignments,
                "string_literals": extractor.string_literals,
                "function_calls": extractor.function_calls,
            },
        )

    # JavaScript fallback: keep best-effort structured signals for detectors/LLM context.
    # NOTE: `tree-sitter` is included as a dependency, but JS parsing requires a language grammar package.
    imports: List[Dict[str, Any]] = []
    functions: List[Dict[str, Any]] = []
    string_literals: List[Dict[str, Any]] = []
    function_calls: List[Dict[str, Any]] = []

    import re

    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("import ") or s.startswith("const ") and "require(" in s:
            imports.append({"raw": s, "line": i})
        if re.match(r"function\s+[A-Za-z0-9_$]+\s*\(", s) or re.match(r"(const|let|var)\s+[A-Za-z0-9_$]+\s*=\s*\(.*\)\s*=>", s):
            functions.append({"raw": s, "line": i})
        for m in re.finditer(r"(['\"])(?:(?=(\\?))\2.)*?\1", line):
            string_literals.append({"value": m.group(0), "line": i})
        if "(" in s and ")" in s and not s.startswith("//"):
            # crude call preview
            function_calls.append({"raw": s[:200], "line": i})

    return ParseResult(
        ok=True,
        language=language,
        error=None,
        elements={
            "functions": functions,
            "imports": imports,
            "assignments": [],
            "string_literals": string_literals,
            "function_calls": function_calls,
        },
    )

