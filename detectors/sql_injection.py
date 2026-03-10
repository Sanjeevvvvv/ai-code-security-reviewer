from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional


SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|JOIN)\b", re.IGNORECASE)


def _make_finding(filename: str, line: int, snippet: str, detail: str) -> Dict[str, Any]:
    return {
        "filename": filename,
        "name": "Potential SQL Injection",
        "severity": "high",
        "description": detail,
        "line_number": line,
        "code_snippet": snippet.strip()[:400],
        "fix_suggestion": "Use parameterized queries / prepared statements. Avoid f-strings, string concatenation, or .format/% formatting for SQL.",
        "owasp_category": "A03-Injection",
        "confidence_score": 0.70,
        "source": "detector:sql_injection",
        "detector_signal": True,
    }


def _regex_scan(filename: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if not SQL_KEYWORDS.search(line):
            continue
        # f-string / format / concatenation patterns
        if "f\"" in line or "f'" in line:
            findings.append(_make_finding(filename, i, line, "SQL query appears to be built using an f-string."))
        if ".format(" in line and "SELECT" in line.upper():
            findings.append(_make_finding(filename, i, line, "SQL query appears to be built using .format()."))
        if "+" in line and ("SELECT" in line.upper() or "WHERE" in line.upper()):
            findings.append(_make_finding(filename, i, line, "SQL query appears to be built via string concatenation."))
        if "%" in line and ("SELECT" in line.upper() or "WHERE" in line.upper()):
            findings.append(_make_finding(filename, i, line, "SQL query appears to be built using %-formatting."))
        if re.search(r"\bexecute\s*\(", line) and re.search(r"[+%]|\bf['\"]", line):
            findings.append(_make_finding(filename, i, line, "Database execute() call appears to receive a dynamically constructed SQL string."))
    return findings


class _ExecuteCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> Any:
        # Look for *.execute(<sql_expr>, ...) where sql_expr is f-string, BinOp(+), Mod(%), or .format()
        func_repr = ""
        try:
            func_repr = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        except Exception:
            func_repr = ""

        if not func_repr.endswith(".execute") and func_repr != "execute":
            self.generic_visit(node)
            return

        if not node.args:
            self.generic_visit(node)
            return

        sql_expr = node.args[0]
        risky = False
        detail = ""
        if isinstance(sql_expr, ast.JoinedStr):
            risky = True
            detail = "SQL string passed to execute() is an f-string (JoinedStr)."
        elif isinstance(sql_expr, ast.BinOp) and isinstance(sql_expr.op, ast.Add):
            risky = True
            detail = "SQL string passed to execute() is built using string concatenation (+)."
        elif isinstance(sql_expr, ast.BinOp) and isinstance(sql_expr.op, ast.Mod):
            risky = True
            detail = "SQL string passed to execute() is built using %-formatting."
        elif isinstance(sql_expr, ast.Call):
            # .format(...)
            try:
                s = ast.unparse(sql_expr) if hasattr(ast, "unparse") else ""
            except Exception:
                s = ""
            if ".format(" in s:
                risky = True
                detail = "SQL string passed to execute() is built using .format()."

        if risky:
            line = getattr(node, "lineno", 1) or 1
            snippet = ""
            try:
                snippet = ast.unparse(node) if hasattr(ast, "unparse") else ""
            except Exception:
                snippet = ""
            self.findings.append(
                _make_finding(
                    filename="<unknown>",
                    line=line,
                    snippet=snippet or "execute(...)",
                    detail=detail,
                )
            )

        self.generic_visit(node)


def detect(filename: str, content: str, language: str, parsed: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    language = language.lower()
    findings: List[Dict[str, Any]] = []

    if language != "python":
        # JS: regex-only
        return _regex_scan(filename, content)

    findings.extend(_regex_scan(filename, content))

    try:
        tree = ast.parse(content)
        v = _ExecuteCallVisitor()
        v.visit(tree)
        for f in v.findings:
            f["filename"] = filename
        findings.extend(v.findings)
    except Exception:
        pass

    # de-dupe
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for f in findings:
        key = (f["name"], f.get("line_number"), f.get("code_snippet", "")[:120])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq

