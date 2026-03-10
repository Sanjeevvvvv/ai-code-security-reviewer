from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def _make(filename: str, line: int, snippet: str, name: str, severity: str, desc: str, fix: str) -> Dict[str, Any]:
    return {
        "filename": filename,
        "name": name,
        "severity": severity,
        "description": desc,
        "line_number": line,
        "code_snippet": snippet.strip()[:400],
        "fix_suggestion": fix,
        "owasp_category": "A08-Data Integrity Failures",
        "confidence_score": 0.75,
        "source": "detector:deserialization",
        "detector_signal": True,
    }


def detect(filename: str, content: str, language: str, parsed: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if "pickle.loads" in s or "pickle.load" in s:
            findings.append(
                _make(
                    filename,
                    i,
                    line,
                    "Unsafe Deserialization (pickle)",
                    "critical",
                    "pickle deserialization can execute attacker-controlled code when input is untrusted.",
                    "Avoid pickle for untrusted input; use safe formats (JSON) and validate inputs strictly.",
                )
            )
        if re.search(r"\byaml\.load\s*\(", s) and "SafeLoader" not in s and "FullLoader" not in s:
            findings.append(
                _make(
                    filename,
                    i,
                    line,
                    "Unsafe YAML Deserialization",
                    "high",
                    "yaml.load without an explicit safe Loader may construct arbitrary objects and can lead to code execution.",
                    "Use yaml.safe_load (or yaml.load with SafeLoader) and validate schema.",
                )
            )
        if re.search(r"\beval\s*\(", s):
            findings.append(
                _make(
                    filename,
                    i,
                    line,
                    "Dynamic Code Execution (eval)",
                    "critical",
                    "eval() can execute arbitrary code if attacker-controlled input reaches it.",
                    "Avoid eval(); use safe parsers (json, ast.literal_eval for trusted literals) and strict validation.",
                )
            )
        if re.search(r"\bexec\s*\(", s):
            findings.append(
                _make(
                    filename,
                    i,
                    line,
                    "Dynamic Code Execution (exec)",
                    "critical",
                    "exec() executes arbitrary code and is dangerous with untrusted input.",
                    "Avoid exec(); refactor to explicit logic and validate any external input.",
                )
            )

    # De-dupe
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for f in findings:
        key = (f["name"], f.get("line_number"), f.get("code_snippet", "")[:120])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq

