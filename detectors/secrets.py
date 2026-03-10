from __future__ import annotations

import re
from typing import Any, Dict, List


AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_TOKEN = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH)? ?PRIVATE KEY-----")

# generic key/value assignments
GENERIC_SECRET_ASSIGN = re.compile(
    r"\b(password|passwd|secret|api_key|apikey|token|private_key)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    re.IGNORECASE,
)


def _make_finding(filename: str, line: int, snippet: str, name: str, severity: str, description: str) -> Dict[str, Any]:
    return {
        "filename": filename,
        "name": name,
        "severity": severity,
        "description": description,
        "line_number": line,
        "code_snippet": snippet.strip()[:400],
        "fix_suggestion": "Remove secrets from code. Use environment variables or a secrets manager. Rotate any exposed credentials immediately.",
        "owasp_category": "A02-Cryptographic Failures",
        "confidence_score": 0.80 if severity in {"high", "critical"} else 0.65,
        "source": "detector:secrets",
        "detector_signal": True,
    }


def detect(filename: str, content: str, language: str, parsed: Dict | None = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        if AWS_ACCESS_KEY.search(line):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "Hardcoded AWS Access Key",
                    "critical",
                    "Detected an AWS Access Key ID pattern in source code.",
                )
            )
        if GITHUB_TOKEN.search(line):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "Hardcoded GitHub Token",
                    "critical",
                    "Detected a GitHub Personal Access Token pattern in source code.",
                )
            )
        if PRIVATE_KEY_HEADER.search(line):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "Private Key Material in Source",
                    "critical",
                    "Detected a private key header; private keys must never be committed to source control.",
                )
            )
        if GENERIC_SECRET_ASSIGN.search(line):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "Hardcoded Secret Assignment",
                    "high",
                    "Detected a suspicious assignment to a secret-like variable name.",
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

