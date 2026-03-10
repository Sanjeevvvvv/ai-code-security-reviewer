from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


HARD_CODED_CRED = re.compile(r"\b(username|user|login|password|passwd)\b\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE)


def _make_finding(filename: str, line: int, snippet: str, name: str, severity: str, description: str, fix: str) -> Dict[str, Any]:
    return {
        "filename": filename,
        "name": name,
        "severity": severity,
        "description": description,
        "line_number": line,
        "code_snippet": snippet.strip()[:400],
        "fix_suggestion": fix,
        "owasp_category": "A07-Authentication Failures",
        "confidence_score": 0.70,
        "source": "detector:auth",
        "detector_signal": True,
    }


def detect(filename: str, content: str, language: str, parsed: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        if "verify=False" in line.replace(" ", ""):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "TLS Certificate Verification Disabled",
                    "medium",
                    "TLS verification appears disabled (verify=False), enabling MITM attacks.",
                    "Remove verify=False and validate certificates. If needed for dev, gate behind an explicit development-only flag.",
                )
            )
        if re.search(r"\b(md5|sha1)\s*\(", line, re.IGNORECASE):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "Weak Hash Used for Passwords",
                    "high",
                    "MD5/SHA1 are not suitable for password hashing and are vulnerable to fast cracking.",
                    "Use a password hashing function like bcrypt or Argon2 with proper salts and parameters.",
                )
            )
        if HARD_CODED_CRED.search(line):
            findings.append(
                _make_finding(
                    filename,
                    i,
                    line,
                    "Hardcoded Credentials",
                    "high",
                    "Potential hardcoded username/password detected.",
                    "Use secure credential storage (env/secrets manager) and avoid embedding credentials in source code.",
                )
            )

    # Heuristic: Flask/Django route without auth decorator (very best-effort)
    if language.lower() == "python" and parsed:
        funcs = parsed.get("functions") or []
        for f in funcs:
            decorators = " ".join([str(d).lower() for d in (f.get("decorators") or [])])
            name = str(f.get("name") or "")
            line = int(f.get("line") or 1)
            if "route" in decorators and not any(k in decorators for k in ["login_required", "require_auth", "auth", "permission", "jwt_required"]):
                findings.append(
                    _make_finding(
                        filename,
                        line,
                        f"def {name}(...):",
                        "Potential Missing Authentication on Route Handler",
                        "medium",
                        "A route handler appears to have no obvious authentication decorator/guard.",
                        "Ensure sensitive routes enforce authentication/authorization checks (e.g., @login_required / RBAC / permission checks).",
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

