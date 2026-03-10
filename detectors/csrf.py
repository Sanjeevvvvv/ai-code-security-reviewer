"""
CSRF (Cross-Site Request Forgery) Detector
Detects missing CSRF protections in web frameworks
"""
import re
from typing import List, Dict

CSRF_PATTERNS = [
    {
        "pattern": r"@app\.route\([^)]+methods\s*=\s*\[[^\]]*['\"]POST['\"][^\]]*\]\s*\)(?!.*csrf)",
        "title": "Flask Route Missing CSRF Protection",
        "severity": "HIGH",
        "cwe": "CWE-352",
        "description": "POST route has no CSRF token validation.",
        "fix": "Use Flask-WTF with CSRFProtect() or validate tokens manually."
    },
    {
        "pattern": r"csrf_exempt",
        "title": "CSRF Protection Explicitly Disabled",
        "severity": "HIGH",
        "cwe": "CWE-352",
        "description": "CSRF protection has been explicitly disabled on this view.",
        "fix": "Remove @csrf_exempt unless absolutely necessary. Add CSRF token validation."
    },
    {
        "pattern": r"CSRF_COOKIE_SECURE\s*=\s*False",
        "title": "CSRF Cookie Not Secured",
        "severity": "MEDIUM",
        "cwe": "CWE-352",
        "description": "CSRF cookie is not set to Secure, making it vulnerable over HTTP.",
        "fix": "Set CSRF_COOKIE_SECURE = True in production."
    },
    {
        "pattern": r"verify_csrf_token\s*=\s*False|csrf_check\s*=\s*False",
        "title": "CSRF Verification Disabled",
        "severity": "CRITICAL",
        "cwe": "CWE-352",
        "description": "CSRF token verification is explicitly turned off.",
        "fix": "Never disable CSRF verification. Implement proper token validation."
    },
    {
        "pattern": r"SameSite\s*=\s*None(?!.*Secure)",
        "title": "Cookie SameSite=None Without Secure Flag",
        "severity": "MEDIUM",
        "cwe": "CWE-352",
        "description": "SameSite=None without Secure flag leaves cookies vulnerable to CSRF.",
        "fix": "Use SameSite=Strict or SameSite=Lax, or add Secure flag."
    },
    {
        "pattern": r"Access-Control-Allow-Origin.*\*",
        "title": "Wildcard CORS Enabling CSRF",
        "severity": "HIGH",
        "cwe": "CWE-352",
        "description": "Wildcard CORS policy allows any origin to make cross-site requests.",
        "fix": "Restrict Access-Control-Allow-Origin to trusted domains only."
    },
]


def detect_csrf(code: str, filename: str = "") -> List[Dict]:
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern_info in CSRF_PATTERNS:
            if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                findings.append({
                    "title": pattern_info["title"],
                    "severity": pattern_info["severity"],
                    "cwe": pattern_info["cwe"],
                    "owasp": "A01:2021 – Broken Access Control",
                    "line": i,
                    "code_snippet": line.strip(),
                    "description": pattern_info["description"],
                    "fix": pattern_info["fix"],
                    "filename": filename,
                    "detector": "csrf"
                })

    return findings
