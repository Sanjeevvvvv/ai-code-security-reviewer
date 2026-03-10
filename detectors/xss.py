"""
XSS (Cross-Site Scripting) Detector
Detects reflected, stored, and DOM-based XSS vulnerabilities
"""
import re
import ast
from typing import List, Dict

XSS_PATTERNS = [
    {
        "pattern": r"innerHTML\s*=\s*[^;\"']+(?:request|input|user|param|query|data)",
        "title": "DOM-based XSS via innerHTML",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "description": "Direct assignment of user input to innerHTML allows script injection.",
        "fix": "Use textContent instead of innerHTML, or sanitize with DOMPurify."
    },
    {
        "pattern": r"document\.write\s*\([^)]*(?:request|input|user|param|query)",
        "title": "XSS via document.write",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "description": "document.write with user input can inject malicious scripts.",
        "fix": "Avoid document.write. Use DOM manipulation methods with sanitized data."
    },
    {
        "pattern": r"render_template_string\s*\([^)]*%",
        "title": "Server-Side Template Injection / XSS",
        "severity": "CRITICAL",
        "cwe": "CWE-79",
        "description": "render_template_string with user input allows template injection and XSS.",
        "fix": "Use render_template with static template files instead."
    },
    {
        "pattern": r"Markup\s*\([^)]*(?:request|input|user|param)",
        "title": "Flask Markup with User Input",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "description": "Wrapping user input in Markup() disables Jinja2 auto-escaping.",
        "fix": "Never wrap user-controlled data in Markup(). Let Jinja2 auto-escape."
    },
    {
        "pattern": r"\.raw\s*\([^)]*(?:request|input|user|param)",
        "title": "Raw HTML Output with User Input",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "description": "Outputting raw HTML from user input enables XSS.",
        "fix": "Escape all user input before rendering in HTML context."
    },
    {
        "pattern": r"HttpResponse\s*\([^)]*(?:request\.GET|request\.POST|request\.data)",
        "title": "Django Unescaped HttpResponse",
        "severity": "MEDIUM",
        "cwe": "CWE-79",
        "description": "Returning user input directly in HttpResponse can cause XSS.",
        "fix": "Use Django's escape() or mark_safe() carefully, prefer template rendering."
    },
    {
        "pattern": r"eval\s*\([^)]*(?:location|document|window|cookie)",
        "title": "DOM XSS via eval",
        "severity": "CRITICAL",
        "cwe": "CWE-79",
        "description": "eval() with DOM sources enables script injection.",
        "fix": "Never use eval() with user-controllable data."
    },
]


def detect_xss(code: str, filename: str = "") -> List[Dict]:
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern_info in XSS_PATTERNS:
            if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                findings.append({
                    "title": pattern_info["title"],
                    "severity": pattern_info["severity"],
                    "cwe": pattern_info["cwe"],
                    "owasp": "A03:2021 – Injection",
                    "line": i,
                    "code_snippet": line.strip(),
                    "description": pattern_info["description"],
                    "fix": pattern_info["fix"],
                    "filename": filename,
                    "detector": "xss"
                })

    return findings
