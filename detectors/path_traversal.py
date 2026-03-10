"""
Path Traversal Detector
Detects directory traversal and local file inclusion vulnerabilities
"""
import re
from typing import List, Dict

PATH_TRAVERSAL_PATTERNS = [
    {
        "pattern": r"open\s*\([^)]*(?:request|input|user|param|query|GET|POST)",
        "title": "File Open with User-Controlled Path",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "description": "Opening files with user-controlled paths allows directory traversal (../../etc/passwd).",
        "fix": "Use os.path.basename() and validate against a whitelist of allowed paths."
    },
    {
        "pattern": r"os\.path\.join\s*\([^)]*(?:request|input|user|param)",
        "title": "Path Join with User Input",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "description": "os.path.join with user input allows traversal if input starts with /.",
        "fix": "Sanitize user input, use os.path.realpath() and verify it stays within base dir."
    },
    {
        "pattern": r"send_file\s*\([^)]*(?:request|input|user|param|filename)",
        "title": "send_file with User-Controlled Filename",
        "severity": "CRITICAL",
        "cwe": "CWE-22",
        "description": "Serving files based on user-supplied filenames allows reading arbitrary files.",
        "fix": "Use Flask's send_from_directory() with a fixed directory and validated filename."
    },
    {
        "pattern": r"\.\./|\.\.[\\\\]",
        "title": "Hardcoded Path Traversal Sequence",
        "severity": "MEDIUM",
        "cwe": "CWE-22",
        "description": "Path traversal sequence detected in code.",
        "fix": "Validate and sanitize all file paths. Use realpath() to resolve paths."
    },
    {
        "pattern": r"include\s*\$[_a-zA-Z][_a-zA-Z0-9]*|require\s*\$[_a-zA-Z][_a-zA-Z0-9]*",
        "title": "PHP Dynamic File Include",
        "severity": "CRITICAL",
        "cwe": "CWE-98",
        "description": "Dynamic file inclusion with user-controlled variable enables RFI/LFI.",
        "fix": "Use a whitelist of allowed files. Never include files based on user input."
    },
    {
        "pattern": r"Path\s*\([^)]*(?:request|input|user|param)\s*\)\.read",
        "title": "Pathlib Read with User Input",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "description": "Reading file content from a user-controlled path.",
        "fix": "Validate path is within allowed directory using Path.resolve() comparison."
    },
]


def detect_path_traversal(code: str, filename: str = "") -> List[Dict]:
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern_info in PATH_TRAVERSAL_PATTERNS:
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
                    "detector": "path_traversal"
                })

    return findings
