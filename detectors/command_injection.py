"""
Command Injection Detector
Detects OS command injection vulnerabilities
"""
import re
from typing import List, Dict

COMMAND_INJECTION_PATTERNS = [
    {
        "pattern": r"os\.system\s*\([^)]*(?:request|input|user|param|query|f[\"']|%s|format)",
        "title": "Command Injection via os.system",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "description": "os.system() with user-controlled input allows arbitrary command execution.",
        "fix": "Use subprocess.run() with a list of arguments (no shell=True) and validate inputs."
    },
    {
        "pattern": r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*(?:request|input|user|param)",
        "title": "Command Injection via subprocess with shell=True",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "description": "subprocess with shell=True and user input allows command injection.",
        "fix": "Pass a list of arguments and set shell=False (the default)."
    },
    {
        "pattern": r"subprocess\.(call|run|Popen)\s*\(\s*(?:f[\"']|[\"'][^\"']*\+)",
        "title": "Subprocess with String Concatenation",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "description": "Building subprocess commands via string concatenation or f-strings is dangerous.",
        "fix": "Use a list: subprocess.run(['cmd', arg1, arg2], shell=False)"
    },
    {
        "pattern": r"commands\.(getoutput|getstatusoutput)\s*\(",
        "title": "Deprecated commands Module Usage",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "description": "The commands module executes shell commands and is deprecated/unsafe.",
        "fix": "Replace with subprocess.run() using argument lists."
    },
    {
        "pattern": r"popen\s*\([^)]*(?:request|input|user|param|f[\"'])",
        "title": "Command Injection via popen",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "description": "popen with user-controlled input allows arbitrary command execution.",
        "fix": "Use subprocess.run() with a list of arguments."
    },
    {
        "pattern": r"exec\s*\([^)]*(?:request|input|user|param)",
        "title": "Code Injection via exec",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "description": "exec() with user input allows arbitrary code execution.",
        "fix": "Never use exec() with user input. Redesign the logic."
    },
    {
        "pattern": r"__import__\s*\([^)]*(?:request|input|user|param)",
        "title": "Dynamic Import with User Input",
        "severity": "HIGH",
        "cwe": "CWE-94",
        "description": "Dynamically importing user-specified modules is dangerous.",
        "fix": "Use a whitelist of allowed module names before importing."
    },
]


def detect_command_injection(code: str, filename: str = "") -> List[Dict]:
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern_info in COMMAND_INJECTION_PATTERNS:
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
                    "detector": "command_injection"
                })

    return findings
