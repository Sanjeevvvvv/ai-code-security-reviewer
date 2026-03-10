from __future__ import annotations

from typing import Dict, Tuple


OWASP_TO_CWE: Dict[str, str] = {
    "A01-Broken Access Control": "CWE-284",
    "A02-Cryptographic Failures": "CWE-310",
    "A03-Injection": "CWE-74",
    "A04-Insecure Design": "CWE-657",
    "A05-Security Misconfiguration": "CWE-16",
    "A06-Vulnerable Components": "CWE-1104",
    "A07-Authentication Failures": "CWE-287",
    "A08-Data Integrity Failures": "CWE-345",
    "A09-Logging Failures": "CWE-778",
    "A10-SSRF": "CWE-918",
}


def _guess_owasp(find_name: str, description: str, source_hint: str = "") -> str:
    hay = f"{find_name} {description} {source_hint}".lower()

    if any(k in hay for k in ["sql injection", "injection", "command injection", "xss", "ldap", "nosql", "template injection"]):
        return "A03-Injection"
    if any(k in hay for k in ["broken access", "authorization", "access control", "idor", "permission", "privilege"]):
        return "A01-Broken Access Control"
    if any(k in hay for k in ["crypto", "encryption", "tls", "ssl", "md5", "sha1", "hash", "weak cipher"]):
        return "A02-Cryptographic Failures"
    if any(k in hay for k in ["auth", "authentication", "login", "password", "session", "jwt", "hardcoded credential"]):
        return "A07-Authentication Failures"
    if any(k in hay for k in ["deserial", "pickle", "yaml.load", "integrity", "signed", "tamper"]):
        return "A08-Data Integrity Failures"
    if any(k in hay for k in ["misconfig", "debug", "verify=false", "unsafe", "cors", "headers", "exposed"]):
        return "A05-Security Misconfiguration"
    if any(k in hay for k in ["dependency", "component", "library", "outdated", "cve"]):
        return "A06-Vulnerable Components"
    if any(k in hay for k in ["logging", "log", "audit", "monitor", "trace"]):
        return "A09-Logging Failures"
    if any(k in hay for k in ["ssrf", "server-side request", "url fetch", "metadata"]):
        return "A10-SSRF"
    if any(k in hay for k in ["insecure design", "threat model", "business logic", "missing validation"]):
        return "A04-Insecure Design"

    # default: injection is the most common scanner category
    return "A03-Injection"


def enrich_finding(finding: Dict) -> Dict:
    name = str(finding.get("name", "Unknown"))
    description = str(finding.get("description", ""))
    source = str(finding.get("source", ""))
    owasp = finding.get("owasp_category") or _guess_owasp(name, description, source_hint=source)
    cwe = OWASP_TO_CWE.get(owasp, "CWE-0")
    finding["owasp_category"] = owasp
    finding["cwe_id"] = finding.get("cwe_id") or cwe
    return finding

