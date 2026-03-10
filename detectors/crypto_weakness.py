"""
Cryptography Weakness Detector
Detects weak encryption, hashing, and random number generation
"""
import re
from typing import List, Dict

CRYPTO_PATTERNS = [
    {
        "pattern": r"hashlib\.md5\s*\(",
        "title": "Weak Hash: MD5",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "description": "MD5 is cryptographically broken and should not be used for security purposes.",
        "fix": "Use hashlib.sha256() or hashlib.sha3_256() instead."
    },
    {
        "pattern": r"hashlib\.sha1\s*\(",
        "title": "Weak Hash: SHA1",
        "severity": "MEDIUM",
        "cwe": "CWE-327",
        "description": "SHA1 is considered weak and vulnerable to collision attacks.",
        "fix": "Use hashlib.sha256() or hashlib.sha3_256() for security-sensitive contexts."
    },
    {
        "pattern": r"DES\.|3DES\.|RC4\.|Blowfish\.",
        "title": "Weak Encryption Algorithm",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "description": "DES, 3DES, RC4, and Blowfish are deprecated encryption algorithms.",
        "fix": "Use AES-256 with GCM mode (cryptography library recommended)."
    },
    {
        "pattern": r"random\.random\(\)|random\.randint\(|random\.choice\(",
        "title": "Insecure Random Number Generator",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "description": "Python's random module is not cryptographically secure.",
        "fix": "Use secrets.token_bytes(), secrets.token_hex(), or os.urandom() for security."
    },
    {
        "pattern": r"MODE_ECB",
        "title": "Weak Cipher Mode: ECB",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "description": "ECB mode does not provide semantic security and reveals patterns.",
        "fix": "Use AES-GCM or AES-CBC with a random IV instead of ECB mode."
    },
    {
        "pattern": r"ssl\._create_unverified_context|verify\s*=\s*False",
        "title": "SSL Certificate Verification Disabled",
        "severity": "HIGH",
        "cwe": "CWE-295",
        "description": "Disabling SSL verification exposes connections to MITM attacks.",
        "fix": "Always verify SSL certificates. Use certifi for certificate bundles."
    },
    {
        "pattern": r"PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1\b",
        "title": "Deprecated SSL/TLS Protocol",
        "severity": "HIGH",
        "cwe": "CWE-326",
        "description": "SSLv2, SSLv3, and TLS 1.0 are deprecated and vulnerable.",
        "fix": "Use ssl.PROTOCOL_TLS_CLIENT with minimum TLS 1.2."
    },
    {
        "pattern": r"pbkdf2_hmac.*(?:sha1|md5)|bcrypt.*rounds\s*=\s*[1-9]\b(?![\d])",
        "title": "Weak Password Hashing Parameters",
        "severity": "MEDIUM",
        "cwe": "CWE-916",
        "description": "Password hashing with weak algorithm or insufficient rounds.",
        "fix": "Use bcrypt with rounds>=12 or Argon2 for password hashing."
    },
]


def detect_crypto_weakness(code: str, filename: str = "") -> List[Dict]:
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern_info in CRYPTO_PATTERNS:
            if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                findings.append({
                    "title": pattern_info["title"],
                    "severity": pattern_info["severity"],
                    "cwe": pattern_info["cwe"],
                    "owasp": "A02:2021 – Cryptographic Failures",
                    "line": i,
                    "code_snippet": line.strip(),
                    "description": pattern_info["description"],
                    "fix": pattern_info["fix"],
                    "filename": filename,
                    "detector": "crypto_weakness"
                })

    return findings
