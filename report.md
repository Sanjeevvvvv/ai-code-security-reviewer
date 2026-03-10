Scanning file: tests\vulnerable_samples\auth_vuln.py
# Security Scan Report

Grade: F (0/100) - Critical - Immediate action required

Total findings: 4

## 1. Flask Route Missing CSRF Protection [HIGH]
- File: tests\vulnerable_samples\auth_vuln.py Line 13
- CWE: CWE-352 | OWASP: A01:2021 – Broken Access Control
- Description: POST route has no CSRF token validation.
- Fix: Use Flask-WTF with CSRFProtect() or validate tokens manually.

## 2. Weak Hash: MD5 [HIGH]
- File: tests\vulnerable_samples\auth_vuln.py Line 26
- CWE: CWE-327 | OWASP: A02:2021 – Cryptographic Failures
- Description: MD5 is cryptographically broken and should not be used for security purposes.
- Fix: Use hashlib.sha256() or hashlib.sha3_256() instead.

## 3. SSL Certificate Verification Disabled [HIGH]
- File: tests\vulnerable_samples\auth_vuln.py Line 37
- CWE: CWE-295 | OWASP: A02:2021 – Cryptographic Failures
- Description: Disabling SSL verification exposes connections to MITM attacks.
- Fix: Always verify SSL certificates. Use certifi for certificate bundles.

## 4. None [high]
- File: tests\vulnerable_samples\auth_vuln.py Line None
- CWE: None | OWASP: None
- Description: MD5/SHA1 are not suitable for password hashing and are vulnerable to fast cracking.
- Fix: None
