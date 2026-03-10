from __future__ import annotations

import json
import os
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from groq import Groq

from utils.chunker import chunk_code


MODEL = "llama3-70b-8192"


SYSTEM_PROMPT = (
    "You are a senior security engineer. Analyze the following code for vulnerabilities. "
    "Focus on OWASP Top 10. For each vulnerability found return: "
    "name, severity (low/medium/high/critical), description, line_number, code_snippet, "
    "fix_suggestion, owasp_category, confidence_score (0.0 to 1.0). "
    "Return JSON only, as an object with a single key `findings` that is a list."
)


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return None
    # direct parse
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # try to extract the first JSON object
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _backoff_sleep(attempt: int) -> None:
    base = min(20.0, 1.5 ** attempt)
    jitter = random.uniform(0.0, 0.35 * base)
    time.sleep(base + jitter)


def _mock_findings_for_code(code: str, filename: str, language: str) -> List[Dict[str, Any]]:
    """
    Mock mode: generate realistic findings based on keyword heuristics.
    Returns 2-3 findings per file when possible.
    """
    language = language.lower()
    lines = code.splitlines()

    def find_line(substr: str) -> int:
        ss = substr.lower()
        for i, line in enumerate(lines, start=1):
            if ss in line.lower():
                return i
        return 1

    findings: List[Dict[str, Any]] = []

    # SQL injection heuristics
    if any(k in code.lower() for k in ["select ", "insert ", "update ", "delete ", "execute("]):
        ln = find_line("execute(") or find_line("select ")
        findings.append(
            {
                "name": "Potential SQL Injection",
                "severity": "high",
                "description": "User-controlled input appears to be interpolated into an SQL query without parameterization.",
                "line_number": ln,
                "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
                "fix_suggestion": "Use parameterized queries (prepared statements) and avoid string concatenation/formatting in SQL.",
                "owasp_category": "A03-Injection",
                "confidence_score": 0.74,
            }
        )

    # Secrets heuristics
    if re.search(r"AKIA[0-9A-Z]{16}", code) or re.search(r"ghp_[A-Za-z0-9]{36}", code) or "BEGIN PRIVATE KEY" in code:
        ln = find_line("AKIA") if "AKIA" in code else find_line("ghp_")
        findings.append(
            {
                "name": "Hardcoded Secret in Source",
                "severity": "critical",
                "description": "A credential-like value is embedded directly in the source code, which risks leakage and unauthorized access.",
                "line_number": ln,
                "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
                "fix_suggestion": "Move secrets to a dedicated secrets manager or environment variables; rotate exposed credentials immediately.",
                "owasp_category": "A02-Cryptographic Failures",
                "confidence_score": 0.83,
            }
        )

    if re.search(r"(password|api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]", code, re.IGNORECASE):
        ln = find_line("password") or find_line("api_key") or find_line("token")
        findings.append(
            {
                "name": "Hardcoded Credential Assignment",
                "severity": "high",
                "description": "A variable assignment looks like a hardcoded credential. Hardcoding secrets increases risk of compromise.",
                "line_number": ln,
                "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
                "fix_suggestion": "Load credentials from environment variables and ensure secrets are not committed to version control.",
                "owasp_category": "A02-Cryptographic Failures",
                "confidence_score": 0.70,
            }
        )

    # Auth / crypto heuristics
    if "verify=False" in code or "md5(" in code.lower() or "sha1(" in code.lower():
        ln = find_line("verify=False") if "verify=False" in code else find_line("md5(") or find_line("sha1(")
        findings.append(
            {
                "name": "Insecure Authentication / Crypto Practice",
                "severity": "medium" if "verify=False" in code else "high",
                "description": "The code appears to disable TLS verification and/or uses weak hashing for credential handling.",
                "line_number": ln,
                "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
                "fix_suggestion": "Do not disable TLS verification in production; use modern password hashing (bcrypt/argon2) and strong algorithms.",
                "owasp_category": "A07-Authentication Failures",
                "confidence_score": 0.68,
            }
        )

    # Deserialization heuristics
    if any(k in code for k in ["pickle.loads", "yaml.load", "eval(", "exec("]):
        ln = find_line("pickle.loads") or find_line("yaml.load") or find_line("eval(") or find_line("exec(")
        findings.append(
            {
                "name": "Unsafe Deserialization / Code Execution",
                "severity": "critical",
                "description": "Potentially unsafe deserialization or dynamic code execution detected. This can lead to remote code execution.",
                "line_number": ln,
                "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
                "fix_suggestion": "Avoid unsafe deserialization and dynamic code execution; use safe loaders and strict input validation.",
                "owasp_category": "A08-Data Integrity Failures",
                "confidence_score": 0.79,
            }
        )

    # Keep 2-3 by default
    if len(findings) > 3:
        findings = findings[:3]
    if not findings:
        findings = [
            {
                "name": "Potential Security Misconfiguration",
                "severity": "low",
                "description": "Mock mode could not identify strong signals; review configuration and dependency hygiene.",
                "line_number": 1,
                "code_snippet": (lines[0].strip() if lines else ""),
                "fix_suggestion": "Enable secure defaults and add automated security testing (SAST/DAST) in CI.",
                "owasp_category": "A05-Security Misconfiguration",
                "confidence_score": 0.35,
            }
        ]
    return findings


class LLMAnalyzer:
    def __init__(self) -> None:
        self.api_key = os.getenv("GROQ_API_KEY")
        self.mock_mode = not bool(self.api_key)

        self._client: Optional[Groq] = None
        if not self.mock_mode:
            self._client = Groq(api_key=self.api_key)

    def analyze(
        self,
        code: str,
        *,
        filename: str,
        language: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Returns (findings, mock_mode_used).
        """
        if self.mock_mode or self._client is None:
            return _mock_findings_for_code(code, filename, language), True

        chunks = chunk_code(code, language=language, max_tokens=3000, overlap_lines=10)
        merged: List[Dict[str, Any]] = []
        for chunk in chunks:
            findings = self._analyze_chunk(
                chunk.content,
                filename=filename,
                language=language,
                context=context,
                line_offset=chunk.start_line - 1,
            )
            merged.extend(findings)

        # De-dupe within LLM results
        uniq: List[Dict[str, Any]] = []
        seen = set()
        for f in merged:
            key = (
                str(f.get("name", "")).lower(),
                str(f.get("severity", "")).lower(),
                int(f.get("line_number") or 0),
                (f.get("code_snippet") or "").strip(),
            )
            if key not in seen:
                seen.add(key)
                uniq.append(f)
        return uniq, False

    def _analyze_chunk(
        self,
        chunk_code_text: str,
        *,
        filename: str,
        language: str,
        context: Optional[Dict[str, Any]],
        line_offset: int,
    ) -> List[Dict[str, Any]]:
        payload_context = context or {}

        user_prompt = (
            f"Filename: {filename}\n"
            f"Language: {language}\n\n"
            "Context from static analysis (parsing + detectors):\n"
            f"{json.dumps(payload_context, ensure_ascii=False)[:8000]}\n\n"
            "Code:\n"
            f"{chunk_code_text}\n\n"
            "Return JSON only."
        )

        for attempt in range(1, 8):
            try:
                resp = self._client.chat.completions.create(  # type: ignore[union-attr]
                    model=MODEL,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.1,
                    max_tokens=1200,
                )
                choice = resp.choices[0]
                content = choice.message.content
                if isinstance(content, str):
                    text = content
                else:
                    # groq python SDK may return a list of content parts
                    try:
                        text = "".join(part["text"] if isinstance(part, dict) and "text" in part else str(part) for part in content)  # type: ignore[arg-type]
                    except Exception:
                        text = str(content)

                obj = _extract_json_object(text)
                if not obj or "findings" not in obj or not isinstance(obj["findings"], list):
                    return []

                out: List[Dict[str, Any]] = []
                for f in obj["findings"]:
                    if not isinstance(f, dict):
                        continue
                    ln = f.get("line_number")
                    try:
                        ln_int = int(ln) if ln is not None else 1
                    except Exception:
                        ln_int = 1
                    f["line_number"] = max(1, ln_int + line_offset)
                    # ensure required keys exist
                    f.setdefault("confidence_score", 0.5)
                    f.setdefault("owasp_category", None)
                    out.append(f)
                return out
            except Exception as e:
                # rate limit / transient errors: backoff
                if "rate" in str(e).lower() or "429" in str(e) or isinstance(e, requests.RequestException):
                    _backoff_sleep(attempt)
                    continue
                _backoff_sleep(attempt)
                continue

        # give up gracefully
        return []

