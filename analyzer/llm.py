from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()

import json
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
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
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
    language = language.lower()
    lines = code.splitlines()

    def find_line(substr: str) -> int:
        ss = substr.lower()
        for i, line in enumerate(lines, start=1):
            if ss in line.lower():
                return i
        return 1

    findings: List[Dict[str, Any]] = []

    if any(k in code.lower() for k in ["select ", "insert ", "update ", "delete ", "execute("]):
        ln = find_line("execute(") or find_line("select ")
        findings.append({
            "name": "Potential SQL Injection",
            "severity": "high",
            "description": "User-controlled input appears to be interpolated into an SQL query without parameterization.",
            "line_number": ln,
            "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
            "fix_suggestion": "Use parameterized queries and avoid string concatenation in SQL.",
            "owasp_category": "A03-Injection",
            "confidence_score": 0.74,
        })

    if re.search(r"(password|api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]", code, re.IGNORECASE):
        ln = find_line("password") or find_line("api_key") or find_line("token")
        findings.append({
            "name": "Hardcoded Credential",
            "severity": "high",
            "description": "A hardcoded credential was detected in the source code.",
            "line_number": ln,
            "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
            "fix_suggestion": "Load credentials from environment variables.",
            "owasp_category": "A02-Cryptographic Failures",
            "confidence_score": 0.70,
        })

    if "verify=False" in code or "md5(" in code.lower() or "sha1(" in code.lower():
        ln = find_line("verify=False") or find_line("md5(") or find_line("sha1(")
        findings.append({
            "name": "Insecure Crypto Practice",
            "severity": "medium",
            "description": "Weak hashing algorithm or disabled TLS verification detected.",
            "line_number": ln,
            "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
            "fix_suggestion": "Use bcrypt/argon2 for passwords, SHA-256+ for hashing.",
            "owasp_category": "A07-Authentication Failures",
            "confidence_score": 0.68,
        })

    if any(k in code for k in ["pickle.loads", "yaml.load", "eval(", "exec("]):
        ln = find_line("pickle.loads") or find_line("yaml.load") or find_line("eval(") or find_line("exec(")
        findings.append({
            "name": "Unsafe Deserialization",
            "severity": "critical",
            "description": "Potentially unsafe deserialization or dynamic code execution detected.",
            "line_number": ln,
            "code_snippet": (lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""),
            "fix_suggestion": "Avoid unsafe deserialization; use safe loaders and strict input validation.",
            "owasp_category": "A08-Data Integrity Failures",
            "confidence_score": 0.79,
        })

    if len(findings) > 3:
        findings = findings[:3]
    if not findings:
        findings = [{
            "name": "Potential Security Misconfiguration",
            "severity": "low",
            "description": "No strong signals found; review configuration and dependency hygiene.",
            "line_number": 1,
            "code_snippet": (lines[0].strip() if lines else ""),
            "fix_suggestion": "Enable secure defaults and add automated security testing in CI.",
            "owasp_category": "A05-Security Misconfiguration",
            "confidence_score": 0.35,
        }]
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
            "Context from static analysis:\n"
            f"{json.dumps(payload_context, ensure_ascii=False)[:8000]}\n\n"
            "Code:\n"
            f"{chunk_code_text}\n\n"
            "Return JSON only."
        )

        for attempt in range(1, 8):
            try:
                resp = self._client.chat.completions.create(
                    model=MODEL,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.1,
                    max_tokens=1200,
                )
                content = resp.choices[0].message.content
                if not isinstance(content, str):
                    try:
                        content = "".join(
                            p["text"] if isinstance(p, dict) and "text" in p else str(p)
                            for p in content
                        )
                    except Exception:
                        content = str(content)

                obj = _extract_json_object(content)
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
                    f.setdefault("confidence_score", 0.5)
                    f.setdefault("owasp_category", None)
                    out.append(f)
                return out

            except Exception as e:
                if "rate" in str(e).lower() or "429" in str(e) or isinstance(e, requests.RequestException):
                    _backoff_sleep(attempt)
                    continue
                _backoff_sleep(attempt)
                continue

        return []