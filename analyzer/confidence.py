from __future__ import annotations

import re
from typing import Dict, Tuple


SEVERITY_BOOST = {"low": 0.02, "medium": 0.05, "high": 0.08, "critical": 0.12}


def _is_test_file(filename: str) -> bool:
    f = filename.replace("\\", "/").lower()
    return "/tests/" in f or f.endswith("_test.py") or f.startswith("test_")


def _looks_commented(code_snippet: str) -> bool:
    s = (code_snippet or "").strip()
    return s.startswith("#") or s.startswith("//") or s.startswith("/*") or s.startswith("*")


def _string_literal_only(code_snippet: str) -> bool:
    s = (code_snippet or "").strip()
    if not s:
        return True
    # crude: treat single quoted string / triple as "literal only"
    return bool(re.fullmatch(r"([rubfRUBF]*)(['\"]).*\2", s)) or s.startswith('"""') or s.startswith("'''")


def score_finding(finding: Dict) -> Tuple[float, str]:
    """
    Returns (confidence_score, reasoning).

    Inputs expected:
      - confidence_score (float) from LLM or detector default
      - severity
      - sources (list) or source (str)
      - detector_signal (bool)
      - filename, code_snippet
    """
    base = float(finding.get("confidence_score") or 0.5)
    severity = str(finding.get("severity") or "medium").lower()
    filename = str(finding.get("filename") or "")
    snippet = str(finding.get("code_snippet") or "")

    reasons = [f"base={base:.2f}"]

    # boosts
    det = bool(finding.get("detector_signal")) or ("detector" in (finding.get("source") or "").lower())
    if det:
        base += 0.12
        reasons.append("boost:detector_flagged(+0.12)")

    sources = finding.get("sources")
    if isinstance(sources, list) and len(sources) >= 2:
        base += 0.06
        reasons.append("boost:multiple_sources(+0.06)")

    base += SEVERITY_BOOST.get(severity, 0.0)
    reasons.append(f"boost:severity({severity})({SEVERITY_BOOST.get(severity, 0.0):+.2f})")

    # penalties
    if _is_test_file(filename):
        base -= 0.12
        reasons.append("penalty:test_file(-0.12)")

    if _looks_commented(snippet):
        base -= 0.10
        reasons.append("penalty:commented_code(-0.10)")

    if _string_literal_only(snippet):
        base -= 0.10
        reasons.append("penalty:string_literal_only(-0.10)")

    base = max(0.0, min(1.0, base))
    return base, "; ".join(reasons)

