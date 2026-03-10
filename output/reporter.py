from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"low": 3, "medium": 7, "high": 15, "critical": 25}


def severity_at_least(sev: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(sev.lower(), 0) >= SEVERITY_RANK.get(minimum.lower(), 0)


def compute_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Overall risk score 0-100 based on severity-weighted, confidence-weighted sum.
    """
    if not findings:
        return 0
    total = 0.0
    for f in findings:
        sev = str(f.get("severity") or "low").lower()
        conf = float(f.get("confidence_score") or 0.5)
        total += SEVERITY_WEIGHT.get(sev, 0) * (0.6 + 0.4 * conf)
    # Normalize: assume "very bad" is ~10 high/critical issues
    score = int(min(100, round((total / 160.0) * 100)))
    return max(0, score)


def build_summary(total_files: int, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_sev = Counter(str(f.get("severity") or "low").lower() for f in findings)
    by_owasp = Counter(str(f.get("owasp_category") or "Unknown") for f in findings)

    # Top 3 most critical (then confidence)
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK.get(str(f.get("severity") or "low").lower(), 0),
            -float(f.get("confidence_score") or 0.0),
        ),
    )
    top3 = sorted_findings[:3]

    return {
        "total_files_scanned": total_files,
        "total_findings": len(findings),
        "vulnerabilities_by_severity": dict(by_sev),
        "owasp_breakdown": dict(by_owasp),
        "top_3_findings": [
            {
                "filename": f.get("filename"),
                "name": f.get("name"),
                "severity": f.get("severity"),
                "line_number": f.get("line_number"),
                "confidence_score": f.get("confidence_score"),
                "owasp_category": f.get("owasp_category"),
                "cwe_id": f.get("cwe_id"),
            }
            for f in top3
        ],
        "overall_risk_score": compute_risk_score(findings),
    }

