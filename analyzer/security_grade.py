"""
Security Grade Scorer
Gives a codebase a letter grade (A-F) based on findings
"""
from typing import List, Dict, Tuple


SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 4,
    "LOW": 1,
}

GRADE_THRESHOLDS = [
    (0,   "A+", "Excellent - No vulnerabilities detected"),
    (5,   "A",  "Very Good - Minor issues only"),
    (15,  "B",  "Good - Some low-severity issues"),
    (30,  "C",  "Fair - Moderate security concerns"),
    (55,  "D",  "Poor - Significant vulnerabilities present"),
    (85,  "F",  "Critical - Immediate action required"),
]


def calculate_security_grade(findings: List[Dict], lines_of_code: int = 100) -> Dict:
    """
    Calculate a security grade for a codebase.
    
    Returns:
        {
            "grade": "B",
            "score": 78,          # 0-100 (higher = more secure)
            "risk_score": 22,     # weighted penalty score
            "label": "Good",
            "breakdown": {...},
            "recommendation": "..."
        }
    """
    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev = finding.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1

    # Calculate raw risk score
    risk_score = sum(counts[sev] * SEVERITY_WEIGHTS[sev] for sev in counts)

    # Normalize by lines of code (per 100 LOC)
    if lines_of_code > 0:
        normalized_risk = risk_score / (lines_of_code / 100)
    else:
        normalized_risk = risk_score

    # Determine grade
    grade = "F"
    label = "Critical"
    for threshold, g, l in GRADE_THRESHOLDS:
        if normalized_risk <= threshold or threshold == 85:
            grade = g
            label = l
            if normalized_risk <= threshold:
                break

    # Convert to 0-100 score (100 = most secure)
    score = max(0, min(100, int(100 - normalized_risk)))

    # Generate recommendation
    recommendation = _generate_recommendation(counts, grade)

    return {
        "grade": grade,
        "score": score,
        "risk_score": round(normalized_risk, 2),
        "label": label,
        "breakdown": counts,
        "total_findings": len(findings),
        "recommendation": recommendation,
        "lines_of_code": lines_of_code,
    }


def _generate_recommendation(counts: Dict, grade: str) -> str:
    if counts["CRITICAL"] > 0:
        return f"🚨 Fix {counts['CRITICAL']} CRITICAL issue(s) immediately — these can be exploited right now."
    elif counts["HIGH"] > 0:
        return f"⚠️  Address {counts['HIGH']} HIGH severity issue(s) before next deployment."
    elif counts["MEDIUM"] > 0:
        return f"🔶 Review {counts['MEDIUM']} MEDIUM severity issue(s) in your next sprint."
    elif counts["LOW"] > 0:
        return f"🔵 {counts['LOW']} LOW severity issue(s) — minor improvements recommended."
    else:
        return "✅ No issues found. Keep following secure coding practices!"


def format_grade_display(grade_result: Dict) -> str:
    """Format grade result for terminal display."""
    grade = grade_result["grade"]
    score = grade_result["score"]
    label = grade_result["label"]
    breakdown = grade_result["breakdown"]
    
    grade_colors = {
        "A+": "bright_green", "A": "green",
        "B": "yellow", "C": "yellow",
        "D": "red", "F": "bright_red"
    }
    
    color = grade_colors.get(grade, "white")
    
    lines = [
        f"\n{'='*50}",
        f"  SECURITY GRADE: {grade}  ({score}/100)",
        f"  {label}",
        f"{'='*50}",
        f"  Critical: {breakdown['CRITICAL']}  High: {breakdown['HIGH']}  "
        f"Medium: {breakdown['MEDIUM']}  Low: {breakdown['LOW']}",
        f"  {grade_result['recommendation']}",
        f"{'='*50}\n",
    ]
    
    return "\n".join(lines)
