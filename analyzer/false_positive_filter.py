"""
False Positive Filter
Reduces noise by filtering out likely false positives from detector findings
"""
import re
from typing import List, Dict

# Patterns that indicate a finding is likely a false positive
FALSE_POSITIVE_INDICATORS = [
    # Comments and documentation
    r"#.*",
    r"\"\"\".*\"\"\"",
    r"'''.*'''",
    # Test files context
    r"test_|_test\.|mock_|fake_|stub_|dummy_",
    # Example/sample strings
    r"example|sample|placeholder|todo|fixme|hack",
]

# Safe function wrappers that neutralize dangerous calls
SAFE_WRAPPERS = {
    "sql_injection": [
        r"parameterized|prepared|cursor\.execute\s*\([^)]+,\s*[\[\(]",  # Parameterized query
        r"escape_string|quote_plus|sqlalchemy",                          # ORM/escaping
    ],
    "xss": [
        r"escape\(|bleach\.clean|DOMPurify|html\.escape",              # HTML escaping
        r"textContent\s*=",                                              # Safe DOM
    ],
    "command_injection": [
        r"shlex\.quote|shlex\.split",                                    # Shell quoting
        r"subprocess\.run\s*\(\s*\[",                                    # List args (safe)
    ],
    "path_traversal": [
        r"os\.path\.realpath|Path\.resolve|safe_join|send_from_directory",
        r"os\.path\.basename\s*\(",
    ],
    "crypto_weakness": [
        r"#.*not for security|#.*checksum only|#.*non-cryptographic",
    ],
}

# Confidence penalties for suspicious but context-dependent patterns
CONFIDENCE_BOOSTS = {
    "CRITICAL": 0.0,   # Never reduce confidence for critical
    "HIGH": -0.05,
    "MEDIUM": -0.1,
    "LOW": -0.15,
}


def filter_false_positives(findings: List[Dict], code_lines: List[str], threshold: float = 0.4) -> List[Dict]:
    """
    Filter out likely false positives from findings list.
    
    Args:
        findings: Raw findings from detectors
        code_lines: All lines of code for context
        threshold: Minimum confidence to keep a finding (0.0 - 1.0)
    
    Returns:
        Filtered findings with adjusted confidence scores
    """
    filtered = []
    
    for finding in findings:
        line_num = finding.get("line", 1) - 1
        snippet = finding.get("code_snippet", "")
        detector = finding.get("detector", "")
        severity = finding.get("severity", "MEDIUM")
        confidence = finding.get("confidence", 0.7)
        
        # Check surrounding context (3 lines above and below)
        start = max(0, line_num - 3)
        end = min(len(code_lines), line_num + 4)
        context = "\n".join(code_lines[start:end])
        
        # Check if finding is inside a comment
        stripped = snippet.lstrip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue  # Skip - it's a comment
        
        # Check for safe wrapper patterns
        is_safe = False
        if detector in SAFE_WRAPPERS:
            for safe_pattern in SAFE_WRAPPERS[detector]:
                if re.search(safe_pattern, context, re.IGNORECASE):
                    is_safe = True
                    break
        
        if is_safe and severity not in ("CRITICAL",):
            continue  # Skip likely false positive
        
        # Adjust confidence based on severity (CRITICAL always passes)
        if severity == "CRITICAL":
            finding["confidence"] = max(confidence, 0.85)
        elif severity == "HIGH":
            finding["confidence"] = max(confidence - 0.05, 0.6)
        elif severity == "MEDIUM":
            finding["confidence"] = max(confidence - 0.1, 0.45)
        else:
            finding["confidence"] = max(confidence - 0.15, 0.35)
        
        # Apply threshold filter
        if finding["confidence"] >= threshold:
            filtered.append(finding)
    
    return filtered


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Remove duplicate findings (same line + same title).
    Keeps the one with highest confidence.
    """
    seen = {}
    
    for finding in findings:
        key = f"{finding.get('filename', '')}:{finding.get('line', 0)}:{finding.get('title', '')}"
        
        if key not in seen:
            seen[key] = finding
        else:
            # Keep the one with higher confidence
            existing_conf = seen[key].get("confidence", 0)
            new_conf = finding.get("confidence", 0)
            if new_conf > existing_conf:
                seen[key] = finding
    
    return list(seen.values())


def sort_findings(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity then confidence."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    
    return sorted(
        findings,
        key=lambda f: (
            severity_order.get(f.get("severity", "LOW"), 3),
            -f.get("confidence", 0)
        )
    )
