"""
UPDATED pipeline.py
Replace your existing analyzer/pipeline.py with this file.
Adds: 5 new detectors, false positive filtering, security grading
"""
import os
import time
from typing import List, Dict, Optional
from pathlib import Path

# Original detectors
from analyzer.parser import parse_code
from analyzer.llm import _mock_findings_for_code as analyze_with_llm
from analyzer.classifier import enrich_finding
from analyzer.confidence import score_finding

# Original detectors
from detectors.sql_injection import detect as detect_sql_injection
from detectors.secrets import detect as detect_secrets
from detectors.auth import detect as detect_auth_issues
from detectors.deserialization import detect as detect_deserialization

# NEW detectors (add these)
from detectors.xss import detect_xss
from detectors.csrf import detect_csrf
from detectors.path_traversal import detect_path_traversal
from detectors.command_injection import detect_command_injection
from detectors.crypto_weakness import detect_crypto_weakness

# NEW utilities (add these)
from analyzer.false_positive_filter import filter_false_positives, deduplicate_findings, sort_findings
from analyzer.security_grade import calculate_security_grade, format_grade_display

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
}


def run_all_detectors(code: str, filename: str = "") -> List[Dict]:
    """Run all static detectors and return combined findings."""
    findings = []

    # Original detectors
    findings.extend(detect_sql_injection(filename, code, "python"))
    findings.extend(detect_secrets(filename, code, "python"))
    findings.extend(detect_auth_issues(filename, code, "python"))
    findings.extend(detect_deserialization(filename, code, "python"))

    # NEW detectors
    findings.extend(detect_xss(code, filename))
    findings.extend(detect_csrf(code, filename))
    findings.extend(detect_path_traversal(code, filename))
    findings.extend(detect_command_injection(code, filename))
    findings.extend(detect_crypto_weakness(code, filename))

    return findings


def analyze_code(
    code: str,
    filename: str = "code.py",
    use_llm: bool = True,
    severity_filter: Optional[str] = None,
    confidence_threshold: float = 0.4,
) -> Dict:
    """
    Full analysis pipeline.
    
    Returns dict with:
        - findings: List of vulnerability findings
        - grade: Security grade result
        - stats: Timing and count stats
        - summary: Human-readable summary
    """
    start_time = time.time()
    code_lines = code.split("\n")
    lines_of_code = len([l for l in code_lines if l.strip()])

    # Step 1: Static detection
    raw_findings = run_all_detectors(code, filename)

    # Step 2: Score confidence
    scored_findings = [dict(f, **{"confidence": score_finding(f)[0]}) for f in raw_findings]

    # Step 3: LLM enhancement (if available)
    if use_llm:
        try:
            llm_findings = analyze_with_llm(code, filename)
            scored_findings.extend(llm_findings)
        except Exception as e:
            pass  # Fall back to static only

    # Step 4: Classify with OWASP
    classified = [enrich_finding(f) for f in scored_findings]

    # Step 5: Filter false positives
    filtered = filter_false_positives(classified, code_lines, threshold=confidence_threshold)

    # Step 6: Deduplicate
    deduped = deduplicate_findings(filtered)

    # Step 7: Sort by severity
    sorted_findings = sort_findings(deduped)

    # Step 8: Apply severity filter
    if severity_filter:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_level = severity_order.get(severity_filter.lower(), 3)
        sorted_findings = [
            f for f in sorted_findings
            if severity_order.get(f.get("severity", "low").lower(), 3) <= min_level
        ]

    # Step 9: Security grade
    grade = calculate_security_grade(sorted_findings, lines_of_code)

    elapsed = round(time.time() - start_time, 2)

    return {
        "findings": sorted_findings,
        "grade": grade,
        "stats": {
            "total_findings": len(sorted_findings),
            "raw_findings": len(raw_findings),
            "filtered_out": len(raw_findings) - len(sorted_findings),
            "lines_of_code": lines_of_code,
            "scan_time_seconds": elapsed,
            "filename": filename,
        },
        "summary": format_grade_display(grade),
    }


def analyze_file(filepath: str, **kwargs) -> Dict:
    """Analyze a single file."""
    path = Path(filepath)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {ext}. Supported: {list(SUPPORTED_EXTENSIONS.keys())}")
    
    code = path.read_text(encoding="utf-8", errors="ignore")
    return analyze_code(code, filename=str(path), **kwargs)


def analyze_directory(dirpath: str, **kwargs) -> Dict:
    """Analyze all supported files in a directory."""
    all_findings = []
    all_stats = []
    
    for root, dirs, files in os.walk(dirpath):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {
            ".git", "node_modules", "__pycache__", ".venv", 
            "venv", "dist", "build", ".tox"
        }]
        
        for file in files:
            filepath = os.path.join(root, file)
            ext = Path(filepath).suffix.lower()
            
            if ext in SUPPORTED_EXTENSIONS:
                try:
                    result = analyze_file(filepath, **kwargs)
                    all_findings.extend(result["findings"])
                    all_stats.append(result["stats"])
                except Exception as e:
                    print(f"  Skipped {filepath}: {e}")
    
    # Aggregate grade for whole directory
    total_loc = sum(s["lines_of_code"] for s in all_stats)
    overall_grade = calculate_security_grade(all_findings, total_loc)
    
    return {
        "findings": sort_findings(all_findings),
        "grade": overall_grade,
        "stats": {
            "total_findings": len(all_findings),
            "files_scanned": len(all_stats),
            "lines_of_code": total_loc,
            "file_stats": all_stats,
        },
        "summary": format_grade_display(overall_grade),
    }
