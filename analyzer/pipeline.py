"""
pipeline.py v3 — Real Groq AI + full codebase scanning
"""
from __future__ import annotations

import os
import io
import time
import zipfile
from typing import List, Dict, Optional
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from analyzer.parser import parse_code
from analyzer.llm import LLMAnalyzer
from analyzer.classifier import enrich_finding
from analyzer.confidence import score_finding

from detectors.sql_injection import detect as detect_sql_injection
from detectors.secrets import detect as detect_secrets
from detectors.auth import detect as detect_auth_issues
from detectors.deserialization import detect as detect_deserialization
from detectors.xss import detect_xss
from detectors.csrf import detect_csrf
from detectors.path_traversal import detect_path_traversal
from detectors.command_injection import detect_command_injection
from detectors.crypto_weakness import detect_crypto_weakness

from analyzer.false_positive_filter import filter_false_positives, deduplicate_findings, sort_findings
from analyzer.security_grade import calculate_security_grade, format_grade_display

# Singleton — reuses one Groq client for all scans
_llm = LLMAnalyzer()

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

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv",
    "venv", "dist", "build", ".tox", ".eggs",
}


def _build_summary(findings: List[Dict], grade: Dict) -> Dict:
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity") or "low").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    owasp_breakdown = {}
    for f in findings:
        owasp = str(f.get("owasp_category") or "Unknown")
        owasp_breakdown[owasp] = owasp_breakdown.get(owasp, 0) + 1

    return {
        "vulnerabilities_by_severity": sev_counts,
        "overall_risk_score": grade.get("score", 0),
        "grade": grade.get("grade", "A+"),
        "grade_label": grade.get("label", ""),
        "owasp_breakdown": owasp_breakdown,
        "grade_display": format_grade_display(grade),
    }


def _run_detectors(code: str, filename: str) -> List[Dict]:
    """Run all 9 regex-based detectors."""
    findings = []
    for fn in [
        lambda: detect_sql_injection(filename, code, "python"),
        lambda: detect_secrets(filename, code, "python"),
        lambda: detect_auth_issues(filename, code, "python"),
        lambda: detect_deserialization(filename, code, "python"),
        lambda: detect_xss(code, filename),
        lambda: detect_csrf(code, filename),
        lambda: detect_path_traversal(code, filename),
        lambda: detect_command_injection(code, filename),
        lambda: detect_crypto_weakness(code, filename),
    ]:
        try:
            findings.extend(fn())
        except Exception:
            pass
    return findings


def analyze_code(
    code: str,
    filename: str = "code.py",
    use_llm: bool = True,
    severity_filter: Optional[str] = None,
    confidence_threshold: float = 0.4,
) -> Dict:
    start_time = time.time()
    lines = code.split("\n")
    loc = len([l for l in lines if l.strip()])
    language = SUPPORTED_EXTENSIONS.get(Path(filename).suffix.lower(), "python")

    # ── Layer 1: Fast regex detectors ──────────────────────────────────────
    detector_raw = _run_detectors(code, filename)
    detector_findings = []
    for f in detector_raw:
        scored = dict(f)
        try:
            scored["confidence"] = score_finding(f)[0]
        except Exception:
            scored["confidence"] = scored.get("confidence_score", 0.5)
        scored["source"] = "detector"
        scored["ai_analyzed"] = False
        detector_findings.append(scored)

    # ── Layer 2: Groq + Llama 3 AI ─────────────────────────────────────────
    ai_findings = []
    mock_mode = False
    if use_llm:
        try:
            raw_ai, mock_mode = _llm.analyze(
                code,
                filename=filename,
                language=language,
                context={"detector_count": len(detector_findings)},
            )
            for f in raw_ai:
                f["source"] = "ai"
                f["ai_analyzed"] = True
                f["mock_mode"] = mock_mode
            ai_findings = raw_ai
        except Exception as e:
            print(f"[LLM] Error: {e}")

    all_findings = detector_findings + ai_findings

    # ── Enrich, filter, deduplicate ────────────────────────────────────────
    classified = []
    for f in all_findings:
        try:
            classified.append(enrich_finding(f))
        except Exception:
            classified.append(f)

    filtered = filter_false_positives(classified, lines, threshold=confidence_threshold)
    deduped = deduplicate_findings(filtered)
    sorted_findings = sort_findings(deduped)

    if severity_filter:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_level = order.get(severity_filter.lower(), 3)
        sorted_findings = [
            f for f in sorted_findings
            if order.get(str(f.get("severity") or "low").lower(), 3) <= min_level
        ]

    grade = calculate_security_grade(sorted_findings, loc)
    elapsed = round(time.time() - start_time, 2)

    return {
        "findings": sorted_findings,
        "grade": grade,
        "mock_mode": mock_mode,
        "stats": {
            "total_findings": len(sorted_findings),
            "raw_detector_findings": len(detector_findings),
            "raw_ai_findings": len(ai_findings),
            "ai_findings": len([f for f in sorted_findings if f.get("ai_analyzed")]),
            "detector_findings": len([f for f in sorted_findings if not f.get("ai_analyzed")]),
            "filtered_out": len(all_findings) - len(sorted_findings),
            "lines_of_code": loc,
            "scan_time_seconds": elapsed,
            "filename": filename,
            "ai_mode": "groq" if not mock_mode else "mock",
        },
        "summary": _build_summary(sorted_findings, grade),
    }


def analyze_file(filepath: str, **kwargs) -> Dict:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {path.suffix}")
    code = path.read_text(encoding="utf-8", errors="ignore")
    return analyze_code(code, filename=str(path), **kwargs)


def analyze_directory(dirpath: str, **kwargs) -> Dict:
    all_findings = []
    file_stats = []

    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            ext = Path(file).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            filepath = os.path.join(root, file)
            try:
                result = analyze_file(filepath, **kwargs)
                all_findings.extend(result["findings"])
                file_stats.append(result["stats"])
                print(f"  Scanned: {filepath} — {result['stats']['total_findings']} findings")
            except Exception as e:
                print(f"  Skipped {filepath}: {e}")

    total_loc = sum(s.get("lines_of_code", 0) for s in file_stats)
    grade = calculate_security_grade(all_findings, total_loc)

    return {
        "findings": sort_findings(all_findings),
        "grade": grade,
        "stats": {
            "total_findings": len(all_findings),
            "files_scanned": len(file_stats),
            "lines_of_code": total_loc,
            "file_stats": file_stats,
        },
        "summary": _build_summary(all_findings, grade),
    }


def analyze_zip(zip_bytes: bytes, **kwargs) -> Dict:
    """Scan all supported files inside a ZIP archive."""
    all_findings = []
    file_stats = []

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            parts = Path(name).parts
            if any(p in SKIP_DIRS for p in parts):
                continue
            ext = Path(name).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            try:
                code = zf.read(name).decode("utf-8", errors="ignore")
                result = analyze_code(code, filename=name, **kwargs)
                all_findings.extend(result["findings"])
                file_stats.append(result["stats"])
                print(f"  Scanned: {name} — {result['stats']['total_findings']} findings")
            except Exception as e:
                print(f"  Skipped {name}: {e}")

    total_loc = sum(s.get("lines_of_code", 0) for s in file_stats)
    grade = calculate_security_grade(all_findings, total_loc)

    return {
        "findings": sort_findings(all_findings),
        "grade": grade,
        "stats": {
            "total_findings": len(all_findings),
            "files_scanned": len(file_stats),
            "lines_of_code": total_loc,
            "file_stats": file_stats,
        },
        "summary": _build_summary(all_findings, grade),
    }


class AnalyzerPipeline:
    """Legacy class kept for backwards compatibility."""

    def analyze(self, code, filename="code.py", **kwargs):
        return analyze_code(code, filename=filename, **kwargs)

    def analyze_file(self, filepath, **kwargs):
        return analyze_file(filepath, **kwargs)

    def run(self, files, severity_filter=None, verbose=False):
        all_findings = []
        for f in files:
            try:
                result = analyze_code(
                    code=f.get("content", ""),
                    filename=f.get("filename", "code.py"),
                )
                all_findings.extend(result.get("findings", []))
            except Exception:
                pass
        grade = calculate_security_grade(all_findings, 100)
        return {
            "findings": all_findings,
            "grade": grade,
            "summary": _build_summary(all_findings, grade),
        }