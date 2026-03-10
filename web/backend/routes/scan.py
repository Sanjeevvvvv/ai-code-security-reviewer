from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, HTTPException, UploadFile, File, status

from analyzer.pipeline import analyze_code, analyze_file
from utils.file_loader import SUPPORTED_EXTS, load_github_repo
from web.backend.models import ScanRequest, ScanResult, Finding, append_scan_result


router = APIRouter(prefix="/api/scan", tags=["scan"])


def _detect_language(filename: str, explicit: str | None = None) -> str:
    if explicit:
        lang = explicit.lower()
        if lang in {"python", "javascript"}:
            return lang
    suffix = Path(filename).suffix.lower()
    return SUPPORTED_EXTS.get(suffix, "python")


def _to_scan_result(
    raw: Dict[str, Any],
    *,
    source: str,
) -> ScanResult:
    findings_raw = raw.get("findings") or []
    grade_data = raw.get("grade") or {}
    summary = raw.get("summary") or {}

    # Get risk score from grade
    if isinstance(grade_data, dict):
        risk_score = int(grade_data.get("score") or 0)
    elif isinstance(summary, dict):
        risk_score = int(summary.get("overall_risk_score") or 0)
    else:
        risk_score = 0

    findings: List[Finding] = []
    for f in findings_raw:
        finding = Finding(
            name=str(f.get("name") or f.get("title") or "Finding"),
            severity=str(f.get("severity") or "low"),
            description=str(f.get("description") or ""),
            line_number=f.get("line_number") or f.get("line"),
            code_snippet=str(f.get("code_snippet") or ""),
            fix_suggestion=str(f.get("fix_suggestion") or f.get("fix") or ""),
            owasp_category=str(f.get("owasp_category") or f.get("owasp") or ""),
            cwe_id=str(f.get("cwe_id") or f.get("cwe") or ""),
            confidence_score=float(f.get("confidence_score") or f.get("confidence") or 0.0),
            filename=f.get("filename"),
            sources=f.get("sources"),
        )
        findings.append(finding)

    from datetime import datetime
    timestamp_str = datetime.utcnow().isoformat()

    # Build summary dict for response
    if isinstance(summary, dict):
        summary_out = summary
    elif isinstance(grade_data, dict):
        breakdown = grade_data.get("breakdown", {}) or {}
        summary_out = {
            "vulnerabilities_by_severity": {
                "critical": breakdown.get("CRITICAL", 0),
                "high": breakdown.get("HIGH", 0),
                "medium": breakdown.get("MEDIUM", 0),
                "low": breakdown.get("LOW", 0),
            },
            "overall_risk_score": risk_score,
            "grade": grade_data.get("grade", "A+"),
        }
    else:
        summary_out = {}

    result = ScanResult(
        id=str(uuid4()),
        timestamp=timestamp_str,
        source=source,
        findings=findings,
        summary=summary_out,
        risk_score=risk_score,
    )
    append_scan_result(result)
    return result


@router.post("", response_model=ScanResult)
async def scan(request: ScanRequest) -> ScanResult:
    mode = request.mode.lower()

    if mode == "file":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use /api/scan/upload for file uploads.",
        )

    if mode == "code":
        if not request.content.strip():
            raise HTTPException(status_code=400, detail="content is required for mode=code")
        filename = request.filename or "pasted_code.py"
        # Scan the actual code content directly
        raw = analyze_code(
            code=request.content,
            filename=filename,
            use_llm=True,
            severity_filter=None,
            confidence_threshold=0.4,
        )
        return _to_scan_result(raw, source=filename)

    if mode == "github":
        if not request.github_url.strip():
            raise HTTPException(status_code=400, detail="github_url is required for mode=github")
        try:
            files = load_github_repo(request.github_url)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to load GitHub repo: {exc}") from exc

        if not files:
            raise HTTPException(status_code=400, detail="No supported files found in repository.")

        from analyzer.pipeline import AnalyzerPipeline
        pipeline = AnalyzerPipeline()
        raw = pipeline.run(files)
        return _to_scan_result(raw, source=request.github_url)

    raise HTTPException(status_code=400, detail=f"Unsupported mode: {request.mode}")


@router.post("/upload", response_model=ScanResult)
async def upload_scan(file: UploadFile = File(...)) -> ScanResult:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    suffix = Path(file.filename).suffix or ".py"
    contents = await file.read()
    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError:
        text = contents.decode("latin-1")

    raw = analyze_code(
        code=text,
        filename=file.filename,
        use_llm=True,
        severity_filter=None,
        confidence_threshold=0.4,
    )
    return _to_scan_result(raw, source=file.filename)