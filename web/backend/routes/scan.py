from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, HTTPException, UploadFile, File, status

from analyzer.pipeline import AnalyzerPipeline
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


def _run_pipeline_for_files(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    pipeline = AnalyzerPipeline()
    return pipeline.run(files, severity_filter=None, verbose=False)


def _to_scan_result(
    raw: Dict[str, Any],
    *,
    source: str,
) -> ScanResult:
    findings_raw = raw.get("findings") or []
    summary = raw.get("summary") or {}
    risk_score = int(summary.get("overall_risk_score") or 0)

    findings: List[Finding] = []
    for f in findings_raw:
        finding = Finding(
            name=str(f.get("name") or "Finding"),
            severity=str(f.get("severity") or "low"),
            description=str(f.get("description") or ""),
            line_number=f.get("line_number"),
            code_snippet=str(f.get("code_snippet") or ""),
            fix_suggestion=str(f.get("fix_suggestion") or ""),
            owasp_category=str(f.get("owasp_category") or ""),
            cwe_id=str(f.get("cwe_id") or ""),
            confidence_score=float(f.get("confidence_score") or 0.0),
            filename=f.get("filename"),
            sources=f.get("sources"),
        )
        findings.append(finding)

    scanned_at = raw.get("scanned_at")
    from datetime import datetime

    # Always store timestamps as ISO strings so FastAPI / JSON encoding doesn't fail.
    if isinstance(scanned_at, str):
        timestamp_str = scanned_at
    else:
        timestamp_str = datetime.utcnow().isoformat()

    result = ScanResult(
        id=str(uuid4()),
        timestamp=timestamp_str,
        source=source,
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
    append_scan_result(result)
    return result


@router.post("", response_model=ScanResult)
async def scan(request: ScanRequest) -> ScanResult:
    """
    Main scan endpoint.

    - mode="code": scan pasted code.
    - mode="github": scan a GitHub repository.
    - mode="file": accepted but use /api/scan/upload for file uploads.
    """
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
        language = _detect_language(filename, request.language)

        with tempfile.NamedTemporaryFile(mode="w", suffix=Path(filename).suffix or ".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(request.content)
            tmp_path = Path(tmp.name)

        files = [
            {
                "filename": str(tmp_path),
                "content": request.content,
                "language": language,
            }
        ]
        raw = _run_pipeline_for_files(files)
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

        raw = _run_pipeline_for_files(files)
        return _to_scan_result(raw, source=request.github_url)

    raise HTTPException(status_code=400, detail=f"Unsupported mode: {request.mode}")


@router.post("/upload", response_model=ScanResult)
async def upload_scan(file: UploadFile = File(...)) -> ScanResult:
    """
    Multipart upload endpoint for scanning a single file.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    suffix = Path(file.filename).suffix or ".py"
    contents = await file.read()
    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError:
        text = contents.decode("latin-1")

    language = _detect_language(file.filename)

    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)

    files = [
        {
            "filename": str(tmp_path),
            "content": text,
            "language": language,
        }
    ]
    raw = _run_pipeline_for_files(files)
    return _to_scan_result(raw, source=file.filename)

