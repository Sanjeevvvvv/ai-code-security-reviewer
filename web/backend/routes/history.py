from __future__ import annotations

from io import BytesIO
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from web.backend.models import load_history, save_history


router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("", response_model=List[Dict[str, Any]])
async def get_history() -> List[Dict[str, Any]]:
    items = load_history()
    # Sort newest first by timestamp if present
    def _key(item: Dict[str, Any]) -> str:
        return str(item.get("timestamp") or "")

    items_sorted = sorted(items, key=_key, reverse=True)
    return items_sorted[:20]


@router.delete("/{scan_id}")
async def delete_history_item(scan_id: str) -> Dict[str, str]:
    items = load_history()
    new_items = [item for item in items if str(item.get("id")) != scan_id]
    if len(new_items) == len(items):
        raise HTTPException(status_code=404, detail="Scan not found")
    save_history(new_items)
    return {"status": "deleted", "id": scan_id}


def _draw_header(c: canvas.Canvas, width: float, height: float, item: Dict[str, Any]) -> None:
    c.setFillColor(colors.HexColor("#00e5ff"))
    c.setFont("Helvetica-Bold", 20)
    c.drawString(20 * mm, height - 30 * mm, "CSE — AI Code Security Reviewer")

    c.setFillColor(colors.white)
    c.setFont("Helvetica", 11)
    ts = str(item.get("timestamp") or "")
    source = str(item.get("source") or "unknown")
    risk = item.get("risk_score", 0)

    c.drawString(20 * mm, height - 40 * mm, f"Scan timestamp: {ts}")
    c.drawString(20 * mm, height - 46 * mm, f"Source: {source}")
    c.drawString(20 * mm, height - 52 * mm, f"Overall risk score: {risk}/100")

    c.setStrokeColor(colors.HexColor("#00e5ff"))
    c.setLineWidth(1.2)
    c.line(20 * mm, height - 56 * mm, width - 20 * mm, height - 56 * mm)


def _draw_findings_table(c: canvas.Canvas, width: float, height: float, item: Dict[str, Any]) -> float:
    findings = item.get("findings") or []
    y = height - 70 * mm

    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(colors.HexColor("#b44fff"))
    c.drawString(20 * mm, y, "Findings")
    y -= 8 * mm

    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(colors.white)
    headers = ["Severity", "Name", "Description", "Fix"]
    col_x = [20 * mm, 45 * mm, 90 * mm, 140 * mm]
    for hx, label in zip(col_x, headers):
        c.drawString(hx, y, label)
    y -= 4 * mm
    c.setStrokeColor(colors.HexColor("#2a2a3a"))
    c.line(20 * mm, y, width - 20 * mm, y)
    y -= 4 * mm

    c.setFont("Helvetica", 9)
    for f in findings:
        severity = str(f.get("severity") or "").upper()
        name = str(f.get("name") or "")
        desc = str(f.get("description") or "")
        fix = str(f.get("fix_suggestion") or "")

        # Truncate long text for PDF readability
        max_lens = [16, 32, 80, 80]
        values = [severity, name, desc, fix]
        truncated = [v if len(v) <= ml else v[: ml - 3] + "..." for v, ml in zip(values, max_lens)]

        c.drawString(col_x[0], y, truncated[0])
        c.drawString(col_x[1], y, truncated[1])
        c.drawString(col_x[2], y, truncated[2])
        c.drawString(col_x[3], y, truncated[3])

        y -= 6 * mm

        if y < 40 * mm:
            c.showPage()
            width, height = A4
            y = height - 30 * mm
            c.setFont("Helvetica", 9)

    return y


def _draw_summary(c: canvas.Canvas, width: float, y: float, item: Dict[str, Any]) -> None:
    summary = item.get("summary") or {}
    sev = summary.get("vulnerabilities_by_severity") or {}
    risk = item.get("risk_score", 0)

    y -= 10 * mm
    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(colors.HexColor("#00e5ff"))
    c.drawString(20 * mm, y, "Summary")
    y -= 8 * mm

    c.setFont("Helvetica-Bold", 10)
    headers = ["Severity", "Count", "Risk Weight"]
    col_x = [20 * mm, 70 * mm, 110 * mm]
    for hx, label in zip(col_x, headers):
        c.drawString(hx, y, label)
    y -= 4 * mm
    c.setStrokeColor(colors.HexColor("#2a2a3a"))
    c.line(20 * mm, y, width - 20 * mm, y)
    y -= 4 * mm

    rows = [
        ("CRITICAL", "critical", 25),
        ("HIGH", "high", 15),
        ("MEDIUM", "medium", 7),
        ("LOW", "low", 3),
    ]
    c.setFont("Helvetica", 9)
    for label, key, weight in rows:
        count = int(sev.get(key, 0))
        c.drawString(col_x[0], y, label)
        c.drawString(col_x[1], y, str(count))
        c.drawString(col_x[2], y, str(weight))
        y -= 6 * mm

    y -= 4 * mm
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(colors.HexColor("#00e5ff"))
    c.drawString(20 * mm, y, f"Overall Risk Score: {risk}/100")


@router.get("/{scan_id}/pdf")
async def get_scan_pdf(scan_id: str):
    items = load_history()
    item = next((i for i in items if str(i.get("id")) == scan_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Scan not found")

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setFillColor(colors.HexColor("#0a0a0f"))
    c.rect(0, 0, width, height, stroke=0, fill=1)

    _draw_header(c, width, height, item)
    y = _draw_findings_table(c, width, height, item)
    _draw_summary(c, width, y, item)

    c.showPage()
    c.save()
    buffer.seek(0)

    filename = f"cse_scan_{scan_id}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)

