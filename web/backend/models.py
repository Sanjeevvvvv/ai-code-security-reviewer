from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
SCAN_HISTORY_FILE = BASE_DIR / "scan_history.json"


class ScanRequest(BaseModel):
    mode: str = Field(..., pattern="^(code|file|github)$")
    content: str = ""
    filename: str = ""
    github_url: str = ""
    # Optional explicit language hint from the UI ("python" | "javascript")
    language: Optional[str] = None


class Finding(BaseModel):
    name: str
    severity: str
    description: str
    line_number: Optional[int] = None
    code_snippet: str = ""
    fix_suggestion: str = ""
    owasp_category: str = ""
    cwe_id: str = ""
    confidence_score: float = 0.0
    # Extra fields from pipeline we want to retain
    filename: Optional[str] = None
    sources: Optional[List[str]] = None


class ScanResult(BaseModel):
    id: str
    # Store timestamps as ISO 8601 strings to avoid JSON serialization issues.
    timestamp: str
    source: str
    findings: List[Finding]
    summary: Dict[str, Any]
    risk_score: int


def ensure_history_file() -> None:
    """
    Ensure scan_history.json exists and is a JSON list.
    """
    SCAN_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not SCAN_HISTORY_FILE.exists():
        SCAN_HISTORY_FILE.write_text("[]", encoding="utf-8")
        return
    try:
        raw = SCAN_HISTORY_FILE.read_text(encoding="utf-8")
        data = json.loads(raw or "[]")
        if not isinstance(data, list):
            raise ValueError("history is not a list")
    except Exception:
        # Reset corrupt history file
        SCAN_HISTORY_FILE.write_text("[]", encoding="utf-8")


def load_history() -> List[Dict[str, Any]]:
    ensure_history_file()
    raw = SCAN_HISTORY_FILE.read_text(encoding="utf-8")
    try:
        data = json.loads(raw or "[]")
    except Exception:
        data = []
    if not isinstance(data, list):
        return []
    return data


def save_history(items: List[Dict[str, Any]]) -> None:
    SCAN_HISTORY_FILE.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")


def append_scan_result(result: ScanResult, *, max_items: int = 200) -> None:
    items = load_history()
    items.append(result.model_dump())
    # Keep only the most recent items
    if len(items) > max_items:
        items = items[-max_items:]
    save_history(items)

