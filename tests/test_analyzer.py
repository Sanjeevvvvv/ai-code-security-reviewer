from __future__ import annotations

import json
import os
from pathlib import Path

from click.testing import CliRunner

from analyzer.pipeline import AnalyzerPipeline
from main import cli
from utils.file_loader import load_single_file


BASE_DIR = Path(__file__).resolve().parent
VULN_DIR = BASE_DIR / "vulnerable_samples"


def _scan_file(rel_path: str, severity: str | None = None):
    path = (VULN_DIR / rel_path).resolve()
    files = load_single_file(path)
    pipeline = AnalyzerPipeline()
    return pipeline.run(files, severity_filter=severity, verbose=False)


def test_sql_vulnerabilities_detected():
    result = _scan_file("sql_vuln.py")
    names = {f["name"] for f in result["findings"]}
    assert any("SQL Injection" in n or "SQL" in n for n in names)


def test_secrets_vulnerabilities_detected():
    result = _scan_file("secrets_vuln.py")
    names = {f["name"] for f in result["findings"]}
    assert any("AWS" in n or "GitHub" in n or "Secret" in n for n in names)


def test_auth_vulnerabilities_detected():
    result = _scan_file("auth_vuln.py")
    names = {f["name"] for f in result["findings"]}
    assert any("Auth" in n or "Credential" in n or "TLS" in n for n in names)


def test_mock_mode_without_api_key(monkeypatch):
    # Ensure API key is not set
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = _scan_file("sql_vuln.py")
    assert result["mock_mode"] is True
    assert len(result["findings"]) >= 1


def test_json_output_is_valid():
    runner = CliRunner()
    # ensure mock mode for determinism
    if "GROQ_API_KEY" in os.environ:
        del os.environ["GROQ_API_KEY"]

    res = runner.invoke(
        cli,
        ["scan", str(VULN_DIR / "sql_vuln.py"), "--output", "json"],
    )
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_severity_filtering_high():
    runner = CliRunner()
    if "GROQ_API_KEY" in os.environ:
        del os.environ["GROQ_API_KEY"]

    res = runner.invoke(
        cli,
        ["scan", str(VULN_DIR), "--output", "json", "--severity", "high"],
    )
    assert res.exit_code == 0
    data = json.loads(res.output)
    severities = {f["severity"] for f in data["findings"]}
    assert severities
    # ensure all findings are >= high
    allowed = {"high", "critical"}
    assert all(s in allowed for s in severities)

