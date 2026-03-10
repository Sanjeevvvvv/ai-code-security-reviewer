from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.rule import Rule

from output.reporter import SEVERITY_WEIGHT


SEVERITY_STYLE = {
    "critical": ("🔴 CRITICAL", "bold bright_red"),
    "high": ("🟠 HIGH", "bold dark_orange"),
    "medium": ("🟡 MEDIUM", "bold yellow1"),
    "low": ("🔵 LOW", "bold bright_cyan"),
}


def _severity_badge(sev: str) -> Text:
    key = (sev or "low").lower()
    label, style = SEVERITY_STYLE.get(key, SEVERITY_STYLE["low"])
    return Text(label, style=style)


def _print_ascii_header(console: Console) -> None:
    header_lines = [
        " ██████╗ ██████╗ ███████╗",
        "██╔════╝██╔════╝ ██╔════╝",
        "██║     ╚█████╗  █████╗  ",
        "██║      ╚═══██╗ ██╔══╝  ",
        "╚██████╗██████╔╝ ███████╗",
        " ╚═════╝╚═════╝  ╚══════╝",
    ]
    for line in header_lines:
        console.print(Text(line, style="bold bright_cyan"))
    subtitle = Text("  AI Code Security Reviewer  |  Powered by Groq + Llama 3", style="italic medium_purple1")
    console.print(subtitle)
    console.print(Rule(characters="─", style="bright_cyan"))


def render_terminal_report(scan_result: Dict[str, Any], *, verbose: bool, console: Console) -> None:
    files = scan_result.get("files", []) or []
    findings = scan_result.get("findings", []) or []
    summary = scan_result.get("summary", {}) or {}
    mock_mode = bool(scan_result.get("mock_mode"))

    _print_ascii_header(console)

    # Scan metadata bar
    ts = scan_result.get("scanned_at") or datetime.utcnow().isoformat()
    if len(files) == 1:
        fname_display = files[0].get("filename") or "<unknown>"
    elif len(files) == 0:
        fname_display = "<no files>"
    else:
        fname_display = f"{len(files)} files"
    meta = Text.assemble(
        ("📂 ", "medium_purple1"),
        (str(fname_display), "bold medium_purple1"),
        ("   🕐 ", "medium_purple1"),
        (ts, "grey62"),
        ("   📊 ", "medium_purple1"),
        (f"{len(findings)} findings", "grey62"),
    )
    console.print(meta)

    # Mock mode warning
    if mock_mode:
        console.print(
            Panel(
                Text("⚡ MOCK MODE — add GROQ_API_KEY to .env for real AI analysis", style="bold yellow1"),
                border_style="yellow1",
            )
        )

    # Findings panels
    for f in findings:
        sev = str(f.get("severity") or "low").lower()
        badge = _severity_badge(sev)

        name = str(f.get("name") or "Finding")
        owasp = str(f.get("owasp_category") or "Unknown")
        cwe = str(f.get("cwe_id") or "CWE-0")
        conf = float(f.get("confidence_score") or 0.0)
        line = f.get("line_number") or "-"
        filename = str(f.get("filename") or "")
        snippet = str(f.get("code_snippet") or "")
        desc = str(f.get("description") or "")
        fix = str(f.get("fix_suggestion") or "")
        reason = str(f.get("confidence_reasoning") or "")

        # Panel title: severity badge + vuln name
        title_text = Text.assemble(
            badge,
            " · ",
            (name, "bold bright_cyan"),
        )
        # Right-hand meta: OWASP + CWE in subtitle
        subtitle = f"{owasp} · {cwe} | confidence {conf:.2f}"
        if verbose and reason:
            subtitle += f"\nreason: {reason}"

        # Build body
        body_parts: List[Any] = []

        # First line: line + filename + confidence
        header_line = Text()
        header_line.append(f"Line {line}", style="grey62")
        if filename:
            header_line.append(" · ", style="grey62")
            header_line.append(filename, style="bold medium_purple1")
        header_line.append(f" · confidence {conf:.2f}", style="grey62")
        body_parts.append(header_line)

        # Code snippet (max 6 lines)
        if snippet:
            code_lines = snippet.splitlines()
            truncated = False
            if len(code_lines) > 6:
                code_lines = code_lines[:6]
                truncated = True
            snippet_display = "\n".join(code_lines)
            body_parts.append(Syntax(snippet_display, "python", theme="monokai", word_wrap=True))
            if truncated:
                body_parts.append(Text("… (truncated)", style="grey62"))

        # Description
        if desc:
            body_parts.append(Text(f"⚠  {desc}", style="grey62"))

        # Fix suggestion
        if fix:
            body_parts.append(Text(f"✔  {fix}", style="cyan1"))

        body = Group(*body_parts) if body_parts else Text("(no details)", style="grey62")

        console.print(
            Panel(
                body,
                title=title_text,
                border_style="medium_purple1",
                subtitle=subtitle,
                subtitle_align="right",
            )
        )

    # Summary table (even if no findings)
    sev_counts = summary.get("vulnerabilities_by_severity", {}) or {}
    risk_score = summary.get("overall_risk_score", 0)

    table = Table(
        title=Text("━━ Scan Summary ━━", style="bold bright_cyan"),
        show_header=True,
        header_style="bold bright_cyan",
        border_style="medium_purple1",
    )
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    table.add_column("Risk Weight", justify="right")

    def _add_row(label: str, key: str, style: str) -> None:
        count = int(sev_counts.get(key, 0))
        weight = SEVERITY_WEIGHT.get(key, 0)
        table.add_row(label, str(count), str(weight), style=style)

    _add_row("🔴 CRITICAL", "critical", "bright_red")
    _add_row("🟠 HIGH", "high", "dark_orange")
    _add_row("🟡 MEDIUM", "medium", "yellow1")
    _add_row("🔵 LOW", "low", "bright_cyan")

    console.print(table)
    console.print(Text(f"Overall Risk Score: {risk_score}/100", style="bold bright_cyan"))


def format_json_report(scan_result: Dict[str, Any]) -> str:
    return json.dumps(scan_result, indent=2, ensure_ascii=False, sort_keys=False)


def format_markdown_report(scan_result: Dict[str, Any]) -> str:
    findings = scan_result.get("findings", [])
    summary = scan_result.get("summary", {})
    files = scan_result.get("files", [])

    lines: List[str] = []
    lines.append("# AI Code Security Reviewer Report")
    lines.append("")
    lines.append(f"- **Files scanned**: {len(files)}")
    lines.append(f"- **Timestamp**: {scan_result.get('scanned_at')}")
    lines.append(f"- **Mock mode**: {bool(scan_result.get('mock_mode'))}")
    lines.append(f"- **Overall risk score (0-100)**: {summary.get('overall_risk_score', 0)}")
    lines.append("")

    sev = summary.get("vulnerabilities_by_severity", {}) or {}
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for s in ["critical", "high", "medium", "low"]:
        lines.append(f"| {s} | {sev.get(s, 0)} |")
    lines.append("")

    owasp = summary.get("owasp_breakdown", {}) or {}
    if owasp:
        lines.append("## OWASP Breakdown")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|---|---:|")
        for k, v in sorted(owasp.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| {k} | {v} |")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.get('name')} ({str(f.get('severity')).upper()})")
        lines.append("")
        lines.append(f"- **File**: `{f.get('filename')}`")
        lines.append(f"- **Line**: {f.get('line_number')}")
        lines.append(f"- **OWASP**: {f.get('owasp_category')} | **CWE**: {f.get('cwe_id')}")
        lines.append(f"- **Confidence**: {float(f.get('confidence_score') or 0.0):.2f}")
        lines.append("")
        lines.append(f"**Description**: {f.get('description')}")
        lines.append("")
        if f.get("code_snippet"):
            lines.append("```")
            lines.append(str(f.get("code_snippet")))
            lines.append("```")
            lines.append("")
        lines.append(f"**Fix suggestion**: {f.get('fix_suggestion')}")
        lines.append("")

    return "\n".join(lines)

