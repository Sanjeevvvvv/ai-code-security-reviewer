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
    "critical": ("CRITICAL", "bold bright_red"),
    "high": ("HIGH", "bold dark_orange"),
    "medium": ("MEDIUM", "bold yellow1"),
    "low": ("LOW", "bold bright_cyan"),
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
    mock_mode = bool(scan_result.get("mock_mode"))

    _print_ascii_header(console)

    ts = scan_result.get("scanned_at") or datetime.utcnow().isoformat()
    if len(files) == 1:
        fname_display = files[0].get("filename") or "<unknown>"
    elif len(files) == 0:
        fname_display = "<no files>"
    else:
        fname_display = f"{len(files)} files"
    meta = Text.assemble(
        ("  ", "medium_purple1"),
        (str(fname_display), "bold medium_purple1"),
        ("   ", "medium_purple1"),
        (ts, "grey62"),
        ("   ", "medium_purple1"),
        (f"{len(findings)} findings", "grey62"),
    )
    console.print(meta)

    if mock_mode:
        console.print(
            Panel(
                Text("MOCK MODE — add GROQ_API_KEY to .env for real AI analysis", style="bold yellow1"),
                border_style="yellow1",
            )
        )

    for f in findings:
        sev = str(f.get("severity") or "low").lower()
        badge = _severity_badge(sev)

        name = str(f.get("name") or f.get("title") or "Finding")
        owasp = str(f.get("owasp_category") or f.get("owasp") or "Unknown")
        cwe = str(f.get("cwe_id") or f.get("cwe") or "CWE-0")
        conf = float(f.get("confidence_score") or f.get("confidence") or 0.0)
        line = f.get("line_number") or f.get("line") or "-"
        filename = str(f.get("filename") or "")
        snippet = str(f.get("code_snippet") or "")
        desc = str(f.get("description") or "")
        fix = str(f.get("fix_suggestion") or f.get("fix") or "")
        reason = str(f.get("confidence_reasoning") or "")

        title_text = Text.assemble(badge, " · ", (name, "bold bright_cyan"))
        subtitle = f"{owasp} · {cwe} | confidence {conf:.2f}"
        if verbose and reason:
            subtitle += f"\nreason: {reason}"

        body_parts: List[Any] = []

        header_line = Text()
        header_line.append(f"Line {line}", style="grey62")
        if filename:
            header_line.append(" · ", style="grey62")
            header_line.append(filename, style="bold medium_purple1")
        header_line.append(f" · confidence {conf:.2f}", style="grey62")
        body_parts.append(header_line)

        if snippet:
            code_lines = snippet.splitlines()
            truncated = False
            if len(code_lines) > 6:
                code_lines = code_lines[:6]
                truncated = True
            snippet_display = "\n".join(code_lines)
            body_parts.append(Syntax(snippet_display, "python", theme="monokai", word_wrap=True))
            if truncated:
                body_parts.append(Text("... (truncated)", style="grey62"))

        if desc:
            body_parts.append(Text(f"  {desc}", style="grey62"))

        if fix:
            body_parts.append(Text(f"  {fix}", style="cyan1"))

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

    # Get counts from grade breakdown
    grade_data = scan_result.get("grade", {}) or {}
    breakdown = grade_data.get("breakdown", {}) or {}
    sev_counts = {
        "critical": breakdown.get("CRITICAL", 0),
        "high": breakdown.get("HIGH", 0),
        "medium": breakdown.get("MEDIUM", 0),
        "low": breakdown.get("LOW", 0),
    }
    risk_score = grade_data.get("score", 0)

    table = Table(
        title=Text("Scan Summary", style="bold bright_cyan"),
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

    _add_row("CRITICAL", "critical", "bright_red")
    _add_row("HIGH", "high", "dark_orange")
    _add_row("MEDIUM", "medium", "yellow1")
    _add_row("LOW", "low", "bright_cyan")

    console.print(table)
    console.print(Text(f"Overall Risk Score: {risk_score}/100", style="bold bright_cyan"))

    # Print grade
    g = grade_data.get("grade", "?")
    label = grade_data.get("label", "")
    recommendation = grade_data.get("recommendation", "")
    grade_colors = {"A+": "bright_green", "A": "green", "B": "yellow", "C": "dark_orange", "D": "red", "F": "bright_red"}
    color = grade_colors.get(g, "white")
    console.print(Text(f"\n  Grade: {g} — {label}", style=f"bold {color}"))
    if recommendation:
        console.print(Text(f"  {recommendation}\n", style=color))


def format_json_report(scan_result: Dict[str, Any]) -> str:
    return json.dumps(scan_result, indent=2, ensure_ascii=False, sort_keys=False)


def format_markdown_report(scan_result: Dict[str, Any]) -> str:
    findings = scan_result.get("findings", [])
    grade_data = scan_result.get("grade", {}) or {}
    files = scan_result.get("files", [])

    lines: List[str] = []
    lines.append("# AI Code Security Reviewer Report")
    lines.append("")
    lines.append(f"- **Files scanned**: {len(files)}")
    lines.append(f"- **Timestamp**: {scan_result.get('scanned_at')}")
    lines.append(f"- **Grade**: {grade_data.get('grade', 'N/A')} ({grade_data.get('score', 0)}/100)")
    lines.append(f"- **Overall risk score**: {grade_data.get('score', 0)}/100")
    lines.append("")

    breakdown = grade_data.get("breakdown", {}) or {}
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    lines.append(f"| critical | {breakdown.get('CRITICAL', 0)} |")
    lines.append(f"| high | {breakdown.get('HIGH', 0)} |")
    lines.append(f"| medium | {breakdown.get('MEDIUM', 0)} |")
    lines.append(f"| low | {breakdown.get('LOW', 0)} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in findings:
        name = f.get("name") or f.get("title") or "Finding"
        sev = str(f.get("severity") or "low").upper()
        lines.append(f"### {name} ({sev})")
        lines.append("")
        lines.append(f"- **File**: `{f.get('filename')}`")
        lines.append(f"- **Line**: {f.get('line_number') or f.get('line')}")
        lines.append(f"- **OWASP**: {f.get('owasp_category') or f.get('owasp')} | **CWE**: {f.get('cwe_id') or f.get('cwe')}")
        lines.append(f"- **Confidence**: {float(f.get('confidence_score') or f.get('confidence') or 0.0):.2f}")
        lines.append("")
        lines.append(f"**Description**: {f.get('description')}")
        lines.append("")
        if f.get("code_snippet"):
            lines.append("```")
            lines.append(str(f.get("code_snippet")))
            lines.append("```")
            lines.append("")
        lines.append(f"**Fix suggestion**: {f.get('fix_suggestion') or f.get('fix')}")
        lines.append("")

    return "\n".join(lines)