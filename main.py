# -*- coding: utf-8 -*-
import click
import json
import sys
import os

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

ASCII_LOGO = r"""
   ██████╗███████╗███████╗
  ██╔════╝██╔════╝██╔════╝
  ██║     ███████╗█████╗  
  ██║     ╚════██║██╔══╝  
  ╚██████╗███████║███████╗
   ╚═════╝╚══════╝╚══════╝
  AI Code Security Reviewer v2.0
"""


def print_banner():
    console.print(Text(ASCII_LOGO, style="bright_cyan"))
    console.print(
        Panel(
            "Scanning for: SQL Injection · XSS · CSRF · Command Injection · "
            "Path Traversal · Weak Crypto · Secrets · Auth Issues · Deserialization",
            style="medium_purple1",
            padding=(0, 2),
        )
    )


@click.group()
def cli():
    """AI Code Security Reviewer — Find vulnerabilities before attackers do."""
    pass


@cli.command()
@click.argument("target", required=False)
@click.option("--github", "-g", help="GitHub repo URL to scan")
@click.option("--severity", "-s", default=None,
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              help="Minimum severity to show")
@click.option("--output", "-o", default="terminal",
              type=click.Choice(["terminal", "json", "markdown"]),
              help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option("--autofix", "-a", is_flag=True, help="Generate AI fix suggestions")
@click.option("--confidence", "-c", default=0.4, type=float,
              help="Minimum confidence threshold (0.0-1.0, default: 0.4)")
@click.option("--no-llm", is_flag=True, help="Skip LLM analysis (faster, offline mode)")
def scan(target, github, severity, output, verbose, autofix, confidence, no_llm):
    """Scan a file, directory, or GitHub repo for security vulnerabilities."""

    print_banner()

    from utils.file_loader import load_github_repo
    from analyzer.pipeline import analyze_file, analyze_directory
    from output.formatter import render_terminal_report, format_json_report, format_markdown_report

    use_llm = not no_llm

    try:
        if github:
            console.print(f"\n[bright_cyan]Fetching GitHub repo:[/] {github}")
            temp_dir, files = load_github_repo(github)
            result = analyze_directory(temp_dir, use_llm=use_llm, severity_filter=severity, confidence_threshold=confidence)
            console.print(f"[dim]Scanned {result['stats']['files_scanned']} files[/]")

        elif target and Path(target).is_file():
            console.print(f"\n[bright_cyan]Scanning file:[/] {target}")
            result = analyze_file(target, use_llm=use_llm, severity_filter=severity, confidence_threshold=confidence)

        elif target and Path(target).is_dir():
            console.print(f"\n[bright_cyan]Scanning directory:[/] {target}")
            result = analyze_directory(target, use_llm=use_llm, severity_filter=severity, confidence_threshold=confidence)

        else:
            console.print("[red]Please provide a file path, directory, or --github URL[/]")
            sys.exit(1)

        if output == "json":
            print(format_json_report(result))
            return

        if output == "markdown":
            print(format_markdown_report(result))
            return

        render_terminal_report(result, verbose=verbose, console=console)

    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[yellow]Warning: {e}[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    cli()