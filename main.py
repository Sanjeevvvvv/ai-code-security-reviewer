import click
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

@click.group()
def cli():
    pass

@cli.command()
@click.argument("target", required=False)
@click.option("--github", "-g", help="GitHub repo URL")
@click.option("--severity", "-s", default=None, type=click.Choice(["critical","high","medium","low"], case_sensitive=False))
@click.option("--output", "-o", default="terminal", type=click.Choice(["terminal","json","markdown"]))
@click.option("--verbose", "-v", is_flag=True)
@click.option("--confidence", "-c", default=0.4, type=float)
@click.option("--no-llm", is_flag=True)
def scan(target, github, severity, output, verbose, confidence, no_llm):
    """Scan a file, directory, or GitHub repo for vulnerabilities."""
    from analyzer.pipeline import analyze_file, analyze_directory
    use_llm = not no_llm

    try:
        if github:
            from utils.file_loader import load_github_repo
            console.print(f"Fetching GitHub repo: {github}")
            temp_dir, files = load_github_repo(github)
            result = analyze_directory(temp_dir, use_llm=use_llm, severity_filter=severity, confidence_threshold=confidence)
        elif target and Path(target).is_file():
            console.print(f"Scanning file: {target}")
            result = analyze_file(target, use_llm=use_llm, severity_filter=severity, confidence_threshold=confidence)
        elif target and Path(target).is_dir():
            console.print(f"Scanning directory: {target}")
            result = analyze_directory(target, use_llm=use_llm, severity_filter=severity, confidence_threshold=confidence)
        else:
            console.print("[red]Please provide a file, directory or --github URL[/red]")
            sys.exit(1)

        if output == "json":
            print(json.dumps(result, indent=2, default=str))
            return

        if output == "markdown":
            findings = result["findings"]
            grade = result["grade"]
            print(f"# Security Scan Report")
            print(f"\nGrade: {grade.get('grade')} ({grade.get('score')}/100) - {grade.get('label')}")
            print(f"\nTotal findings: {len(findings)}")
            for i, f in enumerate(findings, 1):
                print(f"\n## {i}. {f.get('title')} [{f.get('severity')}]")
                print(f"- File: {f.get('filename')} Line {f.get('line')}")
                print(f"- CWE: {f.get('cwe')} | OWASP: {f.get('owasp')}")
                print(f"- Description: {f.get('description')}")
                print(f"- Fix: {f.get('fix')}")
            return

        # Terminal output
        grade = result["grade"]
        findings = result["findings"]
        g = grade.get("grade", "?")
        score = grade.get("score", 0)
        label = grade.get("label", "")
        breakdown = grade.get("breakdown", {})
        rec = grade.get("recommendation", "")

        console.print()
        console.print(f"[bold magenta]Security Grade: {g} ({score}/100) - {label}[/bold magenta]")
        console.print(f"Critical: {breakdown.get('CRITICAL',0)}  High: {breakdown.get('HIGH',0)}  Medium: {breakdown.get('MEDIUM',0)}  Low: {breakdown.get('LOW',0)}")
        console.print(rec)
        console.print(f"\nTotal findings: {len(findings)}")

        for f in findings:
            sev = f.get("severity", "LOW")
            color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "white")
            console.print(f"\n[{color}][{sev}][/{color}] {f.get('title')} - Line {f.get('line')}")
            console.print(f"  File: {f.get('filename')}")
            console.print(f"  {f.get('description')}")
            console.print(f"  Fix: {f.get('fix')}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    cli()
