from __future__ import annotations

import json
from enum import Enum

import typer
from rich.console import Console
from rich.table import Table

from weightguard import MODEL_EXTENSIONS, scan as run_scan
from weightguard.models import Report, Severity
from weightguard.report_format import to_json, to_sarif
from weightguard.resolver import UnresolvableTarget

app = typer.Typer(help="weightguard — security scanner for ML model artifacts.", no_args_is_help=True)
console = Console()


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


@app.command(name="version")
def version() -> None:
    """Print the weightguard version."""
    from importlib.metadata import version as _v

    console.print(_v("weightguard"))


@app.command(name="list-extensions")
def list_extensions() -> None:
    """Print every file extension weightguard's detectors recognize, one per line.

    Intended for scripting (e.g. filtering a changed-file list in CI) rather
    than human reading.
    """
    for ext in sorted(MODEL_EXTENSIONS):
        print(ext)


@app.command(name="scan")
def scan(
    target: str = typer.Argument(..., help="Hugging Face repo URL, git URL, or local path to scan."),
    fail_on: Severity = typer.Option(Severity.HIGH, help="Exit non-zero if a finding >= this severity is present."),
    provenance: bool = typer.Option(
        True, help="For Hugging Face targets, also check repo-metadata risk signals (age, downloads, license, HF security scan)."
    ),
    apply_policy: bool = typer.Option(
        True, "--apply-policy/--no-apply-policy", help="Apply a .weightguard.yml allowlist from the target directory, if present."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Output format: table (human-readable), json, or sarif (for code-scanning dashboards)."
    ),
) -> None:
    """Scan a model (HF repo, git repo, or local directory/file) for known artifact-level security risks."""
    try:
        report = run_scan(target, provenance=provenance, apply_policy=apply_policy)
    except UnresolvableTarget as exc:
        if output_format == OutputFormat.TABLE:
            console.print(f"[red]Error:[/red] {exc}")
        else:
            console.print(json.dumps({"error": str(exc)}) if output_format == OutputFormat.JSON else str(exc))
        raise typer.Exit(code=2) from exc

    if output_format == OutputFormat.JSON:
        print(to_json(report))
    elif output_format == OutputFormat.SARIF:
        print(to_sarif(report))
    else:
        _render_table(report, target)

    if report.fails(fail_on):
        raise typer.Exit(code=1)


def _render_table(report: Report, target: str) -> None:
    if report.provenance:
        prov_table = Table(title=f"weightguard provenance signals — {target}")
        prov_table.add_column("Severity")
        prov_table.add_column("Source")
        prov_table.add_column("Title")
        prov_table.add_column("Description")
        for p in sorted(report.provenance, key=lambda p: -p.severity.rank):
            prov_table.add_row(p.severity.value, p.source, p.title, p.description)
        console.print(prov_table)

    if not report.findings:
        console.print(f"[green]No static findings.[/green] Scanned: {target}")
        return

    table = Table(title=f"weightguard findings — {target}")
    table.add_column("Severity")
    table.add_column("Detector")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Mitigation")

    for f in sorted(report.findings, key=lambda f: -f.severity.rank):
        table.add_row(f.severity.value, f.detector, f.title, f.file or "-", f.mitigation)

    console.print(table)


if __name__ == "__main__":
    app()
