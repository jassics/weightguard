from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from weightguard import resolve, scan_path
from weightguard.models import Severity
from weightguard.resolver import UnresolvableTarget

app = typer.Typer(help="weightguard — security scanner for ML model artifacts.", no_args_is_help=True)
console = Console()


@app.command(name="version")
def version() -> None:
    """Print the weightguard version."""
    from importlib.metadata import version as _v

    console.print(_v("weightguard"))


@app.command(name="scan")
def scan(
    target: str = typer.Argument(..., help="Hugging Face repo URL, git URL, or local path to scan."),
    fail_on: Severity = typer.Option(Severity.HIGH, help="Exit non-zero if a finding >= this severity is present."),
) -> None:
    """Scan a model (HF repo, git repo, or local directory/file) for known artifact-level security risks."""
    try:
        path = resolve(target)
    except UnresolvableTarget as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    report = scan_path(path)

    if not report.findings:
        console.print(f"[green]No findings.[/green] Scanned: {target}")
        raise typer.Exit(code=0)

    table = Table(title=f"weightguard findings — {target}")
    table.add_column("Severity")
    table.add_column("Detector")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Mitigation")

    for f in sorted(report.findings, key=lambda f: -f.severity.rank):
        table.add_row(f.severity.value, f.detector, f.title, f.file or "-", f.mitigation)

    console.print(table)

    if report.fails(fail_on):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
