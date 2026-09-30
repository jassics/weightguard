from __future__ import annotations

from pathlib import Path

from weightguard.models import Finding, Report, Severity
from weightguard.resolver import UnresolvableTarget, resolve
from weightguard.scanner import scan_path

__all__ = [
    "Finding",
    "Report",
    "Severity",
    "UnresolvableTarget",
    "resolve",
    "scan_path",
    "scan",
]


def scan(target: str | Path) -> Report:
    """Resolve and scan a target (HF repo URL, git URL, or local path).

    Convenience wrapper around `resolve()` + `scan_path()` for library use.
    Raises `UnresolvableTarget` if the target can't be resolved. Check
    `report.fails(Severity.HIGH)` (or another threshold) on the result.
    """
    path = resolve(str(target)) if isinstance(target, str) else target
    return scan_path(path)
