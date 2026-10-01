from __future__ import annotations

from pathlib import Path

from weightguard.detectors import ALL_DETECTORS
from weightguard.manifest import build_file_records
from weightguard.models import Report


def scan_path(target: Path) -> Report:
    """Static scan of a local directory or file. Never executes/deserializes content."""
    report = Report(target=str(target))
    files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]

    for file in files:
        for detector in ALL_DETECTORS:
            if detector.applies_to(file):
                report.findings.extend(detector.scan(file))

    report.files = build_file_records(files, base=target)
    return report
