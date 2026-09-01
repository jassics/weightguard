from __future__ import annotations

from pathlib import Path
from typing import Protocol

from modelsec.models import Finding


class Detector(Protocol):
    """A detector inspects one file and returns zero or more findings.

    Detectors must never execute or deserialize untrusted content outside
    a sandbox (Phase 2). Phase-1 detectors are static-analysis only.
    """

    name: str

    def applies_to(self, path: Path) -> bool: ...

    def scan(self, path: Path) -> list[Finding]: ...
