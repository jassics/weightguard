from __future__ import annotations

import zlib
from pathlib import Path

from weightguard.detectors._pickle_common import analyze_pickle_bytes
from weightguard.models import Finding, Severity

JOBLIB_EXTENSIONS = {".joblib", ".jbl"}

_MITIGATION = (
    "Do not call joblib.load() on this file directly. Joblib dumps are pickle "
    "streams under the hood — the same RCE surface as raw pickle. Migrate to "
    "SafeTensors/NumPy (non-object dtype) or inspect with `fickling` first."
)


class JoblibDetector:
    """joblib.dump() serializes via pickle (optionally zlib/lz4-compressed on
    top). We decompress if possible and run the same Fickling AST analysis
    used for raw pickle files — joblib adds no additional exec surface beyond
    the underlying pickle stream."""

    name = "joblib-pickle"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in JOBLIB_EXTENSIONS

    def scan(self, path: Path) -> list[Finding]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Could not read file",
                    description=str(exc),
                    file=str(path),
                    mitigation="Verify the file is accessible and not corrupted.",
                )
            ]

        try:
            data = zlib.decompress(data)
        except zlib.error:
            pass  # not zlib-compressed; treat as a raw pickle stream

        result = analyze_pickle_bytes(data)
        if result.severity is None:
            return []

        return [
            Finding(
                detector=self.name,
                severity=result.severity,
                title=result.title,
                description=result.description,
                file=str(path),
                evidence=result.evidence,
                mitigation=_MITIGATION,
            )
        ]
