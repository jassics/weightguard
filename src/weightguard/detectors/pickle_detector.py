from __future__ import annotations

import zipfile
from pathlib import Path

from weightguard.detectors._pickle_common import analyze_pickle_bytes
from weightguard.models import Finding, Severity

PICKLE_EXTENSIONS = {".pkl", ".pickle", ".bin", ".pt", ".pth"}

_MITIGATION = (
    "Do not call torch.load()/pickle.load() on this file directly. Use "
    "`torch.load(..., weights_only=True)`, migrate the model to SafeTensors, "
    "or inspect it further with `fickling --check-safety` before loading."
)
_ZIP_MITIGATION = (
    "Do not call torch.load() on this file directly. Use "
    "`torch.load(..., weights_only=True)`, migrate the model to SafeTensors, "
    "or inspect data.pkl further with `fickling --check-safety` before loading."
)


class PickleDetector:
    """Wraps Trail of Bits' Fickling for AST-level pickle-bytecode analysis.

    Fickling is used rather than a hand-rolled opcode allowlist because
    pattern/denylist scanners (e.g. picklescan) are known to be bypassable
    via malformed-but-valid opcode streams (the "nullifAI" technique).
    """

    name = "pickle-fickling"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in PICKLE_EXTENSIONS

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

        if zipfile.is_zipfile(path):
            return self._scan_zip_container(path)

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

    def _scan_zip_container(self, path: Path) -> list[Finding]:
        """Modern torch.save() output: a zip archive with a top-level
        `<name>/data.pkl` plus raw tensor storage files. Extract and analyze
        the embedded pickle stream(s) rather than the zip bytes themselves."""
        findings: list[Finding] = []
        with zipfile.ZipFile(path) as zf:
            pkl_members = [m for m in zf.namelist() if m.endswith("/data.pkl") or m == "data.pkl"]
            if not pkl_members:
                return [
                    Finding(
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        title="Zip-container .pt/.pth file has no recognizable data.pkl",
                        description=(
                            "This file is a zip archive (torch.save's modern container format) "
                            "but does not contain the expected '<archive>/data.pkl' entry. It may "
                            "be a non-standard or crafted archive."
                        ),
                        file=str(path),
                        mitigation=_ZIP_MITIGATION,
                    )
                ]

            for member in pkl_members:
                result = analyze_pickle_bytes(zf.read(member))
                if result.severity is None:
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=result.severity,
                        title=result.title,
                        description=result.description,
                        file=f"{path}::{member}",
                        evidence=result.evidence,
                        mitigation=_ZIP_MITIGATION,
                    )
                )
        return findings
