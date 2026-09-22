from __future__ import annotations

from pathlib import Path

from safetensors import safe_open

from weightguard.models import Finding, Severity

SAFETENSORS_EXTENSIONS = {".safetensors"}


class SafeTensorsDetector:
    """SafeTensors has no exec surface (header is JSON metadata + raw tensor
    bytes, no opcode/callable resolution) so a well-formed file is safe by
    construction. This detector only flags files that fail to parse as valid
    SafeTensors, since that's either corruption or a format-spoofing attempt
    (e.g. a renamed pickle)."""

    name = "safetensors-format-check"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in SAFETENSORS_EXTENSIONS

    def scan(self, path: Path) -> list[Finding]:
        try:
            with safe_open(str(path), framework="numpy") as f:
                list(f.keys())
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="File claims .safetensors extension but is not valid SafeTensors",
                    description=(
                        f"Failed to parse as SafeTensors: {exc}. This may be a "
                        "misnamed/spoofed file (e.g. a pickle renamed to evade "
                        "extension-based scanning)."
                    ),
                    file=str(path),
                    mitigation=(
                        "Do not load this file with a SafeTensors loader assuming it is "
                        "safe. Re-identify the real format via magic bytes and re-scan."
                    ),
                )
            ]
        return []
