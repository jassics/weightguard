from __future__ import annotations

from pathlib import Path

from fickling.analysis import Severity as FicklingSeverity
from fickling.analysis import check_safety
from fickling.fickle import Pickled

from modelsec.models import Finding, Severity

PICKLE_EXTENSIONS = {".pkl", ".pickle", ".bin", ".pt", ".pth"}

# Fickling's Severity enum instances are not hashable, so map by rank (the
# int stored in Severity.value[0]) rather than by dict key.
_SEVERITY_BY_RANK = {
    FicklingSeverity.LIKELY_SAFE.value[0]: None,
    FicklingSeverity.POSSIBLY_UNSAFE.value[0]: Severity.LOW,
    FicklingSeverity.SUSPICIOUS.value[0]: Severity.MEDIUM,
    FicklingSeverity.LIKELY_UNSAFE.value[0]: Severity.HIGH,
    FicklingSeverity.LIKELY_OVERTLY_MALICIOUS.value[0]: Severity.CRITICAL,
    FicklingSeverity.OVERTLY_MALICIOUS.value[0]: Severity.CRITICAL,
}

_MITIGATION = (
    "Do not call torch.load()/pickle.load() on this file directly. Use "
    "`torch.load(..., weights_only=True)`, migrate the model to SafeTensors, "
    "or inspect it further with `fickling --check-safety` before loading."
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

        try:
            pickled = Pickled.load(data)
            result = check_safety(pickled)
        except Exception as exc:  # noqa: BLE001 - malformed pickle is itself a signal
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Malformed or non-standard pickle stream",
                    description=(
                        "The pickle bytecode could not be fully disassembled by Fickling. "
                        f"Malformed opcode streams are a known scanner-evasion technique: {exc}"
                    ),
                    file=str(path),
                    mitigation=_MITIGATION,
                )
            ]

        mapped = _SEVERITY_BY_RANK[result.severity.value[0]]
        if mapped is None:
            return []

        return [
            Finding(
                detector=self.name,
                severity=mapped,
                title=f"Fickling analysis: {result.severity.value[1]}",
                description=(
                    result.to_string()
                    or "Fickling could not identify overtly unsafe code, but the pickle "
                    "may still be unsafe if the source is untrusted."
                ),
                file=str(path),
                evidence="; ".join(f"{k}: {v}" for k, v in result.detailed_results().get("AnalysisResult", {}).items()),
                mitigation=_MITIGATION,
            )
        ]
