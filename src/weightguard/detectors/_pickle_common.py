from __future__ import annotations

from fickling.analysis import Severity as FicklingSeverity
from fickling.analysis import check_safety
from fickling.fickle import Pickled

from weightguard.models import Severity

# Fickling's Severity enum instances are not hashable, so map by rank (the
# int stored in Severity.value[0]) rather than by dict key.
SEVERITY_BY_RANK = {
    FicklingSeverity.LIKELY_SAFE.value[0]: None,
    FicklingSeverity.POSSIBLY_UNSAFE.value[0]: Severity.LOW,
    FicklingSeverity.SUSPICIOUS.value[0]: Severity.MEDIUM,
    FicklingSeverity.LIKELY_UNSAFE.value[0]: Severity.HIGH,
    FicklingSeverity.LIKELY_OVERTLY_MALICIOUS.value[0]: Severity.CRITICAL,
    FicklingSeverity.OVERTLY_MALICIOUS.value[0]: Severity.CRITICAL,
}


class PickleStreamResult:
    """Normalized result of running Fickling against one embedded pickle stream."""

    def __init__(self, severity: Severity | None, title: str, description: str, evidence: str):
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence


def analyze_pickle_bytes(data: bytes) -> PickleStreamResult:
    """Run Fickling's AST-level safety check against a raw pickle byte stream."""
    try:
        pickled = Pickled.load(data)
        result = check_safety(pickled)
    except Exception as exc:  # noqa: BLE001 - malformed pickle is itself a signal
        return PickleStreamResult(
            severity=Severity.HIGH,
            title="Malformed or non-standard pickle stream",
            description=(
                "The pickle bytecode could not be fully disassembled by Fickling. "
                f"Malformed opcode streams are a known scanner-evasion technique: {exc}"
            ),
            evidence="",
        )

    mapped = SEVERITY_BY_RANK[result.severity.value[0]]
    return PickleStreamResult(
        severity=mapped,
        title=f"Fickling analysis: {result.severity.value[1]}",
        description=(
            result.to_string()
            or "Fickling could not identify overtly unsafe code, but the pickle "
            "may still be unsafe if the source is untrusted."
        ),
        evidence="; ".join(f"{k}: {v}" for k, v in result.detailed_results().get("AnalysisResult", {}).items()),
    )
