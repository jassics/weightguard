from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class Finding(BaseModel):
    detector: str
    severity: Severity
    title: str
    description: str
    file: str | None = None
    evidence: str | None = None
    mitigation: str


class ProvenanceSignal(BaseModel):
    """A non-static-analysis risk signal about the target's origin/metadata
    (e.g. Hugging Face repo age, downloads, gated/license status)."""

    source: str
    severity: Severity
    title: str
    description: str


class FileRecord(BaseModel):
    """One scanned file's identity, for the scan manifest."""

    path: str
    sha256: str
    size_bytes: int


class Report(BaseModel):
    target: str
    findings: list[Finding] = Field(default_factory=list)
    provenance: list[ProvenanceSignal] = Field(default_factory=list)
    files: list[FileRecord] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        severities = [f.severity for f in self.findings] + [p.severity for p in self.provenance]
        if not severities:
            return Severity.INFO
        return max(severities, key=lambda s: s.rank)

    def fails(self, threshold: Severity) -> bool:
        return self.max_severity.rank >= threshold.rank
