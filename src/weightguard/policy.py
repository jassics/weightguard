from __future__ import annotations

import fnmatch
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from weightguard.models import Finding, Report

DEFAULT_POLICY_FILENAME = ".weightguard.yml"


class Allowance(BaseModel):
    """One allowlist entry: suppress findings matching detector + file glob
    (and optionally an exact sha256 pin), with a mandatory justification."""

    detector: str
    file: str = "*"
    sha256: str | None = None
    reason: str
    expires: date | None = None

    def matches(self, finding: Finding, file_hashes: dict[str, str] | None = None) -> bool:
        if finding.detector != self.detector:
            return False
        if finding.file is not None and not fnmatch.fnmatch(finding.file, self.file):
            return False
        if self.sha256 is not None:
            finding_file = finding.file or ""
            actual = next(
                (h for path, h in (file_hashes or {}).items() if finding_file.endswith(path)),
                None,
            )
            if actual != self.sha256:
                return False
        return True

    def is_expired(self, today: date | None = None) -> bool:
        return self.expires is not None and self.expires < (today or date.today())


class Policy(BaseModel):
    allow: list[Allowance] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        data = yaml.safe_load(path.read_text()) or {}
        return cls.model_validate(data)

    @classmethod
    def load_default(cls, search_root: Path) -> "Policy":
        """Look for `.weightguard.yml` in search_root (if it's a dir) or its
        parent (if it's a file). Returns an empty policy if none exists."""
        candidate_dir = search_root if search_root.is_dir() else search_root.parent
        candidate = candidate_dir / DEFAULT_POLICY_FILENAME
        if candidate.is_file():
            return cls.load(candidate)
        return cls()

    def apply(self, report: Report) -> Report:
        """Return a new Report with allowlisted findings removed. Expired
        allowances are ignored (fail closed, not silently extended)."""
        active = [a for a in self.allow if not a.is_expired()]
        file_hashes = {rec.path: rec.sha256 for rec in report.files}
        kept = [f for f in report.findings if not any(a.matches(f, file_hashes) for a in active)]
        return report.model_copy(update={"findings": kept})
