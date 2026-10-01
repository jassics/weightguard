from __future__ import annotations

from pathlib import Path

from weightguard.detectors import MODEL_EXTENSIONS
from weightguard.models import Finding, FileRecord, ProvenanceSignal, Report, Severity
from weightguard.policy import Policy
from weightguard.resolver import UnresolvableTarget, hf_repo_id, resolve
from weightguard.scanner import scan_path

__all__ = [
    "Finding",
    "FileRecord",
    "ProvenanceSignal",
    "Report",
    "Severity",
    "Policy",
    "UnresolvableTarget",
    "MODEL_EXTENSIONS",
    "resolve",
    "scan_path",
    "scan",
]


def scan(target: str | Path, *, provenance: bool = True, apply_policy: bool = True) -> Report:
    """Resolve and scan a target (HF repo URL, git URL, or local path).

    Convenience wrapper around `resolve()` + `scan_path()` for library use.
    Raises `UnresolvableTarget` if the target can't be resolved. Check
    `report.fails(Severity.HIGH)` (or another threshold) on the result.

    If `target` is a Hugging Face repo URL and `provenance` is True (default),
    also attaches repo-metadata risk signals (age, downloads, license, HF's
    own security scan status) to `report.provenance`.

    If `apply_policy` is True (default), loads a `.weightguard.yml` allowlist
    from the resolved target's directory (if present) and filters out any
    findings it allows.
    """
    repo_id = hf_repo_id(target) if isinstance(target, str) else None
    path = resolve(str(target)) if isinstance(target, str) else target
    report = scan_path(path)

    if provenance and repo_id is not None:
        from weightguard.provenance import collect_hf_signals

        report.provenance = collect_hf_signals(repo_id)

    if apply_policy:
        report = Policy.load_default(path).apply(report)

    return report
