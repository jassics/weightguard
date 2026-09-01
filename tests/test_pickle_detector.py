from pathlib import Path

from modelsec.detectors.pickle_detector import PickleDetector
from modelsec.models import Severity
from modelsec.scanner import scan_path


def test_flags_malicious_pickle_as_critical(malicious_pickle: Path) -> None:
    findings = PickleDetector().scan(malicious_pickle)
    assert findings, "expected at least one finding for a REDUCE-based payload"
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_benign_pickle_has_no_findings(benign_pickle: Path) -> None:
    findings = PickleDetector().scan(benign_pickle)
    assert findings == []


def test_scan_path_walks_directory_and_fails_gate(tmp_path: Path, malicious_pickle: Path) -> None:
    report = scan_path(malicious_pickle.parent)
    assert report.max_severity == Severity.CRITICAL
    assert report.fails(Severity.HIGH)
    assert report.fails(Severity.CRITICAL)
