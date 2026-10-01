from pathlib import Path

from weightguard.detectors.numpy_detector import NumpyDetector
from weightguard.models import Severity


def test_flags_object_dtype_npy_as_malicious(malicious_npy: Path) -> None:
    findings = NumpyDetector().scan(malicious_npy)
    assert findings
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_benign_npy_has_no_findings(benign_npy: Path) -> None:
    assert NumpyDetector().scan(benign_npy) == []


def test_flags_object_dtype_member_inside_npz(malicious_npz: Path) -> None:
    findings = NumpyDetector().scan(malicious_npz)
    assert findings
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("b.npy" in (f.file or "") for f in findings)
