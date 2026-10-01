from pathlib import Path

from weightguard.detectors.joblib_detector import JoblibDetector
from weightguard.models import Severity


def test_flags_malicious_joblib_as_critical(malicious_joblib: Path) -> None:
    findings = JoblibDetector().scan(malicious_joblib)
    assert findings
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_benign_joblib_has_no_findings(benign_joblib: Path) -> None:
    assert JoblibDetector().scan(benign_joblib) == []
