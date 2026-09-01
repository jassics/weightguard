from pathlib import Path

from modelsec.detectors.keras_detector import KerasDetector
from modelsec.models import Severity


def test_lambda_layer_is_flagged_critical(keras_lambda_layer_h5: Path) -> None:
    findings = KerasDetector().scan(keras_lambda_layer_h5)
    assert findings
    assert findings[0].severity == Severity.CRITICAL


def test_benign_dense_layer_has_no_findings(keras_benign_h5: Path) -> None:
    assert KerasDetector().scan(keras_benign_h5) == []
