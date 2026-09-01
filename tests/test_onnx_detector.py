from modelsec.detectors.onnx_detector import OnnxDetector
from modelsec.models import Severity


def test_standard_onnx_model_has_no_findings(onnx_standard_model) -> None:
    assert OnnxDetector().scan(onnx_standard_model) == []


def test_custom_op_domain_is_flagged(onnx_custom_op_model) -> None:
    findings = OnnxDetector().scan(onnx_custom_op_model)
    assert findings
    assert findings[0].severity == Severity.HIGH
    assert "com.evil.custom" in findings[0].evidence
