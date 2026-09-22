from pathlib import Path

from weightguard.detectors.safetensors_detector import SafeTensorsDetector


def test_valid_safetensors_has_no_findings(valid_safetensors: Path) -> None:
    assert SafeTensorsDetector().scan(valid_safetensors) == []


def test_spoofed_safetensors_is_flagged(spoofed_safetensors: Path) -> None:
    findings = SafeTensorsDetector().scan(spoofed_safetensors)
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
