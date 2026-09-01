from pathlib import Path

from modelsec.detectors.gguf_detector import GgufDetector


def test_valid_gguf_has_no_findings(gguf_valid_model: Path) -> None:
    assert GgufDetector().scan(gguf_valid_model) == []


def test_malformed_gguf_is_flagged(tmp_path: Path) -> None:
    p = tmp_path / "fake.gguf"
    p.write_bytes(b"NOTGGUF" + b"\x00" * 32)
    findings = GgufDetector().scan(p)
    assert findings
    assert findings[0].severity.value == "HIGH"
