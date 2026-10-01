import hashlib
from pathlib import Path

from weightguard.scanner import scan_path


def test_scan_path_populates_file_manifest(tmp_path: Path) -> None:
    f = tmp_path / "weights.bin"
    f.write_bytes(b"not a real model, just bytes")

    report = scan_path(tmp_path)

    assert len(report.files) == 1
    record = report.files[0]
    assert record.path == "weights.bin"
    assert record.size_bytes == len(b"not a real model, just bytes")
    assert record.sha256 == hashlib.sha256(b"not a real model, just bytes").hexdigest()
