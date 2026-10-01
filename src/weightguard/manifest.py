from __future__ import annotations

import hashlib
from pathlib import Path

from weightguard.models import FileRecord

_HASH_CHUNK_SIZE = 1024 * 1024


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_file_records(files: list[Path], base: Path) -> list[FileRecord]:
    """Build an SBOM-style manifest entry per scanned file: relative path,
    sha256, and size. This is the audit trail proving *which exact bytes*
    were scanned, independent of any finding."""
    records = []
    for file in files:
        try:
            rel = file.relative_to(base) if base.is_dir() else file.name
        except ValueError:
            rel = file.name
        records.append(
            FileRecord(
                path=str(rel),
                sha256=hash_file(file),
                size_bytes=file.stat().st_size,
            )
        )
    return records
