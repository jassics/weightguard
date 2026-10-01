from __future__ import annotations

import ast
import zipfile
from pathlib import Path

from weightguard.detectors._pickle_common import analyze_pickle_bytes
from weightguard.models import Finding, Severity

NUMPY_EXTENSIONS = {".npy", ".npz"}
_MAGIC = b"\x93NUMPY"

_MITIGATION = (
    "Do not call numpy.load(..., allow_pickle=True) on this file. Re-save the "
    "array with a non-object dtype, or load only with allow_pickle=False "
    "(the numpy default) and verify it still works."
)


class NumpyDetector:
    """`.npy`/`.npz` arrays with an object dtype embed a pickle stream that is
    only deserializable via `numpy.load(..., allow_pickle=True)` — the same
    arbitrary-code-execution surface as a raw pickle file."""

    name = "numpy-object-dtype"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in NUMPY_EXTENSIONS

    def scan(self, path: Path) -> list[Finding]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return [self._unreadable(path, str(exc))]

        if path.suffix.lower() == ".npz":
            return self._scan_npz(path, data)
        return self._scan_npy_bytes(path, data, member=None)

    def _scan_npz(self, path: Path, data: bytes) -> list[Finding]:
        try:
            with zipfile.ZipFile(path) as zf:
                findings: list[Finding] = []
                for member in zf.namelist():
                    if not member.endswith(".npy"):
                        continue
                    findings.extend(self._scan_npy_bytes(path, zf.read(member), member=member))
                return findings
        except zipfile.BadZipFile as exc:
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Malformed .npz archive",
                    description=f"Failed to open as a zip archive: {exc}",
                    file=str(path),
                    mitigation=_MITIGATION,
                )
            ]

    def _scan_npy_bytes(self, path: Path, data: bytes, member: str | None) -> list[Finding]:
        if not data.startswith(_MAGIC):
            return []

        header_dict = _parse_npy_header(data)
        if header_dict is None:
            return []
        descr = header_dict.get("descr")
        if not (isinstance(descr, str) and descr.startswith("|O")):
            return []

        location = f"{path}::{member}" if member else str(path)
        pickle_payload = _npy_payload_after_header(data)
        result = analyze_pickle_bytes(pickle_payload)

        severity = result.severity or Severity.MEDIUM
        return [
            Finding(
                detector=self.name,
                severity=severity,
                title="Object-dtype array requires allow_pickle=True to load",
                description=(
                    "This array's dtype is `object`, meaning numpy.load() must be called "
                    "with allow_pickle=True to deserialize it, and the array data is itself "
                    f"a pickle stream. Fickling verdict: {result.title}. {result.description}"
                ),
                file=location,
                evidence=result.evidence,
                mitigation=_MITIGATION,
            )
        ]

    def _unreadable(self, path: Path, msg: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=Severity.INFO,
            title="Could not read file",
            description=msg,
            file=str(path),
            mitigation="Verify the file is accessible and not corrupted.",
        )


def _parse_npy_header(data: bytes) -> dict | None:
    """Parse the NPY header dict without importing numpy's loader (avoids
    ever calling numpy.load on untrusted data)."""
    if len(data) < 10:
        return None
    major = data[6]
    if major == 1:
        header_len = int.from_bytes(data[8:10], "little")
        header_start = 10
    else:
        header_len = int.from_bytes(data[8:12], "little")
        header_start = 12
    header_str = data[header_start : header_start + header_len].decode("latin1")
    try:
        return ast.literal_eval(header_str)
    except (ValueError, SyntaxError):
        return None


def _npy_payload_after_header(data: bytes) -> bytes:
    major = data[6]
    if major == 1:
        header_len = int.from_bytes(data[8:10], "little")
        header_start = 10
    else:
        header_len = int.from_bytes(data[8:12], "little")
        header_start = 12
    return data[header_start + header_len :]
