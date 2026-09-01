from __future__ import annotations

from pathlib import Path

import gguf
from gguf.constants import GGUFValueType

from modelsec.models import Finding, Severity

GGUF_EXTENSIONS = {".gguf"}

# No dedicated OSS GGUF security scanner exists (see PROPOSAL.md gap analysis).
# We reuse gguf-py (llama.cpp) for spec-correct header/KV parsing and layer our
# own anomaly checks on top, rather than hand-rolling a parser.
MAX_STRING_KV_BYTES = 1_000_000  # 1MB — legitimate KV strings (names, templates) are tiny
MAX_ARRAY_KV_LEN = 1_000_000
KNOWN_QUANT_TYPES = {t.value for t in gguf.GGMLQuantizationType}


class GgufDetector:
    """Static checks on GGUF header/KV metadata for anomalies that could
    indicate a crafted file: oversized KV blobs, unknown quantization types,
    or tensor metadata inconsistent with the file's actual size."""

    name = "gguf-header-anomaly"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in GGUF_EXTENSIONS

    def scan(self, path: Path) -> list[Finding]:
        try:
            reader = gguf.GGUFReader(str(path))
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Malformed or non-standard GGUF header",
                    description=(
                        f"gguf-py failed to parse this file's header/KV metadata: {exc}. "
                        "A file with the .gguf extension that doesn't conform to the GGUF "
                        "spec may be attempting to evade format-based scanning."
                    ),
                    file=str(path),
                    mitigation=(
                        "Do not load this file with llama.cpp/Ollama. Verify it is a "
                        "genuine GGUF export from a trusted conversion tool."
                    ),
                )
            ]

        findings: list[Finding] = []
        file_size = path.stat().st_size

        for name, field in reader.fields.items():
            if not field.types:
                continue
            value_type = field.types[-1]
            if value_type == GGUFValueType.STRING:
                length = sum(len(p) for p in field.parts if hasattr(p, "__len__"))
                if length > MAX_STRING_KV_BYTES:
                    findings.append(
                        _oversized_kv_finding(path, name, f"string KV of {length} bytes")
                    )
            elif value_type == GGUFValueType.ARRAY and len(field.parts) > MAX_ARRAY_KV_LEN:
                findings.append(
                    _oversized_kv_finding(path, name, f"array KV of {len(field.parts)} elements")
                )

        for tensor in reader.tensors:
            if int(tensor.tensor_type) not in KNOWN_QUANT_TYPES:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.HIGH,
                        title="Unknown tensor quantization type",
                        description=(
                            f"Tensor '{tensor.name}' declares quantization type "
                            f"{tensor.tensor_type!r}, which is not a recognized GGML "
                            "quantization type. This may indicate a hand-crafted file "
                            "targeting a parser bug in a specific loader version."
                        ),
                        file=str(path),
                        evidence=f"tensor={tensor.name} type={tensor.tensor_type!r}",
                        mitigation=(
                            "Do not load this model with an out-of-date or forked GGUF "
                            "loader. Re-export from a trusted source using current llama.cpp "
                            "conversion tooling."
                        ),
                    )
                )
            # A tensor claiming far more elements than the whole file could hold
            # is a classic crafted-header trick to trigger an oversized allocation
            # or out-of-bounds read in a loader.
            if tensor.n_elements > 0 and tensor.n_elements > file_size:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title="Tensor element count exceeds file size",
                        description=(
                            f"Tensor '{tensor.name}' claims {tensor.n_elements} elements, "
                            f"which exceeds the file size ({file_size} bytes). This is "
                            "consistent with a crafted header aimed at triggering an "
                            "out-of-bounds read or oversized allocation in a loader."
                        ),
                        file=str(path),
                        evidence=f"tensor={tensor.name} n_elements={tensor.n_elements} file_size={file_size}",
                        mitigation=(
                            "Do not load this file. Report it as a likely malicious/crafted "
                            "GGUF artifact."
                        ),
                    )
                )

        return findings


def _oversized_kv_finding(path: Path, key: str, detail: str) -> Finding:
    return Finding(
        detector="gguf-header-anomaly",
        severity=Severity.MEDIUM,
        title="Oversized metadata key-value entry",
        description=(
            f"KV key '{key}' contains an unusually large {detail}. Legitimate GGUF "
            "metadata (names, chat templates, tokenizer config) is normally small; "
            "an oversized blob may be an attempt to smuggle payload data or trigger "
            "a parser resource-exhaustion bug."
        ),
        file=str(path),
        evidence=f"key={key} {detail}",
        mitigation="Inspect this KV entry's content manually before loading the model.",
    )
