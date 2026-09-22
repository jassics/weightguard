from __future__ import annotations

from pathlib import Path

import onnx

from weightguard.models import Finding, Severity

ONNX_EXTENSIONS = {".onnx"}

# Ops in these domains are provided by ONNX Runtime's built-in kernels.
# Anything else means a custom-op shared library must be loaded at runtime.
STANDARD_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training", "ai.onnx.training"}

_MITIGATION = (
    "Custom ops require ai.onnx Runtime to load an external native (.so/.dll) "
    "library at inference time — this is arbitrary native code execution. Verify "
    "the referenced custom-op library's provenance before running this model, or "
    "run inference only inside an isolated sandbox with no filesystem/network access."
)


class OnnxDetector:
    """Flags ONNX graphs that reference non-standard operator domains, i.e.
    custom ops capable of loading arbitrary native code at inference time."""

    name = "onnx-custom-op"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in ONNX_EXTENSIONS

    def scan(self, path: Path) -> list[Finding]:
        try:
            model = onnx.load(str(path), load_external_data=False)
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Could not parse as ONNX",
                    description=str(exc),
                    file=str(path),
                    mitigation="Verify this is a valid ONNX model file before loading.",
                )
            ]

        custom_domains = {
            opset.domain for opset in model.opset_import if opset.domain not in STANDARD_DOMAINS
        }
        custom_node_domains = {
            node.domain for node in model.graph.node if node.domain not in STANDARD_DOMAINS
        }
        all_custom = custom_domains | custom_node_domains

        if not all_custom:
            return []

        return [
            Finding(
                detector=self.name,
                severity=Severity.HIGH,
                title="Non-standard operator domain(s) referenced",
                description=(
                    "This ONNX graph references custom-op domain(s) not provided by "
                    "ONNX Runtime's built-in kernel set: " + ", ".join(sorted(all_custom))
                ),
                file=str(path),
                evidence=", ".join(sorted(all_custom)),
                mitigation=_MITIGATION,
            )
        ]
