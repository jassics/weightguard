from __future__ import annotations

import json
from pathlib import Path

import h5py

from modelsec.models import Finding, Severity

KERAS_EXTENSIONS = {".h5", ".hdf5", ".keras"}

# Layer types that embed and execute arbitrary Python at deserialization time.
DANGEROUS_LAYER_TYPES = {"Lambda"}

_MITIGATION = (
    "Do not call keras.models.load_model() on this file. Inspect the model_config "
    "JSON for the flagged layer(s), rewrite them as named functions registered via "
    "@keras.saving.register_keras_serializable, or reject the model if you cannot "
    "verify the embedded code."
)


class KerasDetector:
    """Keras H5/.keras files can embed a serialized Python function inside a
    Lambda layer's config, which is deserialized (and effectively executed)
    on load. This is the same technique ModelScan's Keras checks target."""

    name = "keras-lambda-layer"

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in KERAS_EXTENSIONS

    def scan(self, path: Path) -> list[Finding]:
        try:
            with h5py.File(path, "r") as f:
                config_raw = f.attrs.get("model_config")
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Could not parse as Keras HDF5",
                    description=str(exc),
                    file=str(path),
                    mitigation="Verify this is a valid Keras H5 file before loading.",
                )
            ]

        if not config_raw:
            return []

        if isinstance(config_raw, bytes):
            config_raw = config_raw.decode("utf-8", errors="replace")

        try:
            config = json.loads(config_raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for layer in _iter_layers(config):
            layer_type = layer.get("class_name")
            if layer_type in DANGEROUS_LAYER_TYPES:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title=f"{layer_type} layer embeds arbitrary code",
                        description=(
                            f"Layer '{layer.get('config', {}).get('name', '?')}' is a "
                            f"{layer_type} layer, which stores a marshalled Python function "
                            "that executes when the model is loaded."
                        ),
                        file=str(path),
                        evidence=json.dumps(layer.get("config", {}))[:300],
                        mitigation=_MITIGATION,
                    )
                )
        return findings


def _iter_layers(config: dict) -> list[dict]:
    layers = config.get("config", {}).get("layers", [])
    if isinstance(layers, list):
        return layers
    return []
