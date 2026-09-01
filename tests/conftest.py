import json
import pickle
from pathlib import Path

import numpy as np
import pytest


class _EicarPayload:
    """Mimics the shape of the mcpotato/42-eicar-street test repo: a pickle
    whose __reduce__ triggers a callable on unpickling."""

    def __reduce__(self):
        return (eval, ("'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'",))


@pytest.fixture()
def malicious_pickle(tmp_path: Path) -> Path:
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(pickle.dumps(_EicarPayload()))
    return p


@pytest.fixture()
def benign_pickle(tmp_path: Path) -> Path:
    p = tmp_path / "weights.pkl"
    p.write_bytes(pickle.dumps({"layer1": [0.1, 0.2, 0.3]}))
    return p


@pytest.fixture()
def valid_safetensors(tmp_path: Path) -> Path:
    from safetensors.numpy import save_file

    p = tmp_path / "model.safetensors"
    save_file({"w": np.zeros((2, 2), dtype=np.float32)}, str(p))
    return p


@pytest.fixture()
def spoofed_safetensors(tmp_path: Path) -> Path:
    """A pickle file renamed to .safetensors to evade extension-based scanning."""
    p = tmp_path / "model.safetensors"
    p.write_bytes(pickle.dumps({"not": "safetensors"}))
    return p


@pytest.fixture()
def keras_lambda_layer_h5(tmp_path: Path) -> Path:
    import h5py

    p = tmp_path / "model.h5"
    config = {
        "class_name": "Sequential",
        "config": {
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {"name": "lambda_1", "function": ["gASVDwAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJST"]},
                }
            ]
        },
    }
    with h5py.File(p, "w") as f:
        f.attrs["model_config"] = json.dumps(config)
    return p


@pytest.fixture()
def keras_benign_h5(tmp_path: Path) -> Path:
    import h5py

    p = tmp_path / "model.h5"
    config = {
        "class_name": "Sequential",
        "config": {"layers": [{"class_name": "Dense", "config": {"name": "dense_1", "units": 10}}]},
    }
    with h5py.File(p, "w") as f:
        f.attrs["model_config"] = json.dumps(config)
    return p


@pytest.fixture()
def onnx_standard_model(tmp_path: Path):
    import onnx
    from onnx import TensorProto, helper

    node = helper.make_node("Relu", ["x"], ["y"])
    graph = helper.make_graph(
        [node],
        "g",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    p = tmp_path / "model.onnx"
    onnx.save(model, str(p))
    return p


@pytest.fixture()
def onnx_custom_op_model(tmp_path: Path):
    import onnx
    from onnx import TensorProto, helper

    node = helper.make_node("MyCustomOp", ["x"], ["y"], domain="com.evil.custom")
    graph = helper.make_graph(
        [node],
        "g",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1])],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 17), helper.make_opsetid("com.evil.custom", 1)],
    )
    p = tmp_path / "model.onnx"
    onnx.save(model, str(p))
    return p


@pytest.fixture()
def gguf_valid_model(tmp_path: Path) -> Path:
    import gguf

    p = tmp_path / "model.gguf"
    w = gguf.GGUFWriter(str(p), "llama")
    w.add_context_length(2048)
    w.add_tensor("weight", np.zeros((4, 4), dtype=np.float32))
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()
    return p
