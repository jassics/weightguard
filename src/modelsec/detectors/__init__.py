from modelsec.detectors.gguf_detector import GgufDetector
from modelsec.detectors.keras_detector import KerasDetector
from modelsec.detectors.onnx_detector import OnnxDetector
from modelsec.detectors.pickle_detector import PickleDetector
from modelsec.detectors.safetensors_detector import SafeTensorsDetector

ALL_DETECTORS = [
    PickleDetector(),
    SafeTensorsDetector(),
    KerasDetector(),
    OnnxDetector(),
    GgufDetector(),
]
