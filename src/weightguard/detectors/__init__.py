from weightguard.detectors.gguf_detector import GgufDetector
from weightguard.detectors.keras_detector import KerasDetector
from weightguard.detectors.onnx_detector import OnnxDetector
from weightguard.detectors.pickle_detector import PickleDetector
from weightguard.detectors.safetensors_detector import SafeTensorsDetector

ALL_DETECTORS = [
    PickleDetector(),
    SafeTensorsDetector(),
    KerasDetector(),
    OnnxDetector(),
    GgufDetector(),
]
