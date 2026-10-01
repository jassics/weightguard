from weightguard.detectors.gguf_detector import GGUF_EXTENSIONS, GgufDetector
from weightguard.detectors.joblib_detector import JOBLIB_EXTENSIONS, JoblibDetector
from weightguard.detectors.keras_detector import KERAS_EXTENSIONS, KerasDetector
from weightguard.detectors.numpy_detector import NUMPY_EXTENSIONS, NumpyDetector
from weightguard.detectors.onnx_detector import ONNX_EXTENSIONS, OnnxDetector
from weightguard.detectors.pickle_detector import PICKLE_EXTENSIONS, PickleDetector
from weightguard.detectors.safetensors_detector import SAFETENSORS_EXTENSIONS, SafeTensorsDetector

ALL_DETECTORS = [
    PickleDetector(),
    SafeTensorsDetector(),
    KerasDetector(),
    OnnxDetector(),
    GgufDetector(),
    NumpyDetector(),
    JoblibDetector(),
]

# Union of every extension any detector recognizes — used by CI integrations
# (e.g. the GitHub Action) to filter a changed-file list down to the files
# worth scanning, without hardcoding the list a second time.
MODEL_EXTENSIONS = (
    PICKLE_EXTENSIONS
    | SAFETENSORS_EXTENSIONS
    | KERAS_EXTENSIONS
    | ONNX_EXTENSIONS
    | GGUF_EXTENSIONS
    | NUMPY_EXTENSIONS
    | JOBLIB_EXTENSIONS
)
