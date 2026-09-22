# weightguard

Security scanner for ML model artifacts. Point it at a Hugging Face repo, a git
URL, or a local path, and it flags known artifact-level risks — malicious
pickle/PyTorch payloads, Keras `Lambda`-layer code injection, ONNX custom-op
RCE surface, and anomalous/crafted GGUF headers — with a severity and a
concrete mitigation for each finding.

Model files are not inert data. Several common serialization formats can
embed code that executes the moment the file is *loaded*, before any
inference happens. `weightguard` is a static, pre-load check you run before
trusting a downloaded model.

## Install

```bash
pip install weightguard
```

## Usage

```bash
# Hugging Face repo
weightguard scan https://huggingface.co/<org>/<repo>

# git repo
weightguard scan https://github.com/<org>/<repo>.git

# local path
weightguard scan /path/to/model

# CI gate — exit non-zero only above a severity threshold (default: HIGH)
weightguard scan <target> --fail-on CRITICAL
```

Exit codes: `0` clean, `1` a finding at/above `--fail-on`, `2` target could
not be resolved.

## What it checks today

| Format | Detector | Technique |
|---|---|---|
| Pickle / PyTorch (`.pkl`, `.bin`, `.pt`, `.pth`) | Fickling AST analysis | Detects arbitrary-code-execution opcode chains; resistant to the malformed-opcode-stream evasion that defeats denylist scanners |
| SafeTensors | Format check | Flags files that fail to parse as valid SafeTensors (renamed/spoofed files) |
| Keras (`.h5`, `.keras`) | Lambda-layer check | Flags `Lambda` layers, which embed a marshalled Python function executed on load |
| ONNX | Custom-op check | Flags graphs referencing non-standard operator domains (native-code load surface) |
| GGUF | Header/KV anomaly check | Flags malformed headers, oversized KV metadata, unknown quantization types, and tensor sizes inconsistent with the file |

## Development

```bash
uv sync
uv run pytest -q
```

## License

MIT
