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

# machine-readable output
weightguard scan <target> --format json
weightguard scan <target> --format sarif   # GitHub code scanning / GitLab SAST

# skip Hugging Face repo-metadata signals or the .weightguard.yml allowlist
weightguard scan <target> --no-provenance --no-apply-policy
```

Exit codes: `0` clean, `1` a finding at/above `--fail-on`, `2` target could
not be resolved.

## Provenance signals

For Hugging Face targets, `weightguard` also surfaces supply-chain/trust
signals from the repo's public metadata — not a static-analysis finding, but
context that should change how much you trust an otherwise-clean file: repo
age, download count, declared license, gated status, and Hugging Face's own
`security_repo_status`. These show up in `report.provenance` / a separate
table in the CLI, and count toward `--fail-on`.

## Policy / allowlisting

Drop a `.weightguard.yml` next to the scan target to suppress specific,
reviewed findings — required for any team running this in a blocking CI gate
without constant false-positive friction:

```yaml
allow:
  - detector: pickle-fickling
    file: "models/legacy_embedding.pt"
    reason: "Reviewed 2026-01-10 by security team; legacy internal model, no untrusted input."
    expires: 2026-07-01   # optional — omit for no expiry
  - detector: keras-lambda-layer
    file: "*.h5"
    sha256: "<pin to an exact file, optional>"
    reason: "Known Lambda layer, source-reviewed."
```

Expired allowances stop suppressing automatically (fail closed). A missing
`.weightguard.yml` is a no-op.

## Use as a library

The CLI is a thin wrapper over the same public API — import it directly to
scan programmatically (CI scripts, pre-deploy hooks, MLOps pipelines):

```python
from weightguard import scan, Severity, UnresolvableTarget

try:
    report = scan("https://huggingface.co/<org>/<repo>")  # or a git URL / local path
except UnresolvableTarget as exc:
    raise SystemExit(f"could not resolve target: {exc}")

for finding in report.findings:
    print(finding.severity, finding.detector, finding.title, finding.file)

if report.fails(Severity.HIGH):
    raise SystemExit("blocking: high-severity finding in model artifact")
```

Lower-level pieces are also exported if you want to resolve and scan
separately, or scan a `pathlib.Path` you already have on disk:

```python
from weightguard import resolve, scan_path

path = resolve("https://github.com/<org>/<repo>.git")  # downloads, returns local Path
report = scan_path(path)
```

`scan_path` never executes or deserializes the target files — it's pure
static analysis, safe to run against untrusted artifacts.

Every `Report` also carries `report.files` (a sha256 + size manifest of every
scanned file — an audit trail of exactly what was scanned) and
`report.provenance` (supply-chain signals, see below). Serialize either with
`weightguard.report_format.to_json`/`to_sarif`.

## GitHub Action

Gate pull requests that touch model artifacts, without installing anything
locally:

```yaml
# .github/workflows/weightguard.yml
on: pull_request

permissions:
  contents: read
  security-events: write   # to upload SARIF to the Security tab

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history, needed to diff against the PR base

      - uses: jassics/weightguard@v0.2.0
        id: weightguard
        with:
          fail-on: HIGH

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.weightguard.outputs.sarif-file
        with:
          sarif_file: ${{ steps.weightguard.outputs.sarif-file }}
```

By default (`target: changed`) it scans only the model-artifact files
changed in the PR — fast even on repos with many pre-existing weights. Set
`target: .` to scan the whole checkout, or `target: <HF/git URL>` to scan a
remote repo directly. See [`action.yml`](action.yml) for all inputs
(`fail-on`, `format`, `provenance`, `apply-policy`, `version`).

## What it checks today

| Format | Detector | Technique |
|---|---|---|
| Pickle / PyTorch (`.pkl`, `.bin`, `.pt`, `.pth`) | Fickling AST analysis | Detects arbitrary-code-execution opcode chains, including inside modern zip-container `torch.save()` archives (`data.pkl`); resistant to the malformed-opcode-stream evasion that defeats denylist scanners |
| NumPy (`.npy`, `.npz`) | Object-dtype + Fickling | Flags arrays with an object dtype (require `allow_pickle=True` to load) and analyzes the embedded pickle stream |
| Joblib (`.joblib`, `.jbl`) | Fickling AST analysis | joblib dumps are pickle under the hood; same AST analysis as the pickle detector, with optional zlib decompression |
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
