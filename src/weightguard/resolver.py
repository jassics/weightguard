from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

HF_HOST = "huggingface.co"
_HF_REPO_RE = re.compile(r"^/(?P<repo_id>[^/]+/[^/]+?)(?:/tree/[^/]+)?/?$")


class UnresolvableTarget(Exception):
    pass


def resolve(target: str) -> Path:
    """Resolve a CLI target (HF repo URL, generic git URL, or local path) to a
    local directory. Never executes/imports any downloaded file — this stage
    only fetches bytes to disk."""
    parsed = urlparse(target)

    if parsed.scheme in ("http", "https") and parsed.netloc == HF_HOST:
        return _resolve_huggingface(parsed.path)

    if parsed.scheme in ("http", "https", "git", "ssh") or target.endswith(".git"):
        return _resolve_git(target)

    path = Path(target)
    if path.exists():
        return path

    raise UnresolvableTarget(f"Could not resolve target: {target!r} is not a valid URL or local path")


def _resolve_huggingface(url_path: str) -> Path:
    match = _HF_REPO_RE.match(url_path)
    if not match:
        raise UnresolvableTarget(f"Could not parse Hugging Face repo id from path: {url_path!r}")
    repo_id = match.group("repo_id")

    from huggingface_hub import snapshot_download

    local_dir = Path(tempfile.mkdtemp(prefix="weightguard-hf-"))
    snapshot_download(repo_id=repo_id, local_dir=str(local_dir))
    return local_dir


def _resolve_git(url: str) -> Path:
    local_dir = Path(tempfile.mkdtemp(prefix="weightguard-git-"))
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(local_dir)],
        check=True,
        capture_output=True,
    )
    return local_dir
