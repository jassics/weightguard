from pathlib import Path

import pytest

from modelsec.resolver import UnresolvableTarget, resolve


def test_local_path_passthrough(tmp_path: Path) -> None:
    assert resolve(str(tmp_path)) == tmp_path


def test_nonexistent_path_is_unresolvable() -> None:
    with pytest.raises(UnresolvableTarget):
        resolve("/definitely/does/not/exist/on/this/machine")


def test_hf_url_regex_parses_repo_id() -> None:
    from modelsec.resolver import _HF_REPO_RE

    m = _HF_REPO_RE.match("/mcpotato/42-eicar-street/tree/main")
    assert m.group("repo_id") == "mcpotato/42-eicar-street"
