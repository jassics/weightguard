from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from weightguard.models import Severity
from weightguard.provenance import collect_hf_signals


def _fake_info(**overrides) -> SimpleNamespace:
    defaults = dict(
        created_at=datetime.now(timezone.utc) - timedelta(days=365),
        downloads_all_time=10_000,
        downloads=10_000,
        card_data={"license": "mit"},
        gated=False,
        security_repo_status="safe",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_flags_new_low_download_unlicensed_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    info = _fake_info(
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
        downloads_all_time=0,
        downloads=0,
        card_data={},
    )
    monkeypatch.setattr("huggingface_hub.HfApi.model_info", lambda self, repo_id: info)

    signals = collect_hf_signals("some/org-repo")

    titles = {s.title for s in signals}
    assert "Repository is newly created" in titles
    assert "Low download count" in titles
    assert "No license declared" in titles


def test_established_repo_has_no_risk_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("huggingface_hub.HfApi.model_info", lambda self, repo_id: _fake_info())

    signals = collect_hf_signals("bert-base-uncased")

    assert signals == []


def test_hf_security_scan_flag_is_surfaced_as_high(monkeypatch: pytest.MonkeyPatch) -> None:
    info = _fake_info(security_repo_status="unsafe")
    monkeypatch.setattr("huggingface_hub.HfApi.model_info", lambda self, repo_id: info)

    signals = collect_hf_signals("some/org-repo")

    assert any(s.severity == Severity.HIGH for s in signals)
