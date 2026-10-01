from __future__ import annotations

from datetime import datetime, timezone

from weightguard.models import ProvenanceSignal, Severity

_NEW_REPO_DAYS = 14
_LOW_DOWNLOAD_THRESHOLD = 50


def collect_hf_signals(repo_id: str) -> list[ProvenanceSignal]:
    """Surface repo-metadata risk signals for a Hugging Face model repo via
    the public HfApi — no scraping, no paid threat-intel feed. These are
    supply-chain/trust signals, distinct from the static artifact findings:
    a technically-clean file from a brand-new, zero-download, unlicensed
    repo warrants more scrutiny than the same file from a well-established one.
    """
    from huggingface_hub import HfApi
    from huggingface_hub.utils import HfHubHTTPError

    signals: list[ProvenanceSignal] = []
    try:
        info = HfApi().model_info(repo_id)
    except HfHubHTTPError as exc:
        return [
            ProvenanceSignal(
                source="huggingface-metadata",
                severity=Severity.INFO,
                title="Could not fetch Hugging Face repo metadata",
                description=str(exc),
            )
        ]

    if info.created_at is not None:
        age_days = (datetime.now(timezone.utc) - info.created_at).days
        if age_days < _NEW_REPO_DAYS:
            signals.append(
                ProvenanceSignal(
                    source="huggingface-metadata",
                    severity=Severity.MEDIUM,
                    title="Repository is newly created",
                    description=(
                        f"Repo was created {age_days} day(s) ago (< {_NEW_REPO_DAYS}-day threshold). "
                        "New repos have no track record; weigh other signals (downloads, author, "
                        "card) before trusting the artifact."
                    ),
                )
            )

    downloads = info.downloads_all_time or info.downloads or 0
    if downloads < _LOW_DOWNLOAD_THRESHOLD:
        signals.append(
            ProvenanceSignal(
                source="huggingface-metadata",
                severity=Severity.LOW,
                title="Low download count",
                description=(
                    f"Repo has {downloads} download(s), below the {_LOW_DOWNLOAD_THRESHOLD} "
                    "threshold typically indicating community vetting."
                ),
            )
        )

    license_ = (info.card_data.get("license") if info.card_data else None) or None
    if not license_:
        signals.append(
            ProvenanceSignal(
                source="huggingface-metadata",
                severity=Severity.LOW,
                title="No license declared",
                description="The model card does not declare a license, which complicates usage review.",
            )
        )

    if info.gated:
        signals.append(
            ProvenanceSignal(
                source="huggingface-metadata",
                severity=Severity.INFO,
                title="Repository is gated",
                description="Access requires HF's gating agreement; this is informational, not a risk by itself.",
            )
        )

    security_status = getattr(info, "security_repo_status", None)
    if security_status and str(security_status).lower() not in ("safe", "none", ""):
        signals.append(
            ProvenanceSignal(
                source="huggingface-security-scan",
                severity=Severity.HIGH,
                title="Hugging Face's own security scan flagged this repo",
                description=f"HF security_repo_status = {security_status!r}.",
            )
        )

    return signals
