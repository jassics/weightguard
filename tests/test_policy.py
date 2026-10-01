from datetime import date, timedelta
from pathlib import Path

from weightguard.policy import Policy
from weightguard.scanner import scan_path


def test_allowlist_suppresses_matching_finding(malicious_pickle: Path) -> None:
    policy_file = malicious_pickle.parent / ".weightguard.yml"
    policy_file.write_text(
        f"""
allow:
  - detector: pickle-fickling
    file: "*{malicious_pickle.name}"
    reason: "reviewed and accepted for this fixture"
"""
    )

    report = scan_path(malicious_pickle.parent)
    assert report.findings  # sanity: detector did fire

    policy = Policy.load_default(malicious_pickle.parent)
    filtered = policy.apply(report)
    assert filtered.findings == []


def test_expired_allowance_does_not_suppress(malicious_pickle: Path) -> None:
    policy_file = malicious_pickle.parent / ".weightguard.yml"
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    policy_file.write_text(
        f"""
allow:
  - detector: pickle-fickling
    file: "*{malicious_pickle.name}"
    reason: "expired exception"
    expires: {yesterday}
"""
    )

    report = scan_path(malicious_pickle.parent)
    policy = Policy.load_default(malicious_pickle.parent)
    filtered = policy.apply(report)
    assert filtered.findings  # not suppressed: allowance expired


def test_no_policy_file_is_a_no_op(malicious_pickle: Path) -> None:
    report = scan_path(malicious_pickle.parent)
    policy = Policy.load_default(malicious_pickle.parent)
    filtered = policy.apply(report)
    assert filtered.findings == report.findings
