import json
from pathlib import Path

from weightguard.report_format import to_json, to_sarif
from weightguard.scanner import scan_path


def test_to_json_round_trips_findings(malicious_pickle: Path) -> None:
    report = scan_path(malicious_pickle.parent)
    data = json.loads(to_json(report))
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert data["files"][0]["path"] == malicious_pickle.name


def test_to_sarif_has_valid_shape(malicious_pickle: Path) -> None:
    report = scan_path(malicious_pickle.parent)
    sarif = json.loads(to_sarif(report))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "weightguard"
    assert run["results"][0]["ruleId"] == "pickle-fickling"
    assert run["results"][0]["level"] == "error"


def test_to_sarif_includes_provenance_as_separate_rule_namespace() -> None:
    from weightguard.models import ProvenanceSignal, Report, Severity

    report = Report(target="x", provenance=[ProvenanceSignal(source="huggingface-metadata", severity=Severity.MEDIUM, title="t", description="d")])
    sarif = json.loads(to_sarif(report))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "provenance/huggingface-metadata"
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
