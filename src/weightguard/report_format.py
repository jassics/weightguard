from __future__ import annotations

import json
from importlib.metadata import version as _pkg_version

from weightguard.models import Finding, Report, Severity

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF only has error/warning/note; map our five severities down to those.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_json(report: Report) -> str:
    """Full-fidelity JSON dump: findings, provenance signals, and the file manifest."""
    return report.model_dump_json(indent=2)


def to_sarif(report: Report) -> str:
    """SARIF 2.1.0, for GitHub code scanning / GitLab SAST / other SARIF-aware
    dashboards. Provenance signals are included as results under a separate
    rule namespace (`provenance/*`) since they aren't code-location findings."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in report.findings:
        rule_id = finding.detector
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": finding.mitigation},
            },
        )
        results.append(_finding_result(rule_id, finding))

    for signal in report.provenance:
        rule_id = f"provenance/{signal.source}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": signal.title},
                "fullDescription": {"text": "Supply-chain / repo-metadata risk signal, not a static-analysis finding."},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[signal.severity],
                "message": {"text": f"{signal.title}: {signal.description}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": report.target}}}
                ],
            }
        )

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "weightguard",
                        "version": _pkg_version("weightguard"),
                        "informationUri": "https://github.com/jassics/weightguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _finding_result(rule_id: str, finding: Finding) -> dict:
    uri = (finding.file or "").split("::", 1)[0] or "."
    return {
        "ruleId": rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}: {finding.description}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }
