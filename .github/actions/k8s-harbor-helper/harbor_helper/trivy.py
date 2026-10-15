from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from harbor_helper.common import WorkflowError, required


def summarize_trivy(environment: Mapping[str, str]) -> dict[str, str]:
    report_path = Path(required(environment, "TRIVY_REPORT"))
    try:
        report = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowError("Trivy did not produce a valid vulnerability report") from error
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise WorkflowError("Trivy did not produce a valid vulnerability report")

    vulnerabilities: list[tuple[str, dict[str, object]]] = []
    for result in report["Results"]:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", ""))
        entries = result.get("Vulnerabilities")
        if not isinstance(entries, list):
            continue
        vulnerabilities.extend(
            (target, vulnerability)
            for vulnerability in entries
            if isinstance(vulnerability, dict)
        )

    severities = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    counts = {
        severity: sum(
            vulnerability.get("Severity") == severity
            for _, vulnerability in vulnerabilities
        )
        for severity in severities
    }
    summary_path = Path(required(environment, "GITHUB_STEP_SUMMARY"))
    with summary_path.open("a") as summary:
        summary.write("### Trivy vulnerability scan\n\n")
        summary.write("| Severity | Count |\n")
        summary.write("|----------|------:|\n")
        for severity in severities:
            summary.write(f"| {severity} | {counts[severity]} |\n")

    if counts["CRITICAL"] == 0:
        print("No CRITICAL vulnerabilities found")
        return {}

    print("CRITICAL vulnerabilities:")
    critical_entries = [
        (target, vulnerability)
        for target, vulnerability in vulnerabilities
        if vulnerability.get("Severity") == "CRITICAL"
    ]
    for target, vulnerability in critical_entries[:50]:
        fields = (
            target,
            vulnerability.get("VulnerabilityID", ""),
            vulnerability.get("PkgName", ""),
            vulnerability.get("InstalledVersion", ""),
            vulnerability.get("FixedVersion", ""),
        )
        print("\t".join(_single_line(str(field)) for field in fields))
    print(
        f"::warning::Trivy found {counts['CRITICAL']} CRITICAL vulnerabilities; "
        "vulnerability scanning is report-only"
    )
    return {}


def _single_line(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
