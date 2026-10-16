from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from harbor_helper.common import WorkflowError, required
from harbor_helper.config import TARGETS


def prepare_trivy(environment: Mapping[str, str]) -> dict[str, str]:
    config = Path(__file__).resolve().parents[1] / "vex" / "repository.yaml"
    if not config.is_file():
        raise WorkflowError("The trusted Trivy VEX repository configuration is missing")
    return {"vex_config": str(config)}


def summarize_trivy(environment: Mapping[str, str]) -> dict[str, str]:
    target = required(environment, "TARGET")
    if target not in TARGETS:
        raise WorkflowError(f"Unknown vulnerability scan target '{target}'")
    report_path = Path(required(environment, "TRIVY_REPORT"))
    try:
        report = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowError("Trivy did not produce a valid vulnerability report") from error
    if not isinstance(report, dict):
        raise WorkflowError("Trivy did not produce a valid vulnerability report")

    results = report.get("Results")
    # Trivy v0.62.1 omits Results when no scan targets were detected.
    # Require the image-report envelope before treating its absence as empty.
    if "Results" not in report and (
        report.get("SchemaVersion") == 2
        and report.get("ArtifactType") == "container_image"
        and isinstance(report.get("ArtifactName"), str)
        and bool(report["ArtifactName"])
        and isinstance(report.get("Metadata"), dict)
    ):
        results = []
    if not isinstance(results, list):
        raise WorkflowError("Trivy did not produce a valid vulnerability report")

    severities = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    vulnerabilities: list[tuple[str, dict[str, object]]] = []
    for result in results:
        if not isinstance(result, dict):
            raise WorkflowError("Trivy did not produce a valid vulnerability report")
        scan_target = str(result.get("Target", ""))
        entries = result.get("Vulnerabilities")
        if entries is None:
            continue
        if not isinstance(entries, list) or not all(
            isinstance(entry, dict) for entry in entries
        ):
            raise WorkflowError("Trivy did not produce a valid vulnerability report")
        if any(
            entry.get("Severity") not in severities
            for entry in entries
        ):
            raise WorkflowError("Trivy did not produce a valid vulnerability report")
        vulnerabilities.extend(
            (scan_target, vulnerability)
            for vulnerability in entries
        )

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
        mode = "report-only" if target == "dev" else "blocking HIGH/CRITICAL"
        summary.write(f"\nTarget: `{target}`; policy: {mode}.\n")

    if counts["HIGH"] == 0 and counts["CRITICAL"] == 0:
        print("No HIGH or CRITICAL vulnerabilities found after VEX filtering")
        return {}

    print("HIGH and CRITICAL vulnerabilities:")
    blocking_entries = [
        (scan_target, vulnerability)
        for scan_target, vulnerability in vulnerabilities
        if vulnerability.get("Severity") in {"HIGH", "CRITICAL"}
    ]
    for scan_target, vulnerability in blocking_entries[:50]:
        fields = (
            scan_target,
            vulnerability.get("Severity", ""),
            vulnerability.get("VulnerabilityID", ""),
            vulnerability.get("PkgName", ""),
            vulnerability.get("InstalledVersion", ""),
            vulnerability.get("FixedVersion", ""),
        )
        print("\t".join(_single_line(str(field)) for field in fields))
    message = (
        f"Trivy found {counts['HIGH']} HIGH and {counts['CRITICAL']} CRITICAL "
        "vulnerabilities after VEX filtering"
    )
    if target != "dev":
        raise WorkflowError(f"{message}; publication to {target} is blocked")
    print(f"::warning::{message}; dev scanning is report-only")
    return {}


def _single_line(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
