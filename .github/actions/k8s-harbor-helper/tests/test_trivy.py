import json
from pathlib import Path
from unittest import mock

from harbor_helper.trivy import prepare_trivy, summarize_trivy
from support import TemporaryTestCase


class TrivyTests(TemporaryTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.report = self.root / "report.json"
        self.summary = self.root / "summary.md"

    def environment(self, target: str = "dev") -> dict[str, str]:
        return {
            "TARGET": target,
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "TRIVY_REPORT": str(self.report),
        }

    def write_report(self, *severities: str) -> None:
        self.report.write_text(json.dumps({
            "Results": [{
                "Target": "application",
                "Vulnerabilities": [
                    {"Severity": severity, "VulnerabilityID": f"CVE-{severity}"}
                    for severity in severities
                ],
            }],
        }))

    def test_summary_and_critical_report(self) -> None:
        self.write_report("HIGH", "CRITICAL")
        with mock.patch("builtins.print") as print_mock:
            summarize_trivy(self.environment())
        self.assertIn("| HIGH | 1 |", self.summary.read_text())
        self.assertIn("| CRITICAL | 1 |", self.summary.read_text())
        self.assertTrue(
            any(
                "::warning::" in str(call) and "report-only" in str(call)
                for call in print_mock.call_args_list
            )
        )

    def test_dev_high_without_critical_is_warning_only(self) -> None:
        self.write_report("HIGH")
        with mock.patch("builtins.print") as print_mock:
            summarize_trivy(self.environment())
        self.assertTrue(any(
            "::warning::" in str(call) for call in print_mock.call_args_list
        ))

    def test_high_and_critical_block_all_non_dev_targets_without_a_fix(self) -> None:
        for target in ("staging", "prod", "critical"):
            for severity in ("HIGH", "CRITICAL"):
                with self.subTest(target=target, severity=severity):
                    self.write_report(severity)
                    original = self.report.read_text()
                    self.assert_workflow_error(
                        f"publication to {target} is blocked",
                        summarize_trivy,
                        self.environment(target),
                    )
                    self.assertIn(f"| {severity} | 1 |", self.summary.read_text())
                    self.assertEqual(self.report.read_text(), original)

    def test_lower_severities_do_not_block_any_target(self) -> None:
        self.write_report("UNKNOWN", "LOW", "MEDIUM")
        for target in ("dev", "staging", "prod", "critical"):
            with self.subTest(target=target):
                summarize_trivy(self.environment(target))

    def test_vex_suppressed_findings_do_not_block_publication(self) -> None:
        self.report.write_text(json.dumps({
            "Results": [{
                "Target": "application",
                "ExperimentalModifiedFindings": [{
                    "Type": "vulnerability",
                    "Status": "not_affected",
                    "Finding": {
                        "Severity": "CRITICAL",
                        "VulnerabilityID": "CVE-SUPPRESSED",
                    },
                }],
            }],
        }))
        original = self.report.read_text()
        summarize_trivy(self.environment("prod"))
        self.assertIn("| CRITICAL | 0 |", self.summary.read_text())
        self.assertEqual(self.report.read_text(), original)

    def test_empty_results_are_allowed(self) -> None:
        self.report.write_text('{"Results": []}')
        summarize_trivy(self.environment("prod"))

    def test_valid_empty_image_report_without_results_is_allowed(self) -> None:
        # The JSON writer in Trivy v0.62.1 omits Results for an empty image.
        self.report.write_text(json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "local-build:test",
            "ArtifactType": "container_image",
            "Metadata": {"ImageConfig": {"config": {}}},
        }))
        for target in ("dev", "staging", "prod", "critical"):
            with self.subTest(target=target):
                summarize_trivy(self.environment(target))
                self.assertIn("| HIGH | 0 |", self.summary.read_text())
                self.assertIn("| CRITICAL | 0 |", self.summary.read_text())

    def test_missing_results_requires_a_valid_image_report_envelope(self) -> None:
        valid = {
            "SchemaVersion": 2,
            "ArtifactName": "local-build:test",
            "ArtifactType": "container_image",
            "Metadata": {},
        }
        for field, value in (
            ("SchemaVersion", None), ("SchemaVersion", 3),
            ("ArtifactName", None), ("ArtifactName", ""),
            ("ArtifactType", None), ("ArtifactType", "filesystem"),
            ("Metadata", None), ("Metadata", []),
        ):
            with self.subTest(field=field, value=value):
                self.report.write_text(json.dumps(valid | {field: value}))
                self.assert_workflow_error(
                    "valid vulnerability report",
                    summarize_trivy,
                    self.environment("prod"),
                )

    def test_explicit_null_results_are_rejected_for_an_image_report(self) -> None:
        self.report.write_text(json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "local-build:test",
            "ArtifactType": "container_image",
            "Metadata": {},
            "Results": None,
        }))
        self.assert_workflow_error(
            "valid vulnerability report", summarize_trivy, self.environment("prod")
        )

    def test_missing_or_unknown_target_is_rejected(self) -> None:
        self.write_report("HIGH")
        for target in ("", "devel", "production", "unknown"):
            with self.subTest(target=target):
                self.assert_workflow_error(
                    "empty|Unknown vulnerability scan target",
                    summarize_trivy,
                    self.environment(target),
                )

    def test_invalid_report_is_rejected(self) -> None:
        for report in (
            "not JSON", "[]", "{}", '{"Results": null}', '{"Results": [null]}',
            '{"Results": [{"Vulnerabilities": {}}]}',
            '{"Results": [{"Vulnerabilities": [null]}]}',
            '{"Results": [{"Vulnerabilities": [{"Severity": "invalid"}]}]}',
            '{"Results": [{"Vulnerabilities": [{"Severity": {}}]}]}',
        ):
            with self.subTest(report=report):
                self.report.write_text(report)
                self.assert_workflow_error(
                    "valid vulnerability report",
                    summarize_trivy,
                    self.environment(),
                )

    def test_missing_report_is_rejected(self) -> None:
        self.assert_workflow_error(
            "valid vulnerability report",
            summarize_trivy,
            self.environment(),
        )

    def test_vex_config_comes_from_the_helper_checkout(self) -> None:
        outputs = prepare_trivy({})
        config = Path(outputs["vex_config"])
        self.assertEqual(
            config, Path(__file__).resolve().parents[1] / "vex" / "repository.yaml"
        )
        self.assertTrue(config.is_file())

    def test_public_vex_sources_are_enabled_and_internal_source_stays_disabled(self) -> None:
        config = Path(prepare_trivy({})["vex_config"]).read_text()
        for name, url, enabled in (
            ("default", "https://github.com/aquasecurity/vexhub", "true"),
            ("dhi-vex", "https://github.com/docker-hardened-images/advisories", "true"),
            ("internal", "https://github.com/lidofinance/vex-db", "false"),
        ):
            with self.subTest(name=name):
                self.assertIn(
                    f"  - name: {name}\n    url: {url}\n    enabled: {enabled}\n",
                    config,
                )

    def test_missing_trusted_vex_config_fails_closed(self) -> None:
        with mock.patch(
            "harbor_helper.trivy.__file__", str(self.root / "missing/trivy.py")
        ):
            self.assert_workflow_error("configuration is missing", prepare_trivy, {})
