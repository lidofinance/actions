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

    def test_report_only_allows_high_and_critical_for_every_target(self) -> None:
        self.write_report("HIGH", "CRITICAL")
        for target in ("dev", "staging", "prod", "critical"):
            self.summary.unlink(missing_ok=True)
            with self.subTest(target=target), mock.patch("builtins.print") as output:
                summarize_trivy(self.environment(target) | {"TRIVY_REPORT_ONLY": "true"})
                self.assertTrue(any("::warning::" in str(call) for call in output.call_args_list))
                self.assertIn("| HIGH | 1 |", self.summary.read_text())
                self.assertIn("| CRITICAL | 1 |", self.summary.read_text())
                self.assertIn("policy: report-only", self.summary.read_text())
                self.assertNotIn("blocking HIGH/CRITICAL", self.summary.read_text())

    def test_report_only_marks_missing_and_invalid_reports_as_unavailable(self) -> None:
        for content in (None, "invalid JSON", "{}", '{"Results": null}', '{"Results": [null]}'):
            self.report.unlink(missing_ok=True)
            self.summary.unlink(missing_ok=True)
            if content is not None:
                self.report.write_text(content)
            with self.subTest(content=content), mock.patch("builtins.print") as output:
                summarize_trivy(self.environment("prod") | {"TRIVY_REPORT_ONLY": "true"})
                self.assertIn("Status: **unavailable**", self.summary.read_text())
                self.assertNotIn("| HIGH |", self.summary.read_text())
                self.assertTrue(any("::warning::" in str(call) for call in output.call_args_list))
                self.assertFalse(any("No HIGH" in str(call) for call in output.call_args_list))

    def test_failed_scan_does_not_trust_a_partial_or_stale_clean_report(self) -> None:
        self.write_report()
        for outcome in ("failure", "skipped", "cancelled", ""):
            self.summary.unlink(missing_ok=True)
            with self.subTest(outcome=outcome), mock.patch("builtins.print"):
                summarize_trivy(self.environment("prod") | {
                    "TRIVY_REPORT_ONLY": "true", "TRIVY_SCAN_OUTCOME": outcome,
                })
                self.assertIn("Status: **unavailable**", self.summary.read_text())
                self.assertNotIn("| HIGH |", self.summary.read_text())

    def test_report_only_clean_scan_still_produces_a_summary(self) -> None:
        self.write_report("LOW")
        summarize_trivy(self.environment("prod") | {
            "TRIVY_REPORT_ONLY": "true", "TRIVY_SCAN_OUTCOME": "success",
        })
        self.assertIn("| LOW | 1 |", self.summary.read_text())
        self.assertIn("policy: report-only", self.summary.read_text())

    def test_report_only_flag_requires_an_explicit_boolean(self) -> None:
        self.assert_workflow_error(
            "TRIVY_REPORT_ONLY must be", summarize_trivy,
            self.environment("prod") | {"TRIVY_REPORT_ONLY": "invalid"},
        )

    def test_critical_blocks_all_non_dev_targets_without_a_fix(self) -> None:
        for target in ("staging", "prod", "critical"):
            with self.subTest(target=target):
                self.summary.unlink(missing_ok=True)
                self.write_report("CRITICAL")
                original = self.report.read_text()
                self.assert_workflow_error(
                    f"publication to {target} is blocked",
                    summarize_trivy,
                    self.environment(target),
                )
                self.assertIn("| CRITICAL | 1 |", self.summary.read_text())
                self.assertEqual(self.report.read_text(), original)

    def test_lower_severities_do_not_block_any_target(self) -> None:
        self.write_report("UNKNOWN", "LOW", "MEDIUM", "HIGH")
        for target in ("dev", "staging", "prod", "critical"):
            with self.subTest(target=target), mock.patch("builtins.print") as output:
                self.summary.unlink(missing_ok=True)
                summarize_trivy(self.environment(target))
                warning = " ".join(str(call) for call in output.call_args_list if "::warning::" in str(call))
                for severity in ("UNKNOWN", "LOW", "MEDIUM", "HIGH"):
                    self.assertIn(severity, warning)
                    self.assertIn(f"| {severity} | 1 |", self.summary.read_text())

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

    def write_image_report(
        self, *findings: tuple[str, str, dict[str, str]], working_directory: object = "/app",
    ) -> None:
        """One CRITICAL finding per (result class, scan target, vulnerability fields)."""
        self.report.write_text(json.dumps({
            "SchemaVersion": 2,
            "ArtifactType": "container_image",
            "ArtifactName": "image.tar",
            "Metadata": {"ImageConfig": {"config": {"WorkingDir": working_directory}}},
            "Results": [
                {
                    "Target": scan_target,
                    "Class": result_class,
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL", "VulnerabilityID": "CVE-1"} | fields
                    ],
                }
                for result_class, scan_target, fields in findings
            ],
        }))

    def socket_gate(self, target: str = "prod") -> dict[str, str]:
        return self.environment(target) | {"TRIVY_APPLICATION_LIBRARIES_REPORT_ONLY": "true"}

    def test_application_library_critical_is_left_to_socket(self) -> None:
        for finding in (
            ("lang-pkgs", "Node.js", {"PkgPath": "app/node_modules/tar/package.json"}),
            ("lang-pkgs", "Java", {"PkgPath": "/app/lib/library.jar"}),
            ("lang-pkgs", "app/server", {"PkgName": "golang.org/x/crypto"}),
            ("lang-pkgs", "app/yarn.lock", {"PkgName": "tar"}),
        ):
            self.summary.unlink(missing_ok=True)
            self.write_image_report(finding)
            for target in ("staging", "prod", "critical"):
                with self.subTest(finding=finding, target=target), \
                        mock.patch("builtins.print") as output:
                    summarize_trivy(self.socket_gate(target))
                    self.assertTrue(any(
                        "::warning::" in str(call) and "left to the Socket release scan" in str(call)
                        for call in output.call_args_list
                    ))
            self.assertIn("| CRITICAL | 1 |", self.summary.read_text())
            self.assertIn("CRITICAL findings in them: 1.", self.summary.read_text())

    def test_findings_socket_cannot_see_still_block(self) -> None:
        for finding in (
            ("os-pkgs", "image.tar (alpine 3.23.4)", {"PkgName": "openssl"}),
            ("os-pkgs", "app/image.tar (alpine 3.23.4)", {"PkgName": "openssl"}),
            ("lang-pkgs", "Node.js", {"PkgPath": "usr/local/lib/node_modules/npm/node_modules/tar/package.json"}),
            ("lang-pkgs", "Python", {"PkgPath": "usr/local/lib/python3.12/site-packages/x/METADATA"}),
            ("lang-pkgs", "Node.js", {"PkgPath": "application/node_modules/tar/package.json"}),
            ("lang-pkgs", "app/server", {"PkgName": "stdlib"}),
            ("lang-pkgs", "Node.js", {"PkgName": "tar"}),
            ("lang-pkgs", "Node.js", {"PkgPath": 7}),
            ("", "Node.js", {"PkgPath": "app/node_modules/tar/package.json"}),
        ):
            self.write_image_report(finding)
            with self.subTest(finding=finding), mock.patch("builtins.print"), \
                    self.assertRaisesRegex(Exception, "publication to prod is blocked"):
                summarize_trivy(self.socket_gate())

    def test_one_finding_outside_the_application_blocks_despite_the_others(self) -> None:
        self.write_image_report(
            ("lang-pkgs", "Node.js", {"PkgPath": "app/node_modules/tar/package.json"}),
            ("os-pkgs", "image.tar (alpine 3.23.4)", {"PkgName": "openssl"}),
        )
        with mock.patch("builtins.print"), \
                self.assertRaisesRegex(Exception, "1 CRITICAL in application libraries"):
            summarize_trivy(self.socket_gate())
        self.assertIn("| CRITICAL | 2 |", self.summary.read_text())

    def test_unknown_working_directory_keeps_every_library_blocking(self) -> None:
        for working_directory in ("", "/", None, 7, ["/app"]):
            self.write_image_report(
                ("lang-pkgs", "Node.js", {"PkgPath": "app/node_modules/tar/package.json"}),
                working_directory=working_directory,
            )
            with self.subTest(working_directory=working_directory), \
                    mock.patch("builtins.print"), \
                    self.assertRaisesRegex(Exception, "publication to prod is blocked"):
                summarize_trivy(self.socket_gate())
        self.report.write_text(json.dumps({"Results": [{
            "Target": "Node.js",
            "Class": "lang-pkgs",
            "Vulnerabilities": [{
                "Severity": "CRITICAL", "PkgPath": "app/node_modules/tar/package.json",
            }],
        }]}))
        with mock.patch("builtins.print"), \
                self.assertRaisesRegex(Exception, "publication to prod is blocked"):
            summarize_trivy(self.socket_gate())

    def test_application_libraries_block_unless_the_socket_gate_is_on(self) -> None:
        self.write_image_report(
            ("lang-pkgs", "Node.js", {"PkgPath": "app/node_modules/tar/package.json"}),
        )
        for value in (None, "false"):
            environment = self.environment("prod")
            if value is not None:
                environment["TRIVY_APPLICATION_LIBRARIES_REPORT_ONLY"] = value
            self.summary.unlink(missing_ok=True)
            with self.subTest(value=value), mock.patch("builtins.print"), \
                    self.assertRaisesRegex(Exception, "publication to prod is blocked"):
                summarize_trivy(environment)
            self.assertNotIn("Socket", self.summary.read_text())
        for value in ("", "TRUE", "1"):
            with self.subTest(value=value), self.assertRaisesRegex(
                Exception, "TRIVY_APPLICATION_LIBRARIES_REPORT_ONLY must be either"
            ):
                summarize_trivy(self.environment("prod") | {
                    "TRIVY_APPLICATION_LIBRARIES_REPORT_ONLY": value,
                })

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
