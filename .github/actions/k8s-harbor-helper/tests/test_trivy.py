import json
from unittest import mock

from harbor_helper.trivy import summarize_trivy
from support import TemporaryTestCase


class TrivyTests(TemporaryTestCase):
    def test_summary_and_critical_report(self) -> None:
        report = self.root / "report.json"
        summary = self.root / "summary.md"
        summary.touch()
        report.write_text(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": "application",
                            "Vulnerabilities": [
                                {
                                    "Severity": "HIGH",
                                    "VulnerabilityID": "CVE-HIGH",
                                },
                                {
                                    "Severity": "CRITICAL",
                                    "VulnerabilityID": "CVE-CRITICAL",
                                    "PkgName": "package",
                                    "InstalledVersion": "1",
                                    "FixedVersion": "2",
                                },
                            ],
                        }
                    ]
                }
            )
        )
        with mock.patch("builtins.print") as print_mock:
            summarize_trivy(
                {"GITHUB_STEP_SUMMARY": str(summary), "TRIVY_REPORT": str(report)}
            )
        self.assertIn("| HIGH | 1 |", summary.read_text())
        self.assertIn("| CRITICAL | 1 |", summary.read_text())
        self.assertTrue(
            any("report-only" in str(call) for call in print_mock.call_args_list)
        )

    def test_invalid_report_is_rejected(self) -> None:
        report = self.root / "report.json"
        report.write_text("[]")
        self.assert_workflow_error(
            "valid vulnerability report",
            summarize_trivy,
            {
                "GITHUB_STEP_SUMMARY": str(self.root / "summary.md"),
                "TRIVY_REPORT": str(report),
            },
        )
