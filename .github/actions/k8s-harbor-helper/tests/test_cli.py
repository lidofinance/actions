import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from harbor_helper.cli import COMMANDS


ACTION_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ACTION_ROOT / "main.py"


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.policy = self.root / "dhi-exceptions.json"
        self.policy.write_text(json.dumps({"exceptions": []}))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def environment(self, **overrides: str) -> dict[str, str]:
        output = self.root / "github-output"
        output.touch()
        environment = os.environ.copy()
        environment.update(
            {
                "DEFAULT_BRANCH": "develop",
                "DOCKERFILE": "Dockerfile",
                "DHI_POLICY": str(self.policy),
                "GITHUB_EVENT_NAME": "workflow_run",
                "GITHUB_OUTPUT": str(output),
                "GITHUB_REPOSITORY": "example/application",
                "GITHUB_SHA": "a" * 40,
                "HARBOR_PROJECT": "team-example",
                "IMAGE": "application",
                "REF_NAME": "develop",
                "REF_TYPE": "branch",
                "TAG": "v1.2.3",
                "TARGET": "prod",
                "UPSTREAM_CONCLUSION": "success",
                "UPSTREAM_EVENT": "release",
                "UPSTREAM_PATH": ".github/workflows/run_on_release.yaml@refs/heads/develop",
                "UPSTREAM_REPOSITORY": "example/application",
            }
        )
        environment.update(overrides)
        return environment

    def run_cli(
        self, command: str, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ENTRYPOINT), command],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_configure_writes_github_outputs(self) -> None:
        environment = self.environment()
        result = self.run_cli("configure", environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = Path(environment["GITHUB_OUTPUT"]).read_text()
        self.assertIn("github_environment=harbor_prod_release", output)
        self.assertIn("source_ref=v1.2.3", output)

    def test_validation_error_uses_workflow_annotation(self) -> None:
        result = self.run_cli("configure", self.environment(IMAGE="invalid,image"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::Invalid image name", result.stdout)

    def test_unknown_command_is_rejected(self) -> None:
        result = self.run_cli("unknown", self.environment())
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)

    def test_dhi_command_warns_in_dev_and_returns_error_in_production(self) -> None:
        dockerfile = self.root / "Dockerfile"
        dockerfile.write_text("FROM nginx:alpine\n")
        for target, expected_status in (("dev", 0), ("prod", 1)):
            with self.subTest(target=target):
                result = self.run_cli("check-dhi", self.environment(
                    TARGET=target, DOCKERFILE=str(dockerfile),
                    BUILD_VERSION="v1.2.3", BUILD_BRANCH="main", BUILD_COMMIT="a" * 40,
                ))
                self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
                self.assertIn("::warning::DHI:", result.stdout)
                if target == "prod":
                    self.assertIn("::error::DHI base-image policy blocks publication", result.stdout)

    def test_command_registry_is_complete(self) -> None:
        self.assertEqual(
            set(COMMANDS),
            {
                "check-dhi",
                "check-rollback",
                "configure",
                "populate-build-info",
                "prepare-context",
                "prepare-dhi-policy",
                "prepare-trivy",
                "resolve-image-digest",
                "revalidate-release",
                "summarize-trivy",
                "validate-release",
                "validate-source",
            },
        )

    def test_vulnerability_gate_returns_error_after_writing_summary(self) -> None:
        report = self.root / "trivy.json"
        summary = self.root / "summary.md"
        report.write_text(json.dumps({
            "Results": [{
                "Vulnerabilities": [
                    {"Severity": "HIGH", "VulnerabilityID": "CVE-HIGH"},
                ],
            }],
        }))
        result = self.run_cli(
            "summarize-trivy",
            self.environment(
                TARGET="prod",
                TRIVY_REPORT=str(report),
                GITHUB_STEP_SUMMARY=str(summary),
            ),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::Trivy found", result.stdout)
        self.assertIn("publication to prod is blocked", result.stdout)
        self.assertIn("| HIGH | 1 |", summary.read_text())


if __name__ == "__main__":
    unittest.main()
