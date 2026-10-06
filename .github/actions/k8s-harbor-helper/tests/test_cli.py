import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ACTION_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ACTION_ROOT / "main.py"


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

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


if __name__ == "__main__":
    unittest.main()
