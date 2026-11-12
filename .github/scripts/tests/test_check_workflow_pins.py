#!/usr/bin/env python3

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-workflow-pins.py"
COMMIT_SHA = "a" * 40
IMAGE_DIGEST = "b" * 64


class PinCheckerTests(unittest.TestCase):
    def check(self, workflow: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text(workflow)
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                text=True,
                capture_output=True,
                check=False,
            )

    def assert_allowed(self, workflow: str) -> None:
        result = self.check(workflow)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_rejected(self, workflow: str, expected: str) -> None:
        result = self.check(workflow)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout)

    def test_pinned_remote_action_is_allowed(self) -> None:
        self.assert_allowed(f"jobs:\n  test:\n    uses: owner/repository@{COMMIT_SHA}\n")

    def test_unpinned_step_action_is_rejected(self) -> None:
        self.assert_rejected(
            "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n",
            "actions/checkout@v4",
        )

    def test_quoted_pinned_action_is_allowed(self) -> None:
        self.assert_allowed(
            f"jobs:\n  test:\n    steps:\n      - uses: \"actions/checkout@{COMMIT_SHA}\"\n"
        )

    def test_quoted_unpinned_action_is_rejected(self) -> None:
        self.assert_rejected(
            "jobs:\n  test:\n    steps:\n      - uses: 'actions/checkout@v4'\n",
            "actions/checkout@v4",
        )

    def test_local_action_is_allowed(self) -> None:
        self.assert_allowed("jobs:\n  test:\n    steps:\n      - uses: ./local-action\n")

    def test_digest_pinned_docker_action_is_allowed(self) -> None:
        self.assert_allowed(
            f"jobs:\n  test:\n    container:\n      uses: docker://image@sha256:{IMAGE_DIGEST}\n"
        )

    def test_tagged_docker_action_is_rejected(self) -> None:
        self.assert_rejected(
            "jobs:\n  test:\n    container:\n      uses: docker://image:latest\n",
            "docker://image:latest",
        )

    def test_inline_mapping_is_checked(self) -> None:
        self.assert_rejected(
            "jobs:\n  test:\n    steps:\n      - {uses: actions/checkout@v4}\n",
            "actions/checkout@v4",
        )

    def test_invalid_yaml_is_rejected(self) -> None:
        self.assert_rejected("jobs: [\n", "Could not parse workflow YAML")


if __name__ == "__main__":
    unittest.main()
