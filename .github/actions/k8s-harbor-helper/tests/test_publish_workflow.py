import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_workflow_contract import WORKFLOW, run_blocks


class PublishWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.output = self.root / "github output"
        self.calls = self.root / "docker-calls.jsonl"
        binary_directory = self.root / "bin"
        binary_directory.mkdir()
        docker = binary_directory / "docker"
        docker.write_text("#!/usr/bin/env python3\n" + textwrap.dedent('''\
            import json
            import os
            import sys
            from pathlib import Path

            args = sys.argv[1:]
            with Path(os.environ["DOCKER_CALLS"]).open("a") as calls:
                calls.write(json.dumps(args) + "\\n")
            if args[0] not in {"tag", "push"}:
                sys.exit(99)
            if args[0] == os.environ.get("FAIL_PHASE"):
                sys.exit(23)
            '''))
        docker.chmod(0o755)
        self.environment = os.environ | {
            "PATH": f"{binary_directory}{os.pathsep}{os.environ['PATH']}",
            "DOCKER_CALLS": str(self.calls),
            "GITHUB_OUTPUT": str(self.output),
            "IMAGE_TAG": "v1.2.3",
            "LOCAL_IMAGE": "local-build:123-1",
            "REMOTE_NAME": "registry.example/team-example/application",
            "FAIL_PHASE": "",
        }
        self.script = next(
            block for block in run_blocks(WORKFLOW.read_text())
            if 'docker push "$remote_ref"' in block
        )

    def run_push(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", self.script], cwd=self.root,
            env=self.environment | overrides, text=True, capture_output=True,
            check=False,
        )

    def docker_calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_successful_push_returns_only_image_ref_without_registry_inspection(self) -> None:
        result = self.run_push()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        remote_ref = "registry.example/team-example/application:v1.2.3"
        self.assertEqual(self.docker_calls(), [
            ["tag", "local-build:123-1", remote_ref], ["push", remote_ref],
        ])
        self.assertEqual(self.output.read_text(), f"image_ref={remote_ref}\n")

    def test_failed_push_is_fatal_and_does_not_return_image_ref(self) -> None:
        result = self.run_push(FAIL_PHASE="push")
        self.assertEqual(result.returncode, 23)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(self.docker_calls()), 2)

    def test_failed_tag_does_not_push_or_return_image_ref(self) -> None:
        result = self.run_push(FAIL_PHASE="tag")
        self.assertEqual(result.returncode, 23)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(self.docker_calls()), 1)
