import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_workflow_contract import WORKFLOW, run_blocks


class TrivyScanWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.runner_temp = self.root / "runner temp"
        self.runner_temp.mkdir()
        self.config = self.root / "trusted VEX config.yaml"
        self.config.write_text("repositories: []\n")
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
            phase = "save" if args[0] == "save" else (
                "vex" if args[-3:] == ["vex", "repo", "download"] else "scan"
            )
            if os.environ.get("FAIL_PHASE") == phase:
                sys.exit(23)
            if phase == "save":
                Path(args[args.index("--output") + 1]).write_bytes(b"test image archive")
            else:
                mounts = {}
                for index, argument in enumerate(args):
                    if argument == "--volume":
                        source, target, *_ = args[index + 1].split(":")
                        mounts[target] = Path(source)
                marker = mounts["/cache"] / "vex-downloaded"
                if phase == "vex":
                    marker.touch()
                else:
                    assert marker.is_file(), "VEX cache must survive between containers"
                    assert mounts["/input/image.tar"].read_bytes() == b"test image archive"
                    (mounts["/reports"] / "trivy-report.json").write_text('{"Results": []}')
            '''))
        docker.chmod(0o755)
        self.environment = os.environ | {
            "PATH": f"{binary_directory}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(self.runner_temp),
            "IMAGE_REF": "local-build:123-1",
            "TRIVY_IMAGE": "example/trivy@sha256:" + "a" * 64,
            "VEX_CONFIG": str(self.config),
            "DOCKER_CALLS": str(self.calls),
            "FAIL_PHASE": "",
        }
        self.script = next(
            block for block in run_blocks(WORKFLOW.read_text())
            if "trivy_args=(" in block
        )

    def run_scan(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", self.script],
            cwd=self.root,
            env=self.environment | overrides,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def docker_calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_scan_exports_image_and_mounts_only_dedicated_paths(self) -> None:
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        save, download, scan = self.docker_calls()
        trivy_dir = self.runner_temp / "trivy"
        self.assertEqual(save, [
            "save", "--output", str(trivy_dir / "image.tar"), "local-build:123-1",
        ])
        common_mounts = {
            f"{trivy_dir}/cache:/cache",
            f"{trivy_dir}/reports:/reports",
            f"{self.config}:/root/.trivy/vex/repository.yaml:ro",
        }
        for args, expected_mounts in (
            (download, common_mounts),
            (scan, common_mounts | {f"{trivy_dir}/image.tar:/input/image.tar:ro"}),
        ):
            mounts = {args[index + 1] for index, value in enumerate(args) if value == "--volume"}
            self.assertEqual(mounts, expected_mounts)
            self.assertIn("TRIVY_CACHE_DIR=/cache", args)
        self.assertEqual(download[-4:], [self.environment["TRIVY_IMAGE"], "vex", "repo", "download"])
        self.assertEqual(scan[scan.index("--input") + 1], "/input/image.tar")
        self.assertEqual(scan[scan.index("--output") + 1], "/reports/trivy-report.json")
        self.assertIn("--skip-vex-repo-update", scan)
        self.assertNotIn("local-build:123-1", scan)
        self.assertTrue((trivy_dir / "reports/trivy-report.json").is_file())

    def test_failed_export_does_not_start_trivy(self) -> None:
        result = self.run_scan(FAIL_PHASE="save")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(len(self.docker_calls()), 1)
        self.assertFalse((self.runner_temp / "trivy/reports/trivy-report.json").exists())

    def test_failed_vex_download_does_not_start_image_scan(self) -> None:
        result = self.run_scan(FAIL_PHASE="vex")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(len(self.docker_calls()), 2)
        self.assertFalse((self.runner_temp / "trivy/reports/trivy-report.json").exists())

    def test_failed_scan_is_not_reported_as_success(self) -> None:
        result = self.run_scan(FAIL_PHASE="scan")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(len(self.docker_calls()), 3)
        self.assertFalse((self.runner_temp / "trivy/reports/trivy-report.json").exists())


if __name__ == "__main__":
    unittest.main()
