import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from harbor_helper.common import WorkflowError
from harbor_helper.trivy import scan_trivy


ENTRYPOINT = Path(__file__).resolve().parents[1] / "main.py"


class TrivyScanTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.runner_temp = self.root / "runner temp"
        self.runner_temp.mkdir()
        self.summary = self.root / "summary.md"
        self.report = self.runner_temp / "trivy/reports/trivy-report.json"
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
                    findings = [{"Severity": item} for item in
                                os.environ.get("SCAN_SEVERITIES", "").split(",") if item]
                    (mounts["/reports"] / "trivy-report.json").write_text(json.dumps({
                        "Results": [{"Vulnerabilities": findings}],
                    }))
            '''))
        docker.chmod(0o755)
        self.environment = os.environ | {
            "PATH": f"{binary_directory}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "TARGET": "prod", "IMAGE_REF": "local-build:123-1",
            "TRIVY_IMAGE": "example/trivy@sha256:" + "a" * 64,
            "DOCKER_CALLS": str(self.calls), "FAIL_PHASE": "", "SCAN_SEVERITIES": "",
        }

    def run_scan(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ENTRYPOINT), "scan-trivy"], cwd=self.root,
            env=self.environment | overrides, capture_output=True, text=True,
            timeout=10, check=False,
        )

    def test_scan_uses_archive_isolated_mounts_and_shared_vex_cache(self) -> None:
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        save, download, scan = [json.loads(line) for line in self.calls.read_text().splitlines()]
        trivy_dir = self.runner_temp / "trivy"
        self.assertEqual(save, ["save", "--output", str(trivy_dir / "image.tar"), "local-build:123-1"])
        config = ENTRYPOINT.parent / "vex/repository.yaml"
        common_mounts = {
            f"{trivy_dir}/cache:/cache", f"{trivy_dir}/reports:/reports",
            f"{config}:/root/.trivy/vex/repository.yaml:ro",
        }
        for args, mounts in (
            (download, common_mounts),
            (scan, common_mounts | {f"{trivy_dir}/image.tar:/input/image.tar:ro"}),
        ):
            actual = {args[i + 1] for i, value in enumerate(args) if value == "--volume"}
            self.assertEqual(actual, mounts)
            self.assertIn("TRIVY_CACHE_DIR=/cache", args)
        self.assertEqual(download[-4:], [self.environment["TRIVY_IMAGE"], "vex", "repo", "download"])
        for flag, value in (
            ("--input", "/input/image.tar"), ("--output", "/reports/trivy-report.json"),
            ("--vex", "repo"), ("--exit-code", "0"), ("--pkg-types", "os,library"),
            ("--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"), ("--scanners", "vuln"),
        ):
            self.assertEqual(scan[scan.index(flag) + 1], value)
        self.assertIn("--skip-vex-repo-update", scan)
        self.assertIn("--show-suppressed", scan)
        self.assertIn("| CRITICAL | 0 |", self.summary.read_text())

    def test_cli_distinguishes_blocked_critical_from_dev_and_warning_only_findings(self) -> None:
        for target, severity, expected in (
            ("prod", "CRITICAL", 1), ("dev", "CRITICAL", 0), ("prod", "HIGH", 0),
        ):
            with self.subTest(target=target, severity=severity):
                self.summary.unlink(missing_ok=True)
                result = self.run_scan(TARGET=target, SCAN_SEVERITIES=severity)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertIn(f"| {severity} | 1 |", self.summary.read_text())
                self.assertNotIn("unavailable", self.summary.read_text())

    def test_command_failures_never_trust_old_reports_and_are_advisory_only_in_dev(self) -> None:
        for phase, expected_calls in (("save", 1), ("vex", 2), ("scan", 3)):
            for target in ("dev", "prod"):
                with self.subTest(phase=phase, target=target):
                    self.report.parent.mkdir(parents=True, exist_ok=True)
                    self.report.write_text('{"Results": []}')
                    self.calls.unlink(missing_ok=True)
                    self.summary.unlink(missing_ok=True)
                    result = self.run_scan(TARGET=target, FAIL_PHASE=phase)
                    self.assertEqual(result.returncode, 0 if target == "dev" else 1)
                    self.assertEqual(len(self.calls.read_text().splitlines()), expected_calls)
                    self.assertFalse(self.report.exists())
                    self.assertIn("Status: **unavailable**", self.summary.read_text())
                    self.assertNotIn("| CRITICAL |", self.summary.read_text())
                    self.assertIn("::warning::" if target == "dev" else "::error::", result.stdout)

    def test_missing_config_and_docker_errors_follow_target_policy(self) -> None:
        for error in (
            WorkflowError("Trusted VEX configuration is missing"), OSError("Docker unavailable"),
            subprocess.TimeoutExpired("docker", 900),
        ):
            for target in ("dev", "prod"):
                with self.subTest(error=str(error), target=target), mock.patch("builtins.print"):
                    self.summary.unlink(missing_ok=True)
                    # Config errors occur before Docker; process errors occur in _docker.
                    patched = "prepare_trivy" if isinstance(error, WorkflowError) else "subprocess.run"
                    with mock.patch(f"harbor_helper.trivy.{patched}", side_effect=error):
                        if target == "dev":
                            scan_trivy(self.environment | {"TARGET": target})
                        else:
                            with self.assertRaisesRegex(WorkflowError, "publication to prod is blocked"):
                                scan_trivy(self.environment | {"TARGET": target})
                    self.assertIn("Status: **unavailable**", self.summary.read_text())
