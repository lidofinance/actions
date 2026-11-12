import re
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/k8s-build-push-harbor.yml"
HELPER_SHA = "59c07e5aefa7e135e92e0c0eeed0e7fc2eb113ac"
HELPER_REFERENCE = "lidofinance/actions/.github/actions/k8s-harbor-helper"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"


def run_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    blocks = []
    index = 0
    while index < len(lines):
        if lines[index] != "        run: |":
            index += 1
            continue
        index += 1
        block = []
        while index < len(lines):
            line = lines[index]
            indentation = len(line) - len(line.lstrip())
            if line and indentation <= 8:
                break
            block.append(line)
            index += 1
        blocks.append(textwrap.dedent("\n".join(block)))
    return blocks


class WorkflowContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text()

    def test_helper_is_pinned_to_bootstrap_commit(self) -> None:
        references = re.findall(
            rf"uses: {re.escape(HELPER_REFERENCE)}@([0-9a-f]{{40}})", self.workflow
        )
        self.assertEqual(len(references), 15)
        self.assertEqual(set(references), {HELPER_SHA})

    def test_concurrency_is_scoped_to_image_and_queues_all_runs(self) -> None:
        self.assertIn(
            "group: harbor-${{ github.repository_id }}-${{ inputs.target }}-"
            "${{ inputs.harbor_project }}-${{ inputs.image }}",
            self.workflow,
        )
        self.assertIn("  cancel-in-progress: false\n  queue: max", self.workflow)

    def test_sandbox_prod_uses_dev_credentials_without_weakening_rollback(self) -> None:
        self.assertIn(
            "if: ${{ needs.validate.outputs.is_release == 'true' && "
            "inputs.target == 'prod' }}",
            self.workflow,
        )
        self.assertIn(
            "if: ${{ needs.validate.outputs.is_release == 'true' && "
            "inputs.target == 'critical' }}",
            self.workflow,
        )
        self.assertEqual(
            self.workflow.count(
                "HARBOR_TOKEN: ${{ secrets.HARBOR_DEV_TOKEN }}"
            ),
            2,
        )
        self.assertEqual(
            self.workflow.count(
                "HARBOR_TOKEN: ${{ secrets.HARBOR_CRIT_TOKEN }}"
            ),
            2,
        )
        self.assertNotIn("secrets.HARBOR_PROD_TOKEN", self.workflow)
        prod_login = re.search(
            r"(?ms)^      - name: Login to development Harbor for production sandbox test"
            r".*?(?=^      - name:)", self.workflow,
        )
        self.assertIsNotNone(prod_login)
        self.assertIn("if: ${{ inputs.target == 'prod' }}", prod_login.group())
        self.assertIn("registry: registry.dev.k8s-dev.org", prod_login.group())
        self.assertIn("password: ${{ secrets.HARBOR_DEV_TOKEN }}", prod_login.group())
        self.assertNotIn("continue-on-error:", prod_login.group())
        self.assertNotIn("HARBOR_DEV_TOKEN ||", self.workflow)

    def test_all_helper_commands_are_wired(self) -> None:
        commands = set(re.findall(r"          command: ([a-z-]+)", self.workflow))
        self.assertEqual(
            commands,
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

    def test_harbor_preflight_runs_before_build_without_docker_login(self) -> None:
        for target, token in (("production", "DEV"), ("critical", "CRIT")):
            block = re.search(
                rf"(?ms)^      - name: Preflight {target} Harbor release.*?(?=^      - name:)",
                self.workflow,
            )
            self.assertIsNotNone(block)
            self.assertIn("command: check-rollback", block.group())
            self.assertIn(f"HARBOR_TOKEN: ${{{{ secrets.HARBOR_{token}_TOKEN }}}}", block.group())
            self.assertNotIn("continue-on-error:", block.group())
            self.assertNotIn("docker/login-action", block.group())
            self.assertLess(block.start(), self.workflow.index("name: Prepare isolated build context"))
        self.assertLess(
            self.workflow.index("command: revalidate-release"),
            self.workflow.index("name: Preflight production Harbor release"),
        )
        self.assertEqual(self.workflow.count("command: check-rollback"), 4)
        self.assertLess(
            self.workflow.index("name: Login to critical Harbor"),
            self.workflow.index("name: Prevent production release rollback"),
        )
        self.assertLess(
            self.workflow.index("name: Prevent critical release rollback"),
            self.workflow.index("name: Push Docker image"),
        )

    def test_vex_is_loaded_from_the_pinned_helper_and_downloaded_before_scanning(self) -> None:
        self.assertIn(
            "VEX_CONFIG: ${{ steps.trivy-config.outputs.vex_config }}", self.workflow
        )
        self.assertIn('"$VEX_CONFIG:/root/.trivy/vex/repository.yaml:ro"', self.workflow)
        self.assertIn('"$TRIVY_IMAGE" vex repo download', self.workflow)
        self.assertIn("--vex repo", self.workflow)
        self.assertIn("--skip-vex-repo-update", self.workflow)
        self.assertIn("--show-suppressed", self.workflow)
        self.assertLess(
            self.workflow.index("vex repo download"),
            self.workflow.index("--vex repo"),
        )

    def test_vulnerability_report_runs_after_upload_and_before_harbor_login(self) -> None:
        self.assertLess(
            self.workflow.index("name: Upload Trivy vulnerability report"),
            self.workflow.index("command: summarize-trivy"),
        )
        self.assertLess(
            self.workflow.index("command: summarize-trivy"),
            self.workflow.index("name: Login to development Harbor"),
        )
        gate = re.search(
            r"(?ms)^      - name: Summarize vulnerability report.*?(?=^      - name:)",
            self.workflow,
        )
        self.assertIsNotNone(gate)
        self.assertIn("TARGET: ${{ inputs.target }}", gate.group())
        self.assertIn("continue-on-error: true", gate.group())
        self.assertIn('TRIVY_REPORT_ONLY: "true"', gate.group())
        self.assertIn("TRIVY_SCAN_OUTCOME: ${{ steps.trivy-scan.outcome }}", gate.group())
        self.assertNotIn("if:", gate.group())

    def test_python_runtime_is_pinned(self) -> None:
        self.assertEqual(
            self.workflow.count(f"uses: actions/setup-python@{SETUP_PYTHON_SHA}"),
            2,
        )
        self.assertEqual(self.workflow.count('python-version: "3.13.15"'), 2)

    def test_both_jobs_use_ubuntu_24_04(self) -> None:
        self.assertEqual(
            re.findall(r"(?m)^    runs-on: (.+)$", self.workflow),
            ["ubuntu-24.04", "ubuntu-24.04"],
        )

    def test_trivy_scans_an_archive_without_daemon_or_runner_temp_access(self) -> None:
        self.assertNotIn("docker.sock", self.workflow)
        self.assertNotIn('$RUNNER_TEMP:/', self.workflow)
        self.assertIn('--input /input/image.tar', self.workflow)
        self.assertIn('"$trivy_dir/image.tar:/input/image.tar:ro"', self.workflow)
        self.assertIn('"$trivy_dir/cache:/cache"', self.workflow)
        self.assertIn('"$trivy_dir/reports:/reports"', self.workflow)
        self.assertIn('TRIVY_CACHE_DIR=/cache', self.workflow)
        self.assertIn(
            'path: ${{ runner.temp }}/trivy/reports/trivy-report.json', self.workflow,
        )
        self.assertIn(
            'TRIVY_REPORT: ${{ runner.temp }}/trivy/reports/trivy-report.json',
            self.workflow,
        )
        self.assertLess(
            self.workflow.index('docker save --output'),
            self.workflow.index('vex repo download'),
        )

    def test_dhi_validation_uses_exported_dockerfile_before_build_and_login(self) -> None:
        self.assertLess(
            self.workflow.index("command: prepare-context"),
            self.workflow.index("command: check-dhi"),
        )
        self.assertLess(
            self.workflow.index("command: check-dhi"),
            self.workflow.index("name: Build Docker image"),
        )
        check = re.search(
            r"(?ms)^      - name: Check DHI.*?(?=^      - name:)", self.workflow,
        )
        self.assertIsNotNone(check)
        self.assertIn("DOCKERFILE: ${{ steps.context.outputs.dockerfile }}", check.group())
        self.assertIn("TARGET: ${{ inputs.target }}", check.group())
        self.assertIn("DHI_POLICY: ${{ steps.dhi-policy.outputs.dhi_policy }}", check.group())
        for argument, output in (
            ("BUILD_VERSION", "image_tag"), ("BUILD_BRANCH", "source_branch"),
            ("BUILD_COMMIT", "source_sha"),
        ):
            self.assertIn(f"{argument}: ${{{{ needs.validate.outputs.{output} }}}}", check.group())
            self.assertIn(f"{argument}=${{{{ needs.validate.outputs.{output} }}}}", self.workflow)
        self.assertIn("continue-on-error: true", check.group())
        self.assertNotIn("if:", check.group())

    def test_policy_snapshot_is_archived_before_validation_even_when_check_blocks(self) -> None:
        self.assertLess(
            self.workflow.index("command: prepare-dhi-policy"),
            self.workflow.index("name: Upload effective DHI exceptions and source"),
        )
        self.assertLess(
            self.workflow.index("name: Upload effective DHI exceptions and source"),
            self.workflow.index("command: check-dhi"),
        )
        self.assertIn("path: ${{ steps.dhi-policy.outputs.dhi_policy_dir }}", self.workflow)
        self.assertIn("name: ${{ steps.dhi-policy.outputs.dhi_policy_id }}", self.workflow)
        prepare = re.search(
            r"(?ms)^      - name: Download trusted DHI exceptions.*?(?=^      - name:)",
            self.workflow,
        )
        self.assertIsNotNone(prepare)
        self.assertIn("RUNNER_TEMP: ${{ runner.temp }}", prepare.group())
        self.assertIn(
            "GITHUB_TOKEN: ${{ secrets.VEX_DB_READ_TOKEN || github.token }}",
            prepare.group(),
        )
        self.assertNotIn("inputs.", prepare.group())
        self.assertNotIn("secrets.HARBOR", prepare.group())

    def test_complex_runner_tools_are_not_used_by_workflow_shell(self) -> None:
        for command in ("curl", "gh api", "jq", "realpath"):
            self.assertNotIn(command, self.workflow)

    def test_only_advisory_security_steps_can_continue_on_error(self) -> None:
        advisory = {
            "Download trusted DHI exceptions",
            "Upload effective DHI exceptions and source",
            "Check DHI base images and approved exceptions",
            "Login to DHI registry",
            "Prepare trusted Trivy VEX configuration",
            "Scan Docker image with Trivy",
            "Upload Trivy vulnerability report",
            "Summarize vulnerability report (report-only)",
        }
        actual = set()
        for block in re.split(r"(?m)^      - name: ", self.workflow)[1:]:
            if "continue-on-error:" in block:
                self.assertIn("continue-on-error: true", block)
                actual.add(block.splitlines()[0])
        self.assertEqual(actual, advisory)
        self.assertNotIn("\n    continue-on-error:", self.workflow)

    def test_dhi_login_is_separate_from_harbor_credentials(self) -> None:
        login = re.search(
            r"(?ms)^      - name: Login to DHI registry.*?(?=^      - name:)",
            self.workflow,
        )
        self.assertIsNotNone(login)
        self.assertIn("registry: dhi.io", login.group())
        self.assertIn("username: ${{ secrets.DHI_USERNAME }}", login.group())
        self.assertIn("password: ${{ secrets.DHI_TOKEN }}", login.group())
        self.assertNotIn("HARBOR_", login.group())
        self.assertLess(
            self.workflow.index("name: Login to DHI registry"),
            self.workflow.index("name: Build Docker image"),
        )
        self.assertEqual(self.workflow.count("secrets.DHI_TOKEN"), 1)
        self.assertEqual(self.workflow.count("secrets.DHI_USERNAME"), 1)

    def test_trivy_version_is_digest_pinned(self) -> None:
        self.assertIn(
            "TRIVY_IMAGE: docker.io/aquasec/trivy@sha256:"
            "8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb  # v0.76.2",
            self.workflow,
        )
        self.assertIn("--pkg-types os,library", self.workflow)
        self.assertNotIn("--vuln-type", self.workflow)

    def test_missing_reports_do_not_block_the_advisory_pipeline(self) -> None:
        for name in (
            "Upload Trivy vulnerability report",
            "Upload effective DHI exceptions and source",
        ):
            block = re.search(
                rf"(?ms)^      - name: {re.escape(name)}.*?(?=^      - name:)",
                self.workflow,
            )
            self.assertIsNotNone(block)
            self.assertIn("continue-on-error: true", block.group())
            self.assertIn("if-no-files-found: warn", block.group())
        scan = re.search(
            r"(?ms)^      - name: Scan Docker image with Trivy.*?(?=^      - name:)",
            self.workflow,
        )
        self.assertIn("if: ${{ steps.trivy-config.outcome == 'success' }}", scan.group())

    def test_expressions_are_not_interpolated_inside_shell(self) -> None:
        blocks = run_blocks(self.workflow)
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
