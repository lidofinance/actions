import re
import textwrap
import unittest
from pathlib import Path

from harbor_helper.cli import COMMANDS


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/k8s-build-push-harbor.yml"
HELPER_SHA = "e0409eb48ea98b57f6c7648494d99d1992267a15"
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
        self.assertEqual(len(references), 13)
        self.assertEqual(set(references), {HELPER_SHA})

    def test_concurrency_is_scoped_to_image_and_queues_all_runs(self) -> None:
        self.assertIn(
            "group: harbor-${{ github.repository_id }}-${{ inputs.target }}-"
            "${{ inputs.harbor_project }}-${{ inputs.image }}",
            self.workflow,
        )
        self.assertIn("  cancel-in-progress: false\n  queue: max", self.workflow)

    def test_rollback_uses_only_the_target_secret(self) -> None:
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
                "HARBOR_TOKEN: ${{ secrets.HARBOR_PROD_TOKEN }}"
            ),
            2,
        )
        self.assertEqual(
            self.workflow.count(
                "HARBOR_TOKEN: ${{ secrets.HARBOR_CRIT_TOKEN }}"
            ),
            2,
        )
        self.assertNotIn(
            "secrets.HARBOR_PROD_TOKEN || secrets.HARBOR_CRIT_TOKEN",
            self.workflow,
        )

    def test_all_helper_commands_are_wired(self) -> None:
        commands = set(re.findall(r"          command: ([a-z-]+)", self.workflow))
        self.assertEqual(commands, set(COMMANDS))

    def test_harbor_preflight_runs_before_build_without_docker_login(self) -> None:
        for target, token in (("production", "PROD"), ("critical", "CRIT")):
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

    def test_python_scan_and_report_upload_run_before_harbor_login(self) -> None:
        scan = re.search(
            r"(?ms)^      - name: Scan Docker image with Trivy.*?(?=^      - name:)", self.workflow,
        )
        upload = re.search(
            r"(?ms)^      - name: Upload Trivy vulnerability report.*?(?=^      - name:)", self.workflow,
        )
        self.assertIsNotNone(scan)
        self.assertIsNotNone(upload)
        self.assertIn("command: scan-trivy", scan.group())
        self.assertIn("TARGET: ${{ inputs.target }}", scan.group())
        self.assertNotIn("continue-on-error:", scan.group())
        self.assertNotIn("TRIVY_REPORT_ONLY", self.workflow)
        self.assertLess(scan.start(), upload.start())
        self.assertLess(upload.start(), self.workflow.index("name: Login to development Harbor"))
        self.assertIn("!cancelled()", upload.group())
        self.assertIn("steps.trivy-scan.outcome == 'failure'", upload.group())
        self.assertIn("path: ${{ runner.temp }}/trivy/reports/trivy-report.json", upload.group())

    def test_publication_returns_only_image_ref(self) -> None:
        self.assertNotIn("image_digest", self.workflow)
        self.assertNotIn("resolve-image-digest", self.workflow)
        self.assertIn("value: ${{ jobs.publish.outputs.image_ref }}", self.workflow)
        self.assertIn("image_ref: ${{ steps.push.outputs.image_ref }}", self.workflow)

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

    def test_only_advisory_steps_can_continue_on_error(self) -> None:
        advisory = {
            "Download trusted DHI exceptions",
            "Upload effective DHI exceptions and source",
            "Check DHI base images and approved exceptions",
            "Login to DHI registry",
            "Upload Trivy vulnerability report",
        }
        actual = set()
        for block in re.split(r"(?m)^      - name: ", self.workflow)[1:]:
            if "continue-on-error:" in block:
                name = block.splitlines()[0]
                self.assertIn("continue-on-error: true", block)
                actual.add(name)
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
        self.assertNotIn("--vuln-type", self.workflow)

    def test_expressions_are_not_interpolated_inside_shell(self) -> None:
        blocks = run_blocks(self.workflow)
        self.assertEqual(len(blocks), 1)
        for block in blocks:
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
