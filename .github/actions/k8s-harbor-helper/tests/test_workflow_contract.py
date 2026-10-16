import re
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/k8s-build-push-harbor.yml"
HELPER_SHA = "9a0b3cc8f86f2244998e18ef77bee422f6b470ee"
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
            1,
        )
        self.assertEqual(
            self.workflow.count(
                "HARBOR_TOKEN: ${{ secrets.HARBOR_CRIT_TOKEN }}"
            ),
            1,
        )
        self.assertNotIn(
            "secrets.HARBOR_PROD_TOKEN || secrets.HARBOR_CRIT_TOKEN",
            self.workflow,
        )

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

    def test_publication_gate_runs_after_report_upload_and_before_registry_login(self) -> None:
        self.assertLess(
            self.workflow.index("name: Upload Trivy vulnerability report"),
            self.workflow.index("command: summarize-trivy"),
        )
        self.assertLess(
            self.workflow.index("command: summarize-trivy"),
            self.workflow.index("name: Login to"),
        )
        gate = re.search(
            r"(?ms)^      - name: Summarize vulnerability report.*?(?=^      - name:)",
            self.workflow,
        )
        self.assertIsNotNone(gate)
        self.assertIn("TARGET: ${{ inputs.target }}", gate.group())
        self.assertNotIn("continue-on-error", gate.group())
        self.assertNotIn("if:", gate.group())

    def test_python_runtime_is_pinned(self) -> None:
        self.assertEqual(
            self.workflow.count(f"uses: actions/setup-python@{SETUP_PYTHON_SHA}"),
            2,
        )
        self.assertEqual(self.workflow.count('python-version: "3.13.15"'), 2)

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
        self.assertNotIn("continue-on-error", check.group())
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

    def test_expressions_are_not_interpolated_inside_shell(self) -> None:
        blocks = run_blocks(self.workflow)
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
