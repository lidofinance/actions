import re
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/k8s-build-push-harbor.yml"
HELPER_SHA = "5b9626ace6d2fe510b571afc22893643a266ddc9"
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
        self.assertEqual(len(references), 9)
        self.assertEqual(set(references), {HELPER_SHA})

    def test_all_helper_commands_are_wired(self) -> None:
        commands = set(re.findall(r"          command: ([a-z-]+)", self.workflow))
        self.assertEqual(
            commands,
            {
                "check-rollback",
                "configure",
                "populate-build-info",
                "prepare-context",
                "resolve-image-digest",
                "revalidate-release",
                "summarize-trivy",
                "validate-release",
                "validate-source",
            },
        )

    def test_python_runtime_is_pinned(self) -> None:
        self.assertEqual(
            self.workflow.count(f"uses: actions/setup-python@{SETUP_PYTHON_SHA}"),
            2,
        )
        self.assertEqual(self.workflow.count('python-version: "3.13.15"'), 2)

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
