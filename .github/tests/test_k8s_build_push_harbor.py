#!/usr/bin/env python3

import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/k8s-build-push-harbor.yml"


def extract_run_step(name: str) -> str:
    lines = WORKFLOW.read_text().splitlines()
    step_start = f"      - name: {name}"

    try:
        start = lines.index(step_start)
    except ValueError as error:
        raise AssertionError(f"Step {name!r} was not found in {WORKFLOW}") from error

    run_start = None
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("      - name:"):
            break
        if lines[index] == "        run: |":
            run_start = index + 1
            break

    if run_start is None:
        raise AssertionError(f"Step {name!r} does not contain a literal run block")

    block = []
    for line in lines[run_start:]:
        if line and len(line) - len(line.lstrip()) <= 8:
            break
        block.append(line)

    return textwrap.dedent("\n".join(block))


def run_step(name: str, cwd: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(environment)
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", extract_run_step(name)],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def git(cwd: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(arguments)} failed with {result.returncode}:\n{result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def write_executable(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class GitFixture:
    def __init__(self, root: Path, production_branch: str = "main") -> None:
        self.root = root
        self.origin = root / "origin.git"
        self.seed = root / "seed"
        self.checkout = root / "checkout"
        self.production_branch = production_branch

        git(root, "init", "--bare", str(self.origin))
        git(root, "init", "--initial-branch", production_branch, str(self.seed))
        git(self.seed, "config", "user.name", "Workflow tests")
        git(self.seed, "config", "user.email", "workflow-tests@example.invalid")

        self.first_sha = self.commit("first")
        git(self.seed, "tag", "v1.0.0", self.first_sha)
        self.second_sha = self.commit("second")
        git(self.seed, "tag", "v1.1.0", self.second_sha)
        git(self.seed, "remote", "add", "origin", str(self.origin))
        git(self.seed, "push", "origin", production_branch, "--tags")
        git(self.origin, "symbolic-ref", "HEAD", f"refs/heads/{production_branch}")

    def commit(self, content: str) -> str:
        (self.seed / "content.txt").write_text(f"{content}\n")
        git(self.seed, "add", "content.txt")
        git(self.seed, "commit", "-m", content)
        return git(self.seed, "rev-parse", "HEAD")

    def add_second_production_branch(self) -> None:
        branch = "master" if self.production_branch == "main" else "main"
        git(self.seed, "branch", branch, self.second_sha)
        git(self.seed, "push", "origin", branch)

    def add_divergent_tag(self, tag: str = "v2.0.0") -> str:
        git(self.seed, "switch", "--detach", self.first_sha)
        divergent_sha = self.commit("divergent")
        git(self.seed, "tag", tag, divergent_sha)
        git(self.seed, "push", "origin", tag)
        git(self.seed, "switch", self.production_branch)
        return divergent_sha

    def clone_at(self, ref: str) -> Path:
        if self.checkout.exists():
            shutil.rmtree(self.checkout)
        git(self.root, "clone", "--no-checkout", str(self.origin), str(self.checkout))
        git(
            self.checkout,
            "fetch",
            "origin",
            "+refs/heads/*:refs/remotes/origin/*",
            "+refs/tags/*:refs/tags/*",
        )
        git(self.checkout, "checkout", "--detach", ref)
        return self.checkout


class WorkflowStepTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def output_file(self) -> Path:
        output = self.root / "github-output"
        output.touch()
        return output

    def assert_failed_with(self, result: subprocess.CompletedProcess[str], message: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)


class ConfigureTargetTests(WorkflowStepTestCase):
    def environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            "DEFAULT_BRANCH": "develop",
            "DOCKERFILE": "Dockerfile",
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_OUTPUT": str(self.output_file()),
            "GITHUB_REPOSITORY": "example/application",
            "GITHUB_SHA": "a" * 40,
            "HARBOR_PROJECT": "team-example",
            "IMAGE": "application/api",
            "REF_NAME": "develop",
            "REF_TYPE": "branch",
            "TAG": "v1.2.3",
            "TARGET": "prod",
            "UPSTREAM_CONCLUSION": "success",
            "UPSTREAM_EVENT": "release",
            "UPSTREAM_PATH": ".github/workflows/run_on_release.yaml@refs/heads/develop",
            "UPSTREAM_REPOSITORY": "example/application",
        }
        environment.update(overrides)
        return environment

    def test_release_may_run_from_non_main_default_branch(self) -> None:
        environment = self.environment()
        result = run_step("Configure target and validate inputs", self.root, environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = Path(environment["GITHUB_OUTPUT"]).read_text()
        self.assertIn("source_ref=v1.2.3", output)
        self.assertIn("is_release=true", output)

    def test_release_rejects_untrusted_upstream_workflow(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(UPSTREAM_PATH=".github/workflows/other.yaml@refs/heads/develop"),
        )

        self.assert_failed_with(result, "Unexpected upstream workflow")

    def test_release_rejects_direct_dispatch(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(GITHUB_EVENT_NAME="workflow_dispatch"),
        )

        self.assert_failed_with(result, "builds must be started by a workflow_run")

    def test_release_rejects_failed_upstream_workflow(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(UPSTREAM_CONCLUSION="failure"),
        )

        self.assert_failed_with(result, "require a successful upstream workflow")

    def test_release_rejects_upstream_from_another_repository(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(UPSTREAM_REPOSITORY="attacker/application"),
        )

        self.assert_failed_with(result, "unexpected repository")

    def test_release_rejects_non_semver_tag(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(TAG="latest"),
        )

        self.assert_failed_with(result, "requires a stable release tag")

    def test_release_rejects_run_outside_default_branch(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(REF_NAME="feature/untrusted"),
        )

        self.assert_failed_with(result, "must run from the repository default branch")

    def test_dev_rejects_release_tag_input(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(TARGET="dev", TAG="v1.2.3"),
        )

        self.assert_failed_with(result, "tag input cannot be used for dev")

    def test_image_name_rejects_multiple_destinations(self) -> None:
        result = run_step(
            "Configure target and validate inputs",
            self.root,
            self.environment(IMAGE="application,attacker/repository"),
        )

        self.assert_failed_with(result, "Invalid image name")


class SourceValidationTests(WorkflowStepTestCase):
    def validate_release(
        self,
        fixture: GitFixture,
        tag: str,
        upstream_sha: str,
        image_tag: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        checkout = fixture.clone_at(tag)
        return run_step(
            "Validate source",
            checkout,
            {
                "GITHUB_OUTPUT": str(self.output_file()),
                "GITHUB_REPOSITORY": "example/application",
                "IMAGE_TAG": image_tag or tag,
                "IS_RELEASE": "true",
                "REQUESTED_SOURCE_BRANCH": "",
                "UPSTREAM_SHA": upstream_sha,
            },
        )

    def test_release_from_main_succeeds(self) -> None:
        fixture = GitFixture(self.root, "main")
        result = self.validate_release(fixture, "v1.1.0", fixture.second_sha)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("source_branch=main", (self.root / "github-output").read_text())

    def test_release_from_master_succeeds(self) -> None:
        fixture = GitFixture(self.root, "master")
        result = self.validate_release(fixture, "v1.1.0", fixture.second_sha)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("source_branch=master", (self.root / "github-output").read_text())

    def test_release_rejects_repository_with_both_production_branches(self) -> None:
        fixture = GitFixture(self.root, "main")
        fixture.add_second_production_branch()
        result = self.validate_release(fixture, "v1.1.0", fixture.second_sha)

        self.assert_failed_with(result, "Both production branches main and master exist")

    def test_release_rejects_repository_without_production_branch(self) -> None:
        fixture = GitFixture(self.root, "develop")
        result = self.validate_release(fixture, "v1.1.0", fixture.second_sha)

        self.assert_failed_with(result, "Neither production branch main nor master exists")

    def test_release_rejects_commit_outside_production_branch(self) -> None:
        fixture = GitFixture(self.root, "main")
        divergent_sha = fixture.add_divergent_tag()
        result = self.validate_release(fixture, "v2.0.0", divergent_sha)

        self.assert_failed_with(result, "is not contained in branch main")

    def test_release_rejects_upstream_sha_mismatch(self) -> None:
        fixture = GitFixture(self.root, "main")
        result = self.validate_release(fixture, "v1.1.0", fixture.first_sha)

        self.assert_failed_with(result, "does not match upstream workflow_run commit")

    def test_release_rejects_different_input_tag(self) -> None:
        fixture = GitFixture(self.root, "main")
        result = self.validate_release(
            fixture,
            "v1.1.0",
            fixture.second_sha,
            image_tag="v1.0.0",
        )

        self.assert_failed_with(result, "does not match tag v1.0.0")


class PublishedReleaseTests(WorkflowStepTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        write_executable(
            self.bin_directory / "gh",
            """
            #!/usr/bin/env bash
            printf '%s\n' "$MOCK_GH_RESPONSE"
            exit "${MOCK_GH_EXIT:-0}"
            """,
        )

    def run_validation(self, response: dict[str, object], exit_code: int = 0) -> subprocess.CompletedProcess[str]:
        return run_step(
            "Validate published GitHub Release",
            self.root,
            {
                "GH_TOKEN": "test-token",
                "GITHUB_REPOSITORY": "example/application",
                "IMAGE_TAG": "v1.2.3",
                "MOCK_GH_EXIT": str(exit_code),
                "MOCK_GH_RESPONSE": json.dumps(response),
                "PATH": f"{self.bin_directory}:{os.environ['PATH']}",
            },
        )

    def stable_release(self, **overrides: object) -> dict[str, object]:
        release = {
            "tag_name": "v1.2.3",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-09-17T00:00:00Z",
        }
        release.update(overrides)
        return release

    def test_published_stable_release_succeeds(self) -> None:
        result = self.run_validation(self.stable_release())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_draft_release_is_rejected(self) -> None:
        result = self.run_validation(self.stable_release(draft=True))
        self.assert_failed_with(result, "must be an existing published stable GitHub Release")

    def test_prerelease_is_rejected(self) -> None:
        result = self.run_validation(self.stable_release(prerelease=True))
        self.assert_failed_with(result, "must be an existing published stable GitHub Release")

    def test_missing_release_is_rejected(self) -> None:
        result = self.run_validation({}, exit_code=1)
        self.assert_failed_with(result, "Published GitHub Release v1.2.3 was not found")


class ReleaseRevalidationTests(WorkflowStepTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixture = GitFixture(self.root, "main")
        self.checkout = self.fixture.clone_at("v1.1.0")
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        write_executable(
            self.bin_directory / "gh",
            """
            #!/usr/bin/env bash
            printf '%s\n' "$MOCK_GH_RESPONSE"
            exit "${MOCK_GH_EXIT:-0}"
            """,
        )

    def stable_release(self, **overrides: object) -> dict[str, object]:
        release = {
            "tag_name": "v1.1.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-09-17T00:00:00Z",
        }
        release.update(overrides)
        return release

    def run_revalidation(self, response: dict[str, object]) -> subprocess.CompletedProcess[str]:
        return run_step(
            "Revalidate release source",
            self.checkout,
            {
                "GH_TOKEN": "test-token",
                "GITHUB_REPOSITORY": "example/application",
                "IMAGE_TAG": "v1.1.0",
                "MOCK_GH_RESPONSE": json.dumps(response),
                "PATH": f"{self.bin_directory}:{os.environ['PATH']}",
                "SOURCE_BRANCH": "main",
                "SOURCE_SHA": self.fixture.second_sha,
            },
        )

    def test_unchanged_release_source_succeeds(self) -> None:
        result = self.run_revalidation(self.stable_release())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_new_second_production_branch_is_rejected(self) -> None:
        git(
            self.checkout,
            "update-ref",
            "refs/remotes/origin/master",
            self.fixture.second_sha,
        )
        result = self.run_revalidation(self.stable_release())

        self.assert_failed_with(result, "Both production branches main and master exist")

    def test_moved_release_tag_is_rejected(self) -> None:
        git(self.checkout, "tag", "--force", "v1.1.0", self.fixture.first_sha)
        result = self.run_revalidation(self.stable_release())

        self.assert_failed_with(result, "Tag v1.1.0 changed after validation")

    def test_release_state_change_is_rejected(self) -> None:
        result = self.run_revalidation(self.stable_release(prerelease=True))

        self.assert_failed_with(result, "GitHub Release v1.1.0 changed after validation")


class RollbackProtectionTests(WorkflowStepTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixture = GitFixture(self.root, "main")
        self.checkout = self.fixture.clone_at("v1.1.0")
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        write_executable(
            self.bin_directory / "curl",
            """
            #!/usr/bin/env python3
            import os
            import pathlib
            import sys

            arguments = sys.argv[1:]
            url = next((argument for argument in reversed(arguments) if argument.startswith("https://")), "")
            if "/service/token" in url:
                print('{"token":"registry-token"}')
                raise SystemExit(0)

            output = pathlib.Path(arguments[arguments.index("--output") + 1])
            output.write_text(os.environ["MOCK_TAGS_RESPONSE"])
            print(os.environ.get("MOCK_HTTP_STATUS", "200"), end="")
            """,
        )

    def run_rollback_check(
        self,
        image_tag: str,
        source_sha: str,
        tags: list[str] | None,
        status: str = "200",
        response: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        tag_response = response or {"name": "team-example/application", "tags": tags}
        return run_step(
            "Prevent release rollback",
            self.checkout,
            {
                "HARBOR_TOKEN": "test-token",
                "IMAGE_TAG": image_tag,
                "MOCK_HTTP_STATUS": status,
                "MOCK_TAGS_RESPONSE": json.dumps(tag_response),
                "PATH": f"{self.bin_directory}:{os.environ['PATH']}",
                "REGISTRY_USERNAME": "robot$example",
                "REMOTE_NAME": "registry.example/team-example/application",
                "RUNNER_TEMP": str(self.root),
                "SOURCE_BRANCH": "main",
                "SOURCE_SHA": source_sha,
            },
        )

    def test_newer_release_succeeds(self) -> None:
        result = self.run_rollback_check(
            "v1.1.0",
            self.fixture.second_sha,
            ["v1.0.0", "v1.1.0", "dev"],
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("follows all stable releases", result.stdout)

    def test_rollback_to_older_commit_is_rejected(self) -> None:
        self.checkout = self.fixture.clone_at("v1.0.0")
        result = self.run_rollback_check(
            "v1.0.0",
            self.fixture.first_sha,
            ["v1.1.0"],
        )

        self.assert_failed_with(result, "predates or diverges from Harbor release")

    def test_harbor_tag_without_git_tag_is_rejected(self) -> None:
        result = self.run_rollback_check(
            "v1.1.0",
            self.fixture.second_sha,
            ["v9.9.9"],
        )

        self.assert_failed_with(result, "has no matching Git tag")

    def test_harbor_tag_outside_production_branch_is_rejected(self) -> None:
        self.fixture.add_divergent_tag()
        self.checkout = self.fixture.clone_at("v1.1.0")
        result = self.run_rollback_check(
            "v1.1.0",
            self.fixture.second_sha,
            ["v2.0.0"],
        )

        self.assert_failed_with(result, "is not contained in main")

    def test_missing_harbor_repository_succeeds(self) -> None:
        result = self.run_rollback_check(
            "v1.1.0",
            self.fixture.second_sha,
            None,
            status="404",
            response={"errors": [{"code": "NAME_UNKNOWN"}]},
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No existing Harbor repository", result.stdout)

    def test_unexpected_harbor_error_is_rejected(self) -> None:
        result = self.run_rollback_check(
            "v1.1.0",
            self.fixture.second_sha,
            None,
            status="500",
            response={"errors": [{"code": "UNKNOWN"}]},
        )

        self.assert_failed_with(result, "Harbor returned HTTP 500")


if __name__ == "__main__":
    unittest.main()
