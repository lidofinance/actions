from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from harbor_helper.common import HttpResponse, WorkflowError


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
            f"git {' '.join(arguments)} failed with {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


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

        (self.seed / "Dockerfile").write_text("FROM scratch\n")
        self.first_sha = self.commit("first")
        git(self.seed, "tag", "v1.0.0", self.first_sha)
        self.second_sha = self.commit("second")
        git(self.seed, "tag", "v1.1.0", self.second_sha)
        git(self.seed, "remote", "add", "origin", str(self.origin))
        git(self.seed, "push", "origin", production_branch, "--tags")
        git(self.origin, "symbolic-ref", "HEAD", f"refs/heads/{production_branch}")

    def commit(self, content: str) -> str:
        (self.seed / "content.txt").write_text(f"{content}\n")
        git(self.seed, "add", ".")
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

    def add_escaping_symlink(self) -> str:
        link = self.seed / "escape"
        link.symlink_to("../../outside")
        sha = self.commit("escaping symlink")
        git(self.seed, "push", "origin", self.production_branch)
        return sha

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


class ResponseQueue:
    def __init__(self, *responses: HttpResponse) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, MappingProxy]] = []

    def __call__(self, url: str, headers: object) -> HttpResponse:
        self.requests.append((url, MappingProxy(dict(headers))))
        if not self.responses:
            raise AssertionError(f"Unexpected HTTP request to {url}")
        return self.responses.pop(0)


class MappingProxy(dict[str, str]):
    """Typed copy of request headers retained by ResponseQueue."""


class TemporaryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def assert_workflow_error(
        self, message: str, function: object, *args: object, **kwargs: object
    ) -> None:
        with self.assertRaisesRegex(WorkflowError, message):
            function(*args, **kwargs)
