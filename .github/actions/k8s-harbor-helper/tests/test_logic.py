from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harbor_helper.logic import (
    HttpResponse,
    WorkflowError,
    check_rollback,
    configure,
    populate_build_info,
    prepare_context,
    resolve_image_digest,
    revalidate_release,
    summarize_trivy,
    validate_published_release,
    validate_source,
    write_outputs,
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


class ConfigureTests(TemporaryTestCase):
    def environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            "DEFAULT_BRANCH": "develop",
            "DOCKERFILE": "Dockerfile",
            "GITHUB_EVENT_NAME": "workflow_run",
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

    def test_release_from_non_main_default_branch(self) -> None:
        outputs = configure(self.environment())
        self.assertEqual(outputs["source_ref"], "v1.2.3")
        self.assertEqual(outputs["is_release"], "true")
        self.assertEqual(outputs["github_environment"], "harbor_dev_release")

    def test_development_configuration(self) -> None:
        outputs = configure(self.environment(TARGET="dev", TAG=""))
        self.assertEqual(outputs["image_tag"], "dev")
        self.assertEqual(outputs["requested_source_branch"], "develop")
        self.assertEqual(outputs["source_ref"], "a" * 40)

    def test_untrusted_upstream_workflow_is_rejected(self) -> None:
        self.assert_workflow_error(
            "Unexpected upstream workflow",
            configure,
            self.environment(UPSTREAM_PATH=".github/workflows/other.yaml"),
        )

    def test_upstream_from_another_repository_is_rejected(self) -> None:
        self.assert_workflow_error(
            "unexpected repository",
            configure,
            self.environment(UPSTREAM_REPOSITORY="attacker/application"),
        )

    def test_direct_dispatch_is_rejected(self) -> None:
        self.assert_workflow_error(
            "must be started by a workflow_run",
            configure,
            self.environment(GITHUB_EVENT_NAME="workflow_dispatch"),
        )

    def test_failed_upstream_is_rejected(self) -> None:
        self.assert_workflow_error(
            "require a successful upstream workflow",
            configure,
            self.environment(UPSTREAM_CONCLUSION="failure"),
        )

    def test_non_semver_tag_is_rejected(self) -> None:
        self.assert_workflow_error(
            "requires a stable release tag",
            configure,
            self.environment(TAG="latest"),
        )

    def test_run_outside_default_branch_is_rejected(self) -> None:
        self.assert_workflow_error(
            "must run from the repository default branch",
            configure,
            self.environment(REF_NAME="feature/untrusted"),
        )

    def test_dev_tag_is_rejected(self) -> None:
        self.assert_workflow_error(
            "tag input cannot be used for dev",
            configure,
            self.environment(TARGET="dev"),
        )

    def test_multiple_image_destinations_are_rejected(self) -> None:
        self.assert_workflow_error(
            "Invalid image name",
            configure,
            self.environment(IMAGE="application,attacker/repository"),
        )

    def test_absolute_dockerfile_is_rejected(self) -> None:
        self.assert_workflow_error(
            "Dockerfile must be a relative repository path",
            configure,
            self.environment(DOCKERFILE="/tmp/Dockerfile"),
        )


class SourceValidationTests(TemporaryTestCase):
    def validate(
        self,
        fixture: GitFixture,
        tag: str,
        upstream_sha: str,
        image_tag: str | None = None,
    ) -> dict[str, str]:
        checkout = fixture.clone_at(tag)
        return validate_source(
            {
                "IMAGE_TAG": image_tag or tag,
                "IS_RELEASE": "true",
                "REQUESTED_SOURCE_BRANCH": "",
                "UPSTREAM_SHA": upstream_sha,
            },
            cwd=checkout,
        )

    def test_main_release(self) -> None:
        fixture = GitFixture(self.root, "main")
        outputs = self.validate(fixture, "v1.1.0", fixture.second_sha)
        self.assertEqual(outputs, {"source_branch": "main", "source_sha": fixture.second_sha})

    def test_master_release(self) -> None:
        fixture = GitFixture(self.root, "master")
        outputs = self.validate(fixture, "v1.1.0", fixture.second_sha)
        self.assertEqual(outputs["source_branch"], "master")

    def test_both_production_branches_are_rejected(self) -> None:
        fixture = GitFixture(self.root)
        fixture.add_second_production_branch()
        self.assert_workflow_error(
            "Both production branches",
            self.validate,
            fixture,
            "v1.1.0",
            fixture.second_sha,
        )

    def test_missing_production_branch_is_rejected(self) -> None:
        fixture = GitFixture(self.root, "develop")
        self.assert_workflow_error(
            "Neither production branch",
            self.validate,
            fixture,
            "v1.1.0",
            fixture.second_sha,
        )

    def test_commit_outside_production_branch_is_rejected(self) -> None:
        fixture = GitFixture(self.root)
        divergent_sha = fixture.add_divergent_tag()
        self.assert_workflow_error(
            "is not contained in branch main",
            self.validate,
            fixture,
            "v2.0.0",
            divergent_sha,
        )

    def test_upstream_sha_mismatch_is_rejected(self) -> None:
        fixture = GitFixture(self.root)
        self.assert_workflow_error(
            "does not match upstream workflow_run commit",
            self.validate,
            fixture,
            "v1.1.0",
            fixture.first_sha,
        )

    def test_invalid_release_mode_is_rejected(self) -> None:
        fixture = GitFixture(self.root)
        checkout = fixture.clone_at("v1.1.0")
        self.assert_workflow_error(
            "IS_RELEASE must be either",
            validate_source,
            {
                "IMAGE_TAG": "v1.1.0",
                "IS_RELEASE": "yes",
                "REQUESTED_SOURCE_BRANCH": "",
                "UPSTREAM_SHA": fixture.second_sha,
            },
            cwd=checkout,
        )

    def test_different_input_tag_is_rejected(self) -> None:
        fixture = GitFixture(self.root)
        self.assert_workflow_error(
            "does not match tag v1.0.0",
            self.validate,
            fixture,
            "v1.1.0",
            fixture.second_sha,
            "v1.0.0",
        )


class ReleaseTests(TemporaryTestCase):
    def release(self, **overrides: object) -> dict[str, object]:
        release = {
            "tag_name": "v1.1.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-09-28T00:00:00Z",
        }
        release.update(overrides)
        return release

    def environment(self) -> dict[str, str]:
        return {
            "GITHUB_REPOSITORY": "example/application",
            "GITHUB_TOKEN": "test-token",
            "IMAGE_TAG": "v1.1.0",
        }

    def test_published_stable_release(self) -> None:
        responses = ResponseQueue(HttpResponse(200, self.release()))
        validate_published_release(self.environment(), http_get=responses)
        self.assertIn("/releases/tags/v1.1.0", responses.requests[0][0])
        self.assertEqual(
            responses.requests[0][1]["Authorization"], "Bearer test-token"
        )

    def test_draft_release_is_rejected(self) -> None:
        responses = ResponseQueue(HttpResponse(200, self.release(draft=True)))
        self.assert_workflow_error(
            "published stable GitHub Release",
            validate_published_release,
            self.environment(),
            http_get=responses,
        )

    def test_prerelease_is_rejected(self) -> None:
        responses = ResponseQueue(HttpResponse(200, self.release(prerelease=True)))
        self.assert_workflow_error(
            "published stable GitHub Release",
            validate_published_release,
            self.environment(),
            http_get=responses,
        )

    def test_missing_release_is_rejected(self) -> None:
        responses = ResponseQueue(HttpResponse(404, {"message": "Not Found"}))
        self.assert_workflow_error(
            "was not found",
            validate_published_release,
            self.environment(),
            http_get=responses,
        )

    def test_unchanged_release_revalidates(self) -> None:
        fixture = GitFixture(self.root)
        checkout = fixture.clone_at("v1.1.0")
        environment = self.environment() | {
            "SOURCE_BRANCH": "main",
            "SOURCE_SHA": fixture.second_sha,
        }
        responses = ResponseQueue(HttpResponse(200, self.release()))
        revalidate_release(environment, cwd=checkout, http_get=responses)

    def test_moved_tag_is_rejected_during_revalidation(self) -> None:
        fixture = GitFixture(self.root)
        checkout = fixture.clone_at("v1.1.0")
        git(checkout, "tag", "--force", "v1.1.0", fixture.first_sha)
        environment = self.environment() | {
            "SOURCE_BRANCH": "main",
            "SOURCE_SHA": fixture.second_sha,
        }
        self.assert_workflow_error(
            "Tag v1.1.0 changed",
            revalidate_release,
            environment,
            cwd=checkout,
            http_get=ResponseQueue(HttpResponse(200, self.release())),
        )

    def test_second_production_branch_is_rejected_during_revalidation(self) -> None:
        fixture = GitFixture(self.root)
        checkout = fixture.clone_at("v1.1.0")
        git(checkout, "update-ref", "refs/remotes/origin/master", fixture.second_sha)
        environment = self.environment() | {
            "SOURCE_BRANCH": "main",
            "SOURCE_SHA": fixture.second_sha,
        }
        self.assert_workflow_error(
            "Both production branches",
            revalidate_release,
            environment,
            cwd=checkout,
            http_get=ResponseQueue(HttpResponse(200, self.release())),
        )


class ContextAndBuildInfoTests(TemporaryTestCase):
    def test_prepare_context_exports_validated_commit(self) -> None:
        fixture = GitFixture(self.root)
        checkout = fixture.clone_at("v1.1.0")
        outputs = prepare_context(
            {
                "DOCKERFILE": "Dockerfile",
                "RUNNER_TEMP": str(self.root),
                "SOURCE_SHA": fixture.second_sha,
            },
            cwd=checkout,
        )
        context = Path(outputs["context_dir"])
        self.assertEqual((context / "content.txt").read_text(), "second\n")
        self.assertEqual(Path(outputs["dockerfile"]), context / "Dockerfile")
        self.assertFalse((context / ".git").exists())

    def test_archive_symlink_escape_is_rejected(self) -> None:
        fixture = GitFixture(self.root)
        source_sha = fixture.add_escaping_symlink()
        checkout = fixture.clone_at(source_sha)
        self.assert_workflow_error(
            "escapes the build context",
            prepare_context,
            {
                "DOCKERFILE": "Dockerfile",
                "RUNNER_TEMP": str(self.root),
                "SOURCE_SHA": source_sha,
            },
            cwd=checkout,
        )

    def test_missing_dockerfile_is_rejected(self) -> None:
        fixture = GitFixture(self.root)
        checkout = fixture.clone_at("v1.1.0")
        self.assert_workflow_error(
            "does not exist",
            prepare_context,
            {
                "DOCKERFILE": "missing.Dockerfile",
                "RUNNER_TEMP": str(self.root),
                "SOURCE_SHA": fixture.second_sha,
            },
            cwd=checkout,
        )

    def test_build_info_is_written_atomically(self) -> None:
        context = self.root / "context"
        context.mkdir()
        populate_build_info(
            {
                "BUILD_BRANCH": "main",
                "BUILD_COMMIT": "a" * 40,
                "BUILD_CONTEXT": str(context),
                "BUILD_VERSION": "v1.2.3",
            }
        )
        self.assertEqual(
            json.loads((context / "build-info.json").read_text()),
            {"version": "v1.2.3", "branch": "main", "commit": "a" * 40},
        )
        self.assertEqual((context / "build-info.json").stat().st_mode & 0o777, 0o644)

    def test_build_info_symlink_is_rejected(self) -> None:
        context = self.root / "context"
        context.mkdir()
        (context / "build-info.json").symlink_to(self.root / "outside")
        self.assert_workflow_error(
            "must not be a symbolic link",
            populate_build_info,
            {
                "BUILD_BRANCH": "main",
                "BUILD_COMMIT": "a" * 40,
                "BUILD_CONTEXT": str(context),
                "BUILD_VERSION": "v1.2.3",
            },
        )


class TrivyTests(TemporaryTestCase):
    def test_summary_and_critical_report(self) -> None:
        report = self.root / "report.json"
        summary = self.root / "summary.md"
        summary.touch()
        report.write_text(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": "application",
                            "Vulnerabilities": [
                                {
                                    "Severity": "HIGH",
                                    "VulnerabilityID": "CVE-HIGH",
                                },
                                {
                                    "Severity": "CRITICAL",
                                    "VulnerabilityID": "CVE-CRITICAL",
                                    "PkgName": "package",
                                    "InstalledVersion": "1",
                                    "FixedVersion": "2",
                                },
                            ],
                        }
                    ]
                }
            )
        )
        with mock.patch("builtins.print") as print_mock:
            summarize_trivy(
                {"GITHUB_STEP_SUMMARY": str(summary), "TRIVY_REPORT": str(report)}
            )
        self.assertIn("| HIGH | 1 |", summary.read_text())
        self.assertIn("| CRITICAL | 1 |", summary.read_text())
        self.assertTrue(
            any("report-only" in str(call) for call in print_mock.call_args_list)
        )

    def test_invalid_report_is_rejected(self) -> None:
        report = self.root / "report.json"
        report.write_text("[]")
        self.assert_workflow_error(
            "valid vulnerability report",
            summarize_trivy,
            {
                "GITHUB_STEP_SUMMARY": str(self.root / "summary.md"),
                "TRIVY_REPORT": str(report),
            },
        )


class RollbackTests(TemporaryTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixture = GitFixture(self.root)
        self.checkout = self.fixture.clone_at("v1.1.0")

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            "HARBOR_TOKEN": "test-token",
            "IMAGE_TAG": "v1.1.0",
            "REGISTRY_USERNAME": "robot$example",
            "REMOTE_NAME": "registry.example/team-example/application",
            "SOURCE_BRANCH": "main",
            "SOURCE_SHA": self.fixture.second_sha,
        }
        environment.update(overrides)
        return environment

    def responses(self, tags: object, status: int = 200) -> ResponseQueue:
        return ResponseQueue(
            HttpResponse(200, {"token": "registry-token"}),
            HttpResponse(
                status,
                {"name": "team-example/application", "tags": tags},
            ),
        )

    def test_forward_release(self) -> None:
        responses = self.responses(["v1.0.0", "v1.1.0", "dev"])
        check_rollback(self.environment(), cwd=self.checkout, http_get=responses)
        self.assertTrue(responses.requests[0][1]["Authorization"].startswith("Basic "))
        self.assertEqual(
            responses.requests[1][1]["Authorization"], "Bearer registry-token"
        )

    def test_rollback_is_rejected(self) -> None:
        self.checkout = self.fixture.clone_at("v1.0.0")
        self.assert_workflow_error(
            "predates or diverges",
            check_rollback,
            self.environment(IMAGE_TAG="v1.0.0", SOURCE_SHA=self.fixture.first_sha),
            cwd=self.checkout,
            http_get=self.responses(["v1.1.0"]),
        )

    def test_missing_git_tag_is_rejected(self) -> None:
        self.assert_workflow_error(
            "has no matching Git tag",
            check_rollback,
            self.environment(),
            cwd=self.checkout,
            http_get=self.responses(["v9.9.9"]),
        )

    def test_tag_outside_production_branch_is_rejected(self) -> None:
        self.fixture.add_divergent_tag()
        self.checkout = self.fixture.clone_at("v1.1.0")
        self.assert_workflow_error(
            "is not contained in main",
            check_rollback,
            self.environment(),
            cwd=self.checkout,
            http_get=self.responses(["v2.0.0"]),
        )

    def test_missing_repository_is_allowed(self) -> None:
        responses = ResponseQueue(
            HttpResponse(200, {"token": "registry-token"}),
            HttpResponse(404, {"errors": [{"code": "NAME_UNKNOWN"}]}),
        )
        check_rollback(self.environment(), cwd=self.checkout, http_get=responses)

    def test_unexpected_harbor_error_is_rejected(self) -> None:
        self.assert_workflow_error(
            "Harbor returned HTTP 500",
            check_rollback,
            self.environment(),
            cwd=self.checkout,
            http_get=self.responses(None, status=500),
        )

    def test_invalid_tag_list_is_rejected(self) -> None:
        self.assert_workflow_error(
            "invalid tag list",
            check_rollback,
            self.environment(),
            cwd=self.checkout,
            http_get=self.responses({"not": "a list"}),
        )


class OutputAndDigestTests(TemporaryTestCase):
    def test_outputs_reject_newlines(self) -> None:
        self.assert_workflow_error(
            "contains a newline",
            write_outputs,
            {"value": "safe\nunsafe=value"},
            self.root / "output",
        )

    def test_image_digest(self) -> None:
        digest = "sha256:" + "a" * 64
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"digest": digest}), stderr=""
        )
        with mock.patch("harbor_helper.logic.subprocess.run", return_value=completed):
            outputs = resolve_image_digest(
                {"REMOTE_REF": "registry.example/project/application:v1.2.3"}
            )
        self.assertEqual(outputs["image_digest"], digest)

    def test_invalid_image_digest_is_rejected(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"digest":"latest"}', stderr=""
        )
        with mock.patch("harbor_helper.logic.subprocess.run", return_value=completed):
            self.assert_workflow_error(
                "Could not determine the digest",
                resolve_image_digest,
                {"REMOTE_REF": "registry.example/project/application:v1.2.3"},
            )


if __name__ == "__main__":
    unittest.main()
