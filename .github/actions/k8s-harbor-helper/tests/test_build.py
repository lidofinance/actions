import json
import subprocess
from pathlib import Path
from unittest import mock

from harbor_helper.build import (
    populate_build_info,
    prepare_context,
    resolve_image_digest,
)
from support import GitFixture, TemporaryTestCase


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


class ImageDigestTests(TemporaryTestCase):
    def test_image_digest(self) -> None:
        digest = "sha256:" + "a" * 64
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"digest": digest}), stderr=""
        )
        with mock.patch("harbor_helper.build.subprocess.run", return_value=completed):
            outputs = resolve_image_digest(
                {"REMOTE_REF": "registry.example/project/application:v1.2.3"}
            )
        self.assertEqual(outputs["image_digest"], digest)

    def test_invalid_image_digest_is_rejected(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"digest":"latest"}', stderr=""
        )
        with mock.patch("harbor_helper.build.subprocess.run", return_value=completed), \
                mock.patch("harbor_helper.build.time.sleep"):
            self.assert_workflow_error(
                "Could not determine the digest",
                resolve_image_digest,
                {"REMOTE_REF": "registry.example/project/application:v1.2.3"},
            )

    def test_digest_lookup_retries_transient_errors(self) -> None:
        digest = "sha256:" + "b" * 64
        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="network error")
        success = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"digest": digest}), stderr="",
        )
        with mock.patch("harbor_helper.build.subprocess.run", side_effect=[failed, failed, success]) as run, \
                mock.patch("harbor_helper.build.time.sleep") as sleep:
            outputs = resolve_image_digest({"REMOTE_REF": "registry.example/project/app:v1.2.3"})
        self.assertEqual(outputs["image_digest"], digest)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(4)])
        self.assertTrue(all(call.kwargs["timeout"] == 30 for call in run.call_args_list))

    def test_failed_digest_lookup_reports_that_push_already_succeeded(self) -> None:
        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="unavailable")
        with mock.patch("harbor_helper.build.subprocess.run", return_value=failed) as run, \
                mock.patch("harbor_helper.build.time.sleep") as sleep:
            self.assert_workflow_error(
                "was pushed, but its digest could not be retrieved after 3 attempts",
                resolve_image_digest,
                {"REMOTE_REF": "registry.example/project/app:v1.2.3"},
            )
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_digest_lookup_retries_timeout_and_invalid_json(self) -> None:
        digest = "sha256:" + "c" * 64
        results = [
            subprocess.TimeoutExpired(cmd="docker", timeout=30),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="not JSON", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps({"digest": digest}), stderr=""),
        ]
        with mock.patch("harbor_helper.build.subprocess.run", side_effect=results), \
                mock.patch("harbor_helper.build.time.sleep"):
            outputs = resolve_image_digest({"REMOTE_REF": "registry.example/project/app:v1.2.3"})
        self.assertEqual(outputs["image_digest"], digest)
