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
        with mock.patch("harbor_helper.build.subprocess.run", return_value=completed):
            self.assert_workflow_error(
                "Could not determine the digest",
                resolve_image_digest,
                {"REMOTE_REF": "registry.example/project/application:v1.2.3"},
            )
