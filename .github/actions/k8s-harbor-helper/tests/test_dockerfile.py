import contextlib
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from harbor_helper.common import WorkflowError
from harbor_helper.dockerfile import check_dhi, image_references


class DockerfileReferencesTests(unittest.TestCase):
    def images(self, text: str, **arguments: str) -> list[str]:
        return [reference.image for reference in image_references(text, arguments)]

    def test_multistage_global_args_platform_aliases_and_indices(self) -> None:
        self.assertEqual(self.images(
            'ARG REGISTRY=dhi.io\n'
            'ARG BASE="${REGISTRY}/node:22-dev"\n'
            'FROM --platform=$BUILDPLATFORM $BASE AS builder\n'
            'RUN echo build\n'
            'FROM builder AS tests\n'
            'FROM dhi.io/node:22\n'
            'COPY --from=builder /app /app\n'
            'COPY --from=0 /other /other\n'
            'RUN --mount=type=bind,from=tests,target=/test echo test\n'
        ), ["dhi.io/node:22-dev", "dhi.io/node:22"])

    def test_all_external_sources_including_unused_stages_are_checked(self) -> None:
        self.assertEqual(self.images(
            'FROM alpine:3 AS unused\n'
            'FROM dhi.io/nginx:1\n'
            'COPY --from=busybox:1 /bin/true /bin/true\n'
            'RUN --mount=type=bind,from=ubuntu:24.04,target=/tmp echo test\n'
        ), ["alpine:3", "dhi.io/nginx:1", "busybox:1", "ubuntu:24.04"])

    def test_quoted_flags_and_tab_separators_cannot_hide_external_images(self) -> None:
        self.assertEqual(self.images(
            'FROM dhi.io/nginx:1\n'
            'COPY --from="busybox:1" /bin/true /bin/true\n'
            "RUN --network=default\t--mount='type=bind,from=alpine:3,target=/tmp' echo test\n"
        ), ["dhi.io/nginx:1", "busybox:1", "alpine:3"])

    def test_mount_csv_and_case_cannot_hide_external_images(self) -> None:
        for mount in (
            'type=bind,FROM=alpine:3,target=/test',
            'type=bind,"from=alpine:3",target=/test',
            'type=bind, from=alpine:3,target=/test',
        ):
            with self.subTest(mount=mount):
                self.assertEqual(self.images(
                    f"FROM dhi.io/nginx:1\nRUN --mount='{mount}' echo test\n"
                ), ["dhi.io/nginx:1", "alpine:3"])

    def test_multiline_comments_and_digest(self) -> None:
        image = "dhi.io/nginx@sha256:" + "a" * 64
        references = image_references(
            '# syntax=docker/dockerfile:1\n'
            '# escape=\\\n'
            '# FROM nginx:alpine\n'
            'FROM \\\n'
            '# comment in a continuation\n'
            f'  {image}\n',
            {},
        )
        self.assertEqual([reference.image for reference in references], [image])
        self.assertEqual(references[0].line, 4)

    def test_actual_build_arguments_override_dockerfile_defaults(self) -> None:
        self.assertEqual(self.images(
            'ARG BUILD_VERSION=latest\nFROM dhi.io/node:$BUILD_VERSION\n',
            BUILD_VERSION="22",
        ), ["dhi.io/node:22"])

    def test_stage_args_do_not_change_subsequent_from_global_scope(self) -> None:
        self.assertEqual(self.images(
            'ARG BASE=dhi.io/node:22\nFROM $BASE\n'
            'ARG BASE=alpine:3\nFROM $BASE\n'
        ), ["dhi.io/node:22", "dhi.io/node:22"])

    def test_unsupported_or_ambiguous_syntax_fails_closed(self) -> None:
        for text in (
            'FROM $MISSING\n',
            'ARG BASE\nFROM ${BASE}\n',
            'FROM ${BASE:-nginx:1}\n',
            'FROM dhi.io/nginx:1\nRUN <<EOF\nFROM busybox\nEOF\n',
            '# escape=`\nFROM dhi.io/nginx:1\n',
            '# syntax=attacker/frontend:1\nFROM dhi.io/nginx:1\n',
            '\ufeff# syntax=attacker/frontend:1\nFROM dhi.io/nginx:1\n',
            'FROM dhi.io/nginx:1\nCOPY --from=99 /bin/a /bin/a\n',
            'ARG BASE=dhi.io/node:22\nFROM $BASE\nARG BASE=nginx\n'
            'RUN --mount=from=${BASE},target=/test echo test\n',
            'FROM dhi.io/nginx:1\nCOPY --from=$BASE /bin/a /bin/a\n',
            'FROM dhi.io/nginx:1 AS\n',
            'FROM "dhi.io/nginx:1\n',
            'FROM dhi.io/nginx:1\nCOPY --from /a /a\n',
            'FROM dhi.io/nginx:1\\',
            'RUN echo no-stage\n',
        ):
            with self.subTest(text=text), self.assertRaises(WorkflowError):
                self.images(text)


class DhiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.dockerfile = self.root / "Dockerfile"
        self.policy = self.root / "exceptions.json"
        self.summary = self.root / "summary.md"
        self.dockerfile.write_text("FROM dhi.io/nginx:1\n")
        self.policy.write_text(json.dumps({"exceptions": []}))

    def environment(self, target: str = "prod", **overrides: str) -> dict[str, str]:
        return {
            "TARGET": target,
            "GITHUB_REPOSITORY": "example/application",
            "DHI_POLICY": str(self.policy),
            "DOCKERFILE": str(self.dockerfile),
            "BUILD_VERSION": "v1.2.3",
            "BUILD_BRANCH": "main",
            "BUILD_COMMIT": "a" * 40,
            "GITHUB_STEP_SUMMARY": str(self.summary),
            **overrides,
        }

    def check(self, target: str = "prod", **overrides: str) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_dhi(
                self.environment(target, **overrides), policy_path=self.policy,
                today=date(2026, 10, 16),
            )
        return output.getvalue()

    def exception(self, **overrides: object) -> dict:
        return {
            "repository": "example/application",
            "targets": ["prod"],
            "image": "nginx:alpine",
            "reason": "Temporary migration exception",
            "expires": "2026-11-01",
            **overrides,
        }

    def set_exceptions(self, *entries: dict) -> None:
        self.policy.write_text(json.dumps({"exceptions": list(entries)}))

    def test_dhi_is_allowed_for_all_targets(self) -> None:
        for target in ("dev", "staging", "prod", "critical"):
            with self.subTest(target=target):
                self.assertIn("All Dockerfile image references use DHI", self.check(target))

    def test_non_dhi_warns_in_dev_and_blocks_all_other_targets(self) -> None:
        self.dockerfile.write_text("FROM nginx:alpine\n")
        self.assertIn("::warning::DHI:", self.check("dev"))
        for target in ("staging", "prod", "critical"):
            with self.subTest(target=target), self.assertRaisesRegex(WorkflowError, "blocks publication"):
                self.check(target)
        self.assertIn("DHI base-image policy", self.summary.read_text())

    def test_registry_lookalikes_and_scratch_are_not_implicitly_allowed(self) -> None:
        for image in (
            "dhi.io.attacker.example/nginx", "attacker.example/dhi.io/nginx",
            "docker.io/dhi.io/nginx", "dhi.io:5000/nginx", "scratch",
        ):
            self.dockerfile.write_text(f"FROM {image}\n")
            with self.subTest(image=image), self.assertRaises(WorkflowError):
                self.check()

    def test_unused_non_dhi_build_stage_is_not_ignored(self) -> None:
        self.dockerfile.write_text("FROM alpine:3 AS unused\nFROM dhi.io/nginx:1\n")
        with self.assertRaises(WorkflowError):
            self.check()

    def test_external_copy_and_mount_sources_are_enforced(self) -> None:
        for instruction in (
            'COPY --from="nginx:alpine" /a /a',
            "RUN --mount=type=bind,from=nginx:alpine,target=/test echo test",
        ):
            self.dockerfile.write_text(f"FROM dhi.io/nginx:1\n{instruction}\n")
            with self.subTest(instruction=instruction), self.assertRaises(WorkflowError):
                self.check()

    def test_exact_active_scoped_exception_allows_and_is_logged(self) -> None:
        self.dockerfile.write_text("FROM nginx:alpine\n")
        self.set_exceptions(self.exception())
        output = self.check()
        self.assertIn("Approved DHI exception:", output)
        self.assertIn("Temporary migration exception", output)
        self.assertIn("Approved exceptions: 1", self.summary.read_text())

    def test_exception_cannot_be_reused_for_other_repository_target_or_image(self) -> None:
        self.dockerfile.write_text("FROM nginx:alpine\n")
        for overrides in (
            {"repository": "example/other"}, {"targets": ["dev"]},
            {"image": "nginx:other"}, {"expires": "2026-10-15"},
        ):
            self.set_exceptions(self.exception(**overrides))
            with self.subTest(overrides=overrides), self.assertRaises(WorkflowError):
                self.check()

    def test_expiry_day_is_inclusive(self) -> None:
        self.dockerfile.write_text("FROM nginx:alpine\n")
        self.set_exceptions(self.exception(expires="2026-10-16"))
        self.check()

    def test_scratch_can_be_explicitly_excepted(self) -> None:
        self.dockerfile.write_text("FROM scratch\n")
        self.set_exceptions(self.exception(image="scratch"))
        self.check()

    def test_parsing_failures_warn_only_in_dev_and_cannot_be_excepted(self) -> None:
        self.dockerfile.write_text("FROM $MISSING\n")
        self.assertIn("unresolved image ARG", self.check("dev"))
        with self.assertRaises(WorkflowError):
            self.check()

    def test_missing_or_invalid_trusted_policy_fails_even_in_dev(self) -> None:
        self.policy.unlink()
        with self.assertRaises(WorkflowError):
            self.check("dev")
        for policy in ({}, {"exceptions": None}, {"exceptions": [{}]}):
            self.policy.write_text(json.dumps(policy))
            with self.subTest(policy=policy), self.assertRaises(WorkflowError):
                self.check("dev")

    def test_invalid_or_wildcard_exceptions_are_rejected(self) -> None:
        for overrides in (
            {"repository": "example/*"}, {"targets": ["*"]},
            {"image": "nginx:*"}, {"reason": ""},
            {"expires": "invalid"}, {"targets": "prod"},
            {"expires": "20261101"},
        ):
            self.set_exceptions(self.exception(**overrides))
            with self.subTest(overrides=overrides), self.assertRaises(WorkflowError):
                self.check("dev")

    def test_unknown_target_fails_closed(self) -> None:
        with self.assertRaisesRegex(WorkflowError, "Unknown DHI policy target"):
            self.check("other")

    def test_missing_build_metadata_fails_even_in_dev(self) -> None:
        for argument in ("BUILD_VERSION", "BUILD_BRANCH", "BUILD_COMMIT"):
            with self.subTest(argument=argument), self.assertRaises(WorkflowError):
                self.check("dev", **{argument: ""})

    def test_missing_prepared_snapshot_path_fails_closed(self) -> None:
        self.dockerfile.write_text("FROM nginx:alpine\n")
        with self.assertRaisesRegex(WorkflowError, "DHI_POLICY is empty"):
            check_dhi(self.environment(DHI_POLICY=""))


if __name__ == "__main__":
    unittest.main()
