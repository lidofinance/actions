from harbor_helper.config import configure
from support import TemporaryTestCase


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
        self.assertEqual(
            outputs["remote_name"],
            "registry.dev.k8s-dev.org/team-example/application/api",
        )
        self.assertEqual(outputs["image_tag"], "v1.2.3")
        self.assertEqual(outputs["requested_source_branch"], "")

    def test_non_prod_destinations_are_unchanged(self) -> None:
        for target, registry, github_environment in (
            ("dev", "registry.dev.k8s-dev.org", "harbor_dev_release"),
            ("staging", "registry.staging.k8s-staging.org", "harbor_stage_release"),
            ("critical", "registry.critical.k8s-prod.org", "harbor_crit_release"),
        ):
            with self.subTest(target=target):
                outputs = configure(self.environment(
                    TARGET=target, TAG="v1.2.3" if target == "critical" else "",
                ))
                self.assertEqual(outputs["github_environment"], github_environment)
                self.assertEqual(
                    outputs["remote_name"], f"{registry}/team-example/application/api",
                )

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

    def dispatch_environment(self, **overrides: str) -> dict[str, str]:
        environment = self.environment(GITHUB_EVENT_NAME="workflow_dispatch")
        for key in tuple(environment):
            if key.startswith("UPSTREAM_"):
                del environment[key]
        environment.update(overrides)
        return environment

    def test_prod_dispatch_uses_input_tag_without_upstream_event(self) -> None:
        outputs = configure(self.dispatch_environment())
        self.assertEqual(outputs["source_ref"], "v1.2.3")
        self.assertEqual(outputs["image_tag"], "v1.2.3")
        self.assertEqual(outputs["is_release"], "true")
        self.assertEqual(outputs["requested_source_branch"], "")
        self.assertEqual(outputs["github_environment"], "harbor_dev_release")

    def test_prod_dispatch_from_another_branch_or_tag_ref_is_rejected(self) -> None:
        for overrides in (
            {"REF_NAME": "feature/untrusted"},
            {"REF_NAME": "v1.2.3", "REF_TYPE": "tag"},
        ):
            with self.subTest(overrides=overrides):
                self.assert_workflow_error(
                    "must run from the repository default branch",
                    configure,
                    self.dispatch_environment(**overrides),
                )

    def test_prod_dispatch_requires_stable_tag(self) -> None:
        for tag in ("", "latest", "v1.2.3-rc.1", "--help"):
            with self.subTest(tag=tag):
                self.assert_workflow_error(
                    "requires a stable release tag",
                    configure,
                    self.dispatch_environment(TAG=tag),
                )

    def test_prod_dispatch_requires_valid_default_branch(self) -> None:
        for branch in ("", "invalid branch"):
            with self.subTest(branch=branch):
                self.assert_workflow_error(
                    "Repository default branch.*is invalid",
                    configure,
                    self.dispatch_environment(DEFAULT_BRANCH=branch),
                )

    def test_critical_dispatch_is_still_rejected(self) -> None:
        self.assert_workflow_error(
            "critical builds must be started by workflow_run",
            configure,
            self.dispatch_environment(TARGET="critical"),
        )

    def test_other_prod_events_are_rejected(self) -> None:
        for event in ("", "push", "pull_request", "release", "workflow_call"):
            with self.subTest(event=event):
                self.assert_workflow_error(
                    "prod builds must be started by",
                    configure,
                    self.environment(GITHUB_EVENT_NAME=event),
                )

    def test_automatic_release_still_requires_upstream_metadata(self) -> None:
        for overrides in (
            {"UPSTREAM_EVENT": ""},
            {"UPSTREAM_CONCLUSION": ""},
            {"UPSTREAM_PATH": ""},
            {"UPSTREAM_REPOSITORY": ""},
        ):
            with self.subTest(overrides=overrides):
                self.assert_workflow_error(
                    "upstream|Upstream", configure, self.environment(**overrides),
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
