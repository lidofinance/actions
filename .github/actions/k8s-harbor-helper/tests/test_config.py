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
