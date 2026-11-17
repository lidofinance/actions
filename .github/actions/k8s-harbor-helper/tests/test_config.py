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
        self.assertEqual(outputs["github_environment"], "harbor_prod_release")

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

    def test_dispatch_from_production_branch_without_upstream_metadata(self) -> None:
        for target in ("prod", "critical"):
            for branch in ("main", "master"):
                with self.subTest(target=target, branch=branch):
                    outputs = configure(self.environment(
                        TARGET=target, GITHUB_EVENT_NAME="workflow_dispatch", REF_NAME=branch,
                        UPSTREAM_EVENT="", UPSTREAM_CONCLUSION="", UPSTREAM_PATH="",
                        UPSTREAM_REPOSITORY="",
                    ))
                    self.assertEqual(outputs["source_ref"], "v1.2.3")
                    self.assertEqual(outputs["image_tag"], "v1.2.3")
                    self.assertEqual(outputs["is_release"], "true")
                    self.assertEqual(outputs["requested_source_branch"], "")

    def test_dispatch_outside_production_branches_is_rejected(self) -> None:
        for ref_type, ref_name in (
            ("branch", "develop"), ("branch", "feature/untrusted"),
            ("tag", "v1.2.3"), ("tag", "main"),
        ):
            with self.subTest(ref_type=ref_type, ref_name=ref_name):
                self.assert_workflow_error(
                    "workflow_dispatch builds must run from main or master",
                    configure,
                    self.environment(
                        GITHUB_EVENT_NAME="workflow_dispatch", REF_TYPE=ref_type, REF_NAME=ref_name,
                    ),
                )

    def test_other_release_triggers_are_rejected(self) -> None:
        for event in ("push", "release", "repository_dispatch", ""):
            with self.subTest(event=event):
                self.assert_workflow_error(
                    "must be started by workflow_run or workflow_dispatch",
                    configure,
                    self.environment(GITHUB_EVENT_NAME=event, REF_NAME="main"),
                )

    def test_failed_upstream_is_rejected(self) -> None:
        self.assert_workflow_error(
            "require a successful upstream workflow",
            configure,
            self.environment(UPSTREAM_CONCLUSION="failure"),
        )

    def test_non_semver_tag_is_rejected(self) -> None:
        for event, branch in (("workflow_run", "develop"), ("workflow_dispatch", "main")):
            with self.subTest(event=event):
                self.assert_workflow_error(
                    "requires a stable release tag",
                    configure,
                    self.environment(TAG="latest", GITHUB_EVENT_NAME=event, REF_NAME=branch),
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
