from harbor_helper.common import HttpResponse
from harbor_helper.harbor import check_rollback
from support import GitFixture, ResponseQueue, TemporaryTestCase


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

    def test_missing_repository_with_harbor_not_found_is_allowed(self) -> None:
        responses = ResponseQueue(
            HttpResponse(200, {"token": "registry-token"}),
            HttpResponse(404, {"errors": [{"code": "NOT_FOUND"}]}),
        )
        check_rollback(self.environment(), cwd=self.checkout, http_get=responses)

    def test_unexpected_not_found_error_is_rejected(self) -> None:
        responses = ResponseQueue(
            HttpResponse(200, {"token": "registry-token"}),
            HttpResponse(404, {"errors": [{"code": "UNAUTHORIZED"}]}),
        )
        self.assert_workflow_error(
            "HTTP 404 with error codes UNAUTHORIZED",
            check_rollback,
            self.environment(),
            cwd=self.checkout,
            http_get=responses,
        )

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
