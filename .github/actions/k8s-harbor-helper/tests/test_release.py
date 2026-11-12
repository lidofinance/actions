from harbor_helper.common import HttpResponse
from harbor_helper.release import (
    revalidate_release,
    validate_published_release,
    validate_source,
)
from support import GitFixture, ResponseQueue, TemporaryTestCase, git


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
        self.assertEqual(
            outputs, {"source_branch": "main", "source_sha": fixture.second_sha}
        )

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
