import base64
import contextlib
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from harbor_helper.common import HttpResponse, WorkflowError
from harbor_helper.dhi_policy import (
    POLICY_API, POLICY_BRANCH, POLICY_FILE, POLICY_REPOSITORY, prepare_dhi_policy,
)
from harbor_helper.dockerfile import check_dhi


class DhiDownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.summary = self.root / "summary.md"
        self.sha = "a" * 40
        self.branch = HttpResponse(200, {
            "ref": f"refs/heads/{POLICY_BRANCH}",
            "object": {"type": "commit", "sha": self.sha},
        })
        self.policy = {"exceptions": [{
            "repository": "example/application",
            "targets": ["staging", "prod", "critical"],
            "image": "nginx:alpine",
            "reason": "Migration to DHI",
            "expires": "2026-12-31",
        }]}
        self.environment = {
            "RUNNER_TEMP": str(self.root),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "GITHUB_TOKEN": "test-github-token",
        }

    def contents(self, policy: object) -> HttpResponse:
        raw = json.dumps(policy).encode()
        return HttpResponse(200, {
            "type": "file", "path": POLICY_FILE, "encoding": "base64",
            "content": base64.encodebytes(raw).decode(),
        })

    def download(self, responses: list, **overrides: str) -> tuple[dict, list, str]:
        requests = []

        def get(url: str, headers: dict) -> HttpResponse:
            requests.append((url, headers))
            response = responses[len(requests) - 1]
            if isinstance(response, Exception):
                raise response
            return response

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = prepare_dhi_policy({**self.environment, **overrides}, http_get=get)
        return result, requests, output.getvalue()

    def assert_snapshot(self, result: dict, policy: dict, status: str) -> dict:
        self.assertEqual(json.loads(Path(result["dhi_policy"]).read_text()), policy)
        directory = Path(result["dhi_policy_dir"])
        self.assertTrue(directory.is_relative_to(self.root))
        self.assertEqual(directory.name, result["dhi_policy_id"])
        source = json.loads((directory / "source.json").read_text())
        self.assertEqual(source["status"], status)
        self.assertEqual(source["repository"], POLICY_REPOSITORY)
        self.assertEqual(source["path"], POLICY_FILE)
        return source

    def test_resolves_branch_once_and_downloads_by_immutable_sha(self) -> None:
        result, requests, output = self.download([self.branch, self.contents(self.policy)])
        self.assertEqual([url for url, _ in requests], [
            f"{POLICY_API}/git/ref/heads/main",
            f"{POLICY_API}/contents/{POLICY_FILE}?ref={self.sha}",
        ])
        self.assertEqual(result["dhi_policy_sha"], self.sha)
        self.assertEqual(self.assert_snapshot(result, self.policy, "downloaded")["commit"], self.sha)
        self.assertIn(self.sha, self.summary.read_text())
        self.assertNotIn("::warning::", output)
        self.assertNotIn("test-github-token", output)
        self.assertTrue(all(headers["Authorization"] == "Bearer test-github-token" for _, headers in requests))

    def test_caller_environment_cannot_change_trusted_source(self) -> None:
        _, requests, _ = self.download(
            [self.branch, self.contents(self.policy)],
            POLICY_REPOSITORY="attacker/policy", POLICY_BRANCH="untrusted",
            GITHUB_API_URL="https://attacker.example", DHI_POLICY="/application/policy.json",
        )
        self.assertTrue(all(url.startswith(POLICY_API + "/") for url, _ in requests))

    def test_missing_repo_auth_rate_limit_and_server_failures_grant_no_exceptions(self) -> None:
        for status in (401, 403, 404, 429, 500, 503):
            with self.subTest(status=status):
                result, requests, output = self.download([HttpResponse(status, {})])
                source = self.assert_snapshot(result, {"exceptions": []}, "empty-fallback")
                self.assertIsNone(source["commit"])
                self.assertEqual(len(requests), 1)
                self.assertIn("::warning::", output)

    def test_missing_file_keeps_resolved_sha_but_grants_no_exceptions(self) -> None:
        result, _, _ = self.download([self.branch, HttpResponse(404, {})])
        source = self.assert_snapshot(result, {"exceptions": []}, "empty-fallback")
        self.assertEqual(source["commit"], self.sha)

    def test_network_timeout_and_invalid_json_grant_no_exceptions(self) -> None:
        for error in (WorkflowError("HTTP returned invalid JSON"), OSError("offline"), TimeoutError()):
            for after_branch in (False, True):
                responses = [self.branch, error] if after_branch else [error]
                with self.subTest(error=error, after_branch=after_branch):
                    result, _, output = self.download(responses)
                    self.assert_snapshot(result, {"exceptions": []}, "empty-fallback")
                    self.assertIn("using an empty exception list", output)

    def test_invalid_branch_response_is_not_used_for_download(self) -> None:
        for payload in (
            [], {}, {"sha": self.sha},
            {"ref": "refs/heads/other", "object": {"type": "commit", "sha": self.sha}},
            {"ref": "refs/heads/main", "object": {"type": "tag", "sha": self.sha}},
            {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "main"}},
        ):
            with self.subTest(payload=payload):
                result, requests, _ = self.download([HttpResponse(200, payload)])
                self.assert_snapshot(result, {"exceptions": []}, "empty-fallback")
                self.assertEqual(len(requests), 1)

    def test_malformed_file_response_or_policy_grants_no_partial_exceptions(self) -> None:
        valid_content = self.contents(self.policy).payload
        responses = [
            HttpResponse(200, []),
            HttpResponse(200, {**valid_content, "encoding": "none"}),
            HttpResponse(200, {**valid_content, "content": "not-base64!"}),
            HttpResponse(200, {**valid_content, "content": base64.b64encode(b"invalid json").decode()}),
            HttpResponse(200, {**valid_content, "type": "symlink"}),
            HttpResponse(200, {**valid_content, "path": "other.json"}),
            self.contents({}), self.contents({"exceptions": None}),
            self.contents({"exceptions": self.policy["exceptions"] + [{}]}),
        ]
        for response in responses:
            with self.subTest(response=response):
                result, _, _ = self.download([self.branch, response])
                self.assert_snapshot(result, {"exceptions": []}, "empty-fallback")

    def test_valid_empty_policy_is_distinguishable_from_download_failure(self) -> None:
        result, _, output = self.download([self.branch, self.contents({"exceptions": []})])
        self.assert_snapshot(result, {"exceptions": []}, "downloaded")
        self.assertNotIn("::warning::", output)

    def test_missing_token_does_not_require_a_new_secret_for_public_repository(self) -> None:
        _, requests, _ = self.download([self.branch, self.contents(self.policy)], GITHUB_TOKEN="")
        self.assertTrue(all("Authorization" not in headers for _, headers in requests))

    def test_snapshots_have_unique_paths_and_artifact_ids(self) -> None:
        first, _, _ = self.download([self.branch, self.contents(self.policy)])
        second, _, _ = self.download([HttpResponse(404, {})])
        self.assertNotEqual(first["dhi_policy_id"], second["dhi_policy_id"])
        self.assert_snapshot(first, self.policy, "downloaded")
        self.assert_snapshot(second, {"exceptions": []}, "empty-fallback")

    def test_downloaded_exception_and_empty_fallback_have_expected_enforcement(self) -> None:
        dockerfile = self.root / "Dockerfile"
        for responses, allowed in (
            ([self.branch, self.contents(self.policy)], True),
            ([HttpResponse(404, {})], False),
        ):
            result, _, _ = self.download(responses)
            for target in ("dev", "staging", "prod", "critical"):
                for image in ("dhi.io/nginx:1", "nginx:alpine"):
                    dockerfile.write_text(f"FROM {image}\n")
                    environment = {
                        "TARGET": target, "GITHUB_REPOSITORY": "example/application",
                        "DOCKERFILE": str(dockerfile), "DHI_POLICY": result["dhi_policy"],
                        "BUILD_VERSION": "v1.2.3", "BUILD_BRANCH": "main", "BUILD_COMMIT": "a" * 40,
                    }
                    with self.subTest(allowed=allowed, image=image, target=target), contextlib.redirect_stdout(io.StringIO()):
                        if image.startswith("dhi.io/") or allowed or target == "dev":
                            check_dhi(environment, today=date(2026, 10, 16))
                        else:
                            with self.assertRaises(WorkflowError):
                                check_dhi(environment, today=date(2026, 10, 16))

    def test_missing_runner_temp_is_an_infrastructure_error(self) -> None:
        with self.assertRaises(WorkflowError):
            prepare_dhi_policy({})


if __name__ == "__main__":
    unittest.main()
