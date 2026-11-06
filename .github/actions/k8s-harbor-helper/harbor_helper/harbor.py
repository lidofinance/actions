from __future__ import annotations

import base64
import urllib.parse
from pathlib import Path
from typing import Mapping

from harbor_helper.common import (
    HttpGetter,
    HttpResponse,
    WorkflowError,
    default_http_get,
    required,
)
from harbor_helper.config import SEMVER_PATTERN
from harbor_helper.git import git_is_ancestor, git_text


def harbor_getter(
    registry: str,
    repository: str,
    username: str,
    password: str,
    *,
    http_get: HttpGetter,
) -> HttpResponse:
    query = urllib.parse.urlencode(
        {
            "service": "harbor-registry",
            "scope": f"repository:{repository}:pull",
        }
    )
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    token_response = http_get(
        f"https://{registry}/service/token?{query}",
        {"Authorization": f"Basic {credentials}"},
    )
    if token_response.status != 200 or not isinstance(token_response.payload, dict):
        raise WorkflowError("Harbor token service returned an invalid response")
    registry_token = token_response.payload.get("token") or token_response.payload.get(
        "access_token"
    )
    if not isinstance(registry_token, str) or not registry_token:
        raise WorkflowError("Harbor token service response does not contain a token")

    repository_path = "/".join(
        urllib.parse.quote(component, safe="") for component in repository.split("/")
    )
    return http_get(
        f"https://{registry}/v2/{repository_path}/tags/list",
        {"Authorization": f"Bearer {registry_token}"},
    )


def _registry_error_codes(payload: object) -> set[str]:
    if not isinstance(payload, dict):
        return set()
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return set()
    return {
        code
        for error in errors
        if isinstance(error, dict)
        and isinstance((code := error.get("code")), str)
    }


def check_rollback(
    environment: Mapping[str, str],
    *,
    cwd: Path | None = None,
    http_get: HttpGetter = default_http_get,
) -> dict[str, str]:
    remote_name = required(environment, "REMOTE_NAME")
    registry, separator, repository = remote_name.partition("/")
    if not separator or not repository:
        raise WorkflowError(f"Invalid remote image name '{remote_name}'")

    response = harbor_getter(
        registry,
        repository,
        required(environment, "REGISTRY_USERNAME"),
        required(environment, "HARBOR_TOKEN"),
        http_get=http_get,
    )
    error_codes = _registry_error_codes(response.payload)
    if response.status == 404:
        if error_codes & {"NAME_UNKNOWN", "NOT_FOUND"}:
            print(f"No existing Harbor repository {remote_name}; skipping rollback check")
            return {}
    if response.status != 200:
        codes = ", ".join(sorted(error_codes)) or "none"
        raise WorkflowError(
            f"Harbor returned HTTP {response.status} with error codes {codes} "
            f"while listing tags for {remote_name}"
        )
    if not isinstance(response.payload, dict) or response.payload.get("name") != repository:
        raise WorkflowError(f"Harbor returned an invalid tag list for {remote_name}")
    tags = response.payload.get("tags")
    if tags is not None and not (
        isinstance(tags, list) and all(isinstance(tag, str) for tag in tags)
    ):
        raise WorkflowError(f"Harbor returned an invalid tag list for {remote_name}")

    stable_tags = [tag for tag in tags or [] if SEMVER_PATTERN.fullmatch(tag)]
    if not stable_tags:
        print(f"No stable release tags found in {remote_name}; skipping rollback check")
        return {}

    image_tag = required(environment, "IMAGE_TAG")
    source_branch = required(environment, "SOURCE_BRANCH")
    source_sha = required(environment, "SOURCE_SHA")
    checked = 0
    for release_tag in stable_tags:
        if release_tag == image_tag:
            continue
        try:
            release_sha = git_text(
                "rev-parse",
                "--verify",
                f"refs/tags/{release_tag}^{{commit}}",
                cwd=cwd,
            )
        except WorkflowError as error:
            raise WorkflowError(
                f"Harbor release {remote_name}:{release_tag} has no matching Git tag"
            ) from error
        branch_ref = f"refs/remotes/origin/{source_branch}"
        if not git_is_ancestor(release_sha, branch_ref, cwd=cwd):
            raise WorkflowError(
                f"Harbor release {remote_name}:{release_tag} points to commit "
                f"{release_sha}, which is not contained in {source_branch}"
            )
        checked += 1
        if not git_is_ancestor(release_sha, source_sha, cwd=cwd):
            raise WorkflowError(
                f"Release commit {source_sha} predates or diverges from Harbor release "
                f"{remote_name}:{release_tag} ({release_sha})"
            )

    if checked == 0:
        print(
            f"No previous stable release tags found in {remote_name}; "
            "skipping rollback check"
        )
    else:
        print(
            f"Release commit {source_sha} follows all stable releases already "
            f"published to {remote_name}"
        )
    return {}
