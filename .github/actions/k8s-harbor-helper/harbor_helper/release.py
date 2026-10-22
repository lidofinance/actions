from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Mapping

from harbor_helper.common import (
    HttpGetter,
    WorkflowError,
    default_http_get,
    required,
)
from harbor_helper.git import (
    git_is_ancestor,
    git_ref_exists,
    git_text,
    select_production_branch,
)


def validate_source(
    environment: Mapping[str, str], *, cwd: Path | None = None
) -> dict[str, str]:
    image_tag = required(environment, "IMAGE_TAG")
    is_release_value = required(environment, "IS_RELEASE")
    if is_release_value not in {"true", "false"}:
        raise WorkflowError("IS_RELEASE must be either 'true' or 'false'")
    is_release = is_release_value == "true"
    requested_source_branch = environment.get("REQUESTED_SOURCE_BRANCH", "")
    upstream_sha = environment.get("UPSTREAM_SHA", "")
    source_sha = git_text("rev-parse", "--verify", "HEAD^{commit}", cwd=cwd)

    if is_release and upstream_sha != source_sha:
        raise WorkflowError(
            f"Release tag commit {source_sha} does not match upstream workflow_run "
            f"commit {upstream_sha}"
        )

    source_branch = (
        select_production_branch(cwd=cwd) if is_release else requested_source_branch
    )
    branch_ref = f"refs/remotes/origin/{source_branch}"
    if not git_ref_exists(branch_ref, cwd=cwd):
        raise WorkflowError(f"Branch {source_branch} does not exist")
    if not git_is_ancestor(source_sha, branch_ref, cwd=cwd):
        raise WorkflowError(
            f"Commit {source_sha} is not contained in branch {source_branch}"
        )

    if is_release:
        tag_sha = git_text(
            "rev-parse", "--verify", f"refs/tags/{image_tag}^{{commit}}", cwd=cwd
        )
        if tag_sha != source_sha:
            raise WorkflowError(
                f"Checked out commit {source_sha} does not match tag {image_tag} ({tag_sha})"
            )

    return {"source_branch": source_branch, "source_sha": source_sha}


def github_release(
    repository: str,
    tag: str,
    token: str,
    *,
    api_url: str = "https://api.github.com",
    http_get: HttpGetter = default_http_get,
) -> object:
    repository_path = urllib.parse.quote(repository, safe="/")
    tag_path = urllib.parse.quote(tag, safe="")
    url = f"{api_url.rstrip('/')}/repos/{repository_path}/releases/tags/{tag_path}"
    response = http_get(
        url,
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if response.status != 200:
        raise WorkflowError(f"Published GitHub Release {tag} was not found")
    return response.payload


def validate_release_payload(payload: object, tag: str) -> None:
    if not isinstance(payload, dict):
        raise WorkflowError(f"{tag} must be an existing published stable GitHub Release")
    if not (
        payload.get("tag_name") == tag
        and payload.get("draft") is False
        and payload.get("prerelease") is False
        and payload.get("published_at") is not None
    ):
        raise WorkflowError(f"{tag} must be an existing published stable GitHub Release")


def validate_published_release(
    environment: Mapping[str, str], *, http_get: HttpGetter = default_http_get
) -> dict[str, str]:
    repository = required(environment, "GITHUB_REPOSITORY")
    tag = required(environment, "IMAGE_TAG")
    token = required(environment, "GITHUB_TOKEN")
    payload = github_release(
        repository,
        tag,
        token,
        api_url=environment.get("GITHUB_API_URL", "https://api.github.com"),
        http_get=http_get,
    )
    validate_release_payload(payload, tag)
    return {}


def revalidate_release(
    environment: Mapping[str, str],
    *,
    cwd: Path | None = None,
    http_get: HttpGetter = default_http_get,
) -> dict[str, str]:
    source_branch = required(environment, "SOURCE_BRANCH")
    source_sha = required(environment, "SOURCE_SHA")
    image_tag = required(environment, "IMAGE_TAG")

    current_branch = select_production_branch(cwd=cwd)
    if current_branch != source_branch:
        raise WorkflowError(
            f"Production branch changed from {source_branch} to {current_branch} after validation"
        )
    branch_ref = f"refs/remotes/origin/{source_branch}"
    if not git_is_ancestor(source_sha, branch_ref, cwd=cwd):
        raise WorkflowError(
            f"Release commit {source_sha} is no longer contained in branch {source_branch}"
        )

    tag_sha = git_text(
        "rev-parse", "--verify", f"refs/tags/{image_tag}^{{commit}}", cwd=cwd
    )
    if tag_sha != source_sha:
        raise WorkflowError(f"Tag {image_tag} changed after validation")

    try:
        validate_published_release(environment, http_get=http_get)
    except WorkflowError as error:
        raise WorkflowError(
            f"GitHub Release {image_tag} changed after validation"
        ) from error
    return {}
