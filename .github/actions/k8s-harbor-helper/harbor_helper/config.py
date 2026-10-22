from __future__ import annotations

import re
from typing import Mapping

from harbor_helper.common import WorkflowError, required
from harbor_helper.git import validate_branch_name


SEMVER_PATTERN = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+")
HARBOR_COMPONENT_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
IMAGE_PATTERN = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
)
DOCKERFILE_PATTERN = re.compile(r"[A-Za-z0-9._/-]+")

TARGETS = {
    "dev": {
        "registry": "registry.dev.k8s-dev.org",
        "github_environment": "harbor_dev_release",
        "image_tag": "dev",
        "is_release": False,
    },
    "staging": {
        "registry": "registry.staging.k8s-staging.org",
        "github_environment": "harbor_stage_release",
        "image_tag": "staging",
        "is_release": False,
    },
    "prod": {
        "registry": "registry.prod.k8s-prod.org",
        "github_environment": "harbor_prod_release",
        "is_release": True,
    },
    "critical": {
        "registry": "registry.critical.k8s-prod.org",
        "github_environment": "harbor_crit_release",
        "is_release": True,
    },
}


def configure(environment: Mapping[str, str]) -> dict[str, str]:
    target = required(environment, "TARGET")
    if target not in TARGETS:
        raise WorkflowError(
            f"Unknown target '{target}'. Expected dev, staging, prod, or critical"
        )

    harbor_project = required(environment, "HARBOR_PROJECT")
    image = required(environment, "IMAGE")
    dockerfile = environment.get("DOCKERFILE", "")
    tag = environment.get("TAG", "")
    ref_name = environment.get("REF_NAME", "")
    ref_type = environment.get("REF_TYPE", "")

    if HARBOR_COMPONENT_PATTERN.fullmatch(harbor_project) is None:
        raise WorkflowError(f"Invalid Harbor project '{harbor_project}'")
    if IMAGE_PATTERN.fullmatch(image) is None:
        raise WorkflowError(f"Invalid image name '{image}'")
    if (
        not dockerfile
        or dockerfile.startswith("/")
        or DOCKERFILE_PATTERN.fullmatch(dockerfile) is None
    ):
        raise WorkflowError(
            "Dockerfile must be a relative repository path using letters, numbers, "
            "'.', '_', '-', and '/'"
        )

    config = TARGETS[target]
    is_release = bool(config["is_release"])

    if is_release:
        event_name = environment.get("GITHUB_EVENT_NAME", "")
        upstream_event = environment.get("UPSTREAM_EVENT", "")
        upstream_conclusion = environment.get("UPSTREAM_CONCLUSION", "")
        upstream_path = environment.get("UPSTREAM_PATH", "").split("@", 1)[0]
        upstream_repository = environment.get("UPSTREAM_REPOSITORY", "")
        repository = required(environment, "GITHUB_REPOSITORY")
        default_branch = environment.get("DEFAULT_BRANCH", "")

        if event_name != "workflow_run":
            raise WorkflowError(f"{target} builds must be started by a workflow_run")
        if upstream_event != "release" or upstream_conclusion != "success":
            raise WorkflowError(
                f"{target} builds require a successful upstream workflow triggered "
                "by a release event"
            )
        if upstream_path != ".github/workflows/run_on_release.yaml":
            raise WorkflowError(
                f"Unexpected upstream workflow '{environment.get('UPSTREAM_PATH', '')}'"
            )
        if upstream_repository != repository:
            raise WorkflowError(
                f"Upstream workflow belongs to unexpected repository '{upstream_repository}'"
            )
        if SEMVER_PATTERN.fullmatch(tag) is None:
            raise WorkflowError(
                f"{target} requires a stable release tag such as v1.2.3 or 1.2.3"
            )
        if not default_branch or not validate_branch_name(default_branch):
            raise WorkflowError(
                f"Repository default branch '{default_branch}' is invalid"
            )
        if ref_type != "branch" or ref_name != default_branch:
            raise WorkflowError(
                f"{target} builds must run from the repository default branch "
                f"'{default_branch}' through workflow_run"
            )

        image_tag = tag
        requested_source_branch = ""
        source_ref = tag
    else:
        if tag:
            raise WorkflowError(f"The tag input cannot be used for {target}")
        if ref_type != "branch":
            raise WorkflowError(f"{target} builds must run from a branch")
        if not validate_branch_name(ref_name):
            raise WorkflowError(f"Invalid source branch '{ref_name}'")

        image_tag = str(config["image_tag"])
        requested_source_branch = ref_name
        source_ref = required(environment, "GITHUB_SHA")

    registry = str(config["registry"])
    return {
        "github_environment": str(config["github_environment"]),
        "image_tag": image_tag,
        "is_release": str(is_release).lower(),
        "remote_name": f"{registry}/{harbor_project}/{image}",
        "requested_source_branch": requested_source_branch,
        "source_ref": source_ref,
    }
