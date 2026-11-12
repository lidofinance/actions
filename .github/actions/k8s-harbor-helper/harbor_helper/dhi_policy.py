"""Download a trusted DHI exception snapshot; failures grant no exceptions."""

from __future__ import annotations

import base64
import binascii
import json
import re
import tempfile
from pathlib import Path
from typing import Mapping

from harbor_helper.common import (
    HttpGetter, WorkflowError, default_http_get, escape_workflow_command, required,
)
from harbor_helper.dockerfile import validate_exceptions


# Policy updates intentionally do not require a helper release. Protect this
# branch with mandatory security review; application callers cannot change it.
POLICY_REPOSITORY = "lidofinance/vex-db"
POLICY_BRANCH = "main"
POLICY_FILE = "policy/dhi-exceptions.json"
POLICY_API = f"https://api.github.com/repos/{POLICY_REPOSITORY}"


def prepare_dhi_policy(
    environment: Mapping[str, str], *, http_get: HttpGetter = default_http_get,
) -> dict[str, str]:
    runner_temp = Path(required(environment, "RUNNER_TEMP")).resolve(strict=True)
    snapshot = Path(tempfile.mkdtemp(prefix="dhi-policy-", dir=runner_temp))
    policy = {"exceptions": []}
    sha = ""
    status = "empty-fallback"
    failure = ""
    stage = "branch lookup"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = environment.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = http_get(f"{POLICY_API}/git/ref/heads/{POLICY_BRANCH}", headers)
        if response.status != 200:
            failure = f"{stage}: HTTP {response.status}"
            raise WorkflowError(failure)
        ref = response.payload
        commit = ref.get("object") if isinstance(ref, dict) else None
        if (
            not isinstance(ref, dict)
            or ref.get("ref") != f"refs/heads/{POLICY_BRANCH}"
            or not isinstance(commit, dict)
            or commit.get("type") != "commit"
            or not isinstance(commit.get("sha"), str)
            or re.fullmatch(r"[0-9a-f]{40}", commit["sha"]) is None
        ):
            raise WorkflowError("invalid policy branch response")
        sha = commit["sha"]
        stage = "file download"
        response = http_get(f"{POLICY_API}/contents/{POLICY_FILE}?ref={sha}", headers)
        if response.status != 200:
            failure = f"{stage}: HTTP {response.status}"
            raise WorkflowError(failure)
        content = response.payload
        if (
            not isinstance(content, dict)
            or content.get("type") != "file"
            or content.get("path") != POLICY_FILE
            or content.get("encoding") != "base64"
            or not isinstance(content.get("content"), str)
        ):
            raise WorkflowError("invalid policy file response")
        raw = base64.b64decode("".join(content["content"].split()), validate=True)
        stage = "policy validation"
        downloaded = json.loads(raw)
        exceptions = validate_exceptions(downloaded)
        # Do not retain a partially validated document on any error.
        policy = {"exceptions": exceptions}
        status = "downloaded"
    except (WorkflowError, OSError, ValueError, binascii.Error) as error:
        # Never include arbitrary remote content or credentials in annotations.
        failure = failure or f"{stage}: {type(error).__name__}"
        print(
            "::warning::DHI exceptions could not be loaded from "
            f"{POLICY_REPOSITORY}@{POLICY_BRANCH} ({escape_workflow_command(failure)}); "
            "using an empty exception list. DHI validation remains enabled."
        )

    policy_path = snapshot / "dhi-exceptions.json"
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")
    source = {
        "repository": POLICY_REPOSITORY,
        "branch": POLICY_BRANCH,
        "path": POLICY_FILE,
        "commit": sha or None,
        "status": status,
        "failure": failure or None,
    }
    (snapshot / "source.json").write_text(json.dumps(source, indent=2) + "\n")
    print(f"DHI exceptions: {POLICY_REPOSITORY}@{sha or 'unresolved'}; {status}")
    summary_path = environment.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a") as summary:
            summary.write(
                "\n### DHI exception source\n\n"
                f"Repository: `{POLICY_REPOSITORY}`. Branch: `{POLICY_BRANCH}`.\n\n"
                f"Commit: `{sha or 'unresolved'}`. Status: `{status}`. "
                f"Loaded exceptions: {len(policy['exceptions'])}.\n"
            )
    return {
        "dhi_policy": str(policy_path),
        "dhi_policy_dir": str(snapshot),
        "dhi_policy_id": snapshot.name,
        "dhi_policy_sha": sha,
    }
