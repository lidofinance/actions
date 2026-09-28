from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Sequence


SEMVER_PATTERN = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+")
HARBOR_COMPONENT_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
IMAGE_PATTERN = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
)
DOCKERFILE_PATTERN = re.compile(r"[A-Za-z0-9._/-]+")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
OUTPUT_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

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


class WorkflowError(RuntimeError):
    """Expected validation failure that should fail the workflow closed."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    payload: object


HttpGetter = Callable[[str, Mapping[str, str]], HttpResponse]


def required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise WorkflowError(f"Required environment variable {name} is empty")
    return value


def git(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    allowed_returncodes: Sequence[int] = (0,),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in allowed_returncodes:
        detail = result.stderr.strip() or result.stdout.strip() or "no error output"
        raise WorkflowError(f"git {' '.join(arguments)} failed: {detail}")
    return result


def git_text(*arguments: str, cwd: Path | None = None) -> str:
    return git(arguments, cwd=cwd).stdout.strip()


def git_ref_exists(ref: str, *, cwd: Path | None = None) -> bool:
    return git(
        ["show-ref", "--verify", "--quiet", ref],
        cwd=cwd,
        allowed_returncodes=(0, 1),
    ).returncode == 0


def git_is_ancestor(ancestor: str, descendant: str, *, cwd: Path | None = None) -> bool:
    return git(
        ["merge-base", "--is-ancestor", ancestor, descendant],
        cwd=cwd,
        allowed_returncodes=(0, 1),
    ).returncode == 0


def validate_branch_name(branch: str) -> bool:
    return git(
        ["check-ref-format", "--branch", branch],
        allowed_returncodes=(0, 128),
    ).returncode == 0


def select_production_branch(*, cwd: Path | None = None) -> str:
    branches = [
        branch
        for branch in ("main", "master")
        if git_ref_exists(f"refs/remotes/origin/{branch}", cwd=cwd)
    ]
    if not branches:
        raise WorkflowError("Neither production branch main nor master exists")
    if len(branches) != 1:
        raise WorkflowError("Both production branches main and master exist; keep exactly one")
    return branches[0]


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


def default_http_get(url: str, headers: Mapping[str, str]) -> HttpResponse:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
    except urllib.error.URLError as error:
        raise WorkflowError(f"HTTP request failed: {error.reason}") from error

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkflowError(f"HTTP endpoint returned invalid JSON with status {status}") from error
    return HttpResponse(status=status, payload=payload)


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
        raise WorkflowError(f"GitHub Release {image_tag} changed after validation") from error
    return {}


def _archive_destination(root: Path, name: str) -> Path:
    pure_path = PurePosixPath(name)
    if pure_path.is_absolute() or not pure_path.parts or ".." in pure_path.parts:
        raise WorkflowError(f"Unsafe path '{name}' in Git archive")
    destination = root.joinpath(*pure_path.parts)
    if not destination.resolve(strict=False).is_relative_to(root):
        raise WorkflowError(f"Git archive path '{name}' escapes the build context")
    return destination


def _extract_git_archive(archive: Path, destination: Path) -> None:
    directories: list[tuple[Path, int]] = []
    symlinks: list[tuple[Path, str]] = []

    with tarfile.open(archive, mode="r:") as source:
        members = source.getmembers()
        for member in members:
            target = _archive_destination(destination, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                directories.append((target, member.mode))
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                file_source = source.extractfile(member)
                if file_source is None:
                    raise WorkflowError(f"Could not read '{member.name}' from Git archive")
                with file_source, target.open("wb") as file_target:
                    shutil.copyfileobj(file_source, file_target)
                target.chmod(member.mode & 0o777)
            elif member.issym():
                symlinks.append((target, member.linkname))
            else:
                raise WorkflowError(
                    f"Unsupported entry '{member.name}' in Git archive"
                )

    for target, link_name in symlinks:
        target.parent.mkdir(parents=True, exist_ok=True)
        link_target = (target.parent / link_name).resolve(strict=False)
        if not link_target.is_relative_to(destination):
            raise WorkflowError(
                f"Symbolic link '{target.relative_to(destination)}' escapes the build context"
            )
        target.symlink_to(link_name)

    for directory, mode in reversed(directories):
        directory.chmod(mode & 0o777)


def prepare_context(
    environment: Mapping[str, str], *, cwd: Path | None = None
) -> dict[str, str]:
    runner_temp_value = required(environment, "RUNNER_TEMP")
    dockerfile_value = required(environment, "DOCKERFILE")
    source_sha = required(environment, "SOURCE_SHA")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    if runner_temp == Path(runner_temp.anchor):
        raise WorkflowError("RUNNER_TEMP must not be the filesystem root")

    context = runner_temp / "docker-build-context"
    if context.exists():
        shutil.rmtree(context)
    context.mkdir(mode=0o700)

    archive_descriptor, archive_name = tempfile.mkstemp(
        prefix="docker-build-context-", suffix=".tar", dir=runner_temp
    )
    os.close(archive_descriptor)
    archive = Path(archive_name)
    try:
        with archive.open("wb") as archive_file:
            result = subprocess.run(
                ["git", "archive", "--format=tar", source_sha],
                cwd=cwd,
                stdout=archive_file,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise WorkflowError(f"git archive failed: {detail}")
        _extract_git_archive(archive, context)
    finally:
        archive.unlink(missing_ok=True)

    requested_dockerfile = context / dockerfile_value
    try:
        dockerfile = requested_dockerfile.resolve(strict=True)
    except FileNotFoundError as error:
        raise WorkflowError(
            f"Dockerfile '{dockerfile_value}' does not exist in the validated commit"
        ) from error
    if not dockerfile.is_relative_to(context):
        raise WorkflowError("Dockerfile must resolve inside the repository build context")
    if not dockerfile.is_file():
        raise WorkflowError(f"Dockerfile '{dockerfile_value}' is not a regular file")

    return {"context_dir": str(context), "dockerfile": str(dockerfile)}


def populate_build_info(environment: Mapping[str, str]) -> dict[str, str]:
    context = Path(required(environment, "BUILD_CONTEXT")).resolve(strict=True)
    build_info = context / "build-info.json"
    if build_info.is_symlink():
        raise WorkflowError("build-info.json must not be a symbolic link")
    if build_info.exists() and not build_info.is_file():
        raise WorkflowError("build-info.json must be a regular file")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".build-info.json.", dir=context
    )
    temporary_file = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(
                {
                    "version": required(environment, "BUILD_VERSION"),
                    "branch": required(environment, "BUILD_BRANCH"),
                    "commit": required(environment, "BUILD_COMMIT"),
                },
                output,
                separators=(",", ":"),
            )
            output.write("\n")
        temporary_file.chmod(0o644)
        temporary_file.replace(build_info)
    finally:
        temporary_file.unlink(missing_ok=True)
    return {}


def summarize_trivy(environment: Mapping[str, str]) -> dict[str, str]:
    report_path = Path(required(environment, "TRIVY_REPORT"))
    try:
        report = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowError("Trivy did not produce a valid vulnerability report") from error
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise WorkflowError("Trivy did not produce a valid vulnerability report")

    vulnerabilities: list[tuple[str, dict[str, object]]] = []
    for result in report["Results"]:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", ""))
        entries = result.get("Vulnerabilities")
        if not isinstance(entries, list):
            continue
        vulnerabilities.extend(
            (target, vulnerability)
            for vulnerability in entries
            if isinstance(vulnerability, dict)
        )

    severities = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    counts = {
        severity: sum(
            vulnerability.get("Severity") == severity
            for _, vulnerability in vulnerabilities
        )
        for severity in severities
    }
    summary_path = Path(required(environment, "GITHUB_STEP_SUMMARY"))
    with summary_path.open("a") as summary:
        summary.write("### Trivy vulnerability scan\n\n")
        summary.write("| Severity | Count |\n")
        summary.write("|----------|------:|\n")
        for severity in severities:
            summary.write(f"| {severity} | {counts[severity]} |\n")

    if counts["CRITICAL"] == 0:
        print("No CRITICAL vulnerabilities found")
        return {}

    print("CRITICAL vulnerabilities:")
    critical_entries = [
        (target, vulnerability)
        for target, vulnerability in vulnerabilities
        if vulnerability.get("Severity") == "CRITICAL"
    ]
    for target, vulnerability in critical_entries[:50]:
        fields = (
            target,
            vulnerability.get("VulnerabilityID", ""),
            vulnerability.get("PkgName", ""),
            vulnerability.get("InstalledVersion", ""),
            vulnerability.get("FixedVersion", ""),
        )
        print("\t".join(_single_line(str(field)) for field in fields))
    print(
        f"::warning::Trivy found {counts['CRITICAL']} CRITICAL vulnerabilities; "
        "vulnerability scanning is report-only"
    )
    return {}


def _single_line(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").replace("\t", " ")


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
    if response.status == 404 and isinstance(response.payload, dict):
        errors = response.payload.get("errors")
        if isinstance(errors, list) and any(
            isinstance(error, dict) and error.get("code") == "NAME_UNKNOWN"
            for error in errors
        ):
            print(f"No existing Harbor repository {remote_name}; skipping rollback check")
            return {}
    if response.status != 200:
        raise WorkflowError(
            f"Harbor returned HTTP {response.status} while listing tags for {remote_name}"
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
        print(f"No previous stable release tags found in {remote_name}; skipping rollback check")
    else:
        print(
            f"Release commit {source_sha} follows all stable releases already "
            f"published to {remote_name}"
        )
    return {}


def resolve_image_digest(environment: Mapping[str, str]) -> dict[str, str]:
    remote_ref = required(environment, "REMOTE_REF")
    result = subprocess.run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            remote_ref,
            "--format",
            "{{json .Manifest}}",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no error output"
        raise WorkflowError(f"Could not inspect {remote_ref} after push: {detail}")
    try:
        manifest = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise WorkflowError(f"Could not determine the digest of {remote_ref} after push") from error
    digest = manifest.get("digest") if isinstance(manifest, dict) else None
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        raise WorkflowError(f"Could not determine the digest of {remote_ref} after push")
    print(f"Published {remote_ref}@{digest}")
    return {"image_ref": remote_ref, "image_digest": digest}


COMMANDS = {
    "check-rollback": check_rollback,
    "configure": configure,
    "populate-build-info": populate_build_info,
    "prepare-context": prepare_context,
    "resolve-image-digest": resolve_image_digest,
    "revalidate-release": revalidate_release,
    "summarize-trivy": summarize_trivy,
    "validate-release": validate_published_release,
    "validate-source": validate_source,
}


def write_outputs(outputs: Mapping[str, str], output_path: Path) -> None:
    with output_path.open("a") as output_file:
        for name, value in outputs.items():
            if OUTPUT_NAME_PATTERN.fullmatch(name) is None:
                raise WorkflowError(f"Invalid workflow output name '{name}'")
            if "\n" in value or "\r" in value:
                raise WorkflowError(f"Workflow output '{name}' contains a newline")
            output_file.write(f"{name}={value}\n")


def escape_workflow_command(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
