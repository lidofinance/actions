from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Mapping

from harbor_helper.common import WorkflowError, required


DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


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
        raise WorkflowError(
            f"Could not determine the digest of {remote_ref} after push"
        ) from error
    digest = manifest.get("digest") if isinstance(manifest, dict) else None
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        raise WorkflowError(f"Could not determine the digest of {remote_ref} after push")
    print(f"Published {remote_ref}@{digest}")
    return {"image_ref": remote_ref, "image_digest": digest}
