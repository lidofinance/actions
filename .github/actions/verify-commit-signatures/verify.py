#!/usr/bin/env python3
"""Verify introduced Git commits using trusted GPG keys and seal commits.

The key files are loaded with ``git show <base>:<path>``. This is deliberate:
pull requests must not be able to make a newly added public key trusted by
changing the checked-out copy of the key list.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


SEAL_TRAILER = "Argocd-gpg-seal"
COMMAND_TIMEOUT_SECONDS = 300
BAD_GPG_STATUSES = (
    "BADSIG",
    "ERRSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "NO_PUBKEY",
    "NODATA",
)


class VerificationError(RuntimeError):
    """An error that should fail the workflow without a Python traceback."""


@dataclass(frozen=True)
class Signature:
    signer_fingerprint: str
    primary_fingerprint: str


def run(*args: str, input_data: str | bytes | None = None, env: dict[str, str] | None = None,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command and include useful output when it fails."""
    try:
        completed = subprocess.run(
            args,
            input=input_data,
            text=isinstance(input_data, str) or input_data is None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise VerificationError(
            f"{' '.join(args)} timed out after {COMMAND_TIMEOUT_SECONDS} seconds"
        ) from error
    except OSError as error:
        raise VerificationError(f"cannot run {args[0]}: {error}") from error
    if check and completed.returncode:
        output = (completed.stdout + completed.stderr).strip()
        raise VerificationError(f"{' '.join(args)} failed{': ' + output if output else ''}")
    return completed


def git(*args: str, input_data: str | None = None, check: bool = True) -> str:
    return run("git", *args, input_data=input_data, check=check).stdout


def require_sha(value: str, name: str) -> str:
    if not value:
        raise VerificationError(f"{name} is required")
    return git("rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}").strip()


def key_paths(value: str) -> list[str]:
    paths = [line.strip() for line in value.splitlines() if line.strip()]
    for path in paths:
        # These paths are used in the <revision>:<path> syntax accepted by Git.
        # Reject revision syntax and traversal rather than trying to quote it.
        if path.startswith(("/", "-")) or ":" in path or ".." in Path(path).parts:
            raise VerificationError(f"unsafe public-key path: {path!r}")
    return paths


def load_key_files(base_sha: str, paths: list[str], directory: Path) -> list[Path]:
    files: list[Path] = []
    for index, path in enumerate(paths):
        result = run("git", "show", f"{base_sha}:{path}", check=False)
        if result.returncode:
            raise VerificationError(
                f"cannot read trusted GPG public-key file {path!r} from base commit {base_sha}"
            )
        target = directory / f"key-{index}.asc"
        target.write_text(result.stdout, encoding="utf-8")
        files.append(target)
    return files


def load_shared_key_files(shared_directory: Path, directory: Path) -> list[Path]:
    """Load public keys bundled with this immutable verifier implementation."""
    if not shared_directory.is_dir():
        raise VerificationError(f"shared GPG key directory does not exist: {shared_directory}")

    files: list[Path] = []
    for index, source in enumerate(sorted(shared_directory.glob("*.asc"))):
        if not source.is_file():
            continue
        target = directory / f"shared-key-{index}.asc"
        target.write_bytes(source.read_bytes())
        files.append(target)
    return files


def imported_primary_fingerprints(gpg_env: dict[str, str]) -> set[str]:
    output = run(
        "gpg", "--batch", "--no-options", "--with-colons", "--list-keys", env=gpg_env
    ).stdout
    fingerprints: set[str] = set()
    awaiting_fingerprint = False
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            awaiting_fingerprint = True
        elif fields[0] == "fpr" and awaiting_fingerprint:
            fingerprints.add(fields[9].upper())
            awaiting_fingerprint = False
    return fingerprints


def import_keys(files: list[Path], gpg_home: Path) -> tuple[dict[str, str], set[str]]:
    gpg_home.mkdir(mode=0o700)
    gpg_env = os.environ.copy()
    gpg_env["GNUPGHOME"] = str(gpg_home)
    for key_file in files:
        # Public-key import and verification do not need a private-key agent.
        # Do not read configuration or retrieve/import keys beyond the key files
        # explicitly selected by the caller's trusted base commit.
        result = run(
            "gpg", "--batch", "--no-tty", "--no-options", "--no-autostart",
            "--no-auto-key-retrieve", "--no-auto-key-import", "--import", str(key_file),
            env=gpg_env,
            check=False,
        )
        if result.returncode:
            raise VerificationError(f"cannot import GPG public key {key_file.name}: {result.stderr.strip()}")
    fingerprints = imported_primary_fingerprints(gpg_env)
    if not fingerprints:
        raise VerificationError("none of the configured public-key files contains a primary GPG key")
    return gpg_env, fingerprints


def gpg_verification_wrapper(gpg: str, directory: Path) -> Path:
    """Create a trusted GPG program for Git's verification invocation."""
    wrapper = directory / "gpg-verify"
    wrapper.write_text(
        "#!/bin/sh\n"
        f"exec {shlex.quote(gpg)} --batch --no-tty --no-options --no-auto-key-retrieve "
        "--no-auto-key-import \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    return wrapper


def verify_signature(commit: str, gpg_env: dict[str, str], allowed_primary_keys: set[str],
                     gpg_wrapper: Path) -> Signature:
    result = run(
        "git", "-c", f"gpg.program={gpg_wrapper}", "verify-commit", "--raw", commit,
        env=gpg_env,
        check=False,
    )
    status = result.stdout + result.stderr
    if result.returncode or any(f"[GNUPG:] {code}" in status for code in BAD_GPG_STATUSES):
        raise VerificationError(f"{commit}: invalid, expired, revoked, or unverifiable GPG signature")

    matches = re.findall(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+) .* ([0-9A-F]+)$", status, re.MULTILINE)
    if len(matches) != 1:
        raise VerificationError(f"{commit}: GPG did not report exactly one valid signature")
    signer, primary = matches[0]
    if primary not in allowed_primary_keys:
        raise VerificationError(f"{commit}: signed by untrusted primary key {primary}")
    return Signature(signer_fingerprint=signer, primary_fingerprint=primary)


def seal_values(message: str) -> list[str]:
    """Return Argo CD seal trailer values, rejecting look-alike trailer text."""
    parsed = git("interpret-trailers", "--parse", input_data=message)
    values = [
        match.group(1).strip()
        for line in parsed.splitlines()
        if (match := re.fullmatch(rf"{SEAL_TRAILER}:\s*(.*)", line, re.IGNORECASE))
    ]
    # ``interpret-trailers`` recognizes only trailers at the end of a commit
    # message.  If a commit appears to declare a seal elsewhere, or with an
    # unsupported separator, fail rather than treating it as an ordinary
    # signed commit.
    raw_markers = re.findall(
        rf"^{SEAL_TRAILER}(?:\s*[:=]|\s*$)", message, re.IGNORECASE | re.MULTILINE
    )
    if raw_markers and (len(values) != 1 or not values[0]):
        raise VerificationError(
            f"a {SEAL_TRAILER} trailer must be a single non-empty terminal Git trailer"
        )
    if len(values) > 1:
        raise VerificationError(f"a seal commit must have exactly one {SEAL_TRAILER} trailer")
    return values


def require_empty_single_parent_seal(commit: str) -> None:
    parents = git("show", "-s", "--format=%P", commit).split()
    if len(parents) != 1:
        raise VerificationError(f"{commit}: seal commits must have exactly one parent")
    tree = git("show", "-s", "--format=%T", commit).strip()
    parent_tree = git("show", "-s", "--format=%T", parents[0]).strip()
    if tree != parent_tree:
        raise VerificationError(f"{commit}: seal commits must be empty (their tree must equal their parent tree)")


def verify_history(base_sha: str, head_sha: str, gpg_env: dict[str, str], allowed_primary_keys: set[str],
                   gpg_wrapper: Path) -> None:
    ancestry = run("git", "merge-base", "--is-ancestor", base_sha, head_sha, check=False)
    if ancestry.returncode == 1:
        raise VerificationError(f"base {base_sha} is not an ancestor of head {head_sha}")
    if ancestry.returncode:
        raise VerificationError(f"cannot determine whether base {base_sha} is an ancestor of head {head_sha}")

    introduced = set(git("rev-list", "--topo-order", f"{base_sha}..{head_sha}").splitlines())
    if not introduced:
        print("No commits introduced by this range.")
        return

    pending = [head_sha]
    visited: set[str] = set()
    sealed = 0
    while pending:
        commit = pending.pop()
        if commit in visited or commit not in introduced:
            continue
        visited.add(commit)
        message = git("show", "-s", "--format=%B", commit)
        is_seal = bool(seal_values(message))
        signature = verify_signature(commit, gpg_env, allowed_primary_keys, gpg_wrapper)
        if is_seal:
            require_empty_single_parent_seal(commit)
            sealed += 1
            print(f"sealed  {commit}  {signature.primary_fingerprint}")
            # A signed seal approves its complete parent graph. Do not traverse it.
            continue

        print(f"verified {commit}  {signature.primary_fingerprint}")
        pending.extend(git("show", "-s", "--format=%P", commit).split())

    print(f"Verified {len(visited)} introduced commit(s); encountered {sealed} seal(s).")


def main() -> None:
    base_sha = require_sha(os.environ.get("BASE_SHA", ""), "BASE_SHA")
    head_sha = require_sha(os.environ.get("HEAD_SHA", ""), "HEAD_SHA")
    paths = key_paths(os.environ.get("ADDITIONAL_GPG_PUBKEYS", ""))

    with tempfile.TemporaryDirectory(prefix="commit-signature-verification-") as temporary:
        directory = Path(temporary)
        key_files = load_shared_key_files(Path(__file__).with_name("trusted-gpg-keys"), directory)
        key_files.extend(load_key_files(base_sha, paths, directory))
        if not key_files:
            raise VerificationError("no shared or caller-provided GPG public-key files are configured")
        gpg_env, allowed_primary_keys = import_keys(key_files, directory / "gnupg")
        gpg = shutil.which("gpg")
        if not gpg:
            raise VerificationError("gpg is not installed")
        wrapper = gpg_verification_wrapper(gpg, directory)
        verify_history(base_sha, head_sha, gpg_env, allowed_primary_keys, wrapper)


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
