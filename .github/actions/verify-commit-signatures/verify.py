#!/usr/bin/env python3
"""Verify pull-request commits using repository-authorized GPG keys.

The trusted-key configuration and public keys live beside this script in the
pinned action revision. Pull requests therefore cannot add a key or change
their repository's allowed signer groups.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


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
class RepositoryPolicy:
    signers: tuple[str, ...]
    dry: bool


def run(*args: str, env: dict[str, str] | None = None,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command and include useful output when it fails."""
    try:
        completed = subprocess.run(
            args,
            text=True,
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


def git(*args: str, check: bool = True) -> str:
    return run("git", *args, check=check).stdout


def require_sha(value: str, name: str) -> str:
    if not value:
        raise VerificationError(f"{name} is required")
    return git("rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}").strip()


def config_scalar(value: str) -> str:
    """Parse the restricted scalar form accepted by the signer config."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_repository_policies(config_path: Path) -> dict[str, RepositoryPolicy]:
    """Read the small, deliberately strict YAML subset used for signer policy.

    The GitHub runner does not guarantee PyYAML, so this avoids a runtime
    dependency. The supported schema is documented in the action README:
    top-level repository names, ``signers`` as an inline or block list, and an
    optional boolean ``dry`` value (which defaults to true).
    """
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise VerificationError(f"cannot read signer configuration {config_path}: {error}") from error

    raw: dict[str, dict[str, object]] = {}
    current_repository: str | None = None
    collecting_signers = False
    for line_number, raw_line in enumerate(lines, start=1):
        if "\t" in raw_line:
            raise VerificationError(f"{config_path}:{line_number}: tabs are not supported")
        line = raw_line.split("#", 1)[0].rstrip()
        if not line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        if indent == 0:
            if not text.endswith(":") or text == ":":
                raise VerificationError(f"{config_path}:{line_number}: expected a repository name followed by ':'")
            repository = config_scalar(text[:-1])
            if not repository or repository in raw:
                raise VerificationError(f"{config_path}:{line_number}: invalid or duplicate repository {repository!r}")
            raw[repository] = {"signers": None}
            current_repository = repository
            collecting_signers = False
            continue
        if current_repository is None:
            raise VerificationError(f"{config_path}:{line_number}: repository entry is required before settings")
        if indent == 4 and collecting_signers and text.startswith("- "):
            signers = raw[current_repository]["signers"]
            assert isinstance(signers, list)
            signer = config_scalar(text[2:])
            if not signer:
                raise VerificationError(f"{config_path}:{line_number}: signer name cannot be empty")
            signers.append(signer)
            continue
        if indent != 2 or ":" not in text:
            raise VerificationError(f"{config_path}:{line_number}: unsupported YAML structure")
        setting, value = (part.strip() for part in text.split(":", 1))
        collecting_signers = False
        if setting == "signers":
            if raw[current_repository]["signers"] is not None:
                raise VerificationError(f"{config_path}:{line_number}: duplicate signers setting")
            if not value:
                raw[current_repository]["signers"] = []
                collecting_signers = True
            elif value.startswith("[") and value.endswith("]"):
                raw[current_repository]["signers"] = [
                    config_scalar(item) for item in value[1:-1].split(",") if item.strip()
                ]
            else:
                raise VerificationError(f"{config_path}:{line_number}: signers must be a YAML list")
        elif setting == "dry":
            if "dry" in raw[current_repository] or value.lower() not in ("true", "false"):
                raise VerificationError(f"{config_path}:{line_number}: dry must be true or false")
            raw[current_repository]["dry"] = value.lower() == "true"
        else:
            raise VerificationError(f"{config_path}:{line_number}: unsupported setting {setting!r}")

    policies: dict[str, RepositoryPolicy] = {}
    for repository, policy in raw.items():
        signers = policy["signers"]
        dry = policy.get("dry", True)
        if not isinstance(signers, list) or not signers or not isinstance(dry, bool):
            raise VerificationError(f"{config_path}: {repository!r} requires non-empty signers")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", signer) for signer in signers):
            raise VerificationError(f"{config_path}: {repository!r} has an unsafe signer group name")
        if len(signers) != len(set(signers)):
            raise VerificationError(f"{config_path}: {repository!r} repeats a signer group")
        policies[repository] = RepositoryPolicy(signers=tuple(signers), dry=dry)
    return policies


def repository_policy(repository: str, key_root: Path) -> RepositoryPolicy:
    if not repository or repository.startswith("/") or repository.endswith("/") or repository.count("/") > 1:
        raise VerificationError(f"invalid GITHUB_REPOSITORY value: {repository!r}")
    policies = parse_repository_policies(key_root / "config.yaml")
    # Prefer owner/repository entries when an organization needs to distinguish
    # identically named repositories. The short repository name matches the
    # common configuration form (for example, "landing:").
    policy = policies.get(repository) or policies.get(repository.rsplit("/", 1)[-1])
    if policy is None:
        raise VerificationError(f"no signer policy is configured for repository {repository!r}")
    return policy


def load_group_key_files(key_root: Path, groups: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for group in groups:
        group_directory = key_root / group
        if not group_directory.is_dir():
            raise VerificationError(f"configured signer group {group!r} has no public-key directory")
        for source in sorted(group_directory.rglob("*.asc")):
            if not source.is_file():
                continue
            files.append(source)
    if not files:
        raise VerificationError("the configured signer groups contain no ASCII-armored public keys")
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


def verify_signature(commit: str, gpg_env: dict[str, str], allowed_primary_keys: set[str]) -> str:
    result = run(
        "git", "verify-commit", "--raw", commit,
        env=gpg_env,
        check=False,
    )
    status = result.stdout + result.stderr
    if result.returncode or any(f"[GNUPG:] {code}" in status for code in BAD_GPG_STATUSES):
        raise VerificationError(f"{commit}: invalid, expired, revoked, or unverifiable GPG signature")

    matches = re.findall(r"^\[GNUPG:\] VALIDSIG [0-9A-F]+ .* ([0-9A-F]+)$", status, re.MULTILINE)
    if len(matches) != 1:
        raise VerificationError(f"{commit}: GPG did not report exactly one valid signature")
    primary = matches[0]
    if primary not in allowed_primary_keys:
        raise VerificationError(f"{commit}: signed by untrusted primary key {primary}")
    return primary


def verify_pr_commits(base_sha: str, head_sha: str, gpg_env: dict[str, str],
                      allowed_primary_keys: set[str], dry: bool) -> None:
    merge_base = run("git", "merge-base", base_sha, head_sha, check=False)
    if merge_base.returncode:
        raise VerificationError(f"base {base_sha} and head {head_sha} have no merge base")
    commits = git("rev-list", "--topo-order", f"{merge_base.stdout.strip()}..{head_sha}").splitlines()
    if not commits:
        print("No commits introduced by this range.")
        return

    errors: list[str] = []
    for commit in commits:
        try:
            primary_fingerprint = verify_signature(commit, gpg_env, allowed_primary_keys)
        except VerificationError as error:
            errors.append(str(error))
            continue
        print(f"verified {commit}  {primary_fingerprint}")

    if errors:
        for error in errors:
            print(f"::warning::{error}" if dry else f"::error::{error}", file=sys.stderr)
        if not dry:
            raise VerificationError(f"{len(errors)} of {len(commits)} PR commit(s) violate the signer policy")
        print(f"Dry run: {len(errors)} of {len(commits)} PR commit(s) violate the signer policy.")
        return
    print(f"Verified {len(commits)} PR commit(s).")


def main() -> None:
    base_sha = require_sha(os.environ.get("BASE_SHA", ""), "BASE_SHA")
    head_sha = require_sha(os.environ.get("HEAD_SHA", ""), "HEAD_SHA")
    key_root = Path(__file__).with_name("trusted-gpg-keys")
    policy = repository_policy(os.environ.get("GITHUB_REPOSITORY", ""), key_root)

    with tempfile.TemporaryDirectory(prefix="commit-signature-verification-") as temporary:
        directory = Path(temporary)
        key_files = load_group_key_files(key_root, policy.signers)
        gpg_env, allowed_primary_keys = import_keys(key_files, directory / "gnupg")
        verify_pr_commits(base_sha, head_sha, gpg_env, allowed_primary_keys, policy.dry)


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
