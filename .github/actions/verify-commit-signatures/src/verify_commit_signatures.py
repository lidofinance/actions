"""Verify GPG signatures on pull-request commits."""

from __future__ import annotations

import sys

from .commands import run_command
from .errors import VerificationError
from .git import get_git_output
from .gpg import extract_valid_signature_primary_fingerprint, import_public_keys


def verify_commit_signature(commit: str, gpg_env: dict[str, str], allowed_primary_keys: set[str]) -> str:
    """Verify one commit and return the signature's primary-key fingerprint."""
    result = run_command("git", "verify-commit", "--raw", commit, env=gpg_env, check=False)
    status = result.stdout + result.stderr
    if result.returncode:
        raise VerificationError(f"{commit}: invalid, expired, revoked, or unverifiable GPG signature")
    try:
        primary = extract_valid_signature_primary_fingerprint(status)
    except VerificationError as error:
        raise VerificationError(f"{commit}: {error}") from error
    if primary not in allowed_primary_keys:
        raise VerificationError(f"{commit}: signed by untrusted primary key {primary}")
    return primary


def verify_introduced_commit_signatures(base_sha: str, head_sha: str, gpg_env: dict[str, str],
                                        allowed_primary_keys: set[str], dry: bool) -> None:
    """Verify only commits introduced between the PR merge base and its head."""
    merge_base = run_command("git", "merge-base", base_sha, head_sha, check=False)
    if merge_base.returncode:
        raise VerificationError(f"base {base_sha} and head {head_sha} have no merge base")
    commits = get_git_output("rev-list", "--topo-order", f"{merge_base.stdout.strip()}..{head_sha}").splitlines()
    if not commits:
        print("No commits introduced by this range.")
        return

    errors: list[str] = []
    for commit in commits:
        try:
            primary_fingerprint = verify_commit_signature(commit, gpg_env, allowed_primary_keys)
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
