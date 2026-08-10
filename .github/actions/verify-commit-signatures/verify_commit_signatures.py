#!/usr/bin/env python3
"""Verify GPG signatures on pull-request commits."""

import os
import sys
import tempfile
from pathlib import Path

from config import REPOSITORIES
from src.errors import VerificationError
from src.git import resolve_commit_sha
from src.gpg import find_group_public_key_files, import_public_keys
from src.verify_commit_signatures import verify_introduced_commit_signatures


def main() -> None:
    """Read GitHub Action inputs and execute PR commit verification."""
    base_sha = resolve_commit_sha(os.environ.get("BASE_SHA", ""), "BASE_SHA")
    head_sha = resolve_commit_sha(os.environ.get("HEAD_SHA", ""), "HEAD_SHA")
    key_root = Path(__file__).with_name("trusted-gpg-keys")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository or repository.startswith("/") or repository.endswith("/") or repository.count("/") > 1:
        raise VerificationError(f"invalid GITHUB_REPOSITORY value: {repository!r}")
    policy = REPOSITORIES.get(repository) or REPOSITORIES.get(repository.rsplit("/", 1)[-1])
    if policy is None:
        raise VerificationError(f"no signer policy is configured for repository {repository!r}")

    with tempfile.TemporaryDirectory(prefix="commit-signature-verification-") as temporary:
        directory = Path(temporary)
        public_key_files = find_group_public_key_files(key_root, policy.signers)
        gpg_env, allowed_primary_keys = import_public_keys(public_key_files, directory / "gnupg")
        verify_introduced_commit_signatures(base_sha, head_sha, gpg_env, allowed_primary_keys, policy.dry)


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1)
