#!/usr/bin/env python3
"""Verify GPG signatures on pull-request commits."""

import os
import re
import sys
import tempfile
from pathlib import Path

from config import GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS, REPOSITORIES
from src.commands import VerificationError, run_command


BAD_GPG_STATUSES = (
    "BADSIG",
    "ERRSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "NO_PUBKEY",
    "NODATA",
)


def import_public_keys(files: list[Path], gpg_env: dict[str, str]) -> set[str]:
    """Import selected public-key files and return all primary fingerprints."""
    for key_file in files:
        result = run_command(
            "gpg", "--batch", "--no-tty", "--no-options", "--no-autostart",
            "--no-auto-key-retrieve", "--no-auto-key-import", "--import", str(key_file),
            env=gpg_env,
            check=False,
        )
        if result.returncode:
            raise VerificationError(
                f"cannot import GPG public key {key_file.name}: {result.stderr.strip()}"
            )

    output = run_command(
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
    if not fingerprints:
        raise VerificationError(
            "none of the configured public-key files contains a primary GPG key"
        )
    return fingerprints


def verify_commit_signature(
    commit: str,
    gpg_env: dict[str, str],
    allowed_primary_keys: set[str],
) -> str:
    """Verify one commit and return the signature's primary-key fingerprint."""
    result = run_command("git", "verify-commit", "--raw", commit, env=gpg_env, check=False)
    status = result.stdout + result.stderr
    if result.returncode or any(f"[GNUPG:] {code}" in status for code in BAD_GPG_STATUSES):
        raise VerificationError(
            f"{commit}: invalid, expired, revoked, or unverifiable GPG signature"
        )

    matches = re.findall(
        r"^\[GNUPG:\] VALIDSIG [0-9A-F]+ .* ([0-9A-F]+)$",
        status,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise VerificationError(f"{commit}: GPG did not report exactly one valid signature")
    primary = matches[0]

    if primary in GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS:
        parents = run_command("git", "show", "-s", "--format=%P", commit).stdout.split()
        if len(parents) != 2:
            raise VerificationError(f"{commit}: GitHub-signed commit is not a two-parent merge")
        expected = run_command(
            "git", "merge-tree", "--write-tree", "--no-messages", *parents, check=False
        )
        if expected.returncode:
            raise VerificationError(
                f"{commit}: GitHub-signed merge is not reproducible as a clean merge"
            )
        actual_tree = run_command("git", "show", "-s", "--format=%T", commit).stdout.strip()
        if expected.stdout.strip() != actual_tree:
            raise VerificationError(
                f"{commit}: GitHub-signed merge tree contains changes beyond the clean parent merge"
            )
    elif primary not in allowed_primary_keys:
        raise VerificationError(f"{commit}: signed by untrusted primary key {primary}")
    return primary


def main() -> None:
    """Read GitHub Action inputs and execute PR commit verification."""
    base_sha = os.environ.get("BASE_SHA", "")
    if not base_sha:
        raise VerificationError("BASE_SHA is required")
    base_sha = run_command(
        "git", "rev-parse", "--verify", "--end-of-options", f"{base_sha}^{{commit}}"
    ).stdout.strip()

    head_sha = os.environ.get("HEAD_SHA", "")
    if not head_sha:
        raise VerificationError("HEAD_SHA is required")
    head_sha = run_command(
        "git", "rev-parse", "--verify", "--end-of-options", f"{head_sha}^{{commit}}"
    ).stdout.strip()

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository or repository.startswith("/") or repository.endswith("/") or repository.count("/") > 1:
        raise VerificationError(f"invalid GITHUB_REPOSITORY value: {repository!r}")
    policy = REPOSITORIES.get(repository) or REPOSITORIES.get(repository.rsplit("/", 1)[-1])
    if policy is None:
        raise VerificationError(f"no signer policy is configured for repository {repository!r}")

    key_root = Path(__file__).with_name("trusted-gpg-keys")
    public_key_files: list[Path] = []
    for group in policy.signers:
        group_directory = key_root / group
        if not group_directory.is_dir():
            raise VerificationError(f"configured signer group {group!r} has no public-key directory")
        public_key_files.extend(
            source for source in sorted(group_directory.glob("*.asc")) if source.is_file()
        )
    if not public_key_files:
        raise VerificationError(
            "the configured signer groups contain no ASCII-armored public keys"
        )

    with tempfile.TemporaryDirectory(prefix="commit-signature-verification-") as temporary:
        gpg_home = Path(temporary) / "gnupg"
        gpg_home.mkdir(mode=0o700)
        gpg_env = os.environ | {"GNUPGHOME": str(gpg_home)}

        allowed_primary_keys = import_public_keys(public_key_files, gpg_env)
        if allowed_primary_keys & GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS:
            raise VerificationError(
                "GitHub web-flow keys must not be configured as contributor signers"
            )

        github_key_file = Path(__file__).with_name("github-web-flow.asc")
        all_primary_keys = import_public_keys([github_key_file], gpg_env)
        if all_primary_keys != allowed_primary_keys | GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS:
            raise VerificationError(
                f"{github_key_file}: GitHub web-flow key fingerprints do not match the pinned policy"
            )

        merge_base = run_command(
            "git", "merge-base", base_sha, head_sha, check=False
        )
        if merge_base.returncode:
            raise VerificationError(
                f"base {base_sha} and head {head_sha} have no merge base"
            )
        commits = run_command(
            "git",
            "rev-list",
            "--topo-order",
            f"{merge_base.stdout.strip()}..{head_sha}",
        ).stdout.splitlines()
        if not commits:
            print("No commits introduced by this range.")
            return

        errors: list[str] = []
        for commit in commits:
            try:
                primary_fingerprint = verify_commit_signature(
                    commit, gpg_env, allowed_primary_keys
                )
            except VerificationError as error:
                errors.append(str(error))
                continue
            print(f"verified {commit}  {primary_fingerprint}")

        if errors:
            for error in errors:
                print(f"::error::{error}", file=sys.stderr)
            raise VerificationError(
                f"{len(errors)} of {len(commits)} PR commit(s) violate the signer policy"
            )
        print(f"Verified {len(commits)} PR commit(s).")


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1)
