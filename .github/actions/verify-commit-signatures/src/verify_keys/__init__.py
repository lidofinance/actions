#!/usr/bin/env python3
"""Validate the lifecycle policy of trusted OpenPGP public-key exports.

Each trusted-gpg-keys/<group>/<contributor>.asc file represents one
contributor. During a master-key rotation, retain old and new primary keys in
that same export. This checker intentionally does not inspect Git commits;
commit-signature verification is handled by verify_commit_signatures.py.
"""

from __future__ import annotations

from pathlib import Path

from config import RepositoryPolicy
from ..commands import run_command
from ..errors import VerificationError
from ..git import get_git_output
from ..gpg import PrimaryKey, find_public_key_files, parse_public_key_files
from .checks import (
    KEY_POLICY_CHECKS,
    CheckContext,
    ContributorKeyFile,
    Finding,
    KeySnapshot,
    find_active_signing_subkeys,
    format_utc_date,
)


def reject_duplicate_primary_key_exports(keys_by_file: dict[Path, list[PrimaryKey]]) -> None:
    """Reject primary keys exported by more than one contributor key file."""
    sources_by_fingerprint: dict[str, Path] = {}
    for source, keys in keys_by_file.items():
        for key in keys:
            previous_source = sources_by_fingerprint.setdefault(key.fingerprint, source)
            if previous_source != source:
                raise VerificationError(
                    f"primary key {key.fingerprint} is exported by both {previous_source} and {source}"
                )


def derive_key_file_identity(source: Path, key_root: Path) -> tuple[str, str]:
    """Derive the contributor identity and signer group from an export path."""
    relative = source.relative_to(key_root)
    if len(relative.parts) != 2:
        raise VerificationError(f"{source}: public keys must be stored as <signer-group>/<member>.asc")
    return relative.with_suffix("").as_posix(), relative.parts[0]


def build_contributor_key_file(source: Path, key_root: Path, primary_keys: list[PrimaryKey], now: int) -> ContributorKeyFile:
    """Build one contributor entry from its parsed public-key export."""
    identity, group = derive_key_file_identity(source, key_root)
    return ContributorKeyFile(
        identity=identity,
        group=group,
        keys={primary.fingerprint: primary for primary in primary_keys},
        shared_uids=set.intersection(*(primary.uids for primary in primary_keys)),
        active_subkeys=[
            subkey
            for primary in primary_keys
            for subkey in find_active_signing_subkeys(primary, now)
        ],
    )


def build_key_snapshot(key_root: Path, now: int) -> KeySnapshot:
    """Parse current exports and build a snapshot for policy comparison."""
    entries: dict[str, ContributorKeyFile] = {}

    parsed_key_files = parse_public_key_files(find_public_key_files(key_root))
    reject_duplicate_primary_key_exports(parsed_key_files)
    for source, primary_keys in parsed_key_files.items():
        entry = build_contributor_key_file(source, key_root, primary_keys, now)
        if entry.identity in entries:
            raise VerificationError(f"{source}: duplicate key-file identity {entry.identity!r}")
        entries[entry.identity] = entry

    return KeySnapshot(entries)


def materialize_base_key_root(base_sha: str, current_root: Path, destination: Path) -> bool:
    """Write the trusted-key tree from a base commit to a temporary directory."""
    repository_root = Path(get_git_output("rev-parse", "--show-toplevel").strip()).resolve()
    try:
        relative_root = current_root.resolve().relative_to(repository_root).as_posix()
    except ValueError as error:
        raise VerificationError(f"key root {current_root} is outside Git repository {repository_root}") from error
    files = get_git_output("ls-tree", "-r", "--name-only", base_sha, "--", relative_root).splitlines()
    if not files:
        return False
    for source in files:
        relative = Path(source).relative_to(relative_root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(get_git_output("show", f"{base_sha}:{source}"), encoding="utf-8")
    return True


def collect_policy_findings(
    before: KeySnapshot | None,
    after: KeySnapshot,
    repositories: dict[str, RepositoryPolicy],
    now: int,
) -> list[Finding]:
    """Run every policy rule against the base and current key snapshots."""
    configured_groups = {
        group
        for policy in repositories.values()
        for group in policy.signers
    }
    context = CheckContext(now, frozenset(configured_groups))
    return [finding for check in KEY_POLICY_CHECKS for finding in check(before, after, context)]


def escape_markdown_table_cell(value: str) -> str:
    """Escape table-breaking characters before writing a Markdown report."""
    return value.replace("|", "\\|").replace("\n", " ")


def render_report(snapshot: KeySnapshot, findings: list[Finding]) -> str:
    """Render the current key state and findings as a PR-friendly report."""
    lines = [
        "## Verify keys",
        "",
        "| Contributor export | Shared name/email UID | Primary keys | Active signing subkeys | Next expiry |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for identity, entry in sorted(snapshot.key_files.items()):
        next_expiry = min((subkey.expires for subkey in entry.active_subkeys if subkey.expires is not None), default=None)
        shared_uid = ", ".join(sorted(entry.shared_uids)) or "—"
        lines.append(
            f"| {identity} | {escape_markdown_table_cell(shared_uid)} | {len(entry.keys)} | {len(entry.active_subkeys)} | {format_utc_date(next_expiry)} |"
        )
    for level, title in (("error", "Errors"), ("warning", "Review warnings")):
        selected = [finding.message for finding in findings if finding.level == level]
        if selected:
            lines.extend(["", f"### {title}", ""])
            lines.extend(f"- {message}" for message in selected)
    if not findings:
        lines.extend(["", "No key changes or findings."])
    return "\n".join(lines) + "\n"
