#!/usr/bin/env python3
"""Validate the lifecycle policy of trusted OpenPGP public-key exports."""

import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from config import REPOSITORIES, RepositoryPolicy
from src.commands import VerificationError, run_command
from src.gpg import (
    PrimaryKey,
    Subkey,
    find_public_key_files,
    parse_public_key_files,
)


EDDSA_ALGORITHM = 22
MAX_SIGNING_SUBKEY_LIFETIME_SECONDS = 366 * 24 * 60 * 60
ROTATION_WINDOW_SECONDS = 30 * 24 * 60 * 60
UNUSABLE_VALIDITIES = {"d", "e", "i", "r"}


@dataclass(frozen=True)
class Finding:
    """One error or warning emitted by the public-key policy."""

    level: str
    message: str


@dataclass
class ContributorKeyFile:
    """The parsed current state of one contributor's public-key export."""

    identity: str
    group: str
    keys: dict[str, PrimaryKey]
    shared_uids: set[str]
    active_subkeys: list[Subkey]


KeySnapshot = dict[str, ContributorKeyFile]


def index_signing_subkeys(entry: ContributorKeyFile) -> dict[str, Subkey]:
    """Index every signing subkey in one contributor export by fingerprint."""
    return {
        subkey.fingerprint: subkey
        for primary in entry.keys.values()
        for subkey in primary.subkeys
        if subkey.can_sign
    }


def active_signing_subkeys(entry: ContributorKeyFile) -> list[Subkey]:
    """Return active subkeys that can sign."""
    return [subkey for subkey in entry.active_subkeys if subkey.can_sign]


def check_current_key_file(
    entry: ContributorKeyFile, configured_groups: frozenset[str], now: int
) -> list[Finding]:
    """Apply current-state policy to one contributor's public-key export."""
    findings: list[Finding] = []
    if not entry.shared_uids:
        findings.append(
            Finding(
                "error",
                f"{entry.identity}: all primary keys in one contributor export must share a name/email UID",
            )
        )

    for primary in entry.keys.values():
        if primary.expires is not None:
            findings.append(
                Finding(
                    "error",
                    f"{entry.identity}: primary key {primary.fingerprint} must not have an expiration",
                )
            )
        if primary.can_sign:
            findings.append(
                Finding(
                    "warning",
                    f"{entry.identity}: primary key {primary.fingerprint} has signing capability; keep it offline",
                )
            )
        if primary.validity in UNUSABLE_VALIDITIES:
            findings.append(
                Finding(
                    "warning",
                    f"{entry.identity}: primary key {primary.fingerprint} is retired "
                    f"({primary.validity or 'unknown status'})",
                )
            )

    for subkey in index_signing_subkeys(entry).values():
        if subkey.expires is None:
            findings.append(
                Finding(
                    "error",
                    f"{entry.identity}: signing subkey {subkey.fingerprint} has no expiration",
                )
            )
        elif subkey.created is None or subkey.expires <= subkey.created:
            findings.append(
                Finding(
                    "error",
                    f"{entry.identity}: signing subkey {subkey.fingerprint} has an invalid expiration",
                )
            )
        elif subkey.expires - subkey.created > MAX_SIGNING_SUBKEY_LIFETIME_SECONDS:
            findings.append(
                Finding(
                    "error",
                    f"{entry.identity}: signing subkey {subkey.fingerprint} is valid for more than one year",
                )
            )
    if entry.group not in configured_groups:
        findings.append(
            Finding(
                "warning",
                f"{entry.identity}: signer group {entry.group!r} is not used by any repository policy",
            )
        )

    active = active_signing_subkeys(entry)
    if not active:
        findings.append(Finding("error", f"{entry.identity}: has no active signing subkey"))
    if len(active) > 4:
        findings.append(
            Finding(
                "error",
                f"{entry.identity}: has {len(active)} active signing subkeys (maximum is 4)",
            )
        )
    else:
        long_lived = [
            subkey
            for subkey in active
            if subkey.expires is None or subkey.expires > now + ROTATION_WINDOW_SECONDS
        ]
        if len(active) > 2 and len(long_lived) > 2:
            findings.append(
                Finding(
                    "error",
                    f"{entry.identity}: rotation has more than two active signing subkeys beyond 30 days",
                )
            )
        elif len(active) > 2:
            findings.append(
                Finding(
                    "warning",
                    f"{entry.identity}: rotation in progress with {len(active)} active signing subkeys",
                )
            )

    for subkey in active:
        if subkey.expires is None:
            continue
        remaining = subkey.expires - now
        if remaining <= 14 * 24 * 60 * 60:
            threshold = 14
        elif remaining <= 30 * 24 * 60 * 60:
            threshold = 30
        elif remaining <= 60 * 24 * 60 * 60:
            threshold = 60
        else:
            continue
        findings.append(
            Finding(
                "warning",
                f"{entry.identity}: signing subkey {subkey.fingerprint} expires within {threshold} days",
            )
        )
    encryption_subkeys = [
        subkey for subkey in entry.active_subkeys if subkey.can_encrypt
    ]
    if len(active) != 2:
        findings.append(
            Finding(
                "warning",
                f"{entry.identity}: has {len(active)} active signing subkey(s); "
                "the GPG signing guide recommends exactly two",
            )
        )
    if len(encryption_subkeys) != 2:
        findings.append(
            Finding(
                "warning",
                f"{entry.identity}: has {len(encryption_subkeys)} active encryption subkey(s); "
                "the GPG signing guide recommends exactly two",
            )
        )
    for primary in entry.keys.values():
        if primary.algorithm != EDDSA_ALGORITHM:
            findings.append(
                Finding(
                    "warning",
                    f"{entry.identity}: primary key {primary.fingerprint} does not use EdDSA "
                    f"(algorithm {primary.algorithm or 'unknown'})",
                )
            )
    for subkey in active:
        if subkey.algorithm != EDDSA_ALGORITHM:
            findings.append(
                Finding(
                    "warning",
                    f"{entry.identity}: signing subkey {subkey.fingerprint} does not use EdDSA "
                    f"(algorithm {subkey.algorithm or 'unknown'})",
                )
            )
    return findings


def format_utc_date(timestamp: int | None) -> str:
    """Render an optional Unix timestamp as a stable UTC date."""
    if timestamp is None:
        return "never"
    return time.strftime("%Y-%m-%d", time.gmtime(timestamp))


def check_key_lifecycle_changes(
    before: KeySnapshot | None, after: KeySnapshot
) -> list[Finding]:
    """Describe additions, removals, rotations, and UID or expiry changes."""
    if before is None:
        return [
            Finding(
                "warning",
                "initial key-policy snapshot; no base export is available for comparison",
            )
        ]

    findings: list[Finding] = []
    for identity in sorted(set(before) | set(after)):
        old = before.get(identity)
        new = after.get(identity)
        if old is None:
            findings.append(Finding("warning", f"{identity}: contributor export added"))
            continue
        if new is None:
            findings.append(Finding("warning", f"{identity}: contributor export removed"))
            continue

        old_fingerprints = set(old.keys)
        new_fingerprints = set(new.keys)
        if not (old.shared_uids & new.shared_uids):
            findings.append(
                Finding(
                    "error",
                    f"{identity}: primary-key change does not preserve a common name/email UID "
                    "with the base export",
                )
            )
        elif old.shared_uids != new.shared_uids:
            findings.append(
                Finding("warning", f"{identity}: shared name/email UID set changed")
            )
        for fingerprint in sorted(new_fingerprints - old_fingerprints):
            findings.append(
                Finding(
                    "warning",
                    f"{identity}: primary key added: {fingerprint} "
                    "(master-key rotation requires SecOps review)",
                )
            )
        for fingerprint in sorted(old_fingerprints - new_fingerprints):
            findings.append(
                Finding("warning", f"{identity}: primary key removed: {fingerprint}")
            )
        for fingerprint in sorted(old_fingerprints & new_fingerprints):
            old_key = old.keys[fingerprint]
            new_key = new.keys[fingerprint]
            for uid in sorted(new_key.uids - old_key.uids):
                findings.append(
                    Finding(
                        "warning",
                        f"{identity}: UID added to primary key {fingerprint}: {uid!r}",
                    )
                )
            for uid in sorted(old_key.uids - new_key.uids):
                findings.append(
                    Finding(
                        "warning",
                        f"{identity}: UID removed from primary key {fingerprint}: {uid!r}",
                    )
                )

        old_subkeys = index_signing_subkeys(old)
        new_subkeys = index_signing_subkeys(new)
        for fingerprint in sorted(set(new_subkeys) - set(old_subkeys)):
            findings.append(
                Finding(
                    "warning",
                    f"{identity}: signing subkey added: {fingerprint} "
                    f"(expires {format_utc_date(new_subkeys[fingerprint].expires)})",
                )
            )
        for fingerprint in sorted(set(old_subkeys) - set(new_subkeys)):
            findings.append(
                Finding("warning", f"{identity}: signing subkey removed: {fingerprint}")
            )
        for fingerprint in sorted(set(old_subkeys) & set(new_subkeys)):
            old_subkey = old_subkeys[fingerprint]
            new_subkey = new_subkeys[fingerprint]
            if old_subkey.expires != new_subkey.expires:
                findings.append(
                    Finding(
                        "warning",
                        f"{identity}: signing subkey {fingerprint} expiration changed from "
                        f"{format_utc_date(old_subkey.expires)} to "
                        f"{format_utc_date(new_subkey.expires)}",
                    )
                )
            if old_subkey.validity != new_subkey.validity:
                findings.append(
                    Finding(
                        "warning",
                        f"{identity}: signing subkey {fingerprint} status changed from "
                        f"{old_subkey.validity or 'unknown'} to "
                        f"{new_subkey.validity or 'unknown'}",
                    )
                )
    return findings


def build_key_snapshot(key_root: Path, now: int) -> KeySnapshot:
    """Parse current exports and build a snapshot for policy comparison."""
    parsed_key_files = parse_public_key_files(find_public_key_files(key_root))
    sources_by_fingerprint: dict[str, Path] = {}
    entries: KeySnapshot = {}

    for source, primary_keys in parsed_key_files.items():
        for primary in primary_keys:
            previous_source = sources_by_fingerprint.setdefault(primary.fingerprint, source)
            if previous_source != source:
                raise VerificationError(
                    f"primary key {primary.fingerprint} is exported by both "
                    f"{previous_source} and {source}"
                )

        relative = source.relative_to(key_root)
        identity = relative.with_suffix("").as_posix()
        entries[identity] = ContributorKeyFile(
            identity=identity,
            group=relative.parts[0],
            keys={primary.fingerprint: primary for primary in primary_keys},
            shared_uids=set.intersection(*(primary.uids for primary in primary_keys)),
            active_subkeys=[
                subkey
                for primary in primary_keys
                if primary.validity not in UNUSABLE_VALIDITIES
                for subkey in primary.subkeys
                if subkey.validity not in UNUSABLE_VALIDITIES
                and (subkey.expires is None or subkey.expires > now)
            ],
        )
    return entries


def materialize_base_key_root(
    base_sha: str, current_root: Path, destination: Path
) -> bool:
    """Write the trusted-key tree from a base commit to a temporary directory."""
    repository_root = Path(
        run_command("git", "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    try:
        relative_root = current_root.resolve().relative_to(repository_root).as_posix()
    except ValueError as error:
        raise VerificationError(
            f"key root {current_root} is outside Git repository {repository_root}"
        ) from error

    files = run_command(
        "git", "ls-tree", "-r", "--name-only", base_sha, "--", relative_root
    ).stdout.splitlines()
    for source in files:
        target = destination / Path(source).relative_to(relative_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            run_command("git", "show", f"{base_sha}:{source}").stdout,
            encoding="utf-8",
        )
    return bool(files)


def collect_policy_findings(
    before: KeySnapshot | None,
    after: KeySnapshot,
    repositories: dict[str, RepositoryPolicy],
    now: int,
) -> list[Finding]:
    """Run every policy rule against the base and current key snapshots."""
    configured_groups = frozenset(
        group for policy in repositories.values() for group in policy.signers
    )
    findings: list[Finding] = []
    for entry in after.values():
        findings.extend(check_current_key_file(entry, configured_groups, now))
    findings.extend(
        Finding("error", f"configured signer group {group!r} has no active signing subkey")
        for group in configured_groups
        if not any(
            entry.group == group and active_signing_subkeys(entry)
            for entry in after.values()
        )
    )
    findings.extend(check_key_lifecycle_changes(before, after))
    return findings


def render_report(snapshot: KeySnapshot, findings: list[Finding]) -> str:
    """Render the current key state and findings as a PR-friendly report."""
    lines = [
        "## Verify keys",
        "",
        "| Contributor export | Shared name/email UID | Primary keys | Active signing subkeys | Next expiry |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for identity, entry in sorted(snapshot.items()):
        signing_subkeys = active_signing_subkeys(entry)
        next_expiry = min(
            (
                subkey.expires
                for subkey in signing_subkeys
                if subkey.expires is not None
            ),
            default=None,
        )
        shared_uid = (", ".join(sorted(entry.shared_uids)) or "—").replace(
            "|", "\\|"
        ).replace("\n", " ")
        lines.append(
            f"| {identity} | {shared_uid} | {len(entry.keys)} | "
            f"{len(signing_subkeys)} | {format_utc_date(next_expiry)} |"
        )
    for level, title in (("error", "Errors"), ("warning", "Review warnings")):
        selected = [finding.message for finding in findings if finding.level == level]
        if selected:
            lines.extend(["", f"### {title}", ""])
            lines.extend(f"- {message}" for message in selected)
    if not findings:
        lines.extend(["", "No key changes or findings."])
    return "\n".join(lines) + "\n"


def main() -> int:
    """Analyze head and base public-key trees, then write a policy report."""
    key_root = Path(__file__).with_name("trusted-gpg-keys")
    try:
        base_value = os.environ.get("BASE_SHA", "")
        if not base_value:
            raise VerificationError("BASE_SHA is required")
        base_sha = run_command(
            "git", "rev-parse", "--verify", "--end-of-options", f"{base_value}^{{commit}}"
        ).stdout.strip()
        now = int(time.time())
        current = build_key_snapshot(key_root, now)
        with tempfile.TemporaryDirectory(prefix="gpg-key-policy-base-") as temporary:
            base_root = Path(temporary) / "trusted-gpg-keys"
            before = build_key_snapshot(base_root, now) if materialize_base_key_root(base_sha, key_root, base_root) else None
        findings = collect_policy_findings(before, current, REPOSITORIES, now)
        content = render_report(current, findings)
    except VerificationError as error:
        findings = [Finding("error", str(error))]
        content = "## Verify keys\n\n### Errors\n\n- " + str(error) + "\n"

    print(content, end="")
    for finding in findings:
        print(f"::{finding.level}::{finding.message}", file=sys.stderr)
    return 1 if any(finding.level == "error" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
