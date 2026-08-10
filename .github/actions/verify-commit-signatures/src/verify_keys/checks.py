"""Independent policy checks for trusted GPG public-key exports."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ..gpg import PrimaryKey, Subkey


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


@dataclass(frozen=True)
class CheckContext:
    """Configuration shared by every public-key policy check."""

    now: int
    configured_groups: frozenset[str]


ContributorKeyFileCheck = Callable[[ContributorKeyFile, CheckContext], list[Finding]]


@dataclass
class KeySnapshot:
    """Trusted-key exports parsed from one Git revision."""

    key_files: dict[str, ContributorKeyFile]


PolicyCheck = Callable[[KeySnapshot | None, KeySnapshot, CheckContext], list[Finding]]


def is_usable(validity: str) -> bool:
    """Return whether GnuPG does not mark a key as retired or unusable."""
    return validity not in UNUSABLE_VALIDITIES


def find_active_signing_subkeys(primary: PrimaryKey, now: int) -> list[Subkey]:
    """Return currently usable signing subkeys for a viable primary key."""
    if not is_usable(primary.validity):
        return []
    return [
        subkey for subkey in primary.subkeys
        if subkey.can_sign and is_usable(subkey.validity) and (subkey.expires is None or subkey.expires > now)
    ]


def index_signing_subkeys(entry: ContributorKeyFile) -> dict[str, Subkey]:
    """Index every signing subkey in one contributor export by fingerprint."""
    return {
        subkey.fingerprint: subkey
        for primary in entry.keys.values()
        for subkey in primary.subkeys
        if subkey.can_sign
    }


def check_primary_keys_share_uid(entry: ContributorKeyFile, _: CheckContext) -> list[Finding]:
    """Require rotated primary keys in one export to share a name/email UID."""
    if entry.shared_uids:
        return []
    return [Finding("error", f"{entry.identity}: all primary keys in one contributor export must share a name/email UID")]


def check_primary_keys(entry: ContributorKeyFile, _: CheckContext) -> list[Finding]:
    """Check primary-key expiry, signing capability, and retirement status."""
    findings: list[Finding] = []
    for primary in entry.keys.values():
        if primary.expires is not None:
            findings.append(Finding("error", f"{entry.identity}: primary key {primary.fingerprint} must not have an expiration"))
        if primary.can_sign:
            findings.append(Finding("warning", f"{entry.identity}: primary key {primary.fingerprint} has signing capability; keep it offline"))
        if not is_usable(primary.validity):
            findings.append(Finding("warning", f"{entry.identity}: primary key {primary.fingerprint} is retired ({primary.validity or 'unknown status'})"))
    return findings


def check_signing_subkeys(entry: ContributorKeyFile, _: CheckContext) -> list[Finding]:
    """Check that every signing subkey has a valid lifetime of at most one year."""
    findings: list[Finding] = []
    for subkey in index_signing_subkeys(entry).values():
        if subkey.expires is None:
            findings.append(Finding("error", f"{entry.identity}: signing subkey {subkey.fingerprint} has no expiration"))
        elif subkey.created is None or subkey.expires <= subkey.created:
            findings.append(Finding("error", f"{entry.identity}: signing subkey {subkey.fingerprint} has an invalid expiration"))
        elif subkey.expires - subkey.created > MAX_SIGNING_SUBKEY_LIFETIME_SECONDS:
            findings.append(Finding("error", f"{entry.identity}: signing subkey {subkey.fingerprint} is valid for more than one year"))
    return findings


def check_signer_group_is_configured(entry: ContributorKeyFile, context: CheckContext) -> list[Finding]:
    """Warn when an export's signer group is not authorized for any repository."""
    if entry.group in context.configured_groups:
        return []
    return [Finding("warning", f"{entry.identity}: signer group {entry.group!r} is not used by any repository policy")]


def check_active_signing_subkey_exists(entry: ContributorKeyFile, _: CheckContext) -> list[Finding]:
    """Require every contributor export to retain an active signing subkey."""
    if entry.active_subkeys:
        return []
    return [Finding("error", f"{entry.identity}: has no active signing subkey")]


def check_signing_subkey_rotation(entry: ContributorKeyFile, context: CheckContext) -> list[Finding]:
    """Limit active signing subkeys while allowing time-bounded rotations."""
    active = entry.active_subkeys
    if len(active) > 4:
        return [Finding("error", f"{entry.identity}: has {len(active)} active signing subkeys (maximum is 4)")]
    long_lived = [subkey for subkey in active if subkey.expires is None or subkey.expires > context.now + ROTATION_WINDOW_SECONDS]
    if len(active) > 2 and len(long_lived) > 2:
        return [Finding("error", f"{entry.identity}: rotation has more than two active signing subkeys beyond 30 days")]
    if len(active) > 2:
        return [Finding("warning", f"{entry.identity}: rotation in progress with {len(active)} active signing subkeys")]
    return []


def check_signing_subkey_expiry(entry: ContributorKeyFile, context: CheckContext) -> list[Finding]:
    """Warn when an active signing subkey expires within 14, 30, or 60 days."""
    findings: list[Finding] = []
    for subkey in entry.active_subkeys:
        if subkey.expires is None:
            continue
        remaining = subkey.expires - context.now
        if remaining <= 14 * 24 * 60 * 60:
            threshold = 14
        elif remaining <= 30 * 24 * 60 * 60:
            threshold = 30
        elif remaining <= 60 * 24 * 60 * 60:
            threshold = 60
        else:
            continue
        findings.append(Finding("warning", f"{entry.identity}: signing subkey {subkey.fingerprint} expires within {threshold} days"))
    return findings


KEY_FILE_CHECKS: tuple[ContributorKeyFileCheck, ...] = (
    check_primary_keys_share_uid,
    check_primary_keys,
    check_signing_subkeys,
    check_signer_group_is_configured,
    check_active_signing_subkey_exists,
    check_signing_subkey_rotation,
    check_signing_subkey_expiry,
)


def check_current_key_files(
    _: KeySnapshot | None, after: KeySnapshot, context: CheckContext
) -> list[Finding]:
    """Run every current-state rule for each export in the new snapshot."""
    return [
        finding
        for entry in after.key_files.values()
        for check in KEY_FILE_CHECKS
        for finding in check(entry, context)
    ]


def check_configured_groups_have_active_keys(
    _: KeySnapshot | None, after: KeySnapshot, context: CheckContext
) -> list[Finding]:
    """Require every configured signer group to have an active signing subkey."""
    return [
        Finding("error", f"configured signer group {group!r} has no active signing subkey")
        for group in context.configured_groups
        if not any(entry.group == group and entry.active_subkeys for entry in after.key_files.values())
    ]


def check_key_lifecycle_changes(before: KeySnapshot | None, after: KeySnapshot, _: CheckContext) -> list[Finding]:
    """Describe additions, removals, rotations, and UID or expiry changes."""
    if before is None:
        return [Finding("warning", "initial key-policy snapshot; no base export is available for comparison")]
    findings: list[Finding] = []
    for identity in sorted(set(before.key_files) | set(after.key_files)):
        old = before.key_files.get(identity)
        new = after.key_files.get(identity)
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
                    f"{identity}: primary-key change does not preserve a common name/email UID with the base export",
                )
            )
        elif old.shared_uids != new.shared_uids:
            findings.append(Finding("warning", f"{identity}: shared name/email UID set changed"))
        for fingerprint in sorted(new_fingerprints - old_fingerprints):
            findings.append(Finding("warning", f"{identity}: primary key added: {fingerprint} (master-key rotation requires SecOps review)"))
        for fingerprint in sorted(old_fingerprints - new_fingerprints):
            findings.append(Finding("warning", f"{identity}: primary key removed: {fingerprint}"))
        for fingerprint in sorted(old_fingerprints & new_fingerprints):
            old_key = old.keys[fingerprint]
            new_key = new.keys[fingerprint]
            for uid in sorted(new_key.uids - old_key.uids):
                findings.append(Finding("warning", f"{identity}: UID added to primary key {fingerprint}: {uid!r}"))
            for uid in sorted(old_key.uids - new_key.uids):
                findings.append(Finding("warning", f"{identity}: UID removed from primary key {fingerprint}: {uid!r}"))

        old_subkeys = index_signing_subkeys(old)
        new_subkeys = index_signing_subkeys(new)
        for fingerprint in sorted(set(new_subkeys) - set(old_subkeys)):
            findings.append(Finding("warning", f"{identity}: signing subkey added: {fingerprint} (expires {format_utc_date(new_subkeys[fingerprint].expires)})"))
        for fingerprint in sorted(set(old_subkeys) - set(new_subkeys)):
            findings.append(Finding("warning", f"{identity}: signing subkey removed: {fingerprint}"))
        for fingerprint in sorted(set(old_subkeys) & set(new_subkeys)):
            old_subkey = old_subkeys[fingerprint]
            new_subkey = new_subkeys[fingerprint]
            if old_subkey.expires != new_subkey.expires:
                findings.append(Finding("warning", f"{identity}: signing subkey {fingerprint} expiration changed from {format_utc_date(old_subkey.expires)} to {format_utc_date(new_subkey.expires)}"))
            if old_subkey.validity != new_subkey.validity:
                findings.append(Finding("warning", f"{identity}: signing subkey {fingerprint} status changed from {old_subkey.validity or 'unknown'} to {new_subkey.validity or 'unknown'}"))
    return findings


def format_utc_date(timestamp: int | None) -> str:
    """Render an optional Unix timestamp as a stable UTC date."""
    if timestamp is None:
        return "never"
    return time.strftime("%Y-%m-%d", time.gmtime(timestamp))


KEY_POLICY_CHECKS: tuple[PolicyCheck, ...] = (
    check_current_key_files,
    check_configured_groups_have_active_keys,
    check_key_lifecycle_changes,
)
