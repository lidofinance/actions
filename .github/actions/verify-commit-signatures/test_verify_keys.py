#!/usr/bin/env python3
"""Unit tests for GPG public-key policy parsing and rotation limits."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import RepositoryPolicy
from src import gpg
from src.errors import VerificationError
from src import verify_keys as policy


class VerifyKeysTest(unittest.TestCase):
    def build_primary_key(self, *subkeys: object) -> object:
        """Build a valid fixture primary key for one contributor export."""
        return gpg.PrimaryKey(
            fingerprint="A" * 40,
            algorithm=22,
            validity="u",
            created=1,
            expires=None,
            capabilities="c",
            uids={"Alice Example <alice@example.invalid>"},
            subkeys=list(subkeys),
        )

    def build_signing_subkey(self, fingerprint: str, created: int, expires: int) -> object:
        """Build a valid fixture signing subkey with a chosen lifetime."""
        return gpg.Subkey(
            fingerprint=fingerprint,
            algorithm=22,
            validity="u",
            created=created,
            expires=expires,
            capabilities="s",
        )

    def write_key_export_fixture(self, root: Path) -> Path:
        """Create a minimal configured signer-group fixture."""
        (root / "secops").mkdir()
        source = root / "secops" / "alice.asc"
        source.write_text("public key fixture", encoding="utf-8")
        return source

    def test_gpg_listing_parses_primary_and_signing_subkey(self) -> None:
        """Parse the primary key, UID, and signing-subkey records from GnuPG."""
        listing = (
            "pub:u:255:22:1234:1:::u:::c::::::23::0:\n"
            f"fpr:::::::::{'A' * 40}:\n"
            "uid:u::::1::hash::Alice Example <alice@example.invalid>::::::::::0:\n"
            "sub:u:255:22:5678:2:31536002:::::s::::::23:\n"
            f"fpr:::::::::{'B' * 40}:\n"
        )
        keys = gpg.parse_gpg_key_listing(Path("alice.asc"), listing)
        self.assertEqual(keys[0].fingerprint, "A" * 40)
        self.assertEqual(keys[0].algorithm, 22)
        self.assertEqual(keys[0].uids, {"Alice Example <alice@example.invalid>"})
        self.assertTrue(keys[0].subkeys[0].can_sign)
        self.assertEqual(keys[0].subkeys[0].fingerprint, "B" * 40)

    def test_gpg_colon_field_decodes_unicode_and_c_style_escapes(self) -> None:
        """Preserve UTF-8 text while decoding the escapes GnuPG uses in UIDs."""
        escaped = r"André\x3a Back\x5cslash\nTab\x09"
        self.assertEqual(
            gpg.unescape_gpg_colon_field(escaped),
            "André: Back\\slash\nTab\t",
        )

    def test_contributor_key_file_requires_group_and_member_path(self) -> None:
        """Reject nested public-key paths outside the documented key-store layout."""
        with self.assertRaisesRegex(VerificationError, "<signer-group>/<member>.asc"):
            policy.derive_key_file_identity(
                Path("trusted-gpg-keys/secops/archived/alice.asc"),
                Path("trusted-gpg-keys"),
            )

    def test_three_key_rotation_allows_an_imminent_retirement(self) -> None:
        """Permit a third active key only while an older key retires soon."""
        now = 10_000_000
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.write_key_export_fixture(root)
            primary = self.build_primary_key(
                self.build_signing_subkey("B" * 40, now, now + 10 * 24 * 60 * 60),
                self.build_signing_subkey("C" * 40, now, now + 200 * 24 * 60 * 60),
                self.build_signing_subkey("D" * 40, now, now + 200 * 24 * 60 * 60),
            )
            with patch.object(policy, "parse_public_key_files", return_value={source: [primary]}):
                snapshot = policy.build_key_snapshot(root, now)
                findings = policy.collect_policy_findings(
                    None, snapshot, {"example": RepositoryPolicy(("secops",))}, now
                )
        self.assertFalse([finding for finding in findings if finding.level == "error"])
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("rotation in progress", messages)
        self.assertIn("guide recommends exactly two", messages)

    def test_three_long_lived_keys_are_rejected(self) -> None:
        """Reject a three-key state that is not a time-bounded rotation."""
        now = 10_000_000
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.write_key_export_fixture(root)
            primary = self.build_primary_key(
                self.build_signing_subkey("B" * 40, now, now + 200 * 24 * 60 * 60),
                self.build_signing_subkey("C" * 40, now, now + 200 * 24 * 60 * 60),
                self.build_signing_subkey("D" * 40, now, now + 200 * 24 * 60 * 60),
            )
            with patch.object(policy, "parse_public_key_files", return_value={source: [primary]}):
                snapshot = policy.build_key_snapshot(root, now)
                findings = policy.collect_policy_findings(
                    None, snapshot, {"example": RepositoryPolicy(("secops",))}, now
                )
        self.assertIn(
            "rotation has more than two active signing subkeys beyond 30 days",
            "\n".join(finding.message for finding in findings),
        )


if __name__ == "__main__":
    unittest.main()
