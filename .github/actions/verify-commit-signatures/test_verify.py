#!/usr/bin/env python3
"""End-to-end tests for the commit-signature verifier.

Each test creates a disposable repository and GPG homedir. Shared keys emulate
the immutable verifier checkout; caller-specific keys are committed before the
tested range, matching the reusable workflow's base-commit key-loading rule.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


VERIFIER = Path(__file__).with_name("verify.py")


@unittest.skipUnless(shutil.which("git") and shutil.which("gpg"), "git and gpg are required")
class VerifyCommitSignaturesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="verify-commit-signatures-test-")
        self.root = Path(self.temporary.name)
        self.gpg_home = self.root / "signing-gnupg"
        self.gpg_home.mkdir(mode=0o700)
        self.gpg_env = os.environ | {"GNUPGHOME": str(self.gpg_home)}
        self.trusted_fingerprint = self.generate_key("Trusted signer <trusted@example.invalid>")
        self.caller_fingerprint = self.generate_key("Caller signer <caller@example.invalid>")
        self.unknown_fingerprint = self.generate_key("Unknown signer <unknown@example.invalid>")

        implementation_directory = self.root / "implementation"
        implementation_directory.mkdir()
        self.verifier = implementation_directory / "verify.py"
        self.verifier.write_bytes(VERIFIER.read_bytes())
        self.shared_key_directory = implementation_directory / "trusted-gpg-keys"
        self.shared_key_directory.mkdir()
        (self.shared_key_directory / "trusted.asc").write_text(
            self.export_key(self.trusted_fingerprint), encoding="utf-8"
        )

        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Verifier test")
        self.git("config", "user.email", "verifier@example.invalid")
        self.git("config", "user.signingkey", self.trusted_fingerprint)

        self.key_path = self.repo / ".github" / "gpg-keys" / "caller.asc"
        self.key_path.parent.mkdir(parents=True)
        self.key_path.write_text(self.export_key(self.caller_fingerprint), encoding="utf-8")
        (self.repo / "README").write_text("base\n", encoding="utf-8")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, *args: str, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            args,
            cwd=self.repo if hasattr(self, "repo") else None,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and completed.returncode:
            self.fail(f"{' '.join(args)} failed:\n{completed.stdout}{completed.stderr}")
        return completed

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.command("git", *args, env=self.gpg_env, check=check)

    def generate_key(self, identity: str) -> str:
        self.command(
            "gpg", "--batch", "--passphrase", "", "--quick-generate-key", identity, "rsa2048", "sign", "1d",
            env=self.gpg_env,
        )
        keys = self.command("gpg", "--batch", "--with-colons", "--list-keys", identity, env=self.gpg_env).stdout
        return next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))

    def export_key(self, fingerprint: str) -> str:
        return self.command(
            "gpg", "--batch", "--armor", "--export", fingerprint, env=self.gpg_env
        ).stdout

    def commit(self, message: str, *, signed: bool = True, signer: str | None = None, change: str | None = None) -> str:
        if change is not None:
            with (self.repo / "README").open("a", encoding="utf-8") as readme:
                readme.write(change)
        self.git("add", ".")
        command = ["commit", "--allow-empty", "-qm", message]
        if signed:
            command.insert(0, f"-c")
            command.insert(1, f"user.signingkey={signer or self.trusted_fingerprint}")
            command.insert(2, "-c")
            command.insert(3, "commit.gpgsign=true")
        else:
            command.insert(0, "-c")
            command.insert(1, "commit.gpgsign=false")
        self.git(*command)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def verify(self, head: str | None = None, base: str | None = None, *,
               additional_key_paths: str | None = None) -> subprocess.CompletedProcess[str]:
        return self.command(
            sys.executable,
            str(self.verifier),
            env=os.environ | {
                "BASE_SHA": base or self.base,
                "HEAD_SHA": head or self.git("rev-parse", "HEAD").stdout.strip(),
                "ADDITIONAL_GPG_PUBKEYS": (
                    ".github/gpg-keys/caller.asc" if additional_key_paths is None else additional_key_paths
                ),
                "GNUPGHOME": str(self.gpg_home),
            },
            check=False,
        )

    def assert_verifies(self, head: str | None = None) -> None:
        result = self.verify(head)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_rejected(self, expected: str, head: str | None = None) -> None:
        result = self.verify(head)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_trusted_signed_commit_is_accepted(self) -> None:
        self.commit("Trusted change", change="trusted\n")
        result = self.verify(additional_key_paths="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unknown_signer_is_rejected(self) -> None:
        self.commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        self.assert_rejected("unverifiable GPG signature")

    def test_caller_specific_key_is_accepted(self) -> None:
        self.commit("Caller change", signer=self.caller_fingerprint, change="caller\n")
        self.assert_verifies()

    def test_no_shared_or_caller_key_is_rejected(self) -> None:
        (self.shared_key_directory / "trusted.asc").unlink()
        result = self.verify(additional_key_paths="")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no shared or caller-provided GPG public-key files", result.stdout + result.stderr)

    def test_pr_key_file_changes_do_not_affect_trust(self) -> None:
        self.key_path.write_text(self.export_key(self.unknown_fingerprint), encoding="utf-8")
        self.commit("Replace trusted key", signer=self.unknown_fingerprint, change="unknown\n")
        self.assert_rejected("unverifiable GPG signature")

    def test_head_must_descend_from_base(self) -> None:
        child = self.commit("Trusted change", change="trusted\n")
        result = self.verify(head=self.base, base=child)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("is not an ancestor", result.stdout + result.stderr)

    def test_revision_input_is_not_parsed_as_an_option(self) -> None:
        result = self.verify(base="--quiet")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--end-of-options", result.stdout + result.stderr)

    def test_valid_empty_seal_stops_traversal(self) -> None:
        self.commit("Unsigned historical change", signed=False, change="unsigned\n")
        self.commit("Seal\n\nArgocd-gpg-seal: reviewed historical change")
        self.commit("Trusted change after seal", change="trusted\n")
        self.assert_verifies()

    def test_non_empty_seal_is_rejected(self) -> None:
        self.commit("Invalid seal\n\nArgocd-gpg-seal: not empty", change="content\n")
        self.assert_rejected("seal commits must be empty")

    def test_merge_seal_is_rejected(self) -> None:
        self.git("checkout", "-qb", "side")
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        self.commit("Side change")
        self.git("checkout", "-q", "master")
        (self.repo / "main.txt").write_text("main\n", encoding="utf-8")
        self.commit("Main change")
        self.git(
            "-c", "commit.gpgsign=true", "merge", "--no-ff", "--no-edit",
            "-m", "Merge seal\n\nArgocd-gpg-seal: invalid merge", "side",
        )
        self.assert_rejected("seal commits must have exactly one parent")

    def test_malformed_or_duplicate_seal_trailer_is_rejected(self) -> None:
        for message in (
            "Malformed seal\n\nArgocd-gpg-seal=wrong separator",
            "Duplicate seal\n\nArgocd-gpg-seal: first\nArgocd-gpg-seal: second",
        ):
            with self.subTest(message=message):
                head = self.commit(message)
                self.assert_rejected("Argocd-gpg-seal trailer", head)
                self.git("reset", "--hard", self.base)


if __name__ == "__main__":
    unittest.main()
