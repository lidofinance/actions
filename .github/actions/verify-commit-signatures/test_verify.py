#!/usr/bin/env python3
"""End-to-end tests for the commit-signature verifier."""

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
        self.unknown_fingerprint = self.generate_key("Unknown signer <unknown@example.invalid>")

        implementation_directory = self.root / "implementation"
        implementation_directory.mkdir()
        self.verifier = implementation_directory / "verify.py"
        self.verifier.write_bytes(VERIFIER.read_bytes())
        self.shared_key_directory = implementation_directory / "trusted-gpg-keys"
        self.shared_key_directory.mkdir()
        self.webexp_directory = self.shared_key_directory / "webexp"
        self.webexp_directory.mkdir()
        (self.webexp_directory / "trusted.asc").write_text(
            self.export_key(self.trusted_fingerprint), encoding="utf-8"
        )
        (self.shared_key_directory / "config.yaml").write_text(
            "test-repository:\n  signers: [webexp]\n  dry: false\n", encoding="utf-8"
        )

        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Verifier test")
        self.git("config", "user.email", "verifier@example.invalid")
        self.git("config", "user.signingkey", self.trusted_fingerprint)

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

    def verify(self, head: str | None = None, base: str | None = None) -> subprocess.CompletedProcess[str]:
        return self.command(
            sys.executable,
            str(self.verifier),
            env=os.environ | {
                "BASE_SHA": base or self.base,
                "HEAD_SHA": head or self.git("rev-parse", "HEAD").stdout.strip(),
                "GITHUB_REPOSITORY": "example/test-repository",
                "GNUPGHOME": str(self.gpg_home),
            },
            check=False,
        )

    def assert_rejected(self, expected: str, head: str | None = None) -> None:
        result = self.verify(head)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_trusted_signed_commit_is_accepted(self) -> None:
        self.commit("Trusted change", change="trusted\n")
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unknown_signer_is_rejected(self) -> None:
        self.commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        self.assert_rejected("unverifiable GPG signature")

    def test_base_only_commits_are_not_validated(self) -> None:
        self.git("checkout", "-qb", "pull-request")
        head = self.commit("Trusted pull-request change", change="trusted\n")
        self.git("checkout", "-q", "master")
        advanced_base = self.commit("Unsigned base change", signed=False, change="base-only\n")
        result = self.verify(head=head, base=advanced_base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dry_run_reports_but_does_not_fail_policy_violation(self) -> None:
        (self.shared_key_directory / "config.yaml").write_text(
            "test-repository:\n  signers: [webexp]\n  dry: true\n", encoding="utf-8"
        )
        self.commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("::warning::", result.stdout + result.stderr)

    def test_dry_run_defaults_to_true(self) -> None:
        (self.shared_key_directory / "config.yaml").write_text(
            "test-repository:\n  signers: [webexp]\n", encoding="utf-8"
        )
        self.commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("::warning::", result.stdout + result.stderr)

    def test_no_policy_for_repository_is_rejected(self) -> None:
        result = self.command(
            sys.executable,
            str(self.verifier),
            env=os.environ | {
                "BASE_SHA": self.base,
                "HEAD_SHA": self.base,
                "GITHUB_REPOSITORY": "example/not-configured",
            },
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no signer policy is configured", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
