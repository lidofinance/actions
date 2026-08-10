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


ACTION_DIRECTORY = Path(__file__).parent
VERIFIER = ACTION_DIRECTORY / "verify_commit_signatures.py"


@unittest.skipUnless(shutil.which("git") and shutil.which("gpg"), "git and gpg are required")
class VerifyCommitSignaturesTest(unittest.TestCase):
    def setUp(self) -> None:
        """Create isolated keys, trusted-key configuration, and a Git fixture."""
        self.temporary = tempfile.TemporaryDirectory(prefix="verify-commit-signatures-test-")
        self.root = Path(self.temporary.name)
        self.gpg_home = self.root / "signing-gnupg"
        self.gpg_home.mkdir(mode=0o700)
        self.gpg_env = os.environ | {"GNUPGHOME": str(self.gpg_home)}
        self.trusted_fingerprint = self.generate_signing_key("Trusted signer <trusted@example.invalid>")
        self.unknown_fingerprint = self.generate_signing_key("Unknown signer <unknown@example.invalid>")

        implementation_directory = self.root / "implementation"
        implementation_directory.mkdir()
        self.verifier = implementation_directory / "verify_commit_signatures.py"
        shutil.copy2(VERIFIER, self.verifier)
        shutil.copytree(ACTION_DIRECTORY / "src", implementation_directory / "src")
        self.config_path = implementation_directory / "config.py"
        self.shared_key_directory = implementation_directory / "trusted-gpg-keys"
        self.shared_key_directory.mkdir()
        self.webexp_directory = self.shared_key_directory / "webexp"
        self.webexp_directory.mkdir()
        (self.webexp_directory / "trusted.asc").write_text(
            self.export_public_key(self.trusted_fingerprint), encoding="utf-8"
        )
        self.write_repository_policy()

        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.run_fixture_git("init", "-q")
        self.run_fixture_git("config", "user.name", "Verifier test")
        self.run_fixture_git("config", "user.email", "verifier@example.invalid")
        self.run_fixture_git("config", "user.signingkey", self.trusted_fingerprint)

        (self.repo / "README").write_text("base\n", encoding="utf-8")
        self.run_fixture_git("add", ".")
        self.run_fixture_git("-c", "commit.gpgsign=false", "commit", "-qm", "base")
        self.base = self.run_fixture_git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        """Remove the temporary test fixture."""
        self.temporary.cleanup()

    def run_fixture_command(self, *args: str, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run a fixture command and fail the test with its captured output."""
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

    def run_fixture_git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run Git against the fixture repository with its isolated GPG home."""
        return self.run_fixture_command("git", *args, env=self.gpg_env, check=check)

    def generate_signing_key(self, identity: str) -> str:
        """Generate one short-lived fixture signing key and return its fingerprint."""
        self.run_fixture_command(
            "gpg", "--batch", "--passphrase", "", "--quick-generate-key", identity, "rsa2048", "sign", "1d",
            env=self.gpg_env,
        )
        keys = self.run_fixture_command("gpg", "--batch", "--with-colons", "--list-keys", identity, env=self.gpg_env).stdout
        return next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))

    def export_public_key(self, fingerprint: str) -> str:
        """Export one fixture public key as ASCII armor."""
        return self.run_fixture_command(
            "gpg", "--batch", "--armor", "--export", fingerprint, env=self.gpg_env
        ).stdout

    def write_repository_policy(self, dry: bool | None = None) -> None:
        """Write a self-contained action configuration for this fixture."""
        dry_argument = "" if dry is None else f", dry={dry!r}"
        self.config_path.write_text(
            "from dataclasses import dataclass\n\n"
            "@dataclass(frozen=True)\n"
            "class RepositoryPolicy:\n"
            "    signers: tuple[str, ...]\n"
            "    dry: bool = False\n\n"
            f"REPOSITORIES = {{'test-repository': RepositoryPolicy(('webexp',){dry_argument})}}\n",
            encoding="utf-8",
        )

    def create_commit(self, message: str, *, signed: bool = True, signer: str | None = None, change: str | None = None) -> str:
        """Create a signed or unsigned fixture commit and return its SHA."""
        if change is not None:
            with (self.repo / "README").open("a", encoding="utf-8") as readme:
                readme.write(change)
        self.run_fixture_git("add", ".")
        command = ["commit", "--allow-empty", "-qm", message]
        if signed:
            command.insert(0, f"-c")
            command.insert(1, f"user.signingkey={signer or self.trusted_fingerprint}")
            command.insert(2, "-c")
            command.insert(3, "commit.gpgsign=true")
        else:
            command.insert(0, "-c")
            command.insert(1, "commit.gpgsign=false")
        self.run_fixture_git(*command)
        return self.run_fixture_git("rev-parse", "HEAD").stdout.strip()

    def run_verifier(self, head: str | None = None, base: str | None = None) -> subprocess.CompletedProcess[str]:
        """Run the action entrypoint for the fixture's selected commit range."""
        return self.run_fixture_command(
            sys.executable,
            str(self.verifier),
            env=os.environ | {
                "BASE_SHA": base or self.base,
                "HEAD_SHA": head or self.run_fixture_git("rev-parse", "HEAD").stdout.strip(),
                "GITHUB_REPOSITORY": "example/test-repository",
                "GNUPGHOME": str(self.gpg_home),
            },
            check=False,
        )

    def assert_verification_rejected(self, expected: str, head: str | None = None) -> None:
        """Assert that verification fails and emits the expected explanation."""
        result = self.run_verifier(head)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_trusted_signed_commit_is_accepted(self) -> None:
        """Accept a PR commit signed by the configured public key."""
        self.create_commit("Trusted change", change="trusted\n")
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unknown_signer_is_rejected(self) -> None:
        """Reject a PR commit signed by a key outside the allowed group."""
        self.create_commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        self.assert_verification_rejected("unverifiable GPG signature")

    def test_base_only_commits_are_not_validated(self) -> None:
        """Ignore unsigned commits introduced only by an advanced base branch."""
        self.run_fixture_git("checkout", "-qb", "pull-request")
        head = self.create_commit("Trusted pull-request change", change="trusted\n")
        self.run_fixture_git("checkout", "-q", "master")
        advanced_base = self.create_commit("Unsigned base change", signed=False, change="base-only\n")
        result = self.run_verifier(head=head, base=advanced_base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dry_run_reports_but_does_not_fail_policy_violation(self) -> None:
        """Report unknown signatures without failing when dry mode is explicit."""
        self.write_repository_policy(dry=True)
        self.create_commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("::warning::", result.stdout + result.stderr)

    def test_dry_run_defaults_to_false(self) -> None:
        """Enforce signature policy when the dry setting is omitted."""
        self.create_commit("Unknown change", signer=self.unknown_fingerprint, change="unknown\n")
        self.assert_verification_rejected("unverifiable GPG signature")

    def test_no_policy_for_repository_is_rejected(self) -> None:
        """Fail closed when no signer policy applies to a repository."""
        result = self.run_fixture_command(
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
