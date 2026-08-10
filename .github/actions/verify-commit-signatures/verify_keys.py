#!/usr/bin/env python3
"""Validate the lifecycle policy of trusted GPG public keys."""

import os
import sys
import tempfile
import time
from pathlib import Path

from config import REPOSITORIES
from src.errors import VerificationError
from src.git import resolve_commit_sha
from src.verify_keys import Finding, build_key_snapshot, collect_policy_findings, materialize_base_key_root, render_report


def main() -> int:
    """Analyze head and base public-key trees, then write a policy report."""
    key_root = Path(__file__).with_name("trusted-gpg-keys")
    try:
        base_sha = resolve_commit_sha(os.environ.get("BASE_SHA", ""), "BASE_SHA")
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
