from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence

from harbor_helper.common import WorkflowError


def git(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    allowed_returncodes: Sequence[int] = (0,),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in allowed_returncodes:
        detail = result.stderr.strip() or result.stdout.strip() or "no error output"
        raise WorkflowError(f"git {' '.join(arguments)} failed: {detail}")
    return result


def git_text(*arguments: str, cwd: Path | None = None) -> str:
    return git(arguments, cwd=cwd).stdout.strip()


def git_ref_exists(ref: str, *, cwd: Path | None = None) -> bool:
    return git(
        ["show-ref", "--verify", "--quiet", ref],
        cwd=cwd,
        allowed_returncodes=(0, 1),
    ).returncode == 0


def git_is_ancestor(ancestor: str, descendant: str, *, cwd: Path | None = None) -> bool:
    return git(
        ["merge-base", "--is-ancestor", ancestor, descendant],
        cwd=cwd,
        allowed_returncodes=(0, 1),
    ).returncode == 0


def validate_branch_name(branch: str) -> bool:
    return git(
        ["check-ref-format", "--branch", branch],
        allowed_returncodes=(0, 128),
    ).returncode == 0


def select_production_branch(*, cwd: Path | None = None) -> str:
    branches = [
        branch
        for branch in ("main", "master")
        if git_ref_exists(f"refs/remotes/origin/{branch}", cwd=cwd)
    ]
    if not branches:
        raise WorkflowError("Neither production branch main nor master exists")
    if len(branches) != 1:
        raise WorkflowError("Both production branches main and master exist; keep exactly one")
    return branches[0]
