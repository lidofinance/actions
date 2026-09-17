#!/usr/bin/env python3

import argparse
import re
from pathlib import Path


USES_PATTERN = re.compile(r"^\s*uses:\s*([^#\s]+)")
REMOTE_ACTION_PATTERN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
DOCKER_ACTION_PATTERN = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def check_file(path: Path) -> list[str]:
    errors = []

    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        match = USES_PATTERN.match(line)
        if not match:
            continue

        action = match.group(1)
        if action.startswith("./"):
            continue

        pattern = DOCKER_ACTION_PATTERN if action.startswith("docker://") else REMOTE_ACTION_PATTERN
        if not pattern.fullmatch(action):
            errors.append(
                f"::error file={path},line={line_number}::Action '{action}' must be pinned to a full commit SHA or image digest"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Require immutable references in GitHub Actions uses directives"
    )
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()

    errors = []
    for path in args.paths:
        errors.extend(check_file(path))

    if errors:
        print("\n".join(errors))
        return 1

    print(f"Checked immutable action references in {len(args.paths)} workflow files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
