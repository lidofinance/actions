#!/usr/bin/env python3

import argparse
import re
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

REMOTE_ACTION_PATTERN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
DOCKER_ACTION_PATTERN = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def uses_entries(node: Node) -> list[tuple[int, str | None]]:
    entries = []

    if isinstance(node, MappingNode):
        for key, value in node.value:
            if isinstance(key, ScalarNode) and key.value == "uses":
                action = value.value if isinstance(value, ScalarNode) else None
                entries.append((key.start_mark.line + 1, action))
            entries.extend(uses_entries(value))
    elif isinstance(node, SequenceNode):
        for item in node.value:
            entries.extend(uses_entries(item))

    return entries


def check_file(path: Path) -> list[str]:
    errors = []

    try:
        documents = yaml.compose_all(path.read_text(), Loader=yaml.SafeLoader)
        entries = [
            entry
            for document in documents
            if document
            for entry in uses_entries(document)
        ]
    except (OSError, yaml.YAMLError) as error:
        detail = " ".join(str(error).splitlines())
        return [f"::error file={path}::Could not parse workflow YAML: {detail}"]

    for line_number, action in entries:
        if action is None:
            errors.append(
                f"::error file={path},line={line_number}::"
                "Action reference must be a scalar value"
            )
            continue
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
