"""Conservative, non-executing checks of Dockerfile image references.

This is not a general Dockerfile parser or an image provenance verifier. Syntax
that cannot be resolved safely is rejected rather than silently ignored.
"""

from __future__ import annotations

import csv
import json
import re
import shlex
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Mapping

from harbor_helper.common import WorkflowError, escape_workflow_command, required
from harbor_helper.config import TARGETS


VARIABLE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
IMAGE = re.compile(
    r"[a-z0-9]+(?:[._:-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?(?:@sha256:[0-9a-f]{64})?"
)
FRONTEND = re.compile(
    r"(?:docker.io/)?docker/dockerfile:1(?:\.[0-9]+){0,2}"
    r"(?:@sha256:[0-9a-f]{64})?"
)


@dataclass(frozen=True)
class ImageReference:
    image: str
    line: int
    instruction: str


def _expand(value: str, variables: Mapping[str, str], line: int) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in variables:
            raise WorkflowError(f"Dockerfile line {line}: unresolved image ARG {name}")
        return variables[name]

    expanded = VARIABLE.sub(replace, value)
    if "$" in expanded:
        raise WorkflowError(f"Dockerfile line {line}: unsupported image ARG expression")
    return expanded


def _instructions(text: str) -> list[tuple[int, str, str]]:
    instructions = []
    pending = ""
    start = 0
    # Docker also strips a UTF-8 BOM before interpreting parser directives.
    for number, raw in enumerate(text.removeprefix("\ufeff").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            directive = re.fullmatch(r"#\s*(escape|syntax)\s*=\s*(\S+)\s*", line, re.I)
            if directive:
                key, value = directive.groups()
                if key.lower() == "escape" and value != "\\":
                    raise WorkflowError(
                        "DHI check supports only the default Dockerfile escape"
                    )
                if key.lower() == "syntax" and FRONTEND.fullmatch(value) is None:
                    raise WorkflowError("DHI check requires the standard Dockerfile frontend")
            continue
        if not pending:
            start = number
        continued = line.endswith("\\")
        pending += line[:-1] if continued else line
        if continued:
            continue
        # Reject heredocs instead of mistaking their bodies for instructions.
        if "<<" in pending or "\x00" in pending:
            raise WorkflowError(
                f"Dockerfile line {start}: heredocs or NUL bytes are not supported by the DHI check"
            )
        parts = pending.split(None, 1)
        if len(parts) != 2:
            raise WorkflowError(f"Dockerfile line {start}: missing instruction arguments")
        instructions.append((start, parts[0].upper(), parts[1]))
        pending = ""
    if pending:
        raise WorkflowError("Dockerfile ends with an unfinished continuation")
    return instructions


def image_references(text: str, build_args: Mapping[str, str]) -> list[ImageReference]:
    """Resolve global ARGs and inspect every stage, including unused stages."""
    references = []
    variables: dict[str, str] = {}
    aliases: set[str] = set()
    stages = 0

    def add(image: str, line: int, instruction: str, *, allow_index: bool = False) -> None:
        if instruction == "FROM":
            image = _expand(image, variables, line)
        elif "$" in image:
            # Stage-local ARG/ENV scope is intentionally not approximated.
            raise WorkflowError(
                f"Dockerfile line {line}: variable image sources are supported only in FROM"
            )
        if image.lower() in aliases:
            return
        if allow_index and image.isdecimal():
            if int(image) >= stages:
                raise WorkflowError(f"Dockerfile line {line}: invalid stage index {image}")
            return
        if IMAGE.fullmatch(image) is None:
            raise WorkflowError(f"Dockerfile line {line}: invalid image reference {image!r}")
        references.append(ImageReference(image, line, instruction))

    for line, instruction, value in _instructions(text):
        if instruction == "ARG" and stages == 0:
            name, separator, default = value.partition("=")
            name = name.strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
                raise WorkflowError(f"Dockerfile line {line}: invalid global ARG")
            if name in build_args:
                variables[name] = build_args[name]
            elif separator:
                # Docker ARG defaults may be quoted, but are never executed.
                try:
                    words = shlex.split(default)
                except ValueError as error:
                    raise WorkflowError(f"Dockerfile line {line}: invalid ARG default") from error
                variables[name] = _expand(" ".join(words), variables, line)
            continue

        if instruction not in {"FROM", "COPY", "ADD", "RUN"}:
            continue
        if instruction == "FROM":
            try:
                words = shlex.split(value)
            except ValueError as error:
                raise WorkflowError(f"Dockerfile line {line}: invalid FROM") from error
            if words and words[0].startswith("--platform="):
                words.pop(0)
            if not words or len(words) not in {1, 3}:
                raise WorkflowError(f"Dockerfile line {line}: unsupported FROM syntax")
            add(words[0], line, instruction)
            if len(words) == 3:
                if (
                    words[1].upper() != "AS"
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", words[2]) is None
                ):
                    raise WorkflowError(f"Dockerfile line {line}: invalid stage alias")
                aliases.add(words[2].lower())
            stages += 1
            continue

        # Only leading Dockerfile flags are relevant; shell commands and JSON
        # bodies are not interpreted. Docker requires --flag=value syntax here.
        lexer = shlex.shlex(value, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            for flag in lexer:
                if not flag.startswith("--"):
                    break
                key, separator, argument = flag.partition("=")
                if not separator:
                    raise WorkflowError(
                        f"Dockerfile line {line}: unsupported Dockerfile flag {flag}"
                    )
                key = key.lower()
                if key == "--from" and instruction in {"COPY", "ADD"}:
                    add(argument, line, instruction, allow_index=True)
                if key == "--mount" and instruction == "RUN":
                    options = next(
                        csv.reader([argument], strict=True, skipinitialspace=True)
                    )
                    for option in options:
                        name, _, source = option.partition("=")
                        if name.strip().lower() == "from":
                            add(source, line, instruction, allow_index=True)
        except (ValueError, csv.Error) as error:
            raise WorkflowError(f"Dockerfile line {line}: invalid Dockerfile flags") from error
    if stages == 0:
        raise WorkflowError("Dockerfile has no FROM instruction")
    return references


def validate_exceptions(policy: object) -> list[dict]:
    if (
        not isinstance(policy, dict)
        or set(policy) != {"exceptions"}
        or not isinstance(policy["exceptions"], list)
    ):
        raise WorkflowError("Invalid trusted DHI exceptions policy")
    for entry in policy["exceptions"]:
        if not isinstance(entry, dict) or set(entry) != {
            "repository", "targets", "image", "reason", "expires",
        }:
            raise WorkflowError("Invalid DHI exception fields")
        if (
            not isinstance(entry["repository"], str)
            or re.fullmatch(
                r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", entry["repository"]
            ) is None
            or not isinstance(entry["image"], str)
            or IMAGE.fullmatch(entry["image"]) is None
            or not isinstance(entry["targets"], list)
            or not entry["targets"]
            or any(
                not isinstance(target, str) or target not in TARGETS
                for target in entry["targets"]
            )
            or not isinstance(entry["reason"], str)
            or not entry["reason"].strip()
            or not isinstance(entry["expires"], str)
        ):
            raise WorkflowError("Invalid DHI exception values")
        try:
            if date.fromisoformat(entry["expires"]).isoformat() != entry["expires"]:
                raise ValueError("Expected YYYY-MM-DD")
        except ValueError as error:
            raise WorkflowError("Invalid DHI exception expiry date") from error
    return policy["exceptions"]


def _load_exceptions(path: Path) -> list[dict]:
    try:
        policy = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise WorkflowError("Cannot read prepared DHI exceptions policy") from error
    return validate_exceptions(policy)


def check_dhi(
    environment: Mapping[str, str],
    *,
    policy_path: Path | None = None,
    today: date | None = None,
) -> dict[str, str]:
    target = required(environment, "TARGET")
    if target not in TARGETS:
        raise WorkflowError(f"Unknown DHI policy target '{target}'")
    repository = required(environment, "GITHUB_REPOSITORY")
    # The prepare step always writes a validated snapshot, including an empty
    # one when downloading fails. A missing/corrupted snapshot is a wiring error.
    if policy_path is None:
        policy_path = Path(required(environment, "DHI_POLICY"))
    exceptions = _load_exceptions(policy_path)
    today = today or date.today()
    build_args = {
        name: required(environment, name)
        for name in ("BUILD_VERSION", "BUILD_BRANCH", "BUILD_COMMIT")
    }
    try:
        text = Path(required(environment, "DOCKERFILE")).read_text()
    except (OSError, UnicodeError) as error:
        raise WorkflowError("Cannot read Dockerfile for DHI validation") from error
    findings = []
    approved = []
    try:
        references = image_references(text, build_args)
        for reference in references:
            if reference.image.startswith("dhi.io/"):
                continue
            exception = next(
                (
                    entry for entry in exceptions
                    if entry["repository"].lower() == repository.lower()
                    and target in entry["targets"]
                    and entry["image"] == reference.image
                    and date.fromisoformat(entry["expires"]) >= today
                ),
                None,
            )
            detail = f"line {reference.line} {reference.instruction}: {reference.image}"
            if exception:
                approved.append(
                    f"{detail} (exception until {exception['expires']}: {exception['reason']})"
                )
            else:
                findings.append(f"{detail} is not a DHI image or an active approved exception")
    except WorkflowError as error:
        findings.append(str(error))

    for detail in approved:
        print(f"Approved DHI exception: {escape_workflow_command(detail)}")
    summary_path = environment.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a") as summary:
            summary.write("\n### DHI base-image policy\n\n")
            summary.write(
                f"Target: `{target}`. Findings: {len(findings)}. "
                f"Approved exceptions: {len(approved)}.\n"
            )
    if findings:
        for finding in findings:
            print(f"::warning::{escape_workflow_command('DHI: ' + finding)}")
        if target != "dev":
            raise WorkflowError(f"DHI base-image policy blocks publication to {target}")
    else:
        print("All Dockerfile image references use DHI or active approved exceptions")
    return {}
