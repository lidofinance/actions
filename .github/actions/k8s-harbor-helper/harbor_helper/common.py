from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping


OUTPUT_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class WorkflowError(RuntimeError):
    """Expected validation failure that should fail the workflow closed."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    payload: object


HttpGetter = Callable[[str, Mapping[str, str]], HttpResponse]


def required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise WorkflowError(f"Required environment variable {name} is empty")
    return value


def default_http_get(url: str, headers: Mapping[str, str]) -> HttpResponse:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
    except urllib.error.URLError as error:
        raise WorkflowError(f"HTTP request failed: {error.reason}") from error

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkflowError(
            f"HTTP endpoint returned invalid JSON with status {status}"
        ) from error
    return HttpResponse(status=status, payload=payload)


def write_outputs(outputs: Mapping[str, str], output_path: Path) -> None:
    with output_path.open("a") as output_file:
        for name, value in outputs.items():
            if OUTPUT_NAME_PATTERN.fullmatch(name) is None:
                raise WorkflowError(f"Invalid workflow output name '{name}'")
            if "\n" in value or "\r" in value:
                raise WorkflowError(f"Workflow output '{name}' contains a newline")
            output_file.write(f"{name}={value}\n")


def escape_workflow_command(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
