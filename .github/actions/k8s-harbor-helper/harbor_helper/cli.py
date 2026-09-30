from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Sequence

from harbor_helper.logic import (
    COMMANDS,
    WorkflowError,
    escape_workflow_command,
    write_outputs,
)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Security helper for the K8s Harbor reusable workflow"
    )
    parser.add_argument("command", choices=sorted(COMMANDS))
    parsed = parser.parse_args(arguments)

    try:
        outputs = COMMANDS[parsed.command](os.environ)
        output_path = os.environ.get("GITHUB_OUTPUT")
        if outputs and not output_path:
            raise WorkflowError("GITHUB_OUTPUT is required for this command")
        if outputs:
            write_outputs(outputs, Path(output_path))
    except WorkflowError as error:
        print(f"::error::{escape_workflow_command(str(error))}")
        return 1
    return 0
