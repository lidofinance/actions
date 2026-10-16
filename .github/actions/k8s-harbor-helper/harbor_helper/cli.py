from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Sequence

from harbor_helper.build import (
    populate_build_info,
    prepare_context,
    resolve_image_digest,
)
from harbor_helper.common import WorkflowError, escape_workflow_command, write_outputs
from harbor_helper.config import configure
from harbor_helper.dockerfile import check_dhi
from harbor_helper.dhi_policy import prepare_dhi_policy
from harbor_helper.harbor import check_rollback
from harbor_helper.release import (
    revalidate_release,
    validate_published_release,
    validate_source,
)
from harbor_helper.trivy import prepare_trivy, summarize_trivy


COMMANDS = {
    "check-dhi": check_dhi,
    "check-rollback": check_rollback,
    "configure": configure,
    "populate-build-info": populate_build_info,
    "prepare-context": prepare_context,
    "prepare-dhi-policy": prepare_dhi_policy,
    "prepare-trivy": prepare_trivy,
    "resolve-image-digest": resolve_image_digest,
    "revalidate-release": revalidate_release,
    "summarize-trivy": summarize_trivy,
    "validate-release": validate_published_release,
    "validate-source": validate_source,
}


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
