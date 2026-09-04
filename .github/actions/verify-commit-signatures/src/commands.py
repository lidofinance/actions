"""Safe subprocess execution for the verification scripts."""

import subprocess


COMMAND_TIMEOUT_SECONDS = 300


class VerificationError(RuntimeError):
    """An error that should fail verification without a Python traceback."""


def run_command(*args: str, env: dict[str, str] | None = None,
                check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command and include useful output when it fails."""
    try:
        completed = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise VerificationError(
            f"{' '.join(args)} timed out after {COMMAND_TIMEOUT_SECONDS} seconds"
        ) from error
    except UnicodeDecodeError as error:
        raise VerificationError(f"{args[0]} returned non-UTF-8 output") from error
    except OSError as error:
        raise VerificationError(f"cannot run {args[0]}: {error}") from error
    if check and completed.returncode:
        output = (completed.stdout + completed.stderr).strip()
        raise VerificationError(f"{' '.join(args)} failed{': ' + output if output else ''}")
    return completed
