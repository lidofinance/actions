"""Git command helpers used by the verifier."""

from .commands import run_command
from .errors import VerificationError


def get_git_output(*args: str) -> str:
    """Run Git and return its standard output."""
    return run_command("git", *args).stdout


def resolve_commit_sha(value: str, name: str) -> str:
    """Resolve a user-supplied revision and require that it names a commit."""
    if not value:
        raise VerificationError(f"{name} is required")
    return get_git_output("rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}").strip()
