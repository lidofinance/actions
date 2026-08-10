"""Shared user-facing verification failures."""


class VerificationError(RuntimeError):
    """An error that should fail verification without a Python traceback."""
