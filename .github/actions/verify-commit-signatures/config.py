"""Repository signer groups."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryPolicy:
    """Signer groups authorized for one repository."""

    signers: tuple[str, ...]
    dry: bool = False


REPOSITORIES = {
    # Repositories currently enforced with the SecOps signer group.
    "blacklist-monitoring": RepositoryPolicy(("secops",)),
    "tf-drift-mon-scan": RepositoryPolicy(("secops",)),
    "tf-drift-mon-image": RepositoryPolicy(("secops",)),
    "secops_release_sandbox": RepositoryPolicy(("secops",)),
}
