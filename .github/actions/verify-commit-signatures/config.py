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
    "linters": RepositoryPolicy(("secops",)),
    "tf-drift-mon-scan": RepositoryPolicy(("secops",)),
    "tf-drift-mon-image": RepositoryPolicy(("secops",)),
    "secops_release_sandbox": RepositoryPolicy(("secops",)),

    # Enable after each repository is ready for signature enforcement.
    # "action-gh-release": RepositoryPolicy(("secops",)),
    # "check-user-permission": RepositoryPolicy(("secops",)),
    # "conventional-changelog-action": RepositoryPolicy(("secops",)),
    # "create-pull-request": RepositoryPolicy(("secops",)),
    # "gh-find-current-pr": RepositoryPolicy(("secops",)),
    # "github-pages-action": RepositoryPolicy(("secops",)),
    # "hadolint-action": RepositoryPolicy(("secops",)),
}
