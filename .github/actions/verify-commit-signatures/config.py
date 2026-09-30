"""Repository signer groups."""

from dataclasses import dataclass


# Public key source: https://github.com/web-flow.gpg
GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS = frozenset({
    "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23",
    "968479A1AFF927E37D1A566BB5690EEEBB952194",
})


@dataclass(frozen=True)
class RepositoryPolicy:
    """Signer groups authorized for one repository."""

    signers: tuple[str, ...]


REPOSITORIES = {
    # Repositories whose access is restricted to SecOps team.
    "blacklist-monitoring": RepositoryPolicy(signers=("secops",)),
    "tf-drift-mon-scan": RepositoryPolicy(signers=("secops",)),
    "tf-drift-mon-image": RepositoryPolicy(signers=("secops",)),
    "secops_release_sandbox": RepositoryPolicy(signers=("secops",)),

    # Repositories whose access is restricted to DevOps team.
    "ansible-blackbox-infra": RepositoryPolicy(signers=("devops",)),
    "ansible-collection-server": RepositoryPolicy(signers=("devops",)),
    "ansible-gitlab-infra": RepositoryPolicy(signers=("devops",)),
    "ansible-k8s-infra": RepositoryPolicy(signers=("devops",)),
    "ansible-vpn-infra": RepositoryPolicy(signers=("devops",)),
    "cf-records-backup": RepositoryPolicy(signers=("devops",)),
    "ci-image": RepositoryPolicy(signers=("devops",)),
    "helm-charts-infra": RepositoryPolicy(signers=("devops",)),
    "infra-external-deps-mirror": RepositoryPolicy(signers=("devops",)),
    "infra-teleport": RepositoryPolicy(signers=("devops",)),
    "ipfs-repinner": RepositoryPolicy(signers=("devops",)),
    "k8s-hello": RepositoryPolicy(signers=("devops",)),
    "k8s-infra": RepositoryPolicy(signers=("devops",)),
    "lido-hello": RepositoryPolicy(signers=("devops",)),
    "onchain-mon-bots-template": RepositoryPolicy(signers=("devops",)),
    "test-ansible-collection-core": RepositoryPolicy(signers=("devops",)),
    "test-ansible-collection-private": RepositoryPolicy(signers=("devops",)),
    "test-ansible-downstream": RepositoryPolicy(signers=("devops",)),
    "tf-blackbox-infra": RepositoryPolicy(signers=("devops",)),
    "tf-docker-hub": RepositoryPolicy(signers=("devops",)),
    "tf-gcp-gitlab-infra": RepositoryPolicy(signers=("devops",)),
    "tf-gcp-infra": RepositoryPolicy(signers=("devops",)),
    "tf-grafana-cloud": RepositoryPolicy(signers=("devops",)),
    "tf-module-gcp-vm": RepositoryPolicy(signers=("devops",)),
    "tf-module-openstack-vm": RepositoryPolicy(signers=("devops",)),
    "tf-onchain-mon-infra": RepositoryPolicy(signers=("devops",)),
    "tf-openstack-gitlab-infra": RepositoryPolicy(signers=("devops",)),
    "tf-openstack-infra": RepositoryPolicy(signers=("devops",)),
    "tf-ovh-infra": RepositoryPolicy(signers=("devops",)),
    "tf-vpn-infra": RepositoryPolicy(signers=("devops",)),

    # Repositories whose access is restricted to DevOps or SecOps teams.
    "harbor-helm": RepositoryPolicy(signers=("devops", "secops")),
    "helm-charts-devops": RepositoryPolicy(signers=("devops", "secops")),
    "helm-charts-secops": RepositoryPolicy(signers=("devops", "secops")),
    "tf-github-policies": RepositoryPolicy(signers=("devops", "secops")),
}
