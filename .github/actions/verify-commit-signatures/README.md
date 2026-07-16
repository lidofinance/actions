# Verify commit signatures

This reusable workflow verifies every commit introduced by a pull request. A
commit must be signed with one of the configured public keys. Shared trusted
keys are ASCII-armored `.asc` files in `trusted-gpg-keys/` in this directory;
they are loaded from the same pinned implementation revision as the verifier. Put
GitHub web-flow's public `.asc` file there when accepting web-flow commits.

It supports [Argo CD strict-mode seal commits](https://argo-cd.readthedocs.io/en/latest/user-guide/source-integrity-git-gpg/):
an empty, single-parent, signed commit containing one non-empty
`Argocd-gpg-seal: <justification>` trailer approves its complete parent graph.
The commit's signature binds its parent SHA, so the seal cannot be moved to a
different history.

Caller-provided key paths are read from the pull request's **base commit**, not
its working tree. Store any caller-specific `.asc` files and the workflow under
protected, code-owned paths. This lets a repository add keys for external
contributors without allowing a pull request to trust a key by editing its
working-tree copy.

```yaml
name: Verify commit signatures

on:
  pull_request:

permissions:
  contents: read

jobs:
  verify-commit-signatures:
    uses: lidofinance/actions/.github/workflows/verify-commit-signatures.yml@<full-commit-sha>
    with:
      base_sha: ${{ github.event.pull_request.base.sha }}
      head_sha: ${{ github.event.pull_request.head.sha }}
      # Optional public keys for approved external contributors.
      additional_gpg_pubkeys: |
        .github/gpg-keys/external/contributor.asc
```

The verifier implementation is pinned in the reusable workflow itself. Changes
to that pin, the caller workflow, or key files remain security-sensitive and
should require the same review as other authentication-policy changes.
