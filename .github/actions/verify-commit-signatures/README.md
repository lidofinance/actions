# Verify commit signatures

This reusable workflow verifies every commit in the pull request range from the
merge base of `base_sha` and `head_sha` through `head_sha`. It does not validate
commits already in the target branch.
Every checked commit must have a valid GPG signature made by a currently present
public key in the repository's configured signer groups. There is no special
handling for seal commits or commit-message trailers.

Public keys and policy are part of this action, so callers cannot add a key with
workflow parameters. Store ASCII-armored keys under
`trusted-gpg-keys/<signer-group>/`; for example,
`trusted-gpg-keys/webexp/alice.asc` and
`trusted-gpg-keys/secops/github-web-flow.asc`.

`trusted-gpg-keys/config.yaml` maps repositories to authorized signer groups:

```yaml
landing:
  signers: [webexp, secops]
  dry: false
another-repository:
  signers:
    - devops
```

The workflow selects `owner/repository` when present in the config, otherwise
the short GitHub repository name (such as `landing`). `dry` is optional and
defaults to `true`. In dry mode, signature-policy violations are reported as
workflow warnings; malformed configuration or missing key material still fails
the workflow. Set `dry: false` to enforce the policy.

```yaml
name: Verify commit signatures

on:
  pull_request:

permissions:
  contents: read

jobs:
  verify-commit-signatures:
    uses: lidofinance/actions/.github/workflows/verify-commit-signatures.yml@<full-commit-sha>
```

This reusable workflow must be called from a `pull_request`-triggered workflow;
it reads the base and head SHAs from that event itself.

The verifier implementation is pinned in the reusable workflow itself. Changes
to that pin, the signer configuration, or key files remain security-sensitive and
should require the same review as other authentication-policy changes.
