# Verify commit signatures

This reusable workflow verifies every commit in the pull request range from the
merge base of `base_sha` and `head_sha` through `head_sha`. It does not validate
commits already in the target branch.
Every checked commit must have a valid GPG signature made by a currently present
public key in the repository's configured signer groups. There is no special
handling for seal commits or commit-message trailers.

Public keys and policy are part of this action, so callers cannot add a key with
workflow parameters. Store ASCII-armored keys under
`trusted-gpg-keys/<signer-group>/<member>.asc`; for example,
`trusted-gpg-keys/webexp/alice.asc` and
`trusted-gpg-keys/secops/github-web-flow.asc`.

`config.py`, beside the action entrypoints, declares repositories and their
authorized signer groups:

```python
REPOSITORIES = {
    "landing": RepositoryPolicy(("webexp", "secops")),
    "another-repository": RepositoryPolicy(("devops",), dry=True),
}
```

The workflow selects `owner/repository` when present in the config, otherwise
the short GitHub repository name (such as `landing`). `dry` is optional and
defaults to `False`. In dry mode, signature-policy violations are reported as
workflow warnings; malformed configuration or missing key material still fails
the workflow. Set `dry=True` to report violations without failing.

```yaml
name: Verify commit signatures

on:
  pull_request:

permissions:
  contents: read

jobs:
  verify_commit_signatures:
    uses: lidofinance/actions/.github/workflows/verify_commit_signatures.yml@<full-commit-sha>
```

This reusable workflow must be called from a `pull_request`-triggered workflow;
it reads the base and head SHAs from that event itself.

The reusable workflow deliberately pins the verifier implementation. Changes to
this action take effect for callers only after that pin is updated. Changes to
the pin, signer configuration, or key files remain security-sensitive and
should require the same review as other authentication-policy changes.

## Public-key policy

`verify_keys.yml` runs on pull requests that change this verifier, its workflow,
or trusted key material. Each key export path is the stable contributor
identity, for example `trusted-gpg-keys/secops/nikita.k.asc`; exports must not
contain private key material. During a master-key rotation, retain the old and
new primary keys in that same file. A primary-key change in one export must
preserve at least one name/email UID with the base export. The checker reports
the change for SecOps review and does not reject it solely because the
fingerprint changed.

The policy requires a non-expiring primary key and signing subkeys valid for at
most one year. Expired or retired signing subkeys do not count as active; their
additions, removals, and status changes are reported when a key export changes.
Active signing subkeys are capped at two normally and four during a rotation.
Any active keys beyond two must expire within the next 30 days. Errors fail the
workflow; warnings are included in the job summary and pull-request comment.
The checker also warns when an export has any number other than two active
signing or encryption subkeys, or when its primary or active signing keys do not use
EdDSA, as recommended by the GPG signing guide.
