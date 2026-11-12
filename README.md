# Common Actions and Workflows

This repo contains common actions and workflows for the Lido applications

> Sandbox-only branch: `test/sre-4380-python-prod-via-dev-rollout`, based on
> `fix/sre-4380-k8s-build-push-harbor-reusable-wf-python` at `9484823`.
> **Do not merge this branch into the release branch or main.** Only `target: prod`
> is redirected to `registry.dev.k8s-dev.org`, Environment `harbor_dev_release`,
> and `HARBOR_DEV_TOKEN`. The release tag, upstream/SHA/branch validation, and
> anti-rollback remain enabled. Other targets are unchanged; `critical` still
> requires its real critical Harbor credentials. This tests workflow behavior,
> not production Harbor pull prevention or other production infrastructure policy.

For this sandbox, keep `target: prod` in the release caller and change its
reusable workflow reference to:

```yaml
uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@test/sre-4380-python-prod-via-dev-rollout
```

Use a dedicated dev image repository (for example, `k8s-hello-python-rollout-test`)
so existing sandbox tags do not affect anti-rollback results. SecOps must provide
`REGISTRY_USERNAME` and `HARBOR_DEV_TOKEN` in `harbor_dev_release`, and DHI
credentials if the base image requires them. Environment deployment rules must
allow the caller repository's default branch. The mapping below reflects this
sandbox override; the remaining release policy is unchanged from its base branch.

## Workflows

- [`verify_commit_signatures.yml`](.github/actions/verify-commit-signatures/README.md)

### `prepare-release-draft.yml`

This workflow creates or updates a release draft for the current application version.
It should be triggered on a push to the `main` (or your variant) branch.

Example:

```yaml
name: Prepare release draft
on:
  push:
    branches:
      - main

permissions:
  contents: write

jobs:
  prepare-release-draft:
    uses: lidofinance/actions/.github/workflows/prepare-release-draft.yml@main
```

### `k8s-build-push-harbor.yml`

This reusable workflow validates application source, builds a Docker image, and
pushes it to the predefined Harbor registry for the selected target.

Security-sensitive validation and Harbor anti-rollback checks are implemented
in a standard-library-only Python helper. Its runtime and reusable action
revision are pinned, and its logic is covered by unit and workflow-contract
tests. The workflow YAML retains orchestration steps such as checkout, Docker
build, Trivy execution, registry login, and push.

It is intended to be called from application repositories through
`jobs.<job_id>.uses`. The caller selects the target, Harbor project, image name,
and Dockerfile. Registry addresses, GitHub Environment names, credential names,
source rules, and published image tags are controlled by the reusable workflow.

#### Inputs

| Name | Required | Description | Default |
|------|----------|-------------|---------|
| `target` | yes | One of `dev`, `staging`, `prod`, or `critical` | - |
| `tag` | for prod/critical | Published stable GitHub Release tag | `""` |
| `harbor_project` | yes | Team-owned Harbor project | - |
| `image` | yes | Image name inside the Harbor project; nested paths are supported | - |
| `dockerfile` | no | Dockerfile path relative to the repository root | `Dockerfile` |

`harbor_project` and `image` are separate values. For example,
`harbor_project: <harbor-project>` and `image: <image-name>` publish to
`<registry>/<harbor-project>/<image-name>:<tag>`.

`harbor_project` is the Harbor project assigned to the application team. It
normally follows the `team-<your_team_name>` naming convention.

#### Trusted target mapping

| Target | Registry | GitHub Environment | Image tag | Environment secret |
|--------|----------|--------------------|-----------|--------------------|
| `dev` | `registry.dev.k8s-dev.org` | `harbor_dev_release` | `dev` | `HARBOR_DEV_TOKEN` |
| `staging` | `registry.staging.k8s-staging.org` | `harbor_stage_release` | `staging` | `HARBOR_STAGE_TOKEN` |
| `prod` (sandbox) | `registry.dev.k8s-dev.org` | `harbor_dev_release` | release tag | `HARBOR_DEV_TOKEN` |
| `critical` | `registry.critical.k8s-prod.org` | `harbor_crit_release` | release tag | `HARBOR_CRIT_TOKEN` |

Each Environment must also provide `REGISTRY_USERNAME` as a GitHub Environment
variable. The caller grants the reusable workflow access to secrets with
`secrets: inherit`. The reusable workflow then selects the Environment and the
fixed token name for the requested target; the caller cannot choose either one.

#### Outputs

| Name | Description |
|------|-------------|
| `image_ref` | Published image reference, including its tag |
| `image_digest` | Published `sha256` image digest |

#### Source selection and validation

For `prod` and `critical`:

- the caller must use `workflow_run` after a successful workflow triggered by a
  published GitHub Release;
- the upstream workflow must be `.github/workflows/run_on_release.yaml` in the
  calling repository;
- the `workflow_run` caller must run from the repository's protected default
  branch;
- the `tag` input must use stable SemVer form such as `v1.2.3` or `1.2.3`;
- the tag must belong to an existing published, non-draft, non-prerelease GitHub
  Release;
- the workflow checks out the tag, not the branch head;
- the tagged commit must match the upstream `workflow_run.head_sha`;
- exactly one production source branch, `main` or `master`, must exist;
- the tagged commit must be contained in that production source branch;
- the tagged commit must not predate or diverge from any stable release already
  published to the target Harbor repository;
- the tag and GitHub Release are checked again before the build.

The branch that runs the trusted caller and the branch that contains production
source are intentionally independent. GitHub starts `workflow_run` from the
repository's default branch, which may have any valid name. The reusable
workflow verifies this relationship but checks the release commit against the
single existing `main` or `master` branch. If both production branch names exist
or neither exists, publication stops.

For rollback protection, the workflow reads stable SemVer tags from the target
Harbor repository after the image has been built and scanned, but before it is
pushed. Each existing Harbor tag must have a matching Git tag from the selected
production source branch, and its commit must be an ancestor of the candidate
commit. Missing or inconsistent history and Harbor authentication or API
failures stop publication. Changing a GitHub Release to prerelease therefore
cannot remove an already published image from the anti-rollback history.

For `dev` and `staging`, the workflow builds `github.sha` from the branch that
started the caller workflow. The `tag` input is forbidden. Access to the Harbor
credential is additionally limited by the deployment branch rules configured
on the corresponding GitHub Environment.

Before the Docker build, the workflow creates or replaces `build-info.json` in
the root of the isolated build context with the validated source information:

```json
{
  "version": "v1.2.3",
  "branch": "main",
  "commit": "0123456789abcdef0123456789abcdef01234567"
}
```

This preserves compatibility with applications that previously relied on the
legacy infrastructure workflow to populate this file before the build. Such
applications only need to copy `build-info.json` as part of their normal Docker
build context.

The same values are also passed as the `BUILD_VERSION`, `BUILD_BRANCH`, and
`BUILD_COMMIT` Docker build arguments. A Dockerfile that uses these arguments
must declare the corresponding `ARG` instructions. The workflow also adds the
standard OCI source, revision, and version labels.

#### Build and credential boundary

The caller cannot select the Docker build context. The workflow exports the
validated commit with `git archive` into an isolated temporary directory. This
context contains tracked repository files only and excludes `.git`, untracked
files, and the runner filesystem. The generated `build-info.json` is the only
file added or replaced in this context before the Docker build.

The selected Dockerfile must resolve to a regular file inside that isolated
context. Docker build runs before Harbor login, so an application-controlled
Dockerfile cannot copy the runner's Harbor Docker configuration into an image.
After a successful build, the workflow logs in to the target registry and pushes
the already-built local image.

Before building, it attempts a separate login to the fixed `dhi.io` registry
using secrets `DHI_USERNAME` and `DHI_TOKEN`. Use a read-only DHI access token,
available to the publish job through repository/organization secrets or its
selected Environment. Repository and Environment secrets are managed through
Terraform code by the SecOps team; request credential changes through that
process rather than configuring secrets manually. Neither value is passed as a
Docker build argument or copied into the build context. BuildKit uses DHI
authentication to pull bases; Harbor credentials remain unavailable to the build.

DHI login is best-effort during rollout, so missing or invalid DHI credentials
do not prevent non-DHI builds. A DHI base that requires authentication can still
fail the actual Docker build when credentials are absent or invalid.

The isolated context does not include Git submodule contents. Applications that
need submodules in the Docker build require additional workflow support.

#### DHI base-image policy

Before building, the helper checks the selected Dockerfile from the isolated
build context. It checks for `dhi.io/` references, including all
`FROM` stages, external `COPY --from` sources, and `RUN --mount=from` sources.
References to previous local stages are allowed. Global `ARG` defaults and the
three workflow-supplied build arguments are resolved for `FROM` instructions.

Mandatory DHI enforcement is temporarily paused for every target. The check
runs before building with `continue-on-error: true`: non-DHI references and
unsupported syntax remain visible, but do not block publication. Policy
preparation and artifact upload are also best-effort during this period.
Allowing images without a DHI base is a temporary rollout exception, not a
permanent relaxation of the base-image policy.
This conservative static check currently rejects heredocs, non-default escape
characters, custom Dockerfile frontends, advanced variable substitutions, and
variable image sources outside `FROM`. Use the standard Dockerfile frontend.
This is not a provenance guarantee: it does not verify image signatures, detect
arbitrary downloads in `RUN`, or certify registry mirrors as DHI images.

Reviewed exceptions are downloaded from `lidofinance/vex-db`, branch `main`,
file `policy/dhi-exceptions.json`. This source is fixed in the helper's
`harbor_helper/dhi_policy.py`; the caller cannot select another repository or
branch. The helper resolves `main` once per publish job to a commit SHA and
downloads the file at that exact commit, not from a moving branch URL.

If the repository or file does not exist, access is denied, the network fails,
or the response/policy is malformed, the helper emits a warning and uses an
empty exception list. Invalid documents are rejected in full, never partially
applied. Non-DHI images receive no exceptions, but advisory validation does not
block publication during the rollout. This fallback applies only to the DHI
exception list, not to Trivy's VEX repositories or vulnerability database.

Each exception must specify the exact caller repository, image reference (no
wildcards), allowed targets, reason, and expiry date (inclusive). For example:

```json
{
  "exceptions": [
    {
      "repository": "example/application",
      "targets": ["staging", "prod"],
      "image": "docker.io/example/legacy-base@sha256:<full-digest>",
      "reason": "Temporary exception while migrating this application to DHI",
      "expires": "2026-12-31"
    }
  ]
}
```

Replace `<full-digest>` with the actual 64-character digest. Exceptions match
the resolved reference exactly as written in the Dockerfile; prefer digest-pinned
references. `scratch` also requires an explicit exception (or use a suitable DHI
static base). Expired exceptions are not accepted by the check. Approved exceptions
are logged, and policy counts appear in the job summary. The effective policy
and a `source.json` record (repository, branch, resolved SHA, download/fallback
status) are uploaded as an artifact for 30 days before DHI validation. The SHA
and status also appear in the job summary. Each publish job gets its own uniquely
named snapshot.

Updating exceptions in the protected policy branch does not require a helper
release or caller changes; new builds pick up the reviewed list. Configure
branch protection and mandatory SecOps approval in Terraform. Renaming the
policy repository or branch requires changing the central helper constants.
The download uses optional `VEX_DB_READ_TOKEN`, falling back to the job's
`GITHUB_TOKEN`. For a private policy repository, provision `VEX_DB_READ_TOKEN`
as a read-only GitHub App/PAT token with Contents access to that repository and
make the secret available to callers. Without that access, the empty-list
fallback still applies. A missing or corrupt local snapshot is reported as a
validation error, but the advisory step does not stop publication. Callers
cannot supply an exception file. DHI exceptions do not suppress Trivy findings.

#### Vulnerability scanning

The locally built image is scanned with Trivy before Harbor login and push. The
scan covers OS and application library vulnerabilities, including vulnerabilities
without an available fix. A JSON report containing all severity levels is stored
as a workflow artifact for 30 days, and severity counts are written to the job
summary.

The scanner reads a `docker save` archive through `trivy image --input` without
access to the Docker socket. Only dedicated cache and report directories under
`RUNNER_TEMP/trivy` are mounted writable; the image archive and trusted VEX
configuration are mounted read-only. The image remains loaded in Docker for
publication without rebuilding. Both reusable workflow jobs use `ubuntu-24.04`.

Trivy uses its standard vulnerability database and applies VEX statements from
both Aqua VEX Hub and Docker Hardened Images advisories:

- `https://github.com/aquasecurity/vexhub`;
- `https://github.com/docker-hardened-images/advisories`.

The repository configuration is stored in the pinned helper action at
`.github/actions/k8s-harbor-helper/vex/repository.yaml`, independently of the
application checkout, and is mounted read-only into Trivy. Both enabled VEX
repositories are downloaded before scanning; a download failure makes the scan
unavailable, not clean.
The internal VEX entry points to `https://github.com/lidofinance/vex-db` but
remains disabled until that repository has a valid Trivy VEX index. To enable
it later, change `enabled` in this central configuration and update the helper
SHA. DHI exception downloads from that repository are independent of this flag.

Trivy is temporarily report-only for every target. Findings remaining after VEX
filtering are reported as follows:

| Target | HIGH or CRITICAL findings |
| --- | --- |
| `dev`, `staging`, `prod`, `critical` | Warning; publication continues. |

Allowing HIGH/CRITICAL findings through CI is a temporary rollout exception,
not the intended permanent publication policy.

Findings without an available fix are also reported. The JSON report is uploaded
before summarizing. VEX-suppressed findings are retained separately through
`--show-suppressed` and excluded from the active severity counts.

Preparation, scanning, report upload, and summary steps use
`continue-on-error: true`. A failed/skipped scan or invalid/missing report is
shown as **unavailable** in the summary, without inventing zero findings;
publication continues. There is no empty-VEX fallback presented as a valid scan.
The workflow sets `TRIVY_REPORT_ONLY=true`; the helper's strict mode remains
available for future enforcement. The CI scan does not apply Harbor CVE
allowlists. The official Trivy `v0.67.0` container is pinned by digest; the Harbor
scanner is not upgraded by this change.

Harbor policy is unchanged: CRITICAL vulnerabilities block image pulls in
staging, production, and critical; dev scans images without this pull block.
This is a pull-time control, not a CI push gate: a successful CI push does not
mean a vulnerable image can be deployed. HIGH findings do not imply the same
Harbor block under this CRITICAL-only policy.

Source validation, build failures, Harbor login, anti-rollback, and push remain
fatal.

#### Required repository and Harbor configuration

- Have SecOps provision the GitHub Environments and variables/secrets listed in
  the target mapping table through Terraform. This includes all Harbor registry
  secrets (`HARBOR_DEV_TOKEN`, `HARBOR_STAGE_TOKEN`, `HARBOR_PROD_TOKEN`, and
  `HARBOR_CRIT_TOKEN`) and the `REGISTRY_USERNAME` Environment variable.
  Repository and Environment secrets, including DHI credentials, follow the
  same managed process; do not provision registry credentials manually.
- Configure each Environment's deployment branch rules. Required reviewers are
  optional; the workflow itself does not require a manual approval.
- Allow only the repository's protected default branch to deploy through
  `harbor_prod_release` and `harbor_crit_release`. This may differ from the
  production source branch.
- Protect both reserved production branch names, `main` and `master`, against
  unauthorized creation, deletion, and force-push. Keep exactly one of them in
  each application repository.
- Enable Harbor tag immutability for production and critical repositories. The
  workflow does not use `docker manifest inspect` as an overwrite protection.
- Keep immutable production and critical images in Harbor. Their stable SemVer
  tags are the authoritative anti-rollback history used by the workflow.
- Protect release tags in GitHub against update and deletion. Restrict creation
  of release tag patterns to trusted maintainers or release automation.
- Scope each Harbor robot credential to the intended team project and target,
  with pull and push access to its repositories.

### Usage examples

#### Production or critical release image

Production uses two caller workflows. The first one runs for a published GitHub
Release and stores its tag as a short-lived artifact without access to Harbor
credentials.

```yaml
name: Run_on_release

on:
  release:
    types:
      - published

permissions:
  contents: read

jobs:
  save-release-tag:
    runs-on: ubuntu-22.04
    steps:
      - name: Validate and save stable release tag
        shell: bash
        env:
          RELEASE_DRAFT: ${{ github.event.release.draft }}
          RELEASE_PRERELEASE: ${{ github.event.release.prerelease }}
          RELEASE_TAG: ${{ github.event.release.tag_name }}
        run: |
          set -euo pipefail

          if [[ "$RELEASE_DRAFT" != "false" || "$RELEASE_PRERELEASE" != "false" ]]; then
            echo "::error::Only published stable releases can start a production build"
            exit 1
          fi

          if [[ ! "$RELEASE_TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "::error::Release tag must use stable SemVer such as v1.2.3 or 1.2.3"
            exit 1
          fi

          printf '%s\n' "$RELEASE_TAG" > release_tag.txt

      - name: Upload release tag
        uses: actions/upload-artifact@<full-commit-sha>
        with:
          name: production-release-tag
          path: release_tag.txt
          if-no-files-found: error
          retention-days: 1
```

The second workflow starts from the protected default branch after the first
workflow succeeds. It downloads and validates the exact artifact from the
triggering run, then passes the tag to the reusable workflow.

```yaml
name: triggered_release

on:
  workflow_run:
    workflows:
      - Run_on_release
    types:
      - completed

permissions: {}

jobs:
  release-tag:
    if: ${{ github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'release' }}
    runs-on: ubuntu-22.04
    permissions:
      actions: read
    outputs:
      tag: ${{ steps.release.outputs.tag }}
    steps:
      - name: Download release tag
        uses: actions/download-artifact@<full-commit-sha>
        with:
          name: production-release-tag
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          path: ${{ runner.temp }}/release-artifact

      - name: Validate release tag
        id: release
        shell: bash
        env:
          TAG_FILE: ${{ runner.temp }}/release-artifact/release_tag.txt
        run: |
          set -euo pipefail

          if [[ ! -f "$TAG_FILE" || -L "$TAG_FILE" ]]; then
            echo "::error::Release tag artifact is not a regular file"
            exit 1
          fi

          mapfile -t lines < "$TAG_FILE"
          if [[ "${#lines[@]}" -ne 1 || ! "${lines[0]}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "::error::Release tag artifact must contain exactly one stable SemVer tag"
            exit 1
          fi

          echo "tag=${lines[0]}" >> "$GITHUB_OUTPUT"

  build:
    needs: release-tag
    permissions:
      contents: read
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main
    with:
      target: prod
      tag: ${{ needs.release-tag.outputs.tag }}
      harbor_project: <harbor-project>
      image: <image-name>
      # dockerfile: path/to/Dockerfile
    secrets: inherit
```

For the critical registry, use the same caller with `target: critical`.

#### Development image

This example publishes the mutable `dev` tag from `develop`. The
`harbor_dev_release` Environment must allow the same branch.

```yaml
name: Build development image

run-name: Build development image from ${{ github.ref_name }}

on:
  workflow_dispatch:
  push:
    branches:
      - develop
    paths-ignore:
      - ".github/**"
      - "test/**"

permissions:
  contents: read

jobs:
  build:
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main
    with:
      target: dev
      harbor_project: <harbor-project>
      image: <image-name>
      # dockerfile: path/to/Dockerfile
    secrets: inherit
```

#### Staging image

Staging uses the same branch-based flow. This example publishes the mutable
`staging` tag from `main`.

```yaml
name: Build staging image

run-name: Build staging image from ${{ github.ref_name }}

on:
  workflow_dispatch:
  push:
    branches:
      - main
    paths-ignore:
      - ".github/**"
      - "test/**"

permissions:
  contents: read

jobs:
  build:
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main
    with:
      target: staging
      harbor_project: <harbor-project>
      image: <image-name>
      # dockerfile: path/to/Dockerfile
    secrets: inherit
```

### Notes

Development and staging use mutable `dev` and `staging` image tags. Production
and critical use the supplied immutable release tag.

The current build loads a single-platform image into the local Docker daemon
before publishing. Multi-platform builds require a different publish design.

The Harbor caller templates temporarily use this reusable workflow at `@main`
during rollout. This is not the permanent pinning policy: after stabilization,
replace it with a reviewed full commit SHA retained in the target branch.
Deploy those callers only after the updated workflow is merged into
`actions/main`. Changes to that protected branch must be reviewed; during this
period callers trust its changing contents. Internal helper actions and
third-party actions remain pinned to full commit SHAs.

`secrets: inherit` grants the called workflow access to secrets available to the
caller. Use it only with the trusted reusable workflow from protected
`lidofinance/actions/main`. The workflow references only the fixed Harbor token
name selected for the requested target and never passes that token to the
Docker build.

## Actions

### `validate-inputs`

Validates GitHub workflow inputs against a basic character allowlist.

This action can reject common shell metacharacters in user-controlled inputs. It
does not validate the grammar or authorization rules of a particular field and
must not be treated as sufficient validation for Docker tags, image names,
registry addresses, filesystem paths, or other security-sensitive values.

The action expects workflow inputs serialized as JSON.

Example:

```yaml
- name: Validate inputs
  uses: lidofinance/actions/.github/actions/validate-inputs@<full-commit-sha>
  with:
    inputs: ${{ toJSON(inputs) }}
```

For pull request testing, use the feature branch instead of `main` until the action is merged:

```yaml
- name: Validate inputs
  uses: lidofinance/actions/.github/actions/validate-inputs@<full-commit-sha>
  with:
    inputs: ${{ toJSON(inputs) }}
```

#### Example in a reusable workflow

```yaml
name: Example reusable workflow

on:
  workflow_call:
    inputs:
      tag:
        required: true
        type: string
      image:
        required: true
        type: string

jobs:
  example:
    runs-on: ubuntu-22.04
    steps:
      - name: Validate inputs
        uses: lidofinance/actions/.github/actions/validate-inputs@<full-commit-sha>
        with:
          inputs: ${{ toJSON(inputs) }}
```

#### Allowed characters

The current validation pattern is:

```text
^[\d\w.,\-/]+$
```

Allowed characters include letters, numbers, underscore, dot, comma, dash and slash.

Inputs containing shell metacharacters such as quotes, semicolons, dollar signs, spaces, or command substitutions will be rejected.

Comma is intentionally accepted by this generic action, but several GitHub
Actions parse comma-containing inputs as lists. Callers must add field-specific
validation that rejects comma whenever a value must represent exactly one tag,
image, path, or destination. The Harbor reusable workflow implements its own
field-specific validation and does not use this generic action.

For other workflows and actions, prefer full commit SHAs for reproducibility.
The documented exception is the centrally managed Harbor reusable workflow at
`lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main`.
