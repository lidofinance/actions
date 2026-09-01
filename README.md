# Common Actions and Workflows

This repo contains common actions and workflows for the Lido applications

## Workflows

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
| `prod` | `registry.prod.k8s-prod.org` | `harbor_prod_release` | release tag | `HARBOR_PROD_TOKEN` |
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

- the caller must use `workflow_dispatch` and the run must be dispatched from
  the `main` branch;
- the `tag` input must use stable SemVer form such as `v1.2.3` or `1.2.3`;
- the tag must belong to an existing published, non-draft, non-prerelease GitHub
  Release;
- the workflow checks out the tag, not the branch head;
- the tagged commit must be contained in `main`;
- the tagged commit must not predate or diverge from the latest other stable
  GitHub Release;
- the tag and GitHub Release are checked again before the build.

The production source branch is intentionally fixed to `main` and does not
follow `github.event.repository.default_branch`. If `main` does not exist, the
workflow stops with a message asking the repository owner to create or rename
the production branch.

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

The isolated context does not include Git submodule contents. Applications that
need submodules in the Docker build require additional workflow support.

#### Vulnerability scanning

The locally built image is scanned with Trivy before Harbor login and push. The
scan covers OS and application library vulnerabilities, including vulnerabilities
without an available fix. A JSON report containing all severity levels is stored
as a workflow artifact for 30 days, and severity counts are written to the job
summary.

Vulnerability scanning is currently report-only for every target. Findings do
not block publication to `dev`, `staging`, `prod`, or `critical`. Blocking can be
enabled after CI and Harbor use a shared CVE allowlist.

Failure to run Trivy or produce a valid report stops publication for every
target. The CI scan uses raw Trivy findings and does not apply Harbor system or
project CVE allowlists. The official Trivy container is pinned by digest at
version `v0.62.1` to match the scanner version used by Harbor.

Harbor automatic scanning and pull prevention remain required. The pre-push CI
scan provides earlier feedback, while Harbor continues to enforce its configured
vulnerability policy for published images.

#### Required repository and Harbor configuration

- Create the GitHub Environments and variables/secrets listed in the target
  mapping table.
- Configure each Environment's deployment branch rules. Required reviewers are
  optional; the workflow itself does not require a manual approval.
- Allow only `main` to deploy through `harbor_prod_release` and
  `harbor_crit_release`.
- Enable Harbor tag immutability for production and critical repositories. The
  workflow does not use `docker manifest inspect` as an overwrite protection.
- Protect release tags in GitHub against update and deletion. Restrict creation
  of release tag patterns to trusted maintainers or release automation.
- Scope each Harbor robot credential to the intended team project and target.

### Usage examples

#### Production or critical release image

The production build is started manually after the stable GitHub Release has
been published. Select `main` in the **Run workflow** branch selector and enter
the release tag.

```yaml
name: Build production image

run-name: Build production image ${{ inputs.tag }}

on:
  workflow_dispatch:
    inputs:
      tag:
        description: Published stable GitHub Release tag
        required: true
        type: string

permissions:
  contents: read

jobs:
  build:
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@<full-commit-sha>
    with:
      target: prod
      tag: ${{ inputs.tag }}
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
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@<full-commit-sha>
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
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@<full-commit-sha>
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

Pin reusable workflows to a reviewed full commit SHA. Do not use a mutable branch
or tag for production and critical release workflows.

`secrets: inherit` grants the called workflow access to secrets available to the
caller. Use it only with the trusted reusable workflow pinned to a reviewed full
commit SHA. The workflow references only the fixed Harbor token name selected for
the requested target and never passes that token to the Docker build.

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

For security and reproducibility, pin reusable workflows and actions to a full commit SHA instead of a mutable branch or tag.
