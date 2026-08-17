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

This reusable workflow builds a Docker image and pushes it to Harbor.

It is intended to be called from application repositories via `jobs.<job_id>.uses`.

The workflow performs:

- Application source checkout and branch validation
- Release tag and rollback validation for production releases
- Docker Buildx setup
- Harbor login
- Existing release image tag check
- Docker image build
- Docker image push
- OCI image labels generation
- GitHub Actions cache usage

#### Inputs

| Name | Required | Description | Default |
|------|----------|-------------|---------|
| `tag` | yes | Image tag to push; for releases, also the Git tag to build | - |
| `registry` | yes | Harbor registry host | - |
| `registry_username` | yes | Harbor username | - |
| `image` | yes | Image path in Harbor, for example `<harbor-project>/<application-name>` | - |
| `environment` | yes | GitHub Environment name used for approvals, vars and secrets | - |
| `branch` | yes | Branch that must contain the commit being built | - |
| `build_context` | no | Docker build context | `.` |
| `dockerfile` | no | Dockerfile path | `Dockerfile` |

#### Secrets

| Name | Required | Description |
|------|----------|-------------|
| `registry_token` | yes | Harbor password or robot token |

#### Source selection and validation

For workflows triggered by a GitHub `release` event:

- `tag` is both the Git tag to check out and the Harbor image tag;
- `branch` must be either `main` or `master`;
- the image tag must match `github.event.release.tag_name`;
- the tag must still reference the commit that triggered the release;
- the tagged commit must be contained in `branch`;
- the tagged commit must not predate or diverge from the latest other stable
  GitHub Release;
- an image with the same registry, image name, and tag must not already exist.

Drafts and prereleases are not used as the rollback baseline. The rollback check
is skipped when the repository has no earlier stable release.

For other events, such as `push` and `workflow_dispatch`, the workflow checks out
`github.sha`. The commit must be contained in `branch`, while `tag` is used only
as the Harbor image tag. When starting a workflow manually, select the same Git
branch that is passed through the `branch` input.

The resolved checkout commit is written to `BUILD_COMMIT` and the
`org.opencontainers.image.revision` OCI label. `BUILD_BRANCH` contains the
validated `branch` input.

### Usage examples

#### Production or critical release image

Publishes an immutable versioned image when a stable GitHub Release is published.

```yaml
name: Build and push <your application name> to production

run-name: Build and push <your application name>:${{ github.event.release.tag_name }} to production

on:
  release:
    types: [released]

permissions:
  contents: read

jobs:
  build-and-push:
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@<full-commit-sha>
    with:
      tag: ${{ github.event.release.tag_name }}
      branch: main
      registry: registry.prod.k8s-prod.org
      registry_username: ${{ vars.REGISTRY_PROD_USERNAME }}
      image: <harbor-project>/<application-name>
      environment: <github-environment-name>
    secrets:
      registry_token: ${{ secrets.HARBOR_TOKEN }}
```

#### Staging image

Builds and pushes a staging image on every push to the `main` branch.

```yaml
name: Build and push <your application name> to staging

run-name: Build and push <your application name>:staging

on:
  workflow_dispatch:
  push:
    branches:
      - main
    paths-ignore:
      - '.github/**'
      - 'test/**'

permissions:
  contents: read

jobs:
  build-and-push:
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@<full-commit-sha>
    with:
      tag: staging
      branch: main
      registry: registry.staging.k8s-staging.org
      registry_username: ${{ vars.REGISTRY_STAGING_USERNAME }}
      image: <harbor-project>/<application-name>
      environment: <staging-github-environment-name>
    secrets:
      registry_token: ${{ secrets.HARBOR_TOKEN }}
```

#### Development image

Builds and pushes a development image on every push to the `develop` branch.

```yaml
name: Build and push <your application name> to dev

run-name: Build and push <your application name>:dev

on:
  workflow_dispatch:
  push:
    branches:
      - develop
    paths-ignore:
      - '.github/**'
      - 'test/**'

permissions:
  contents: read

jobs:
  build-and-push:
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@<full-commit-sha>
    with:
      tag: dev
      branch: develop
      registry: registry.dev.k8s-dev.org
      registry_username: ${{ vars.REGISTRY_DEVEL_USERNAME }}
      image: <harbor-project>/<application-name>
      environment: <dev-github-environment-name>
    secrets:
      registry_token: ${{ secrets.HARBOR_TOKEN }}
```

### Notes

For development and staging environments it is common to use mutable tags such as `dev` and `staging`. Each successful build updates the corresponding image.

For production releases, use immutable version tags (for example `1.15.0` or `v1.15.0`) to ensure reproducible deployments.

Pin reusable workflows to a reviewed full commit SHA. Do not use a mutable branch
or tag for production and critical release workflows.

## Actions

### `validate-inputs`

Validates GitHub workflow inputs against a safe character allowlist.

This action is useful for reusable workflows that receive user-controlled inputs and later pass them to shell commands, Docker build arguments, labels, tags, or deployment workflows.

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

For security and reproducibility, pin reusable workflows and actions to a full commit SHA instead of a mutable branch or tag.
