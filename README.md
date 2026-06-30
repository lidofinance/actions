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

- Docker Buildx setup
- Harbor login
- Docker image build
- Docker image push
- OCI image labels generation
- GitHub Actions cache usage

#### Inputs

| Name | Required | Description | Default |
|------|----------|-------------|---------|
| `tag` | yes | Image tag to push | - |
| `registry` | yes | Harbor registry host | - |
| `registry_username` | yes | Harbor username | - |
| `image` | yes | Image path in Harbor, for example `<harbor-project>/<application-name>` | - |
| `environment` | yes | GitHub Environment name used for approvals, vars and secrets | - |
| `build_context` | no | Docker build context | `.` |
| `dockerfile` | no | Dockerfile path | `Dockerfile` |

#### Secrets

| Name | Required | Description |
|------|----------|-------------|
| `registry_token` | yes | Harbor password or robot token |

### Usage examples

#### Production image

Manual build and push of a release image.

```yaml
name: Build and push <your application name> to <env name>

run-name: Build and push <your application name>:${{ inputs.TAG }} to <env name>

on:
  workflow_dispatch:
    inputs:
      TAG:
        description: Image tag to push
        required: true
        type: string

permissions:
  contents: read

jobs:
  build-and-push:
    if: github.ref_name == '<release branch name>'
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main
    with:
      tag: ${{ inputs.TAG }}
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
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main
    with:
      tag: staging-${{ github.sha }}
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
    uses: lidofinance/actions/.github/workflows/k8s-build-push-harbor.yml@main
    with:
      tag: dev
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

Prefer pinning reusable workflow versions to a release tag (for example `@v1`) once the workflow API is stable.
