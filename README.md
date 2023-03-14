# Common Actions and Workflows
This repo contains common actions and workflows for the Lido applications

## Workflows
### `prepare-release-draft.yml`
This workflow creates or updates a release draft for the current application version. 
It should be triggered on a push to the `main` (or your variant) branch.
Example:
```yaml
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
