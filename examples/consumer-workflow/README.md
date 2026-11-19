# InfraFlow Consumer Repository Guide

> **NOTICE: Illustrative Template (Pending First Public Release)**  
> This guide and the accompanying workflow in `.github/workflows/infraflow-consume.yml` illustrate how an external repository calls the InfraFlow reusable core. Because release tags (`v1`, `v1.0.0`) have not yet been published to a remote GitHub repository, referencing `@v1` will not resolve until the first release is tagged and pushed.

---

## 1. Prerequisites: GitHub Cross-Repository Access

For an independent repository to invoke InfraFlow's reusable workflows:

1. **If InfraFlow is in the same GitHub Organization (Private Repo)**:
   - In the `infraflow` repository, navigate to:  
     `Settings -> Actions -> General -> Access`
   - Select: **"Accessible from repositories in the '{organization}' organization"**
2. **If InfraFlow is Public**:
   - Any public or private repository on GitHub can reference it directly via `YOUR_OWNER/YOUR_REPOSITORY/.github/workflows/reusable-tf-validate.yml@<ref>`.
3. **If InfraFlow is Private and Caller is in Another Organization**:
   - GitHub does not support cross-organization invocation of private reusable workflows without public visibility or enterprise sharing policies.

---

## 2. Versioning Strategy: How `@v1` and Commit SHAs Work

| Reference Type | Example Syntax | When to Use | Status Before First Release |
|---|---|---|---|
| **Immutable Commit SHA** | `@8a3f9c012...` | **Recommended for production**: Guarantees zero drift and complete supply-chain immutability. | Valid as soon as the commit is pushed to GitHub. |
| **Floating Major Tag** | `@v1` | **Recommended for general CI**: Receives backward-compatible bug fixes and security patches automatically. | **Invalid until first release**. Fails with `reference is not a tree` if called before tagging. |
| **Semantic Release Tag** | `@v1.0.0` | Pinning to an exact release without tracking moving tags. | **Invalid until tagged**. |

### When and How `@v1` Becomes Valid
Once the repository is published, the release engineer creates the release tags:
```bash
# 1. Tag the immutable semantic release
git tag -a v1.0.0 -m "Release v1.0.0"

# 2. Create or update the floating major version tag
git tag -fa v1 -m "Release v1"

# 3. Push tags to the remote repository
git push origin v1.0.0 v1
```
After step 3 completes on GitHub, caller workflows referencing `@v1` will resolve and execute successfully.

---

## 3. Quick Start: Pull Request Validation

Create `.github/workflows/infraflow-validate.yml` in your consumer repository, replacing `YOUR_OWNER/YOUR_REPOSITORY` and `YOUR_INFRAFLOW_COMMIT_SHA`:

```yaml
name: "Terraform CI"

on:
  pull_request:
    branches: [main]
    paths:
      - "terraform/**"
      - ".github/workflows/infraflow-validate.yml"

permissions:
  contents: read

jobs:
  validate:
    name: "Validate Terraform"
    # Replace YOUR_OWNER/YOUR_REPOSITORY with your GitHub org/repo
    # Replace YOUR_INFRAFLOW_COMMIT_SHA with the 40-character commit SHA (e.g., 8a3f9c...) or @v1 once published
    uses: YOUR_OWNER/YOUR_REPOSITORY/.github/workflows/reusable-tf-validate.yml@YOUR_INFRAFLOW_COMMIT_SHA
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      enable-fmt-check: true
      enable-validate: true
      enable-test: true
```

---

## 4. Matrix Multi-Directory Validation

To validate multiple sub-modules or directories in parallel:

```yaml
jobs:
  matrix-validate:
    name: "Validate Submodule"
    strategy:
      fail-fast: false
      matrix:
        dir:
          - "modules/networking"
          - "modules/database"
          - "modules/compute"
    uses: YOUR_OWNER/YOUR_REPOSITORY/.github/workflows/reusable-tf-validate.yml@YOUR_INFRAFLOW_COMMIT_SHA
    with:
      terraform-version: "1.10.4"
      working-directory: ${{ matrix.dir }}
```

---

## 5. Related Links

- [InfraFlow System Architecture](../../docs/architecture/ARCHITECTURE.md)
- [Requirements Specification](../../docs/architecture/REQUIREMENTS.md)
- [Reusable Workflow Source](../../.github/workflows/reusable-tf-validate.yml)
