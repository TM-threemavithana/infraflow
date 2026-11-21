# InfraFlow — Consumer Governance Enforcement Guide (Milestone G08.3)

> **Audience:** Platform Engineering Leads, DevSecOps Auditors, and Consumer Infrastructure Authors  
> **Platform Version:** v0.5.0 (`f1ad39fb0f0bdce7c475ed36e717e859b2e9b106`)  
> **Document Status:** OPERATIONAL REFERENCE GUIDE  

---

## 1. Overview

This guide explains how engineering teams integrate and operate the **InfraFlow Centralized Governance Gate** in their consumer repositories. 

The governance gate verifies that every consuming repository:
1. Conforms to the `infraflow.config.yaml` schema contract.
2. Contains all Terraform assets strictly within the repository workspace.
3. Uses least-privilege permissions (`contents: read` only).
4. Pins the authoritative InfraFlow platform to an immutable 40-character commit SHA.
5. Invokes the appropriate cloud adapter workflow (`reusable-tf-aws.yml`, `reusable-tf-azure.yml`, or `reusable-tf-gcp.yml`).
6. Passes all 15 centralized Open Policy Agent (OPA) enterprise governance rules.

---

## 2. Consumer Implementation Steps

### Step 1: Declare the Governance Gate in CI Workflow

In your repository's caller workflow (e.g. `.github/workflows/infraflow-ci.yml`), declare the `governance-gate` job as the very first job, and make subsequent speculative planning or validation jobs depend on it:

```yaml
name: "Infrastructure CI"

on:
  pull_request:
    branches: [main]
    paths:
      - "terraform/**"
      - "infraflow.config.yaml"
      - ".github/workflows/infraflow-ci.yml"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  governance-gate:
    name: "InfraFlow Governance Gate"
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-governance.yml@f1ad39fb0f0bdce7c475ed36e717e859b2e9b106
    with:
      config-file: "infraflow.config.yaml"
      working-directory: "."
      platform-sha: "f1ad39fb0f0bdce7c475ed36e717e859b2e9b106"
      expected-adapter: "aws" # Set to 'aws', 'azure', 'gcp', or 'generic'

  aws-speculative-plan:
    name: "AWS Speculative Plan (Cloud-Free)"
    needs: [governance-gate]
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@f1ad39fb0f0bdce7c475ed36e717e859b2e9b106
    with:
      aws-region: "us-east-1"
      terraform-version: "1.10.4"
      working-directory: "terraform"
      environment: "dev"
      backend-bucket: "net-infraflow-tfstate"
      backend-key: "env/dev/terraform.tfstate"
      enable-aws-auth: false
```

### Step 2: Validate Locally Before Pushing (Layer A)

Run the standalone InfraFlow validator locally to catch contract violations before triggering GitHub Actions:

```bash
python3 /path/to/infraflow/scripts/validate-consumer.py \
  --config infraflow.config.yaml \
  --repo-dir .
```

---

## 3. Platform Administration: Setting Up Branch Rulesets (Layer C)

To ensure that pull requests cannot bypass the governance gate by modifying or removing workflows, platform administrators must configure GitHub Branch Protection or Rulesets on the `main` branch:

1. In GitHub Repository Settings, navigate to **Rules** -> **Rulesets**.
2. Create a ruleset targeting branch `main`.
3. Under **Branch Protections**:
   - Enable **Require a pull request before merging**.
   - Enable **Require status checks to pass**.
   - Add status check: `InfraFlow Governance Gate / Evaluate Consumer Governance & Adoption Contracts`.
   - Enable **Require branches to be up to date before merging**.
   - Enable **Block force pushes**.
   - Enable **Block branch deletions**.

---

## 4. Periodic Fleet Auditing (Layer D)

The platform team runs the fleet auditor script periodically or as part of a scheduled monitoring workflow:

```bash
python3 scripts/audit-consumer-fleet.py \
  --fleet-root /home/tharuka/projects \
  --check-remote
```

Or for specific repositories:

```bash
python3 scripts/audit-consumer-fleet.py \
  /path/to/infraflow-consumer-networking \
  /path/to/infraflow-consumer-application \
  /path/to/infraflow-consumer-data-platform
```

---

## 5. Troubleshooting Governance Failures

| Error Message | Cause | Resolution |
|---|---|---|
| `Adapter Invocation: Config specifies adapter 'aws' (requires 'reusable-tf-aws.yml'), but workflow calls: ...` | The workflow does not invoke the required adapter for the configured workload. | Update `.github/workflows/` to call `reusable-tf-aws.yml@<SHA>`. |
| `Platform Pinning: Mutable reference 'main' rejected` | The configuration or workflow references a branch tag (`@main`) instead of an immutable commit SHA. | Pin the exact 40-character commit SHA (e.g. `f1ad39fb...`). |
| `Permissions: 'id-token: write' is strictly forbidden` | The workflow requested OIDC token minting permissions. | In cloud-free mode, set permissions to `contents: read`. |
| `Trigger Safety: 'pull_request_target' trigger is strictly forbidden` | Workflow defines `pull_request_target`, creating privilege escalation risk. | Change workflow trigger to `pull_request`. |
| `Secret Safety: Workflow call specifies 'secrets: inherit'` | Workflow passes repository secrets to reusable workflow. | Remove `secrets: inherit`. Reusable workflows do not require consumer secrets in cloud-free mode. |
