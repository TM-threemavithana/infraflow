# InfraFlow Self-Service Consumer Onboarding Tutorial & Guide

**Milestone:** G10.2  
**Platform Version:** `v0.7.0`  
**Tooling:** `infraflow` CLI (`init`, `validate`, `register`, `doctor`)  

Welcome to the **InfraFlow Self-Service Consumer Onboarding Guide**. This tutorial guides platform engineers and application development teams through creating, validating, testing, and registering new infrastructure repositories under InfraFlow enterprise governance.

---

## 1. Overview & Core Tenets

InfraFlow enables self-service infrastructure delivery without sacrificing centralized security, compliance, or operational controls:

1. **$0.00 Cloud Spending Guarantee:** Everything can be initialized, tested, and validated locally and offline with zero billable cloud API calls.
2. **Immutable Platform Pinning:** All generated workflows reference immutable 40-character commit SHAs (e.g. `@be51718f06a2662099500a710e93e6e8201b4f1c`). Mutable branch tags (`@main`, `@master`, `@latest`) are strictly forbidden.
3. **Fail-Closed Overwrite Protection:** The CLI never overwrites an existing non-empty directory unless the explicit `--force` flag is provided.
4. **Least-Privilege Token Permissions:** Workflows default to read-only permissions (`contents: read`) with zero secret inheritance.
5. **Central Fleet Registration:** Registration into `config/fleet-manifest.yaml` requires pre-flight validation and enforces global repository and consumer ID uniqueness.

---

## 2. Step-by-Step Onboarding Tutorial

### Step 1: Verify Local Environment Readiness
Ensure your developer environment has required dependencies installed:
```bash
infraflow doctor
```
If any warnings appear, resolve them before proceeding.

---

### Step 2: Scaffold a New Infrastructure Repository (`infraflow init`)

You can scaffold a consumer project interactively or non-interactively.

#### Option A: Interactive Wizard
```bash
infraflow init --interactive
```
The wizard will guide you through entering:
- **Consumer Identifier:** e.g. `billing-platform`
- **Target Cloud Adapter:** `aws`, `azure`, `gcp`, or `provider-neutral`
- **Deployment Environment:** `dev`, `staging`, or `prod`
- **Owning Team:** e.g. `billing-engineering`
- **Workload Category:** `application`, `networking`, `data-platform`, `general`
- **Destination Directory:** e.g. `./billing-platform`

#### Option B: Non-Interactive CLI Command

**AWS Workload Example:**
```bash
infraflow init \
  --name billing-platform \
  --adapter aws \
  --environment dev \
  --workload-type application \
  --team billing-team \
  --output-dir ./billing-platform
```

**Azure Workload Example:**
```bash
infraflow init \
  --name identity-service \
  --adapter azure \
  --environment dev \
  --workload-type application \
  --team security-team \
  --output-dir ./identity-service
```

**GCP Workload Example:**
```bash
infraflow init \
  --name analytics-pipeline \
  --adapter gcp \
  --environment dev \
  --workload-type data-platform \
  --team data-eng \
  --output-dir ./analytics-pipeline
```

---

### Step 3: Inspect the Generated Project Structure

The generated repository is fully organized and ready for CI/CD:
```text
billing-platform/
├── .github/
│   └── workflows/
│       └── infraflow-ci.yml        # CI/CD pipeline calling immutable reusable workflows
├── terraform/
│   ├── versions.tf                 # Terraform >= 1.6.0 constraint
│   ├── main.tf                     # 100% cloud-free testable module (terraform_data)
│   ├── variables.tf                # Standard workload variables and mandatory tags
│   ├── outputs.tf                  # Workload IDs and metadata outputs
│   └── tests/
│       └── unit.tftest.hcl         # Native offline unit tests
├── policies/
│   └── local_governance.rego       # Consumer-local Rego policy template
├── infraflow.config.yaml           # Schema v1.0 governance contract
├── .infraflow-metadata.json        # Scaffolding timestamp and template metadata
└── README.md                       # Consumer project landing page
```

---

### Step 4: Run Offline Unit Tests

Navigate into the Terraform directory and run native Terraform unit tests without cloud credentials:
```bash
cd billing-platform/terraform
terraform init -backend=false
terraform test
```
**Expected Output:**
```
tests/unit.tftest.hcl... in progress
  run "verify_workload_defaults"... pass
tests/unit.tftest.hcl... tearing down
tests/unit.tftest.hcl... pass

Success! 1 passed, 0 failed.
```

---

### Step 5: Validate Consumer Governance Contract

Run the InfraFlow governance validator against your configuration:
```bash
infraflow validate --config billing-platform/infraflow.config.yaml
```
**Expected Output:**
```
======================================================================
  [ PASS ] Config Schema: No unknown keys
  [ PASS ] Contract Version: Valid (1.0)
  [ PASS ] Consumer Identity: Valid (billing-platform)
  [ PASS ] Consumer Team: Valid (billing-team)
  [ PASS ] Workload Type: Valid (application)
  [ PASS ] Environment: Valid (dev)
  [ PASS ] Adapter: Valid (aws)
  [ PASS ] Platform Reference: Canonical (TM-threemavithana/infraflow)
  [ PASS ] Platform Pinning: Immutable 40-char SHA (be51718f...)
  [ PASS ] Terraform Version: Valid (1.10.4)
  [ PASS ] Terraform Directory: Path format valid ('terraform')
  [ PASS ] Security Controls: Mandatory scanners enforced
  [ PASS ] Security Controls: Deletion ceiling valid (10)
  [ PASS ] Terraform Workspace: Contained (4 .tf files found)
  [ PASS ] Workflow Pinning: Pinned to immutable SHA
  [ PASS ] Adapter Invocation: Expected workflow 'reusable-tf-aws.yml' invoked
======================================================================
Total Checks: 17 | Passed: 17 | Failed: 0
>>> ALL CONSUMER ONBOARDING CHECKS PASSED <<<
```

---

### Step 6: Preview Fleet Registration (Dry-Run)

Before modifying the central fleet manifest, generate a safe preview diff:
```bash
infraflow register \
  --config billing-platform/infraflow.config.yaml \
  --dry-run
```
**Expected Output:**
```
==============================================================================
 InfraFlow Fleet Registration Preview (Dry-Run)
==============================================================================
Target Manifest:          /path/to/config/fleet-manifest.yaml
Consumer Identifier:      billing-platform
Repository Identity:      TM-threemavithana/infraflow-billing-platform
Target Adapter:           aws
Rollout Role:             progressive
Target Candidate SHA:     be51718f...
Rollback Reference SHA:   f1ad39fb...
Max Allowed Deletions:    10
Caller Workflow:          .github/workflows/infraflow-ci.yml
------------------------------------------------------------------------------
Existing Consumers:       3
Projected Total:          4
==============================================================================
[PREVIEW] Validation passed. Zero disk modifications made. Omit --dry-run to commit.
==============================================================================
```

---

### Step 7: Commit Fleet Registration

Atomically register the consumer into `config/fleet-manifest.yaml`:
```bash
infraflow register \
  --config billing-platform/infraflow.config.yaml \
  --stage progressive
```
**Expected Output:**
```
==============================================================================
✔ Consumer Registration Committed: billing-platform
==============================================================================
Target Manifest:          /path/to/config/fleet-manifest.yaml
Registered Repository:    TM-threemavithana/infraflow-billing-platform
Rollout Role:             progressive
Status:                   registered
Fleet Consumers Total:    4 (previously 3)
==============================================================================
```

---

## 3. Security Boundaries & Guardrails

| Boundary / Guard | Mechanism | Failure Behavior |
|---|---|---|
| **Overwrite Safeguard** | `ConsumerScaffolder` checks for existing files | Refuses fail-closed unless `--force` is provided. |
| **Identity Validation** | Regex `^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$` | Exits with security exit code 2 on malformed names. |
| **Repository Uniqueness** | `ConsumerRegistrar` scans existing manifest entries | Rejects duplicate repository identities or consumer IDs (exit code 1). |
| **Path Traversal Guard** | Checks for `..` in all input path strings | Rejects paths attempting directory escape (exit code 2). |
| **Symlink Rejection** | `is_symlink()` and `os.path.islink()` | Rejects symbolic links fail-closed across all inputs (exit code 2). |
| **Atomic File Update** | `NamedTemporaryFile` + `fsync` + schema verification + `os.replace` | Guarantees zero manifest corruption; rolls back automatically on error. |
