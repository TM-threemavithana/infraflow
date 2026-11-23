# InfraFlow v0.8.0 — Unified Developer Experience & Distributed State Governance (Cloud-Free)

InfraFlow **v0.8.0** delivers the **G10 milestone release in the v0.x development cycle** (Unified Platform CLI & Distributed State Locking).

This milestone release completes the fifth evolutionary stage of the InfraFlow platform, elevating the platform from a collection of standalone backend scripts into a unified, installable Python CLI package (`infraflow`) and developer experience engine, while introducing single-host distributed state locking, monotonic fencing token tracking, transactional consumer onboarding, and mandatory consumer secret defense—all while strictly maintaining the core platform invariant of **zero live cloud credentials and zero infrastructure spend ($0.00)**.

> [!CAUTION]
> **CLOUD-FREE GOVERNANCE & SAFETY SCOPE NOTICE**:
> This release operates strictly in an offline, cloud-free validation model:
> - **Zero Live Infrastructure Modification:** Absolutely no live Terraform apply, destroy, or force-unlock operations are performed against any live cloud account.
> - **Zero Cloud Expenditure:** Cloud infrastructure expenditure is strictly **$0.00** across all local test harnesses and GitHub Actions runners.
> - **Zero Live Cloud Credentials:** No AWS Access Keys, GCP Service Account JSON keys, Azure Client Secrets, or SAS tokens are required, accepted, or stored.
> - **Simulated State Drift & Speculative Planning:** Drift detection and upgrade campaigns simulate state comparisons and PR creation offline without connecting to live cloud provider APIs.
> - **SEC-02 Fail-Closed Invariant:** Any untrusted pull request requesting live cloud authentication is unconditionally aborted before toolchain execution.

---

## What's New in v0.8.0

### 1. Unified Platform CLI & Developer Experience Diagnostic Engine (G10.1 / G10.1.1)
- **Standardized Console Entrypoint (`infraflow`)**: Consolidates disparate platform automation scripts into a single, cohesive command-line interface with subcommands: `doctor`, `validate`, `drift`, `upgrade`, `init`, `register`, and `lock`.
- **Platform Diagnostic Engine (`infraflow doctor`)**: Executes 12-dimension environment and dependency checks (Python runtime >= 3.10, Terraform CLI >= 1.6.0, Git CLI, TFLint, Trivy, Conftest/OPA, Actionlint, Zizmor, directory hierarchy, core policy contracts, PyYAML/cryptography libraries, and Git workspace status) with `--strict` fail-closed support and structured JSON reporting.
- **Enhanced Policy Error Reporting**: Enriches raw OPA/Conftest policy violation outputs with clear, human-readable remediation advice, documentation links, and severity tagging.
- **Python Packaging & Standard Distribution (`pyproject.toml`)**: Packages the platform engine as standard Python package `infraflow` with setuptools build backend (`setuptools.build_meta`), entrypoint `infraflow = infraflow.cli:main`, and full runtime parity via `python3 -m infraflow.cli`.

### 2. Self-Service Consumer Onboarding & Scaffolding Engine (G10.2)
- **Transactional Repository Scaffolding (`infraflow init`)**: Automatically scaffolds self-service consumer repositories from multi-cloud templates (`networking`, `application`, `data-platform`) targeting AWS, Azure, or GCP.
- **Automated Manifest Registration (`infraflow register`)**: Safely updates and validates `config/fleet-manifest.yaml` using atomic temporary file staging, preventing corruption upon invalid schema input.
- **Safe Dry-Run Operations**: Supports `--dry-run` across onboarding operations to verify configuration syntax and directory structures prior to disk modifications.

### 3. Consumer Secret Defense & Semantic Destruction Governance (G10.3 / G10.3.1)
- **Mandatory Consumer Secret Defense Engine (`scripts/scan-secrets.py`)**: Multi-rule regex and entropy credential scanning blocking exposed AWS access keys, GitHub personal access tokens, GCP API keys, private key blocks, and bearer tokens before workflow execution.
- **Multi-Cloud Semantic Destruction Governance**: Enforces fine-grained OPA policy gates across AWS, Azure, and GCP preventing unintended deletion of critical stateful resources (e.g., S3 buckets, RDS clusters, Azure Storage accounts, Google Cloud Storage buckets).
- **Explicit Schema-Validated Decommission Tokens**: Closes heuristic substring-based naming bypasses (such as resource addresses containing the word "decommission"), requiring explicit `infraflow_authorization` payload blocks with schema validation (`infraflow-destruction-confirmation-v1`) and rejection of generic approval tokens to permit critical resource destruction.

### 4. Distributed State Locking & Fencing Token Engine (G10.4)
- **Modular Locking Architecture (`infraflow.locking`)**: Implements `DistributedLockDriver` interface supporting pluggable backends (`LocalFSDriver`, `MockDistributedDriver`) and high-level `LockManager`.
- **Monotonic High-Water Mark Fencing Tokens**: Emits strictly incrementing, durable 64-bit integer fencing tokens ($token_{n+1} > token_n$) per canonical state target, preventing split-brain state corruption from delayed or zombie processes.
- **Target Mutual Exclusion & Ownership Verification**: Prevents concurrent plan execution against identical backend targets (`LOCK_HELD` error); validates owner identity and lease validity.
- **CLI State Lock Inspection (`infraflow lock inspect`)**: Inspects active state locks with human-readable formatting or `--json` structured schema output.

### 5. Plan Lifecycle State Correctness & Workflow Integration (G10.4.4 / G10.5.1)
- **Plan Replay Ledger Integration (`scripts/verify-plan-lifecycle.py`)**: Binds cryptographic plan identity to distributed locks, recording state transitions (`RESERVED` -> `CONSUMED` / `FAILED` / `OUTCOME_UNCERTAIN` / `INTERRUPTED`) in an ACID SQLite ledger.
- **Stale Fencing Token Rejection**: Rejects plan consumption attempts presenting superseded fencing tokens with `STALE_FENCING_TOKEN`.
- **Workflow Lock Lifecycle Integration (`.github/workflows/reusable-tf-apply.yml`)**: Introduces `enable-lock`, `lock-dir`, and `lock-ttl-seconds` workflow inputs; wraps Terraform simulation in automated lock acquisition, idempotent consumption, and failure/cancellation traps (`lock-fail`).
- **Lost Handle Fast-Fail Protection**: Subprocess monitor terminates child execution immediately upon lock handle loss or heartbeat failure.

---

## Architectural Scope & Operational Boundaries

Potential adopters and platform operators should note the following architectural boundaries and design constraints:

1. **LocalFS Driver Single-Host Confinement:**
   - The default `LocalFSDriver` provides kernel-level mutual exclusion (`flock`) strictly within a **single host** or local POSIX environment.
   - It **does not** provide mutual exclusion across distinct, isolated GitHub Actions runner virtual machines. Cross-runner distributed locking requires a distributed coordination backend (e.g., DynamoDB, Redis, Consul), scheduled for future milestones.
2. **Ephemeral Runner SQLite Ledger Storage:**
   - The Plan Replay Ledger stores historical plan reservations and fencing states in a local SQLite database (`.infraflow/plan_replay_ledger.db`). On ephemeral CI runners, this database does not survive runner VM destruction without external persistent storage (e.g., remote database or object store).
3. **Provider REST API Boundary:**
   - Fencing token monotonicity and stale owner checks protect against concurrent state overwrites within the InfraFlow orchestration engine and plan replay ledger. They are not enforced by cloud provider REST endpoints (AWS, Azure, GCP).
4. **Best-Effort Runner Cancellation:**
   - Process cancellation cleanup follows the sequence: `SIGINT` -> wait 7,500 ms -> `SIGTERM` -> wait 2,500 ms -> process tree kill. If the runner VM itself times out (5-minute cancellation limit), uncoordinated termination occurs without external notification.
5. **Simulation-Only Cloud Execution ($0.00 Spend):**
   - Cloud adapters validate plan synthesis, OIDC claim topologies, and policy gates in simulation mode without contacting live cloud APIs or incurring infrastructure costs.

---

## Quality & Compliance Verification Metrics

- **Local Platform Quality Gates:** **485 / 485 passed (100%)** (`scripts/validate-local.sh` across Sections 1–31).
- **Python Unit & Adversarial Test Suite:** **707 / 707 passed (100%)** (`tests/test_*.py` in ~38s).
- **OPA / Rego Enterprise Policies:** **213 / 213 passed (100%)** (`conftest verify --policy policies`).
- **GitHub Actions Workflow Linter (`actionlint`):** 0 syntax, schema, or contract errors across all 7 workflows.
- **Supply Chain Security (`zizmor`):** 0 findings (3 ignored, 4 suppressed).
- **Shell Script Linter (`shellcheck`):** 0 errors across all platform shell scripts.
- **Secret Detection (`gitleaks`):** 0 leaked secrets detected across commit history and filesystem.
- **Python Packaging & Build Validation:** Clean `python -m build` (sdist and wheel), strict `twine check --strict`, and clean wheel installation.
- **Cloud Expenditure:** Exactly **$0.00** incurred across all local test runs and CI runners.
