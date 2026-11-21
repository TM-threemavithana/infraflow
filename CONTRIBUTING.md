# Contributing to InfraFlow

Thank you for your interest in contributing to **InfraFlow**! We welcome community contributions, bug fixes, documentation improvements, and architecture enhancements.

---

## 1. Code of Conduct & Core Principles

All contributors are expected to uphold respectful, inclusive, and professional collaboration.

### Invariant Safety Principles:
1. **Zero Cloud Spending ($0.00)**: All workflows, adapters, tests, and verifications must execute locally or in CI without requiring live cloud credentials or incurring billing.
2. **Zero Automated Destructive Remediation**: Drift detection, security auditing, and compliance scoring must remain strictly read-only simulations. Destructive resource remediation is strictly blocked.
3. **Supply Chain Immutability**: All external GitHub Action references and consumer platform references must be pinned to immutable 40-character commit SHAs. Mutable tags (`@v1`, `@main`) are strictly rejected.
4. **Least Privilege**: Workflows and local scripts must require minimal permissions (`contents: read`).
5. **Deterministic Verification**: All scripts, cryptographic digests, and reports must produce deterministic outputs.

---

## 2. Local Development & Toolchain Setup

### Prerequisites
- **Operating System**: Linux, macOS, or Windows WSL2 (Ubuntu 22.04+ recommended)
- **Python**: 3.10+ (standard library only for core runtime; `PyYAML` optional)
- **Terraform**: 1.6.0+ (Terraform 1.10+ recommended)
- **Linters & Auditing Tools**:
  - `actionlint` (GitHub Actions workflow linter)
  - `zizmor` (CI/CD security auditor)
  - `shellcheck` (Bash script linter)
  - `conftest` (OPA / Rego policy engine)
  - `tflint` (Terraform linter)
  - `trivy` (IaC vulnerability scanner)
  - `gitleaks` (Secret scanner)

---

## 3. Local Verification Suite

Before submitting a Pull Request, all local quality gates must pass cleanly:

```bash
# 1. Run full Python test suite (535+ tests)
python3 -m unittest discover -s tests -p 'test_*.py'

# 2. Run OPA Rego policy tests (194 tests)
conftest verify --policy policies

# 3. Run complete platform quality gates (407 checks)
./scripts/validate-local.sh

# 4. Run CI workflow linters
actionlint
zizmor -c .zizmor.yml --min-severity medium .github/workflows
```

---

## 4. Submitting a Pull Request

1. **Fork & Branch**: Create a feature branch from `main` or the active feature branch (e.g. `feature/your-feature-name`).
2. **Commit Conventions**: Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(...)`: New platform capabilities or tools.
   - `fix(...)`: Bug fixes or security remediations.
   - `docs(...)`: Documentation and architectural updates.
   - `test(...)`: Unit, integration, or adversarial test additions.
3. **Evidence & Documentation**: Any architectural change or new milestone must update `docs/architecture/MILESTONES.md` and provide an accompanying evidence report under `docs/evidence/`.
4. **Quality Gates**: Ensure `validate-local.sh` passes 100% (407/407 checks) with clean git status.

---

## 5. Security Vulnerabilities

If you discover a security vulnerability or potential credential leak, please do **NOT** open a public issue. Contact the platform maintainers directly or submit a private security advisory through GitHub.
