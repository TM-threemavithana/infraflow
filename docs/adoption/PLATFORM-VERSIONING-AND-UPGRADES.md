# InfraFlow — Platform Versioning, Pinning & Upgrade Policy

> **Audience:** Platform Engineers, Repository Maintainers, and Security Auditors  
> **Platform Version:** v0.5.0 (`2ce0ddd5de01530b6bf7aba749f0081620fb9b27`)  
> **Standard:** Semantic Versioning 2.0.0, SLSA Level 3 Supply Chain Controls

---

## 1. Versioning Architecture

InfraFlow follows **Semantic Versioning 2.0.0** (`vMAJOR.MINOR.PATCH`):
- **MAJOR (e.g., v1.0.0)**: Breaking changes to workflow inputs, contract outputs, or required permissions. Requires consumer workflow modifications.
- **MINOR (e.g., v0.5.0)**: New features, new cloud adapters, expanded policy checks, or non-breaking input additions. Fully backward-compatible.
- **PATCH (e.g., v0.5.1)**: Security fixes, bug fixes, or performance optimizations with zero contract changes.

---

## 2. Immutable SHA Pinning vs Mutable Tags

### The Security Risk of Mutable Git Tags
In Git, git tags (such as `@v0.5.0` or `@v1`) are **pointers that can technically be moved or overwritten** by repository administrators. Furthermore, floating branch references (such as `@main` or `@master`) change with every commit.

If a consuming repository calls:
```yaml
# UNSAFE: Tag can be moved or compromised
uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@v0.5.0
```
An attacker who compromises an upstream branch or tag could inject malicious steps into the caller workflow.

### The Immutable 40-Character SHA Standard
For cryptographically guaranteed immutability and compliance with **CIS Software Supply Chain Security Standard 1.0 (Section 4.1.3)**, InfraFlow requires all production consumer workflows to pin the full **40-character hexadecimal commit SHA**:

```yaml
# SECURE & IMMUTABLE: Pinned to exact SHA
uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27 # v0.5.0
```

> [!TIP]
> Always append the human-readable release tag as an inline YAML comment (`# v0.5.0`) so maintainers understand which platform release the SHA corresponds to.

---

## 3. Platform Release Schedule & Upgrades

### Release Announcement & Cadence
1. **Release Published**: A new release is tagged (`v0.X.0`) on `TM-threemavithana/infraflow`.
2. **Release Notes Issued**: The release notes list:
   - Full 40-character commit SHA on `main`.
   - Summary of new features, policy changes, and adapter enhancements.
   - Any deprecation notices.
3. **Consumer Upgrade Window**: Consumer teams are notified to upgrade their pinned SHA within standard sprint cycles.

### Step-by-Step Upgrade Procedure for Consumers
To upgrade your repository to a new InfraFlow release:

1. **Check Current Version**:
   Inspect your `infraflow.config.yaml`:
   ```yaml
   platform_sha: "2ce0ddd5de01530b6bf7aba749f0081620fb9b27"
   ```
2. **Obtain the Target Release SHA**:
   Verify the new release commit SHA on the [InfraFlow Releases Page](https://github.com/TM-threemavithana/infraflow/releases).
3. **Update `infraflow.config.yaml`**:
   Update `platform_sha` to the new 40-character SHA.
4. **Update Caller Workflows**:
   Update all occurrences of the SHA in `.github/workflows/infraflow.yml`:
   ```yaml
   uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@<NEW_40_CHAR_SHA> # v0.X.0
   ```
5. **Run Pre-Flight Validation**:
   ```bash
   python3 scripts/validate-consumer.py --config infraflow.config.yaml --repo-dir .
   ```
6. **Submit PR & Verify CI**:
   Create a pull request in your repository to test the upgrade on GitHub Actions runners before merging to `main`.

---

## 4. Deprecation Handling & Breaking Changes

1. **Deprecation Notice**: Any workflow input, output, or policy slated for deprecation is announced in release notes at least one minor release in advance.
2. **Backward Compatibility**: Deprecated inputs remain functional with warnings during the deprecation period.
3. **Removal in Major Release**: Deprecated features are removed only when the platform increments its MAJOR version.
4. **Emergency Rollback**: If an upgraded platform SHA causes unexpected failures, the consumer team can immediately revert the commit SHA in their caller workflow and `infraflow.config.yaml` to the prior verified SHA.

---

## 5. Fleet-Wide Upgrade Orchestration & Automated Rollback (Milestone G08.4)

For multi-repository fleets, platform upgrades can be coordinated centrally using the InfraFlow Fleet Upgrade Tooling:

### Central Fleet Manifest (`config/fleet-manifest.yaml`)
Authoritative registry of registered consumers, workload types, adapters, rollback reference SHAs, and candidate SHAs.

### Staged Rollout Strategy
1. **Compatibility Check**: `python3 scripts/plan-fleet-upgrade.py --compatibility`
2. **Dry-Run Planning**: `python3 scripts/plan-fleet-upgrade.py --plan`
3. **Canary Upgrade**: `python3 scripts/plan-fleet-upgrade.py --apply --stage canary` (Networking consumer first, with strict isolation of remaining fleet members)
4. **Progressive Rollout**: `python3 scripts/plan-fleet-upgrade.py --apply --stage progressive` (Application and Data Platform consumers)
5. **Drift Audit**: `python3 scripts/plan-fleet-upgrade.py --check-drift` and `python3 scripts/audit-consumer-fleet.py --check-remote`
6. **Automated Rollback**: `python3 scripts/plan-fleet-upgrade.py --rollback --consumer <CONSUMER_ID>` atomically reverts `infraflow.config.yaml` and caller workflows to the registered `known_good_rollback_sha`.

