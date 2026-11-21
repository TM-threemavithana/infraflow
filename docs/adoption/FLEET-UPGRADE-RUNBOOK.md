# InfraFlow Operator Runbook: Fleet-Wide Upgrade Orchestration & Rollback (G08.4)

## Overview

This runbook guides platform engineers and operations teams through executing safe, controlled, and auditable upgrades of the InfraFlow platform across all registered consumer repositories in the fleet.

---

## 1. Prerequisites & Environment Setup

Before initiating any fleet upgrade, verify your local environment:
- Python 3.11+ installed.
- PyYAML installed (`pip install pyyaml`).
- Terraform v1.10.4 installed.
- Conftest v0.71.1 installed.
- GitHub CLI (`gh`) authenticated with repository read access.
- Local working copies of platform and consumer repositories available in your workspace root (e.g., `~/projects/`).

---

## 2. Pre-Upgrade Checklist

1. **Verify Upstream Platform Candidate:**
   Confirm that the platform candidate commit has been pushed to GitHub, that all platform quality gates pass (`./scripts/validate-local.sh` -> 347/347 passing), and that PR #6 checks are green.
   ```bash
   cd ~/projects/infraflow
   git status
   gh pr checks 6
   ```

2. **Inspect Current Fleet Inventory:**
   ```bash
   python3 scripts/plan-fleet-upgrade.py --inventory --fleet-root ~/projects
   ```
   Ensure all consumers currently report active governance workflows and valid baseline pins (`f1ad39fb0f0bdce7c475ed36e717e859b2e9b106`).

3. **Verify Candidate Compatibility:**
   ```bash
   python3 scripts/plan-fleet-upgrade.py --compatibility
   ```
   Confirm that the candidate commit provides all mandatory outputs required by AWS, Azure, and GCP adapters.

4. **Generate Dry-Run Upgrade Plan:**
   ```bash
   python3 scripts/plan-fleet-upgrade.py --plan
   ```
   Review the generated plan. Stage 1 MUST specify the canary consumer (`consumer-networking`), and Stage 2 MUST specify progressive consumers (`consumer-application`, `consumer-data-platform`).

---

## 3. Stage 1: Canary Deployment (AWS Networking)

1. **Apply Upgrade to Canary Only:**
   ```bash
   python3 ~/projects/infraflow/scripts/plan-fleet-upgrade.py \
     --manifest ~/projects/infraflow/config/fleet-manifest.yaml \
     --fleet-root ~/projects \
     --apply \
     --stage canary
   ```

2. **Validate Canary Locally:**
   ```bash
   cd ~/projects/infraflow-consumer-networking
   python3 ~/projects/infraflow/scripts/validate-consumer.py -c infraflow.config.yaml -r .
   terraform -chdir=terraform test
   ```

3. **Verify Canary Isolation:**
   Confirm that Application and Data Platform repositories remain unchanged on their baseline commit:
   ```bash
   python3 ~/projects/infraflow/scripts/plan-fleet-upgrade.py --inventory --fleet-root ~/projects
   ```

4. **Commit & Push Canary to Pull Request:**
   ```bash
   cd ~/projects/infraflow-consumer-networking
   git commit -am "feat(canary): upgrade platform pin to <CANDIDATE_SHA>"
   git push origin feature/onboard-infraflow
   ```

5. **Monitor Canary CI Execution:**
   ```bash
   gh run watch --repo TM-threemavithana/infraflow-consumer-networking
   ```
   Confirm that all CI jobs pass:
   - InfraFlow Governance Gate
   - AWS Speculative Plan (Cloud-Free)
   - Input validation & execution summary

---

## 4. Stage 2: Progressive Rollout (Azure & GCP)

**Do NOT proceed to Stage 2 if Stage 1 failed.**

1. **Apply Progressive Rollout to Remaining Fleet:**
   ```bash
   python3 ~/projects/infraflow/scripts/plan-fleet-upgrade.py \
     --manifest ~/projects/infraflow/config/fleet-manifest.yaml \
     --fleet-root ~/projects \
     --apply \
     --stage progressive
   ```

2. **Validate Progressive Consumers Locally:**
   ```bash
   cd ~/projects/infraflow-consumer-application
   python3 ~/projects/infraflow/scripts/validate-consumer.py -c infraflow.config.yaml -r .
   terraform -chdir=terraform test

   cd ~/projects/infraflow-consumer-data-platform
   python3 ~/projects/infraflow/scripts/validate-consumer.py -c infraflow.config.yaml -r .
   terraform -chdir=terraform test
   ```

3. **Commit & Push Progressive Updates:**
   ```bash
   cd ~/projects/infraflow-consumer-application
   git commit -am "feat(upgrade): progressive rollout to platform <CANDIDATE_SHA>"
   git push origin feature/onboard-infraflow

   cd ~/projects/infraflow-consumer-data-platform
   git commit -am "feat(upgrade): progressive rollout to platform <CANDIDATE_SHA>"
   git push origin feature/onboard-infraflow
   ```

4. **Monitor Fleet CI Executions:**
   ```bash
   gh run list --repo TM-threemavithana/infraflow-consumer-application -L 1
   gh run list --repo TM-threemavithana/infraflow-consumer-data-platform -L 1
   ```

---

## 5. Stage 3: Post-Rollout Fleet Drift Audit

1. **Audit Fleet Alignment & Drift:**
   ```bash
   python3 ~/projects/infraflow/scripts/plan-fleet-upgrade.py --check-drift --fleet-root ~/projects
   ```
   Expected output: `Fleet Drift Verdict: CLEAN (NO DRIFT)`.

2. **Run Central Fleet Governance Audit:**
   ```bash
   python3 ~/projects/infraflow/scripts/audit-consumer-fleet.py --check-remote --fleet-root ~/projects
   ```
   Confirm that all repositories report `Drift Severity: NONE` and `Fleet Status: COMPLIANT`.

---

## 6. Emergency Rollback Procedures

If any consumer experiences a regression, unexpected failure, or supply chain policy violation during rollout:

1. **Execute Single-Consumer Rollback:**
   ```bash
   python3 ~/projects/infraflow/scripts/plan-fleet-upgrade.py \
     --manifest ~/projects/infraflow/config/fleet-manifest.yaml \
     --fleet-root ~/projects \
     --rollback \
     --consumer <CONSUMER_ID>
   ```

2. **Execute Fleet-Wide Emergency Rollback:**
   ```bash
   python3 ~/projects/infraflow/scripts/plan-fleet-upgrade.py \
     --manifest ~/projects/infraflow/config/fleet-manifest.yaml \
     --fleet-root ~/projects \
     --rollback
   ```

3. **Verify Restored Baseline Locally:**
   ```bash
   cd ~/projects/<CONSUMER_REPO>
   python3 ~/projects/infraflow/scripts/validate-consumer.py -c infraflow.config.yaml -r .
   terraform -chdir=terraform test
   ```
   Verify that `platform_sha` and workflow references have returned to `f1ad39fb0f0bdce7c475ed36e717e859b2e9b106`.

4. **Push Rollback to Remote PR:**
   ```bash
   git commit -am "fix(rollback): emergency rollback to baseline f1ad39f"
   git push origin feature/onboard-infraflow
   ```
   Ensure CI turns green on the restored baseline.
