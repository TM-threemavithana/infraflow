#!/usr/bin/env python3
"""
InfraFlow — Protected Apply Workflow Contract Unit Tests
Milestone: G06.3 — Protected Apply Workflow Contract

Adversarial unit test suite verifying the reusable workflow contract:
1. Valid synthetic authorization.
2. Expired plan.
3. Incorrect source commit.
4. Unauthorized repository.
5. Wrong environment.
6. Wrong backend.
7. Wrong workspace.
8. State serial mismatch.
9. State lineage mismatch.
10. Corrupted encrypted plan.
11. Incorrect digest.
12. Unverified provenance.
13. Forged simulation evidence.
14. Replayed plan ID.
15. Duplicate concurrent reservations.
16. Missing required job output.
17. Skipped mandatory verification job.
18. Invalid workflow reference.
19. Untrusted PR execution.
20. Unauthorized attempt to enable real Terraform execution.
"""

import datetime
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import yaml
from typing import Any, Dict

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
LIFECYCLE_SCRIPT = os.path.join(SCRIPTS_DIR, "verify-plan-lifecycle.py")
WORKFLOW_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "reusable-tf-apply.yml"))

if not os.path.isfile(LIFECYCLE_SCRIPT):
    raise FileNotFoundError(f"Missing {LIFECYCLE_SCRIPT}")
if not os.path.isfile(WORKFLOW_FILE):
    raise FileNotFoundError(f"Missing {WORKFLOW_FILE}")

spec = importlib.util.spec_from_file_location("verify_plan_lifecycle", LIFECYCLE_SCRIPT)
vpl = importlib.util.module_from_spec(spec)
sys.modules["verify_plan_lifecycle"] = vpl
spec.loader.exec_module(vpl)

PlanLifecycleVerifier = vpl.PlanLifecycleVerifier
PlanReplayLedger = vpl.PlanReplayLedger
PlanReplayError = vpl.PlanReplayError
DECISION_AUTHORIZED = vpl.DECISION_AUTHORIZED
DECISION_REJECTED = vpl.DECISION_REJECTED
STATUS_RESERVED = vpl.STATUS_RESERVED
STATUS_CONSUMED = vpl.STATUS_CONSUMED
ENVELOPE_SCHEMA_VERSION = vpl.ENVELOPE_SCHEMA_VERSION


class TestApplyWorkflowContract(unittest.TestCase):
    """20-scenario adversarial test suite for reusable protected apply simulation workflow."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-g06-3-test-")
        self.ref_now = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.valid_repo = "TM-threemavithana/infraflow-consumer-test"
        self.valid_commit = "d0660de837ca07d5bdd56f04b0e50691ce98bd28"
        self.valid_env = "production"
        self.valid_lineage = "3f2e1d0c-4b5a-6789-0123-abcdef456789"
        self.valid_serial = 42
        self.valid_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.valid_workflow_sha = "484b067aa500d5523d1bccc06ce111cfe736a8af"
        self.valid_backend = "s3://infraflow-tfstate-bucket/env/production/tf.state"
        self.valid_workspace = "default"

        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            self.workflow_yaml = yaml.safe_load(f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_synthetic_envelope(
        self,
        created_at: str,
        expires_at: str,
        repo: str = None,
        commit: str = None,
        environment: str = None,
        digest: str = None,
        plan_id: str = "plan-apply-001",
        schema_version: str = ENVELOPE_SCHEMA_VERSION,
    ) -> Dict[str, Any]:
        return {
            "schema_version": schema_version,
            "algorithm": "AES-256-GCM",
            "plan_id": plan_id,
            "created_at": created_at,
            "expires_at": expires_at,
            "context": {
                "repository": repo or self.valid_repo,
                "commit_sha": commit or self.valid_commit,
                "environment": environment or self.valid_env,
                "plan_digest_sha256": digest or self.valid_digest,
                "workflow_sha": self.valid_workflow_sha,
                "workflow": "reusable-tf-plan.yml",
            },
            "wrapped_dek": {"algorithm": "AES-256-GCM"},
            "payload": {"nonce": "AAAA", "ciphertext": "BBBB"},
        }

    def _create_synthetic_state(
        self,
        serial: int = None,
        lineage: str = None,
    ) -> Dict[str, Any]:
        return {
            "version": 4,
            "terraform_version": "1.10.4",
            "serial": self.valid_serial if serial is None else serial,
            "lineage": self.valid_lineage if lineage is None else lineage,
            "outputs": {},
            "resources": [],
        }

    # 1. Valid synthetic authorization
    def test_01_valid_synthetic_authorization(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_workflow_sha=self.valid_workflow_sha,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_AUTHORIZED)
        self.assertEqual(decision.decision_code, "AUTH_SUCCESS")

    # 2. Expired plan
    def test_02_expired_plan_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=6)).isoformat()
        expires_at = (self.ref_now - datetime.timedelta(minutes=10)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "PLAN_EXPIRED")

    # 3. Incorrect source commit
    def test_03_incorrect_source_commit_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, commit="0000000000000000000000000000000000000000")
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "COMMIT_MISMATCH")

    # 4. Unauthorized repository
    def test_04_unauthorized_repository_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, repo="rogue-user/rogue-repo")
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "REPO_MISMATCH")

    # 5. Wrong environment
    def test_05_wrong_environment_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, environment="staging")
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment="production",
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "ENVIRONMENT_MISMATCH")

    # 6. Wrong backend
    def test_06_wrong_backend_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend="s3://target-bucket/tf.state",
            actual_backend="s3://attacker-bucket/tf.state",
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "BACKEND_MISMATCH")

    # 7. Wrong workspace
    def test_07_wrong_workspace_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_workspace="production",
            actual_workspace="staging",
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "WORKSPACE_MISMATCH")

    # 8. State serial mismatch
    def test_08_state_serial_mismatch_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state(serial=43)  # Drift forward

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=42,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "STALE_STATE_SERIAL")

    # 9. State lineage mismatch
    def test_09_state_lineage_mismatch_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state(lineage="00000000-0000-0000-0000-000000000000")

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "STATE_LINEAGE_MISMATCH")

    # 10. Corrupted encrypted plan
    def test_10_corrupted_encrypted_plan_rejected(self):
        state = self._create_synthetic_state()
        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data={"corrupted": "bad_json"},
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "UNSUPPORTED_SCHEMA_VERSION")

    # 11. Incorrect digest
    def test_11_incorrect_digest_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, digest="invalid-digest")
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "INVALID_PLAN_DIGEST")

    # 12. Unverified provenance
    def test_12_unverified_provenance_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            provenance_status="UNVERIFIED",
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "UNVERIFIED_PROVENANCE")

    # 13. Forged simulation evidence
    def test_13_forged_simulation_evidence_rejected(self):
        # Even if someone provides a dict claiming decision = AUTHORIZED_FOR_SIMULATION,
        # verify_authorization computes the decision from scratch and rejects if inputs fail.
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        envelope["decision"] = "AUTHORIZED_FOR_SIMULATION"  # Forgery attempt
        state = self._create_synthetic_state(serial=999)  # Wrong serial

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=42,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)

    # 14. Replayed plan ID
    def test_14_replayed_plan_id_rejected(self):
        ledger = PlanReplayLedger(db_path=os.path.join(self.test_dir, "ledger_replay.db"))
        plan_id = "plan-replay-001"
        expires_at = (self.ref_now + datetime.timedelta(hours=4)).isoformat()

        ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=self.valid_digest,
            repository=self.valid_repo,
            commit_sha=self.valid_commit,
            environment=self.valid_env,
            expires_at=expires_at,
            execution_context={},
            current_time=self.ref_now,
        )
        ledger.consume_plan(plan_id=plan_id, current_time=self.ref_now)

        with self.assertRaises(PlanReplayError) as ctx:
            ledger.reserve_plan(
                plan_id=plan_id,
                plan_digest_sha256=self.valid_digest,
                repository=self.valid_repo,
                commit_sha=self.valid_commit,
                environment=self.valid_env,
                expires_at=expires_at,
                execution_context={},
                current_time=self.ref_now,
            )
        self.assertIn("ALREADY_CONSUMED", str(ctx.exception))

    # 15. Duplicate concurrent reservations
    def test_15_duplicate_concurrent_reservations(self):
        ledger = PlanReplayLedger(db_path=os.path.join(self.test_dir, "ledger_concurrent.db"))
        plan_id = "plan-conc-001"
        expires_at = (self.ref_now + datetime.timedelta(hours=4)).isoformat()

        successes = []
        failures = []

        def worker():
            try:
                ledger.reserve_plan(
                    plan_id=plan_id,
                    plan_digest_sha256=self.valid_digest,
                    repository=self.valid_repo,
                    commit_sha=self.valid_commit,
                    environment=self.valid_env,
                    expires_at=expires_at,
                    execution_context={"thread": threading.get_ident()},
                    current_time=self.ref_now,
                )
                successes.append(1)
            except PlanReplayError:
                failures.append(1)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 3)

    # 16. Missing required job output
    def test_16_missing_required_job_output_rejected(self):
        # Verify workflow contract defines all required outputs
        on_block = self.workflow_yaml.get("on") or self.workflow_yaml.get(True, {})
        wf_outputs = on_block.get("workflow_call", {}).get("outputs", {})
        required_outputs = {
            "plan-verification-status",
            "provenance-status",
            "state-consistency-status",
            "replay-status",
            "authorization-status",
            "simulation-status",
        }
        for ro in required_outputs:
            self.assertIn(ro, wf_outputs, f"Workflow missing required output: {ro}")

    # 17. Skipped mandatory verification job
    def test_17_skipped_mandatory_verification_job_rejected(self):
        # Inspect summary job logic in reusable-tf-apply.yml:
        # If guard_result != success OR verify_result != success, final_auth must be REJECTED.
        summary_run_script = self.workflow_yaml["jobs"]["summary"]["steps"][0]["run"]
        self.assertIn('if [[ "${GUARD_RESULT}" == "success" && "${VERIFY_RESULT}" == "success"', summary_run_script)
        self.assertIn('FINAL_AUTH="REJECTED"', summary_run_script)
        self.assertIn('FINAL_AUTH="AUTHORIZED_FOR_SIMULATION"', summary_run_script)
        self.assertIn('exit 1', summary_run_script)

    # 18. Invalid workflow reference
    def test_18_invalid_workflow_reference_rejected(self):
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        # Must enforce 40-character hex commit SHA pattern
        self.assertIn('^[0-9a-f]{40}$', guard_script)
        # Must enforce trusted platform repository
        self.assertIn('TRUSTED_PLATFORM_REPO="TM-threemavithana/infraflow"', guard_script)

    # 19. Untrusted PR execution
    def test_19_untrusted_pr_execution_rejected(self):
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        # Must reject pull_request and pull_request_target
        self.assertIn('"${EVENT_NAME}" == "pull_request"', guard_script)
        self.assertIn('"${EVENT_NAME}" == "pull_request_target"', guard_script)

    # 20. Unauthorized attempt to enable real Terraform execution
    def test_20_unauthorized_attempt_to_enable_real_terraform_execution(self):
        # Inspect workflow: must NOT execute terraform apply or destroy or force-unlock
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        # Check absence of state-modifying terraform execution commands
        self.assertNotIn("terraform apply", content.lower())
        self.assertNotIn("terraform destroy", content.lower())
        self.assertNotIn("force-unlock", content.lower())

        # Check absence of execution bypass inputs
        on_block = self.workflow_yaml.get("on") or self.workflow_yaml.get(True, {})
        inputs = on_block.get("workflow_call", {}).get("inputs", {})
        self.assertNotIn("enable-apply", inputs)
        self.assertNotIn("enable-destroy", inputs)
        self.assertNotIn("execute", inputs)


if __name__ == "__main__":
    unittest.main()
