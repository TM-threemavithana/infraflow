#!/usr/bin/env python3
"""
InfraFlow — Plan Lifecycle, State Consistency & Replay Protection Unit Tests
Milestone: G06.2 — Protected Apply & Destroy (Verification Foundation)

Comprehensive adversarial unit test suite covering:
1. Valid synthetic plan authorization.
2. Expired plan rejection.
3. Future timestamp rejection.
4. Missing timestamp rejection.
5. Malformed timestamp rejection.
6. Plan exceeding maximum TTL (12 hours).
7. Valid state serial and lineage.
8. Stale state serial rejection.
9. State lineage mismatch rejection.
10. Backend identity mismatch rejection.
11. Workspace mismatch rejection.
12. Missing state metadata rejection.
13. Incorrect source commit SHA rejection.
14. Incorrect repository identity rejection.
15. Incorrect workflow SHA rejection.
16. Incorrect target environment rejection.
17. Modified / corrupted envelope structure rejection.
18. Incorrect plan digest rejection.
19. Replay prevention: Already consumed plan rejection.
20. Replay prevention: Concurrent duplicate reservations.
21. Replay prevention: Interrupted reservation recovery fail-closed.
22. Replay prevention: Persistence and replay detection across database restarts.
23. Unverified provenance rejection.
24. Invalid envelope schema version rejection.
25. Unauthorized metadata substitution rejection.
26. State serial regression rejection (serial lower than plan).
27. Initial bootstrap state handling (serial 0 accepted with initial flag).
28. Initial bootstrap state rejection without initial flag.
29. CLI integration end-to-end roundtrip.
"""

import datetime
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from typing import Any, Dict

# Dynamically import scripts/verify-plan-lifecycle.py
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
LIFECYCLE_SCRIPT = os.path.join(SCRIPTS_DIR, "verify-plan-lifecycle.py")
if not os.path.isfile(LIFECYCLE_SCRIPT):
    raise FileNotFoundError(f"Missing {LIFECYCLE_SCRIPT}")

spec = importlib.util.spec_from_file_location("verify_plan_lifecycle", LIFECYCLE_SCRIPT)
vpl = importlib.util.module_from_spec(spec)
sys.modules["verify_plan_lifecycle"] = vpl
spec.loader.exec_module(vpl)

PlanExpirationValidator = vpl.PlanExpirationValidator
PlanExpirationError = vpl.PlanExpirationError
StateConsistencyValidator = vpl.StateConsistencyValidator
StateConsistencyError = vpl.StateConsistencyError
PlanReplayLedger = vpl.PlanReplayLedger
PlanReplayError = vpl.PlanReplayError
PlanLifecycleVerifier = vpl.PlanLifecycleVerifier
AuthorizationDecision = vpl.AuthorizationDecision
DECISION_AUTHORIZED = vpl.DECISION_AUTHORIZED
DECISION_REJECTED = vpl.DECISION_REJECTED
STATUS_RESERVED = vpl.STATUS_RESERVED
STATUS_CONSUMED = vpl.STATUS_CONSUMED
STATUS_FAILED = vpl.STATUS_FAILED
STATUS_INTERRUPTED = vpl.STATUS_INTERRUPTED
ENVELOPE_SCHEMA_VERSION = vpl.ENVELOPE_SCHEMA_VERSION
AUTHORIZATION_SCHEMA_VERSION = vpl.AUTHORIZATION_SCHEMA_VERSION


class TestPlanLifecycle(unittest.TestCase):
    """Adversarial test suite for G06.2 pre-execution plan authorization."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-g06-lifecycle-test-")
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
        workflow_sha: str = None,
        schema_version: str = ENVELOPE_SCHEMA_VERSION,
        plan_id: str = "plan-test-001",
    ) -> Dict[str, Any]:
        return {
            "schema_version": schema_version,
            "algorithm": "AES-256-GCM",
            "plan_id": plan_id,
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/mock-infraflow-plan-kek",
            "created_at": created_at,
            "expires_at": expires_at,
            "context": {
                "repository": repo or self.valid_repo,
                "commit_sha": commit or self.valid_commit,
                "environment": environment or self.valid_env,
                "plan_digest_sha256": digest or self.valid_digest,
                "workflow_sha": workflow_sha or self.valid_workflow_sha,
                "workflow": "reusable-tf-plan.yml",
                "terraform_version": "1.10.4",
            },
            "wrapped_dek": {
                "algorithm": "AES-256-GCM",
                "nonce": "AAAAAAAAAAAAAAAA",
                "ciphertext": "BBBBBBBBBBBBBBBB",
                "auth_tag": "CCCCCCCCCCCCCCCC",
            },
            "payload": {
                "nonce": "DDDDDDDDDDDDDDDD",
                "ciphertext": "EEEEEEEEEEEEEEEE",
                "auth_tag": "FFFFFFFFFFFFFFFF",
            },
        }

    def _create_synthetic_state(
        self,
        serial: int = None,
        lineage: str = None,
        version: int = 4,
    ) -> Dict[str, Any]:
        return {
            "version": version,
            "terraform_version": "1.10.4",
            "serial": self.valid_serial if serial is None else serial,
            "lineage": self.valid_lineage if lineage is None else lineage,
            "outputs": {},
            "resources": [],
        }

    # -------------------------------------------------------------------------
    # Scenario 1: Valid synthetic plan
    # -------------------------------------------------------------------------
    def test_01_valid_synthetic_plan_authorized(self):
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
        self.assertEqual(len(decision.reasons), 0)
        self.assertIsNotNone(decision.contract)
        self.assertEqual(decision.contract["schema_version"], AUTHORIZATION_SCHEMA_VERSION)
        self.assertEqual(decision.contract["replay_status"], STATUS_RESERVED)

    # -------------------------------------------------------------------------
    # Scenario 2: Expired plan rejection
    # -------------------------------------------------------------------------
    def test_02_expired_plan_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=6)).isoformat()
        expires_at = (self.ref_now - datetime.timedelta(minutes=5)).isoformat()  # Expired 5m ago
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
        self.assertTrue(any("PLAN_EXPIRED" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 3: Future timestamp rejection
    # -------------------------------------------------------------------------
    def test_03_future_created_plan_rejected(self):
        created_at = (self.ref_now + datetime.timedelta(hours=2)).isoformat()  # Future created
        expires_at = (self.ref_now + datetime.timedelta(hours=8)).isoformat()
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
        self.assertEqual(decision.decision_code, "FUTURE_CREATED_PLAN")
        self.assertTrue(any("FUTURE_CREATED_PLAN" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 4: Missing timestamp rejection
    # -------------------------------------------------------------------------
    def test_04_missing_timestamp_rejected(self):
        with self.assertRaises(PlanExpirationError) as ctx:
            PlanExpirationValidator.validate(created_at_str="", expires_at_str="2026-11-20T12:00:00Z")
        self.assertIn("MISSING_TIMESTAMP", str(ctx.exception))

        with self.assertRaises(PlanExpirationError) as ctx:
            PlanExpirationValidator.validate(created_at_str="2026-11-20T12:00:00Z", expires_at_str="")
        self.assertIn("MISSING_TIMESTAMP", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 5: Malformed timestamp rejection
    # -------------------------------------------------------------------------
    def test_05_malformed_timestamp_rejected(self):
        malformed_inputs = [
            "not-a-timestamp",
            "2026/11/20 12:00:00",
            "2026-11-20T12:00:00",  # Missing UTC timezone offset
            "invalid-iso-string",
            123456789,
        ]
        for bad_ts in malformed_inputs:
            with self.assertRaises(PlanExpirationError):
                PlanExpirationValidator.validate(created_at_str=str(bad_ts), expires_at_str="2026-11-20T15:00:00Z")

    # -------------------------------------------------------------------------
    # Scenario 6: Plan exceeds maximum TTL (12 hours)
    # -------------------------------------------------------------------------
    def test_06_plan_exceeds_maximum_ttl_rejected(self):
        created_at = self.ref_now.isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=12, seconds=1)).isoformat()  # 12h + 1s

        with self.assertRaises(PlanExpirationError) as ctx:
            PlanExpirationValidator.validate(created_at_str=created_at, expires_at_str=expires_at, current_time=self.ref_now)
        self.assertIn("TTL_EXCEEDED", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 7: Valid state serial
    # -------------------------------------------------------------------------
    def test_07_valid_state_serial_and_lineage_accepted(self):
        state = self._create_synthetic_state(serial=100, lineage="uuid-1234")
        res = StateConsistencyValidator.validate(
            current_state=state,
            expected_lineage="uuid-1234",
            expected_serial=100,
        )
        self.assertEqual(res["serial"], 100)
        self.assertEqual(res["lineage"], "uuid-1234")

    # -------------------------------------------------------------------------
    # Scenario 8: Stale serial rejection
    # -------------------------------------------------------------------------
    def test_08_stale_serial_rejected(self):
        # Current state serial has progressed to 43, but plan expects 42
        state = self._create_synthetic_state(serial=43)
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state=state,
                expected_lineage=self.valid_lineage,
                expected_serial=42,
            )
        self.assertIn("STALE_STATE_SERIAL", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 9: State lineage mismatch rejection
    # -------------------------------------------------------------------------
    def test_09_state_lineage_mismatch_rejected(self):
        state = self._create_synthetic_state(lineage="forged-or-recreated-lineage")
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state=state,
                expected_lineage=self.valid_lineage,
                expected_serial=self.valid_serial,
            )
        self.assertIn("STATE_LINEAGE_MISMATCH", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 10: Backend mismatch rejection
    # -------------------------------------------------------------------------
    def test_10_backend_mismatch_rejected(self):
        state = self._create_synthetic_state()
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state=state,
                expected_lineage=self.valid_lineage,
                expected_serial=self.valid_serial,
                expected_backend="s3://target-prod-bucket/state.tfstate",
                actual_backend="s3://attacker-bucket/state.tfstate",
            )
        self.assertIn("BACKEND_MISMATCH", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 11: Workspace mismatch rejection
    # -------------------------------------------------------------------------
    def test_11_workspace_mismatch_rejected(self):
        state = self._create_synthetic_state()
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state=state,
                expected_lineage=self.valid_lineage,
                expected_serial=self.valid_serial,
                expected_workspace="production",
                actual_workspace="staging",
            )
        self.assertIn("WORKSPACE_MISMATCH", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 12: Missing state metadata rejection
    # -------------------------------------------------------------------------
    def test_12_missing_state_metadata_rejected(self):
        # Empty dictionary without initial state flag
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state={},
                expected_lineage=self.valid_lineage,
                expected_serial=self.valid_serial,
                is_initial_state=False,
            )
        self.assertIn("MISSING_STATE_METADATA", str(ctx.exception))

        # Missing required lineage attribute
        corrupt_state = {"version": 4, "serial": 42}
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state=corrupt_state,
                expected_lineage=self.valid_lineage,
                expected_serial=42,
            )
        self.assertIn("MALFORMED_STATE_METADATA", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 13: Incorrect source commit rejection
    # -------------------------------------------------------------------------
    def test_13_incorrect_source_commit_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, commit="1111111111111111111111111111111111111111")
        state = self._create_synthetic_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,  # Mismatch
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )

        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "COMMIT_MISMATCH")
        self.assertTrue(any("COMMIT_MISMATCH" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 14: Incorrect repository identity rejection
    # -------------------------------------------------------------------------
    def test_14_incorrect_repository_identity_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, repo="attacker-org/rogue-repo")
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
        self.assertTrue(any("REPO_MISMATCH" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 15: Incorrect workflow SHA rejection
    # -------------------------------------------------------------------------
    def test_15_incorrect_workflow_sha_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, workflow_sha="2222222222222222222222222222222222222222")
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
            expected_workflow_sha=self.valid_workflow_sha,  # Mismatch
            current_time=self.ref_now,
        )

        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "WORKFLOW_SHA_MISMATCH")
        self.assertTrue(any("WORKFLOW_SHA_MISMATCH" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 16: Incorrect target environment rejection
    # -------------------------------------------------------------------------
    def test_16_incorrect_target_environment_rejected(self):
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
            expected_environment="production",  # Mismatch
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )

        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "ENVIRONMENT_MISMATCH")
        self.assertTrue(any("ENVIRONMENT_MISMATCH" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 17: Modified encrypted payload / malformed envelope rejection
    # -------------------------------------------------------------------------
    def test_17_malformed_envelope_structure_rejected(self):
        state = self._create_synthetic_state()
        verifier = PlanLifecycleVerifier()

        # Non-dictionary envelope
        decision = verifier.verify_authorization(
            envelope_data="corrupted-string",
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "MALFORMED_ENVELOPE")

    # -------------------------------------------------------------------------
    # Scenario 18: Incorrect plan digest rejection
    # -------------------------------------------------------------------------
    def test_18_incorrect_plan_digest_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, digest="not-a-valid-sha256")
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

    # -------------------------------------------------------------------------
    # Scenario 19: Already consumed plan rejection (Replay prevention)
    # -------------------------------------------------------------------------
    def test_19_already_consumed_plan_rejected(self):
        ledger_db = os.path.join(self.test_dir, "test_consumed.db")
        ledger = PlanReplayLedger(db_path=ledger_db)

        plan_id = "plan-replay-001"
        expires_at = (self.ref_now + datetime.timedelta(hours=4)).isoformat()

        # Initial reservation succeeds
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

        # Plan is consumed
        ledger.consume_plan(plan_id=plan_id, current_time=self.ref_now)

        # Re-reservation attempt must raise PlanReplayError
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

    # -------------------------------------------------------------------------
    # Scenario 20: Concurrent duplicate reservations
    # -------------------------------------------------------------------------
    def test_20_concurrent_duplicate_reservations(self):
        ledger_db = os.path.join(self.test_dir, "test_concurrent.db")
        ledger = PlanReplayLedger(db_path=ledger_db)
        plan_id = "plan-concurrent-001"
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
                successes.append(threading.get_ident())
            except PlanReplayError as e:
                failures.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly ONE thread must succeed; all others must fail closed
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 4)
        for fail_msg in failures:
            self.assertTrue("DUPLICATE_RESERVATION" in fail_msg or "ALREADY_CONSUMED" in fail_msg)

    # -------------------------------------------------------------------------
    # Scenario 21: Interrupted reservation recovery fails closed
    # -------------------------------------------------------------------------
    def test_21_interrupted_reservation_fails_closed(self):
        ledger_db = os.path.join(self.test_dir, "test_interrupted.db")
        ledger = PlanReplayLedger(db_path=ledger_db)
        plan_id = "plan-interrupted-001"
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

        # Crash / interrupt occurs
        ledger.fail_plan(plan_id=plan_id, interrupted=True)

        # Re-reservation must fail closed without manual review
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
        self.assertIn("UNCERTAIN_EXECUTION_STATE", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 22: Replay protection across database / process restart
    # -------------------------------------------------------------------------
    def test_22_replay_protection_persists_across_restarts(self):
        ledger_db = os.path.join(self.test_dir, "test_persistence.db")
        plan_id = "plan-persistent-001"
        expires_at = (self.ref_now + datetime.timedelta(hours=4)).isoformat()

        # Session 1: Reserve and consume
        ledger1 = PlanReplayLedger(db_path=ledger_db)
        ledger1.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=self.valid_digest,
            repository=self.valid_repo,
            commit_sha=self.valid_commit,
            environment=self.valid_env,
            expires_at=expires_at,
            execution_context={},
            current_time=self.ref_now,
        )
        ledger1.consume_plan(plan_id=plan_id, current_time=self.ref_now)

        # Session 2: Fresh ledger instance representing post-restart worker
        ledger2 = PlanReplayLedger(db_path=ledger_db)
        status = ledger2.get_plan_status(plan_id=plan_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["status"], STATUS_CONSUMED)

        with self.assertRaises(PlanReplayError) as ctx:
            ledger2.reserve_plan(
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

    # -------------------------------------------------------------------------
    # Scenario 23: Unverified provenance rejection
    # -------------------------------------------------------------------------
    def test_23_unverified_provenance_rejected(self):
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
            provenance_status="UNVERIFIED",  # Signature unverified
            current_time=self.ref_now,
        )

        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "UNVERIFIED_PROVENANCE")
        self.assertTrue(any("UNVERIFIED_PROVENANCE" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 24: Invalid envelope schema version rejection
    # -------------------------------------------------------------------------
    def test_24_invalid_envelope_schema_version_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at, schema_version="infraflow-plan-envelope-v999")
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
        self.assertEqual(decision.decision_code, "UNSUPPORTED_SCHEMA_VERSION")

    # -------------------------------------------------------------------------
    # Scenario 25: Unauthorized metadata substitution rejection
    # -------------------------------------------------------------------------
    def test_25_unauthorized_metadata_substitution_rejected(self):
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        # Attacker tries to authorize with an expected repo different from the signed envelope
        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo="different-org/different-repo",
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            current_time=self.ref_now,
        )

        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertTrue(any("REPO_MISMATCH" in r for r in decision.reasons))

    # -------------------------------------------------------------------------
    # Scenario 26: State serial regression rejection
    # -------------------------------------------------------------------------
    def test_26_state_serial_regression_rejected(self):
        # Current state serial is 30, but plan was prepared against 42
        state = self._create_synthetic_state(serial=30)
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state=state,
                expected_lineage=self.valid_lineage,
                expected_serial=42,
            )
        self.assertIn("STATE_SERIAL_REGRESSION", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 27: Initial bootstrap state accepted with flag
    # -------------------------------------------------------------------------
    def test_27_initial_bootstrap_state_accepted(self):
        res = StateConsistencyValidator.validate(
            current_state={},
            expected_lineage=self.valid_lineage,
            expected_serial=0,
            is_initial_state=True,
        )
        self.assertTrue(res["is_initial_state"])
        self.assertEqual(res["serial"], 0)

    # -------------------------------------------------------------------------
    # Scenario 28: Initial bootstrap state rejected without flag
    # -------------------------------------------------------------------------
    def test_28_initial_bootstrap_state_rejected_without_flag(self):
        with self.assertRaises(StateConsistencyError) as ctx:
            StateConsistencyValidator.validate(
                current_state={},
                expected_lineage=self.valid_lineage,
                expected_serial=0,
                is_initial_state=False,
            )
        self.assertIn("MISSING_STATE_METADATA", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 29: CLI Subcommands End-to-End
    # -------------------------------------------------------------------------
    def test_29_cli_subcommands_end_to_end(self):
        env_file = os.path.join(self.test_dir, "plan.enc.json")
        state_file = os.path.join(self.test_dir, "terraform.tfstate")
        ledger_db = os.path.join(self.test_dir, "cli_ledger.db")

        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=5)).isoformat()
        envelope = self._create_synthetic_envelope(created_at, expires_at)
        state = self._create_synthetic_state()

        with open(env_file, "w", encoding="utf-8") as f:
            json.dump(envelope, f)
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f)

        # 1. validate-expiration CLI
        cmd_exp = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "validate-expiration",
            "--created-at", created_at,
            "--expires-at", expires_at,
            "--current-time", self.ref_now.isoformat(),
        ]
        p = subprocess.run(cmd_exp, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, f"validate-expiration failed: {p.stderr}")

        # 2. validate-state CLI
        cmd_state = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "validate-state",
            "--state-file", state_file,
            "--expected-lineage", self.valid_lineage,
            "--expected-serial", str(self.valid_serial),
        ]
        p = subprocess.run(cmd_state, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, f"validate-state failed: {p.stderr}")

        # 3. full verify CLI
        cmd_verify = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "verify",
            "--envelope-file", env_file,
            "--state-file", state_file,
            "--expected-repo", self.valid_repo,
            "--expected-commit", self.valid_commit,
            "--expected-environment", self.valid_env,
            "--expected-lineage", self.valid_lineage,
            "--expected-serial", str(self.valid_serial),
            "--expected-workflow-sha", self.valid_workflow_sha,
            "--ledger-db", ledger_db,
            "--current-time", self.ref_now.isoformat(),
        ]
        p = subprocess.run(cmd_verify, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, f"verify failed: {p.stderr}")
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], DECISION_AUTHORIZED)

        # 4. Duplicate verify CLI on same ledger must fail (replay rejection)
        p_dup = subprocess.run(cmd_verify, capture_output=True, text=True)
        self.assertEqual(p_dup.returncode, 1)
        data_dup = json.loads(p_dup.stdout)
        self.assertEqual(data_dup["decision"], DECISION_REJECTED)
        self.assertEqual(data_dup["decision_code"], "DUPLICATE_RESERVATION")


if __name__ == "__main__":
    unittest.main()
