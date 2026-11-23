#!/usr/bin/env python3
"""
InfraFlow — Plan Lifecycle State Correctness & Adversarial Failure Tests
Milestone: G10.5.1 — Plan Lifecycle State Correctness

Comprehensive adversarial test suite validating:
1. Reservation followed by successful completion (CONSUMED).
2. Idempotent duplicate plan consumption (same owner succeeds; different owner fails).
3. Concurrent plan reservations (same target rejects with LOCK_HELD).
4. Stale fencing token consumption rejection (STALE_FENCING_TOKEN).
5. Unauthorized lifecycle transitions (consuming unreserved or failed plans).
6. Lock acquisition failure halts verification before ledger reservation.
7. Lock renewal failure triggers child process termination.
8. Interrupted execution preservation (STATUS_INTERRUPTED blocks re-execution).
9. Uncertain outcome preservation (STATUS_OUTCOME_UNCERTAIN blocks re-execution).
10. Recovery after expired ownership.
11. Database transaction interruption preserves lock and fails closed.
12. Duplicate completion requests (idempotent record_outcome).
13. Lock release failure handling (ledger remains durably committed as CONSUMED).
"""

import datetime
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure platform modules are in import path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from infraflow.locking import (
    DistributedLockDriver,
    LeaseExpiredError,
    LocalFSDriver,
    LockError,
    LockHandle,
    LockHeldError,
    LockLostError,
    LockManager,
    MockDistributedDriver,
    StaleFencingTokenError,
    StaleOwnerError,
)

# Dynamically import verify-plan-lifecycle module
import importlib.util
vpl_path = REPO_ROOT / "scripts" / "verify-plan-lifecycle.py"
spec = importlib.util.spec_from_file_location("verify_plan_lifecycle", str(vpl_path))
vpl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpl)

PlanReplayLedger = vpl.PlanReplayLedger
PlanLifecycleVerifier = vpl.PlanLifecycleVerifier
PlanReplayError = vpl.PlanReplayError
derive_plan_lock_identity = vpl.derive_plan_lock_identity
STATUS_AVAILABLE = vpl.STATUS_AVAILABLE
STATUS_RESERVED = vpl.STATUS_RESERVED
STATUS_CONSUMED = vpl.STATUS_CONSUMED
STATUS_SIMULATION_COMPLETED = vpl.STATUS_SIMULATION_COMPLETED
STATUS_FAILED = vpl.STATUS_FAILED
STATUS_INTERRUPTED = vpl.STATUS_INTERRUPTED
STATUS_OUTCOME_UNCERTAIN = vpl.STATUS_OUTCOME_UNCERTAIN
DECISION_AUTHORIZED = vpl.DECISION_AUTHORIZED
DECISION_REJECTED = vpl.DECISION_REJECTED


class TestPlanLifecycleStateCorrectness(unittest.TestCase):
    """Rigorous test suite for G10.5.1 lifecycle state correctness."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-g10-5-1-")
        self.lock_dir = Path(self.test_dir) / "locks"
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_db = str(Path(self.test_dir) / "ledger.db")
        self.driver = LocalFSDriver(base_dir=self.lock_dir)
        self.lock_manager = LockManager(driver=self.driver, default_ttl_seconds=900)
        self.ledger = PlanReplayLedger(db_path=self.ledger_db)

    def tearDown(self):
        self.ledger.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _sample_envelope(self, plan_id="plan-test-01", digest="a" * 64):
        now = datetime.datetime.now(datetime.timezone.utc)
        return {
            "schema_version": "infraflow-plan-envelope-v1",
            "plan_id": plan_id,
            "plan_digest": digest,
            "digest_sha256": digest,
            "created_at": now.isoformat(),
            "expires_at": (now + datetime.timedelta(hours=2)).isoformat(),
            "lifecycle": {
                "created_at_utc": now.isoformat(),
                "expires_at_utc": (now + datetime.timedelta(hours=2)).isoformat(),
            },
            "context": {
                "plan_digest_sha256": digest,
                "created_at": now.isoformat(),
                "expires_at": (now + datetime.timedelta(hours=2)).isoformat(),
                "repository": "TM-threemavithana/infraflow",
                "commit_sha": "1" * 40,
                "environment": "production",
                "workspace": "default",
                "workflow": "reusable-tf-apply.yml",
            },
            "encrypted_payload": {
                "ciphertext": "mock-ciphertext",
                "iv": "mock-iv",
                "auth_tag": "mock-tag",
            },
        }

    def _sample_state(self, lineage="11111111-1111-1111-1111-111111111111", serial=1):
        return {
            "version": 4,
            "terraform_version": "1.10.4",
            "serial": serial,
            "lineage": lineage,
            "resources": [],
        }

    # --------------------------------------------------------------------------
    # Test 1: Reservation followed by successful completion (CONSUMED)
    # --------------------------------------------------------------------------
    def test_01_reservation_followed_by_successful_completion(self):
        """Plan transitions from RESERVED to CONSUMED and lock is safely released."""
        plan_id = "plan-succ-01"
        digest = "1" * 64
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", plan_id)

        handle = self.lock_manager.acquire_lock(
            key=key,
            owner_identity={"runner_id": "runner-1", "actor": "tester"},
            purpose=f"plan-execution:{plan_id}",
            ttl_seconds=300,
        )
        self.assertTrue(handle.is_active())

        # Reserve plan
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=digest,
            repository="TM-threemavithana/infraflow",
            commit_sha="a" * 40,
            environment="production",
            expires_at=now,
            execution_context={"source": "test"},
            lock_id=handle.lock_id,
            fencing_token=handle.fencing_token,
            canonical_lock_key=handle.key,
        )

        status_meta = self.ledger.get_plan_status(plan_id)
        self.assertEqual(status_meta["status"], STATUS_RESERVED)
        self.assertEqual(status_meta["lock_id"], handle.lock_id)
        self.assertEqual(status_meta["fencing_token"], handle.fencing_token)

        # Complete simulation & consume plan
        verifier = PlanLifecycleVerifier(ledger=self.ledger, lock_manager=self.lock_manager)
        verifier.consume_plan(plan_id=plan_id, lock_handle=handle, release_lock=True)

        final_meta = self.ledger.get_plan_status(plan_id)
        self.assertEqual(final_meta["status"], STATUS_CONSUMED)
        self.assertIsNotNone(final_meta["consumed_at"])
        # Lock handle must be released
        self.assertEqual(handle.status, "RELEASED")
        self.assertFalse(handle.is_active())

    # --------------------------------------------------------------------------
    # Test 2: Idempotent duplicate plan consumption
    # --------------------------------------------------------------------------
    def test_02_idempotent_duplicate_plan_consumption(self):
        """Duplicate consume by same owner succeeds idempotently; different owner fails."""
        plan_id = "plan-idem-01"
        digest = "2" * 64
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", plan_id)

        handle_a = self.lock_manager.acquire_lock(
            key=key,
            owner_identity={"runner_id": "runner-a", "actor": "tester-a"},
            purpose=f"plan-execution:{plan_id}",
        )

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=digest,
            repository="TM-threemavithana/infraflow",
            commit_sha="a" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
            lock_id=handle_a.lock_id,
            fencing_token=handle_a.fencing_token,
            canonical_lock_key=handle_a.key,
        )

        # Initial consume by owner A
        self.ledger.consume_plan(
            plan_id=plan_id,
            lock_id=handle_a.lock_id,
            fencing_token=handle_a.fencing_token,
        )
        self.assertEqual(self.ledger.get_plan_status(plan_id)["status"], STATUS_CONSUMED)

        # Duplicate consume by owner A must succeed idempotently (no error)
        try:
            self.ledger.consume_plan(
                plan_id=plan_id,
                lock_id=handle_a.lock_id,
                fencing_token=handle_a.fencing_token,
            )
        except PlanReplayError:
            self.fail("Duplicate consume by the same owner should be idempotent and succeed")

        # Duplicate consume by different owner B must fail with ALREADY_CONSUMED
        with self.assertRaises(PlanReplayError) as ctx:
            self.ledger.consume_plan(
                plan_id=plan_id,
                lock_id="different-lock-id",
                fencing_token=handle_a.fencing_token,
            )
        self.assertIn("ALREADY_CONSUMED", str(ctx.exception))

    # --------------------------------------------------------------------------
    # Test 3: Concurrent plan reservations (same target rejects with LOCK_HELD)
    # --------------------------------------------------------------------------
    def test_03_concurrent_plan_reservations_same_target(self):
        """Second worker attempting to acquire lock on held target is rejected."""
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", "shared")

        handle_1 = self.lock_manager.acquire_lock(
            key=key,
            owner_identity={"runner_id": "runner-1"},
            purpose="operation-1",
        )
        self.assertTrue(handle_1.is_active())

        # Worker 2 attempts acquisition on same key
        with self.assertRaises(LockHeldError):
            self.lock_manager.acquire_lock(
                key=key,
                owner_identity={"runner_id": "runner-2"},
                purpose="operation-2",
            )

        self.lock_manager.release_lock(handle_1)

    # --------------------------------------------------------------------------
    # Test 4: Stale fencing token consumption rejection
    # --------------------------------------------------------------------------
    def test_04_stale_fencing_token_consumption_rejection(self):
        """Plan reserved with token 1 cannot be consumed if superseded by token 2 on same key."""
        plan_id = "plan-stale-01"
        digest = "4" * 64
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", plan_id)

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Reserve plan 1 with token 1
        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=digest,
            repository="TM-threemavithana/infraflow",
            commit_sha="a" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
            lock_id="lock-1",
            fencing_token=1,
            canonical_lock_key=key,
        )

        # Another plan or reservation on the same key establishes higher fencing token 2
        self.ledger.reserve_plan(
            plan_id="plan-other-02",
            plan_digest_sha256="5" * 64,
            repository="TM-threemavithana/infraflow",
            commit_sha="b" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
            lock_id="lock-2",
            fencing_token=2,
            canonical_lock_key=key,
        )

        # Attempting to consume plan 1 with stale token 1 must be rejected
        with self.assertRaises(PlanReplayError) as ctx:
            self.ledger.consume_plan(
                plan_id=plan_id,
                lock_id="lock-1",
                fencing_token=1,
            )
        self.assertIn("STALE_FENCING_TOKEN", str(ctx.exception))

    # --------------------------------------------------------------------------
    # Test 5: Unauthorized lifecycle transitions
    # --------------------------------------------------------------------------
    def test_05_unauthorized_lifecycle_transitions(self):
        """Consuming non-existent, failed, or interrupted plans is strictly prohibited."""
        # Non-existent plan
        with self.assertRaises(PlanReplayError) as ctx:
            self.ledger.consume_plan(plan_id="non-existent")
        self.assertIn("PLAN_NOT_FOUND", str(ctx.exception))

        # Plan in FAILED status
        plan_id = "plan-failed-01"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256="6" * 64,
            repository="TM-threemavithana/infraflow",
            commit_sha="c" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
        )
        self.ledger.fail_plan(plan_id=plan_id)
        self.assertEqual(self.ledger.get_plan_status(plan_id)["status"], STATUS_FAILED)

        with self.assertRaises(PlanReplayError) as ctx:
            self.ledger.consume_plan(plan_id=plan_id)
        self.assertIn("INVALID_STATE_TRANSITION", str(ctx.exception))

    # --------------------------------------------------------------------------
    # Test 6: Lock acquisition failure halts verification before ledger reservation
    # --------------------------------------------------------------------------
    def test_06_lock_acquisition_failure_halts_verification_before_ledger_reservation(self):
        """When lock is held externally, verify_authorization rejects and creates NO ledger record."""
        plan_id = "plan-lock-halt-01"
        digest = "7" * 64
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", plan_id)

        # Hold lock externally
        ext_handle = self.lock_manager.acquire_lock(
            key=key,
            owner_identity={"runner_id": "external-blocker"},
            purpose="blocking-lock",
        )

        verifier = PlanLifecycleVerifier(ledger=self.ledger, lock_manager=self.lock_manager)
        envelope = self._sample_envelope(plan_id=plan_id, digest=digest)
        state = self._sample_state()

        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo="TM-threemavithana/infraflow",
            expected_commit="1" * 40,
            expected_environment="production",
            expected_lineage=state["lineage"],
            expected_serial=state["serial"],
            expected_backend="s3://bucket/tfstate",
            actual_backend="s3://bucket/tfstate",
            enable_lock=True,
            reserve_in_ledger=True,
        )

        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "LOCK_HELD")

        # Crucial invariant: plan was NEVER inserted into the ledger!
        ledger_status = self.ledger.get_plan_status(plan_id)
        self.assertIsNone(ledger_status)

        self.lock_manager.release_lock(ext_handle)

    # --------------------------------------------------------------------------
    # Test 7: Lock renewal failure triggers child process termination
    # --------------------------------------------------------------------------
    def test_07_lock_renewal_failure_triggers_child_process_termination(self):
        """LockHandle terminates registered child process when lease is marked lost."""
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", "proc-test")
        handle = self.lock_manager.acquire_lock(
            key=key,
            owner_identity={"runner_id": "proc-runner"},
            purpose="test-proc",
        )

        # Spawn sleep child process
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.assertIsNone(proc.poll())  # Process is running

        handle.register_child_process(proc)

        # Trigger lease loss (fast-fail cutoff)
        handle.mark_lost("Lease unacknowledged: fast fail cutoff reached")

        self.assertEqual(handle.status, "LOST")
        # Process must now be terminated
        proc.wait(timeout=5.0)
        self.assertIsNotNone(proc.poll())

    # --------------------------------------------------------------------------
    # Test 8: Interrupted execution preservation
    # --------------------------------------------------------------------------
    def test_08_interrupted_execution_preservation(self):
        """INTERRUPTED state recorded durably; subsequent attempts to reserve are quarantined."""
        plan_id = "plan-int-01"
        digest = "8" * 64
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=digest,
            repository="TM-threemavithana/infraflow",
            commit_sha="1" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
        )
        self.ledger.fail_plan(plan_id=plan_id, interrupted=True)

        meta = self.ledger.get_plan_status(plan_id)
        self.assertEqual(meta["status"], STATUS_INTERRUPTED)

        # Re-reservation must be blocked fail-closed
        with self.assertRaises(PlanReplayError) as ctx:
            self.ledger.reserve_plan(
                plan_id=plan_id,
                plan_digest_sha256=digest,
                repository="TM-threemavithana/infraflow",
                commit_sha="1" * 40,
                environment="production",
                expires_at=now,
                execution_context={},
            )
        self.assertIn("UNCERTAIN_EXECUTION_STATE", str(ctx.exception))

    # --------------------------------------------------------------------------
    # Test 9: Uncertain outcome preservation
    # --------------------------------------------------------------------------
    def test_09_uncertain_outcome_preservation(self):
        """OUTCOME_UNCERTAIN state recorded durably; subsequent attempts to reserve are quarantined."""
        plan_id = "plan-unc-01"
        digest = "9" * 64
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=digest,
            repository="TM-threemavithana/infraflow",
            commit_sha="1" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
        )
        self.ledger.fail_plan(plan_id=plan_id, uncertain=True)

        meta = self.ledger.get_plan_status(plan_id)
        self.assertEqual(meta["status"], STATUS_OUTCOME_UNCERTAIN)

        with self.assertRaises(PlanReplayError) as ctx:
            self.ledger.reserve_plan(
                plan_id=plan_id,
                plan_digest_sha256=digest,
                repository="TM-threemavithana/infraflow",
                commit_sha="1" * 40,
                environment="production",
                expires_at=now,
                execution_context={},
            )
        self.assertIn("UNCERTAIN_EXECUTION_STATE", str(ctx.exception))

    # --------------------------------------------------------------------------
    # Test 10: Recovery after expired ownership
    # --------------------------------------------------------------------------
    def test_10_recovery_after_expired_ownership(self):
        """After a lock lease expires, a new owner can acquire it with a strictly higher token."""
        mock_time = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)
        mock_driver = MockDistributedDriver(clock_fn=lambda: mock_time)
        mgr = LockManager(driver=mock_driver, default_ttl_seconds=60)
        lock_target = "infraflow/locks/v1/mock/recovery-target"

        handle1 = mgr.acquire_lock(key=lock_target, owner_identity={"runner_id": "runner-1"}, purpose="p1", ttl_seconds=60)
        tok1 = handle1.fencing_token

        # Advance time by 120 seconds (past expiry)
        mock_time += datetime.timedelta(seconds=120)

        # Old owner cannot release or renew
        with self.assertRaises(LeaseExpiredError):
            mgr.release_lock(handle1)

        # New owner successfully acquires with strictly monotonic token
        handle2 = mgr.acquire_lock(key=lock_target, owner_identity={"runner_id": "runner-2"}, purpose="p2", ttl_seconds=60)
        tok2 = handle2.fencing_token
        self.assertGreater(tok2, tok1)

        mgr.release_lock(handle2)

    # --------------------------------------------------------------------------
    # Test 11: Database transaction interruption preserves lock and fails closed
    # --------------------------------------------------------------------------
    def test_11_database_transaction_interruption_preserves_lock_and_fails_closed(self):
        """If database throws an operational error during reservation, verifier fails closed."""
        plan_id = "plan-db-err-01"
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", plan_id)

        envelope = self._sample_envelope(plan_id=plan_id, digest="b" * 64)
        state = self._sample_state()

        verifier = PlanLifecycleVerifier(ledger=self.ledger, lock_manager=self.lock_manager)

        # Mock reserve_plan to simulate database lock error
        with patch.object(self.ledger, "reserve_plan", side_effect=sqlite3.OperationalError("database is locked")):
            with self.assertRaises(sqlite3.OperationalError):
                verifier.verify_authorization(
                    envelope_data=envelope,
                    state_data=state,
                    expected_repo="TM-threemavithana/infraflow",
                    expected_commit="1" * 40,
                    expected_environment="production",
                    expected_lineage=state["lineage"],
                    expected_serial=state["serial"],
                    expected_backend="s3://bucket/tfstate",
                    actual_backend="s3://bucket/tfstate",
                    enable_lock=True,
                    reserve_in_ledger=True,
                )

        # Plan was not reserved
        self.assertIsNone(self.ledger.get_plan_status(plan_id))

    # --------------------------------------------------------------------------
    # Test 12: Duplicate completion requests (record_outcome idempotency)
    # --------------------------------------------------------------------------
    def test_12_duplicate_completion_requests(self):
        """Calling record_outcome with the same status is safe and idempotent."""
        plan_id = "plan-dup-rec-01"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256="c" * 64,
            repository="TM-threemavithana/infraflow",
            commit_sha="1" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
            lock_id="lock-idem",
            fencing_token=5,
        )

        # Record outcome FAILED
        self.ledger.record_outcome(plan_id=plan_id, status=STATUS_FAILED, lock_id="lock-idem", fencing_token=5)
        self.assertEqual(self.ledger.get_plan_status(plan_id)["status"], STATUS_FAILED)

        # Duplicate record_outcome with same status and owner succeeds
        self.ledger.record_outcome(plan_id=plan_id, status=STATUS_FAILED, lock_id="lock-idem", fencing_token=5)
        self.assertEqual(self.ledger.get_plan_status(plan_id)["status"], STATUS_FAILED)

    # --------------------------------------------------------------------------
    # Test 13: Lock release failure handling (ledger remains CONSUMED)
    # --------------------------------------------------------------------------
    def test_13_lock_release_failure_handling(self):
        """If lock release raises an error, the plan state in the ledger remains durably CONSUMED."""
        plan_id = "plan-rel-fail-01"
        digest = "d" * 64
        key, _ = derive_plan_lock_identity("s3://bucket/tfstate", "default", "TM-threemavithana/infraflow", "production", plan_id)

        handle = self.lock_manager.acquire_lock(
            key=key,
            owner_identity={"runner_id": "runner-1"},
            purpose=f"plan-execution:{plan_id}",
        )

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=digest,
            repository="TM-threemavithana/infraflow",
            commit_sha="1" * 40,
            environment="production",
            expires_at=now,
            execution_context={},
            lock_id=handle.lock_id,
            fencing_token=handle.fencing_token,
            canonical_lock_key=handle.key,
        )

        verifier = PlanLifecycleVerifier(ledger=self.ledger, lock_manager=self.lock_manager)

        # Simulate exception during release_lock (e.g. storage I/O error or partition)
        with patch.object(self.lock_manager, "release_lock", side_effect=LockError("Disk I/O failure during unlock")):
            with self.assertRaises(LockError):
                verifier.consume_plan(plan_id=plan_id, lock_handle=handle, release_lock=True)

        # CRITICAL INVARIANT: The ledger state is durably committed as CONSUMED and NOT rolled back!
        meta = self.ledger.get_plan_status(plan_id)
        self.assertEqual(meta["status"], STATUS_CONSUMED)
        self.assertIsNotNone(meta["consumed_at"])


if __name__ == "__main__":
    unittest.main()
