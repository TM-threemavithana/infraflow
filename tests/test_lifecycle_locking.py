#!/usr/bin/env python3
"""
InfraFlow — Plan Lifecycle & Lock Authority Validation Tests
Milestone: G10.4.4 — Lifecycle Integration & Lock Authority Validation

Adversarial and functional validation for the integration of LockManager
and canonical distributed locking into the pre-execution plan lifecycle:
1. Happy path: Lock acquisition & binding in authorization contract and replay ledger.
2. Safe consumption: Plan consumption with lock release and active lease check.
3. Mutual exclusion: Concurrent execution attempts on the same target rejected with LOCK_HELD.
4. Target isolation: Independent state targets execute concurrently without contention.
5. Fencing token protection: Stale owners with superseded fencing tokens cannot consume plans.
6. Heartbeat/Lease loss fast-fail: Lost lock handles reject plan consumption (StaleOwnerError).
7. Uncertain outcome preservation: OUTCOME_UNCERTAIN recorded upon partition and fails closed.
8. Interrupted execution preservation: INTERRUPTED recorded on crash/kill and blocks duplicate apply.
9. Telemetry emission: Telemetry events (lock_acquired, lock_released) emitted and scrubbed.
10. CLI subcommands roundtrip: lock-identity, lock-reserve, lock-consume, lock-fail, verify --enable-lock.
"""

import datetime
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict

from infraflow.locking import (
    LocalFSDriver,
    LockError,
    LockHandle,
    LockHeldError,
    LockLostError,
    LockManager,
    LockRecord,
    MockDistributedDriver,
    StaleOwnerError,
    derive_canonical_lock_identity,
)

# Dynamically import scripts/verify-plan-lifecycle.py
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
LIFECYCLE_SCRIPT = os.path.join(SCRIPTS_DIR, "verify-plan-lifecycle.py")
if not os.path.isfile(LIFECYCLE_SCRIPT):
    raise FileNotFoundError(f"Missing {LIFECYCLE_SCRIPT}")

spec = importlib.util.spec_from_file_location("verify_plan_lifecycle", LIFECYCLE_SCRIPT)
vpl = importlib.util.module_from_spec(spec)
sys.modules["verify_plan_lifecycle"] = vpl
spec.loader.exec_module(vpl)

PlanLifecycleVerifier = vpl.PlanLifecycleVerifier
PlanReplayLedger = vpl.PlanReplayLedger
PlanReplayError = vpl.PlanReplayError
derive_plan_lock_identity = vpl.derive_plan_lock_identity
DECISION_AUTHORIZED = vpl.DECISION_AUTHORIZED
DECISION_REJECTED = vpl.DECISION_REJECTED
STATUS_RESERVED = vpl.STATUS_RESERVED
STATUS_CONSUMED = vpl.STATUS_CONSUMED
STATUS_FAILED = vpl.STATUS_FAILED
STATUS_INTERRUPTED = vpl.STATUS_INTERRUPTED
STATUS_OUTCOME_UNCERTAIN = vpl.STATUS_OUTCOME_UNCERTAIN
ENVELOPE_SCHEMA_VERSION = vpl.ENVELOPE_SCHEMA_VERSION
AUTHORIZATION_SCHEMA_VERSION = vpl.AUTHORIZATION_SCHEMA_VERSION


class TestLifecycleLocking(unittest.TestCase):
    """Integration and adversarial test suite for Milestone G10.4.4."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-g10-lifecycle-lock-")
        self.locks_dir = os.path.join(self.test_dir, "locks")
        os.makedirs(self.locks_dir, exist_ok=True)
        self.ledger_db = os.path.join(self.test_dir, "ledger.sqlite")

        self.ref_now = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)
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
        plan_id: str = "plan-test-lock-001",
        digest: str = None,
        backend: str = None,
    ) -> Dict[str, Any]:
        created_at = self.ref_now.isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=2)).isoformat()
        return {
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "algorithm": "AES-256-GCM",
            "plan_id": plan_id,
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/mock-infraflow-plan-kek",
            "created_at": created_at,
            "expires_at": expires_at,
            "context": {
                "repository": self.valid_repo,
                "commit_sha": self.valid_commit,
                "environment": self.valid_env,
                "plan_digest_sha256": digest or self.valid_digest,
                "workflow_sha": self.valid_workflow_sha,
                "workflow": "reusable-tf-plan.yml",
                "terraform_version": "1.10.4",
                "backend": backend or self.valid_backend,
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
    ) -> Dict[str, Any]:
        return {
            "version": 4,
            "terraform_version": "1.10.4",
            "serial": self.valid_serial if serial is None else serial,
            "lineage": self.valid_lineage if lineage is None else lineage,
            "backend": {
                "type": "s3",
                "config": {
                    "bucket": "infraflow-tfstate-bucket",
                    "key": "env/production/tf.state",
                    "region": "us-east-1",
                },
            },
            "resources": [],
        }

    def test_01_happy_path_lock_and_reserve(self):
        """Test happy-path authorization with locking enabled."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        envelope = self._create_synthetic_envelope("plan-hp-001")
        state = self._create_synthetic_state()

        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            expected_workspace=self.valid_workspace,
            require_lock=True,
            current_time=self.ref_now,
        )

        self.assertEqual(decision.decision, DECISION_AUTHORIZED, f"Reasons: {decision.reasons}")
        self.assertEqual(decision.decision_code, "AUTH_SUCCESS")
        self.assertIsNotNone(decision.contract)
        contract = decision.contract

        # Contract must bind lock identity and authority
        self.assertIsNotNone(contract["lock_id"])
        self.assertGreaterEqual(contract["fencing_token"], 1)
        self.assertIn("production", contract["canonical_lock_key"])
        self.assertEqual(contract["lock_authority"], "InfraFlow-Orchestration-Lock-v1")

        # Active lock handle attached to decision
        self.assertIsNotNone(decision.lock_handle)
        self.assertTrue(decision.lock_handle.is_active())

        # Ledger record must persist lock metadata
        record = ledger.get_plan_status("plan-hp-001")
        self.assertEqual(record["status"], STATUS_RESERVED)
        self.assertEqual(record["lock_id"], contract["lock_id"])
        self.assertEqual(record["fencing_token"], contract["fencing_token"])
        self.assertEqual(record["canonical_lock_key"], contract["canonical_lock_key"])

    def test_02_consume_plan_releases_lock(self):
        """Test consuming a plan updates ledger and safely releases the orchestration lock."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        envelope = self._create_synthetic_envelope("plan-consume-001")
        state = self._create_synthetic_state()

        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_AUTHORIZED)
        handle = decision.lock_handle

        # Consume the plan
        verifier.consume_plan(
            plan_id="plan-consume-001",
            lock_handle=handle,
            release_lock=True,
        )

        # Ledger state transitioned to CONSUMED
        record = ledger.get_plan_status("plan-consume-001")
        self.assertEqual(record["status"], STATUS_CONSUMED)
        self.assertIsNotNone(record["consumed_at"])

        # Lock handle must be released
        self.assertFalse(handle.is_active())
        self.assertEqual(handle.status, "RELEASED")

        # Another worker can now acquire lock immediately on same target
        handle2 = mgr.acquire_lock(
            key=handle.key,
            owner_identity={"repo": self.valid_repo, "env": self.valid_env},
            purpose="test-next-run",
            ttl_seconds=60,
        )
        self.assertTrue(handle2.is_active())
        self.assertGreater(handle2.fencing_token, handle.fencing_token)
        mgr.release_lock(handle2)

    def test_03_concurrent_race_same_backend_rejected(self):
        """Test that two workers attempting execution on the same backend produce mutual exclusion."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        env1 = self._create_synthetic_envelope("plan-race-001", digest="1111" + "a" * 60)
        env2 = self._create_synthetic_envelope("plan-race-002", digest="2222" + "b" * 60)
        state = self._create_synthetic_state()

        # Worker 1 acquires lock & reservation
        d1 = verifier.verify_authorization(
            envelope_data=env1,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(d1.decision, DECISION_AUTHORIZED)

        # Worker 2 attempts authorization on same backend & environment
        d2 = verifier.verify_authorization(
            envelope_data=env2,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(d2.decision, DECISION_REJECTED)
        self.assertEqual(d2.decision_code, "LOCK_HELD")
        self.assertTrue(any("currently held by another worker" in r for r in d2.reasons))

        # After Worker 1 consumes and releases, Worker 2 succeeds
        verifier.consume_plan("plan-race-001", lock_handle=d1.lock_handle, release_lock=True)

        d2_retry = verifier.verify_authorization(
            envelope_data=env2,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(d2_retry.decision, DECISION_AUTHORIZED)
        verifier.consume_plan("plan-race-002", lock_handle=d2_retry.lock_handle, release_lock=True)

    def test_04_key_isolation_different_backends_succeed(self):
        """Test independent backends acquire separate locks concurrently without contention."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        backend_vpc = "s3://infraflow-tfstate-bucket/env/production/network/vpc.tfstate"
        backend_db = "s3://infraflow-tfstate-bucket/env/production/database/rds.tfstate"

        env_vpc = self._create_synthetic_envelope("plan-iso-vpc", digest="3333" + "c" * 60, backend=backend_vpc)
        env_db = self._create_synthetic_envelope("plan-iso-db", digest="4444" + "d" * 60, backend=backend_db)

        state_vpc = self._create_synthetic_state()
        state_db = self._create_synthetic_state()

        d_vpc = verifier.verify_authorization(
            envelope_data=env_vpc,
            state_data=state_vpc,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=backend_vpc,
            actual_backend=backend_vpc,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(d_vpc.decision, DECISION_AUTHORIZED)

        d_db = verifier.verify_authorization(
            envelope_data=env_db,
            state_data=state_db,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=backend_db,
            actual_backend=backend_db,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(d_db.decision, DECISION_AUTHORIZED)

        # Both hold active locks simultaneously on distinct canonical keys
        self.assertNotEqual(d_vpc.lock_handle.key, d_db.lock_handle.key)
        self.assertTrue(d_vpc.lock_handle.is_active())
        self.assertTrue(d_db.lock_handle.is_active())

        verifier.consume_plan("plan-iso-vpc", lock_handle=d_vpc.lock_handle)
        verifier.consume_plan("plan-iso-db", lock_handle=d_db.lock_handle)

    def test_05_stale_owner_fencing_token_rejection(self):
        """Test stale owner cannot consume a plan if a superseding fencing token exists."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        env1 = self._create_synthetic_envelope("plan-stale-001", digest="5555" + "e" * 60)
        state1 = self._create_synthetic_state()

        d1 = verifier.verify_authorization(
            envelope_data=env1,
            state_data=state1,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(d1.decision, DECISION_AUTHORIZED)
        token1 = d1.contract["fencing_token"]
        key = d1.contract["canonical_lock_key"]

        # Simulate subsequent higher fencing token recorded for the same key
        # (e.g. Worker 2 acquired a lock later on the same target)
        token2 = token1 + 1
        ledger.reserve_plan(
            plan_id="plan-superseding-002",
            plan_digest_sha256="6666" + "f" * 60,
            repository=self.valid_repo,
            commit_sha=self.valid_commit,
            environment=self.valid_env,
            expires_at=(self.ref_now + datetime.timedelta(hours=1)).isoformat(),
            execution_context={},
            lock_id="lock-superseding-id",
            fencing_token=token2,
            canonical_lock_key=key,
        )

        # Worker 1 now attempts to consume plan-stale-001 with stale token1
        with self.assertRaises(PlanReplayError) as ctx:
            ledger.consume_plan(
                plan_id="plan-stale-001",
                fencing_token=token1,
            )
        self.assertIn("STALE_FENCING_TOKEN", str(ctx.exception))

    def test_06_lost_handle_consume_rejected(self):
        """Test that a lost or expired lock handle cannot consume a plan (StaleOwnerError)."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        env = self._create_synthetic_envelope("plan-lost-001")
        state = self._create_synthetic_state()

        decision = verifier.verify_authorization(
            envelope_data=env,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_AUTHORIZED)
        handle = decision.lock_handle

        # Simulate lease loss (e.g., heartbeat failure, partition)
        handle.mark_lost("heartbeat_failure")

        with self.assertRaises(StaleOwnerError) as ctx:
            verifier.consume_plan(
                plan_id="plan-lost-001",
                lock_handle=handle,
            )
        self.assertIn("is no longer active", str(ctx.exception))

        # Ledger state remains RESERVED (not silently marked consumed)
        rec = ledger.get_plan_status("plan-lost-001")
        self.assertEqual(rec["status"], STATUS_RESERVED)

    def test_07_uncertain_outcome_preservation(self):
        """Test OUTCOME_UNCERTAIN fails closed and prevents retry without investigation."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        env = self._create_synthetic_envelope("plan-uncertain-001")
        state = self._create_synthetic_state()

        decision = verifier.verify_authorization(
            envelope_data=env,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_AUTHORIZED)

        # Mark execution outcome uncertain (e.g. cloud apply timed out during API call)
        verifier.fail_plan(
            plan_id="plan-uncertain-001",
            uncertain=True,
            lock_handle=decision.lock_handle,
            release_lock=True,
        )

        rec = ledger.get_plan_status("plan-uncertain-001")
        self.assertEqual(rec["status"], STATUS_OUTCOME_UNCERTAIN)

        # Attempting to re-authorize or reserve this plan must fail closed
        with self.assertRaises(PlanReplayError) as ctx:
            ledger.reserve_plan(
                plan_id="plan-uncertain-001",
                plan_digest_sha256=self.valid_digest,
                repository=self.valid_repo,
                commit_sha=self.valid_commit,
                environment=self.valid_env,
                expires_at=(self.ref_now + datetime.timedelta(hours=1)).isoformat(),
                execution_context={},
            )
        self.assertIn("UNCERTAIN_EXECUTION_STATE", str(ctx.exception))

    def test_08_interrupted_execution_preservation(self):
        """Test INTERRUPTED state fails closed and prevents silent re-execution."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        env = self._create_synthetic_envelope("plan-interrupted-001")
        state = self._create_synthetic_state()

        decision = verifier.verify_authorization(
            envelope_data=env,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_AUTHORIZED)

        # Fail with interrupted
        verifier.fail_plan(
            plan_id="plan-interrupted-001",
            interrupted=True,
            lock_handle=decision.lock_handle,
            release_lock=True,
        )

        rec = ledger.get_plan_status("plan-interrupted-001")
        self.assertEqual(rec["status"], STATUS_INTERRUPTED)

        # Duplicate reserve must fail closed
        with self.assertRaises(PlanReplayError) as ctx:
            ledger.reserve_plan(
                plan_id="plan-interrupted-001",
                plan_digest_sha256=self.valid_digest,
                repository=self.valid_repo,
                commit_sha=self.valid_commit,
                environment=self.valid_env,
                expires_at=(self.ref_now + datetime.timedelta(hours=1)).isoformat(),
                execution_context={},
            )
        self.assertIn("INTERRUPTED", str(ctx.exception))

    def test_09_telemetry_emission(self):
        """Test that LockManager emits structured telemetry for lock events."""
        telemetry_events = []

        def capture_telemetry(evt_type: str, data: Dict[str, Any]):
            telemetry_events.append({"event_type": evt_type, "data": data})

        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300, telemetry_callback=capture_telemetry)
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        verifier = PlanLifecycleVerifier(ledger=ledger, lock_manager=mgr)

        env = self._create_synthetic_envelope("plan-telem-001")
        state = self._create_synthetic_state()

        decision = verifier.verify_authorization(
            envelope_data=env,
            state_data=state,
            expected_repo=self.valid_repo,
            expected_commit=self.valid_commit,
            expected_environment=self.valid_env,
            expected_lineage=self.valid_lineage,
            expected_serial=self.valid_serial,
            expected_backend=self.valid_backend,
            actual_backend=self.valid_backend,
            require_lock=True,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_AUTHORIZED)

        # Check telemetry includes lock_acquired
        acquired_events = [e for e in telemetry_events if e["event_type"] == "lock_acquired"]
        self.assertGreaterEqual(len(acquired_events), 1)
        self.assertIn("key", acquired_events[0]["data"])
        self.assertIn("lock_id", acquired_events[0]["data"])

        # Consume and release
        verifier.consume_plan("plan-telem-001", lock_handle=decision.lock_handle, release_lock=True)

        # Check telemetry includes lock_released
        released_events = [e for e in telemetry_events if e["event_type"] == "lock_released"]
        self.assertGreaterEqual(len(released_events), 1)

    def test_10_cli_roundtrip(self):
        """Test complete CLI subcommand roundtrip: identity, reserve, consume, fail, and verify."""
        env_file = os.path.join(self.test_dir, "test_env.json")
        state_file = os.path.join(self.test_dir, "test_state.json")
        with open(env_file, "w", encoding="utf-8") as f:
            json.dump(self._create_synthetic_envelope("plan-cli-001"), f)
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(self._create_synthetic_state(), f)

        # 1. lock-identity CLI
        cmd_id = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "lock-identity",
            "--repo", self.valid_repo,
            "--environment", self.valid_env,
            "--backend", self.valid_backend,
            "--workspace", "default",
        ]
        p_id = subprocess.run(cmd_id, capture_output=True, text=True)
        self.assertEqual(p_id.returncode, 0, f"lock-identity failed: {p_id.stderr}")
        data_id = json.loads(p_id.stdout)
        self.assertIn("canonical_lock_key", data_id)
        self.assertIn("resource_fingerprint", data_id)

        # 2. lock-reserve CLI
        cmd_res = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "lock-reserve",
            "--plan-id", "plan-cli-reserve",
            "--plan-digest", self.valid_digest,
            "--repo", self.valid_repo,
            "--commit", self.valid_commit,
            "--environment", self.valid_env,
            "--expires-at", (self.ref_now + datetime.timedelta(hours=1)).isoformat(),
            "--backend", self.valid_backend,
            "--ledger-db", self.ledger_db,
            "--lock-dir", self.locks_dir,
        ]
        p_res = subprocess.run(cmd_res, capture_output=True, text=True)
        self.assertEqual(p_res.returncode, 0, f"lock-reserve failed: {p_res.stderr}")
        data_res = json.loads(p_res.stdout)
        self.assertEqual(data_res["status"], "PASS")
        self.assertIn("lock_id", data_res)
        self.assertGreaterEqual(data_res["fencing_token"], 1)

        # 3. lock-consume CLI
        cmd_con = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "lock-consume",
            "--plan-id", "plan-cli-reserve",
            "--ledger-db", self.ledger_db,
            "--lock-dir", self.locks_dir,
            "--lock-id", data_res["lock_id"],
            "--fencing-token", str(data_res["fencing_token"]),
        ]
        p_con = subprocess.run(cmd_con, capture_output=True, text=True)
        self.assertEqual(p_con.returncode, 0, f"lock-consume failed: {p_con.stderr}")
        data_con = json.loads(p_con.stdout)
        self.assertEqual(data_con["status"], "PASS")

        # 4. lock-fail CLI with --uncertain
        cmd_res2 = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "lock-reserve",
            "--plan-id", "plan-cli-fail-unc",
            "--plan-digest", "7777" + "a" * 60,
            "--repo", self.valid_repo,
            "--commit", self.valid_commit,
            "--environment", self.valid_env,
            "--expires-at", (self.ref_now + datetime.timedelta(hours=1)).isoformat(),
            "--backend", self.valid_backend,
            "--ledger-db", self.ledger_db,
            "--lock-dir", self.locks_dir,
        ]
        p_res2 = subprocess.run(cmd_res2, capture_output=True, text=True)
        self.assertEqual(p_res2.returncode, 0)
        data_res2 = json.loads(p_res2.stdout)

        cmd_fail = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "lock-fail",
            "--plan-id", "plan-cli-fail-unc",
            "--uncertain",
            "--ledger-db", self.ledger_db,
            "--lock-dir", self.locks_dir,
            "--lock-id", data_res2["lock_id"],
            "--fencing-token", str(data_res2["fencing_token"]),
        ]
        p_fail = subprocess.run(cmd_fail, capture_output=True, text=True)
        self.assertEqual(p_fail.returncode, 0, f"lock-fail failed: {p_fail.stderr}")
        data_fail = json.loads(p_fail.stdout)
        self.assertEqual(data_fail["status"], "PASS")

        # Verify status in ledger
        ledger = PlanReplayLedger(db_path=self.ledger_db)
        self.assertEqual(ledger.get_plan_status("plan-cli-fail-unc")["status"], STATUS_OUTCOME_UNCERTAIN)

        # 5. verify --enable-lock CLI with a fresh plan digest
        env_file_fresh = os.path.join(self.test_dir, "test_env_fresh.json")
        with open(env_file_fresh, "w", encoding="utf-8") as f:
            json.dump(self._create_synthetic_envelope("plan-cli-fresh", digest="8888" + "b" * 60), f)

        cmd_ver = [
            sys.executable,
            LIFECYCLE_SCRIPT,
            "verify",
            "--envelope-file", env_file_fresh,
            "--state-file", state_file,
            "--expected-repo", self.valid_repo,
            "--expected-commit", self.valid_commit,
            "--expected-environment", self.valid_env,
            "--expected-lineage", self.valid_lineage,
            "--expected-serial", str(self.valid_serial),
            "--expected-workflow-sha", self.valid_workflow_sha,
            "--expected-backend", self.valid_backend,
            "--actual-backend", self.valid_backend,
            "--ledger-db", self.ledger_db,
            "--lock-dir", self.locks_dir,
            "--enable-lock",
            "--current-time", self.ref_now.isoformat(),
        ]
        p_ver = subprocess.run(cmd_ver, capture_output=True, text=True)
        self.assertEqual(p_ver.returncode, 0, f"verify --enable-lock failed: stdout={p_ver.stdout} stderr={p_ver.stderr}")
        data_ver = json.loads(p_ver.stdout)
        self.assertEqual(data_ver["decision"], DECISION_AUTHORIZED)
        self.assertIsNotNone(data_ver["contract"]["lock_id"])
        self.assertGreaterEqual(data_ver["contract"]["fencing_token"], 1)

    def test_11_fast_fail_child_process_termination(self):
        """Test that losing a lock immediately terminates child execution processes."""
        driver = LocalFSDriver(base_dir=self.locks_dir)
        mgr = LockManager(driver=driver, default_ttl_seconds=300)
        handle = mgr.acquire_lock(
            key="org/repo:env:prod:s3_bucket:default",
            owner_identity={"repo": self.valid_repo, "env": self.valid_env},
            purpose="test-child-proc-termination",
            ttl_seconds=60,
        )

        # Launch simulated Terraform child process
        child_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            self.assertIsNone(child_proc.poll(), "Child process should be running")
            handle.register_child_process(child_proc)

            # Simulate lease loss event
            handle.mark_lost("heartbeat_failure")

            # Process must be aborted quickly
            child_proc.wait(timeout=5)
            self.assertIsNotNone(child_proc.poll(), "Child process must be terminated upon lock loss")
        finally:
            if child_proc.poll() is None:
                child_proc.kill()


if __name__ == "__main__":
    unittest.main()
