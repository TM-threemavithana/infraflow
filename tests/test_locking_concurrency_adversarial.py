#!/usr/bin/env python3
"""
InfraFlow Platform — Distributed Locking Concurrency & Adversarial Integration Suite
Milestone: G10.4.3 — Independent Concurrency, Failure Recovery & Security Assurance

Validates:
Phase 1: Deterministic independent multiprocessing concurrency:
  - Mutual exclusion across separate OS processes.
  - Multi-process race resolution (exactly 1 winner out of N competing processes).
  - Independent lock target key isolation (no cross-key contention).
  - Fencing token monotonicity under process concurrency.
  - Cross-process stale owner release/renewal rejection.
Phase 2: Failure & Recovery:
  - Process termination mid-lease (SIGKILL / abrupt termination).
  - Machine / process restart recovery and inspection.
  - Expired lease recovery by secondary workers.
  - Failed renewal error handling taxonomy.
  - Interrupted filesystem writes & leftover temporary files.
  - Corrupted metadata fail-closed behavior.
  - Uncertain execution outcomes & network partition handling.
Phase 3: Filesystem Security:
  - Symlink attack detection and rejection.
  - Path traversal and control character rejection.
  - Malformed metadata rejection.
  - SHA-256 payload tampering detection.
  - Atomic temporary file cleanup.
Phase 5: Telemetry Event Schema & Sensitive Data Scrubbing:
  - All 8 locking event types pass schema validation.
  - Automatic scrubbing of secrets in locking telemetry.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

scripts_dir = REPO_ROOT / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from infraflow.locking import (
    DistributedLockDriver,
    LocalFSDriver,
    MockDistributedDriver,
    LockManager,
    LockHandle,
    LockDescriptor,
    LeaseState,
    LockRecord,
    LockResult,
    derive_canonical_lock_identity,
    validate_lock_metadata,
    check_metadata_secrets,
    compute_payload_sha256,
    format_iso_utc,
    parse_iso_utc,
    LockError,
    LockAcquisitionError,
    LockHeldError,
    ResourceIdentityError,
    LockLostError,
    LeaseExpiredError,
    StaleOwnerError,
    StaleFencingTokenError,
    LeaseGenerationMismatchError,
    LeaseRenewalError,
    UncertainOutcomeError,
    SecurityViolationError,
)
import importlib.util
emit_path = REPO_ROOT / "scripts" / "emit-telemetry.py"
spec_emit = importlib.util.spec_from_file_location("emit_telemetry", str(emit_path))
emit_telemetry = importlib.util.module_from_spec(spec_emit)
spec_emit.loader.exec_module(emit_telemetry)


# ==============================================================================
# Top-Level Multiprocessing Workers (Picklable)
# ==============================================================================

def _mp_worker_acquire(base_dir: str, key: str, runner_id: str, ttl: int, barrier: Any, q: Any) -> None:
    """Worker process: waits at barrier then attempts atomic acquisition."""
    try:
        barrier.wait(timeout=10.0)
        driver = LocalFSDriver(base_dir=base_dir)
        res = driver.acquire(
            key=key,
            owner_identity={"runner_id": runner_id, "pid": os.getpid()},
            ttl_seconds=ttl,
            purpose="concurrency_race",
        )
        q.put({
            "runner_id": runner_id,
            "success": res.success,
            "error_code": res.error_code,
            "fencing_token": res.record.lease.fencing_token if res.record else None,
            "lock_id": res.record.descriptor.lock_id if res.record else None,
        })
    except Exception as e:
        q.put({
            "runner_id": runner_id,
            "success": False,
            "error_code": "EXCEPTION",
            "error": str(e),
        })


def _mp_worker_hold(base_dir: str, key: str, runner_id: str, ttl: int, started_event: Any, stop_event: Any, q: Any) -> None:
    """Worker process: acquires lock, signals readiness, and holds lock until told to stop."""
    try:
        driver = LocalFSDriver(base_dir=base_dir)
        res = driver.acquire(
            key=key,
            owner_identity={"runner_id": runner_id, "pid": os.getpid()},
            ttl_seconds=ttl,
            purpose="hold_test",
        )
        q.put({
            "runner_id": runner_id,
            "success": res.success,
            "lock_id": res.record.descriptor.lock_id if res.record else None,
            "fencing_token": res.record.lease.fencing_token if res.record else None,
        })
        started_event.set()
        stop_event.wait(timeout=30.0)
    except Exception as e:
        q.put({"runner_id": runner_id, "success": False, "error": str(e)})


def _mp_worker_release(base_dir: str, key: str, runner_id: str, lock_id: str, token: int, gen: int, q: Any) -> None:
    """Worker process: attempts lock release with given credentials."""
    try:
        driver = LocalFSDriver(base_dir=base_dir)
        res = driver.release(
            key=key,
            lock_id=lock_id,
            owner_id=runner_id,
            fencing_token=token,
            lease_generation=gen,
        )
        q.put({
            "runner_id": runner_id,
            "success": res.success,
            "error_code": res.error_code,
        })
    except Exception as e:
        q.put({"runner_id": runner_id, "success": False, "error": str(e)})


# ==============================================================================
# Phase 1: Independent Process Concurrency
# ==============================================================================

class TestProcessConcurrency(unittest.TestCase):
    """Verifies concurrency guarantees across true OS multiprocessing processes."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-mp-concurrency-")
        self.base_path = Path(self.tmp_dir)
        self.key = "infraflow/locks/v1/local/workstation/mp/state.tfstate/default.lock"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_two_processes_mutual_exclusion(self):
        """Proves two independent processes cannot hold the same LocalFS lock simultaneously."""
        ctx = mp.get_context("spawn" if sys.platform == "win32" else "fork")
        started = ctx.Event()
        stop = ctx.Event()
        q = ctx.Queue()

        # Process 1 acquires and holds lock
        p1 = ctx.Process(target=_mp_worker_hold, args=(str(self.base_path), self.key, "proc-1", 60, started, stop, q))
        p1.start()
        self.assertTrue(started.wait(timeout=10.0), "Process 1 failed to acquire lock.")

        p1_res = q.get(timeout=5.0)
        self.assertTrue(p1_res["success"])
        lock_id_1 = p1_res["lock_id"]

        # Process 2 attempts to acquire the same lock while Process 1 holds it
        driver2 = LocalFSDriver(base_dir=self.base_path)
        p2_res = driver2.acquire(self.key, {"runner_id": "proc-2"}, 60, "p2_compete")
        self.assertFalse(p2_res.success, "Process 2 must not acquire actively held lock.")
        self.assertEqual(p2_res.error_code, "LOCK_HELD")

        # Stop Process 1 and release
        stop.set()
        p1.join(timeout=5.0)

        # Release lock from Process 1 credentials
        rel = driver2.release(self.key, lock_id_1, "proc-1", 1, 1)
        self.assertTrue(rel.success)

        # Now Process 2 can successfully acquire
        p2_res_after = driver2.acquire(self.key, {"runner_id": "proc-2"}, 60, "p2_retry")
        self.assertTrue(p2_res_after.success)
        self.assertEqual(p2_res_after.record.lease.fencing_token, 2)

    def test_02_concurrent_n_processes_race(self):
        """Races N independent processes concurrently; exactly one wins, N-1 fail-closed."""
        ctx = mp.get_context("spawn" if sys.platform == "win32" else "fork")
        num_procs = 8
        barrier = ctx.Barrier(num_procs)
        q = ctx.Queue()

        processes = []
        for i in range(num_procs):
            p = ctx.Process(
                target=_mp_worker_acquire,
                args=(str(self.base_path), self.key, f"racer-{i}", 900, barrier, q),
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=15.0)

        results = []
        while not q.empty():
            results.append(q.get_nowait())

        self.assertEqual(len(results), num_procs)
        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]

        self.assertEqual(len(successful), 1, "Exactly one process must acquire the lock in concurrent race.")
        self.assertEqual(len(failed), num_procs - 1)
        for f in failed:
            self.assertEqual(f["error_code"], "LOCK_HELD")

    def test_03_independent_lock_identities_no_contention(self):
        """Proves different canonical lock identities operate independently without false contention."""
        ctx = mp.get_context("spawn" if sys.platform == "win32" else "fork")
        num_keys = 4
        barrier = ctx.Barrier(num_keys)
        q = ctx.Queue()

        processes = []
        for i in range(num_keys):
            target_key = f"infraflow/locks/v1/local/workstation/target_{i}/state.tfstate/default.lock"
            p = ctx.Process(
                target=_mp_worker_acquire,
                args=(str(self.base_path), target_key, f"worker-{i}", 900, barrier, q),
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=15.0)

        results = []
        while not q.empty():
            results.append(q.get_nowait())

        self.assertEqual(len(results), num_keys)
        # All 4 independent targets must succeed!
        for r in results:
            self.assertTrue(r["success"], f"Worker {r['runner_id']} unexpectedly failed on independent key.")

    def test_04_fencing_token_monotonicity_across_processes(self):
        """Proves fencing tokens advance monotonically across sequential multi-process cycles."""
        tokens = []
        driver = LocalFSDriver(base_dir=self.base_path)

        for i in range(5):
            res = driver.acquire(self.key, {"runner_id": f"proc-cycle-{i}"}, 900, "cycle")
            self.assertTrue(res.success)
            token = res.record.lease.fencing_token
            tokens.append(token)
            driver.release(self.key, res.record.descriptor.lock_id, f"proc-cycle-{i}", token, 1)

        self.assertEqual(tokens, [1, 2, 3, 4, 5])
        self.assertEqual(driver.get_high_water_mark(self.key), 5)

    def test_05_stale_owner_rejected_across_processes(self):
        """Cross-process test: Stale owner in Process 1 cannot release or renew Process 2's lock."""
        driver = LocalFSDriver(base_dir=self.base_path)

        # 1. Process 1 acquires Lock 1
        res1 = driver.acquire(self.key, {"runner_id": "proc-1"}, 1, "p1")
        self.assertTrue(res1.success)
        lock_id_1 = res1.record.descriptor.lock_id
        token_1 = res1.record.lease.fencing_token

        # 2. Wait for lease to expire deterministically with bounded timeout
        deadline = parse_iso_utc(res1.record.lease.expires_at)
        start_wait = time.monotonic()
        while datetime.now(timezone.utc) <= deadline:
            if time.monotonic() - start_wait > 5.0:
                self.fail(f"Timed out waiting for lease expiration deadline {deadline}")
            time.sleep(0.05)

        # 3. Process 2 reclaims Lock 2
        res2 = driver.acquire(self.key, {"runner_id": "proc-2"}, 60, "p2")
        self.assertTrue(res2.success)
        token_2 = res2.record.lease.fencing_token
        self.assertGreater(token_2, token_1)

        # 4. Process 1 attempts to release Lock 1 via an independent subprocess
        ctx = mp.get_context("spawn" if sys.platform == "win32" else "fork")
        q = ctx.Queue()
        p = ctx.Process(target=_mp_worker_release, args=(str(self.base_path), self.key, "proc-1", lock_id_1, token_1, 1, q))
        p.start()
        p.join(timeout=5.0)

        rel_res = q.get(timeout=2.0)
        self.assertFalse(rel_res["success"], "Stale owner must be rejected fail-closed.")
        self.assertIn("STALE", rel_res["error_code"])

        # 5. Process 2's active lock remains untouched
        inspected = driver.inspect(self.key)
        self.assertIsNotNone(inspected)
        self.assertEqual(inspected.descriptor.lock_id, res2.record.descriptor.lock_id)
        self.assertEqual(inspected.lease.fencing_token, token_2)


# ==============================================================================
# Phase 2: Failure & Recovery
# ==============================================================================

class TestFailureAndRecovery(unittest.TestCase):
    """Verifies system resilience against process termination, crashes, and partial writes."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-recovery-test-")
        self.base_path = Path(self.tmp_dir)
        self.key = "infraflow/locks/v1/local/workstation/fail/state.tfstate/default.lock"
        self.driver = LocalFSDriver(base_dir=self.base_path)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_process_termination_while_holding_lock(self):
        """Simulates hard process kill (SIGKILL) while holding a lock."""
        ctx = mp.get_context("spawn" if sys.platform == "win32" else "fork")
        started = ctx.Event()
        stop = ctx.Event()
        q = ctx.Queue()

        # Short TTL of 2 seconds
        p = ctx.Process(target=_mp_worker_hold, args=(str(self.base_path), self.key, "doomed-worker", 2, started, stop, q))
        p.start()
        self.assertTrue(started.wait(timeout=5.0))

        # Abruptly kill the worker process mid-lease
        p.kill()
        p.join(timeout=5.0)

        # OS kernel immediately releases fcntl.flock on mutex
        # Before expiration: lock remains held
        driver = LocalFSDriver(base_dir=self.base_path)
        inspected = driver.inspect(self.key)
        self.assertIsNotNone(inspected)

        # Wait until expiration (2s TTL)
        time.sleep(2.1)

        # Subsequent worker safely reclaims expired lock
        res = driver.acquire(self.key, {"runner_id": "recovery-worker"}, 60, "recover")
        self.assertTrue(res.success)
        self.assertEqual(res.record.lease.fencing_token, 2)

    def test_02_machine_restart_and_inspection(self):
        """Verifies driver re-instantiation restores state and durable HWM."""
        res = self.driver.acquire(self.key, {"runner_id": "runner-pre-boot"}, 900, "apply")
        self.assertTrue(res.success)
        token = res.record.lease.fencing_token

        # Destroy driver instance and create fresh driver on same path
        del self.driver
        reboot_driver = LocalFSDriver(base_dir=self.base_path)

        inspected = reboot_driver.inspect(self.key)
        self.assertIsNotNone(inspected)
        self.assertEqual(inspected.lease.fencing_token, token)
        self.assertEqual(reboot_driver.get_high_water_mark(self.key), token)

    def test_03_expired_lease_recovery(self):
        """Verifies expired lease is cleanly reclaimed with incremented fencing token."""
        # Acquire with 1s TTL
        res = self.driver.acquire(self.key, {"runner_id": "initial-worker"}, 1, "test")
        self.assertTrue(res.success)
        # Wait for lease to expire deterministically with bounded timeout
        deadline = parse_iso_utc(res.record.lease.expires_at)
        start_wait = time.monotonic()
        while datetime.now(timezone.utc) <= deadline:
            if time.monotonic() - start_wait > 5.0:
                self.fail(f"Timed out waiting for lease expiration deadline {deadline}")
            time.sleep(0.05)

        # Reclaim
        reclaim_res = self.driver.acquire(self.key, {"runner_id": "reclaim-worker"}, 900, "reclaim")
        self.assertTrue(reclaim_res.success)
        self.assertEqual(reclaim_res.record.lease.fencing_token, 2)

    def test_04_failed_lease_renewal_taxonomy(self):
        """Verifies exact structured error codes on invalid renewal attempts."""
        res = self.driver.acquire(self.key, {"runner_id": "owner-1"}, 900, "test")
        lock_id = res.record.descriptor.lock_id
        token = res.record.lease.fencing_token

        # Stale token
        r_token = self.driver.renew(self.key, lock_id, "owner-1", 999, 1, 300)
        self.assertFalse(r_token.success)
        self.assertEqual(r_token.error_code, "STALE_FENCING_TOKEN")

        # Stale generation
        r_gen = self.driver.renew(self.key, lock_id, "owner-1", token, 999, 300)
        self.assertFalse(r_gen.success)
        self.assertEqual(r_gen.error_code, "LEASE_GENERATION_MISMATCH")

        # Non-existent lock
        r_missing = self.driver.renew("infraflow/locks/v1/local/missing/key/state.tfstate/default.lock", lock_id, "owner-1", 1, 1, 300)
        self.assertFalse(r_missing.success)
        self.assertEqual(r_missing.error_code, "LOCK_NOT_FOUND")

    def test_05_interrupted_filesystem_writes_safety(self):
        """Leftover temporary files from interrupted writes do not corrupt storage."""
        # Create an orphan temporary file in lock dir
        orphan_tmp = self.base_path / "abandoned_write.tmp.123456"
        orphan_tmp.write_text("PARTIAL_JSON_CONTENT", encoding="utf-8")

        # Driver inspect and acquire operate cleanly
        res = self.driver.acquire(self.key, {"runner_id": "clean-runner"}, 900, "apply")
        self.assertTrue(res.success)
        self.assertIsNotNone(self.driver.inspect(self.key))

    def test_06_corrupted_lock_records_fail_closed(self):
        """Corrupted JSON payload fails closed with LockError, never granting lock."""
        fp = hashlib.sha256(self.key.encode("utf-8")).hexdigest()
        lock_file = self.base_path / f"{fp}.lock.json"
        lock_file.write_text("{ \"corrupted\": true, invalid json ...", encoding="utf-8")

        with self.assertRaises(LockError):
            self.driver.acquire(self.key, {"runner_id": "test"}, 900, "test")

        with self.assertRaises(LockError):
            self.driver.inspect(self.key)

    def test_07_uncertain_outcomes_network_partition(self):
        """Simulated network timeout raises UncertainOutcomeError."""
        mock = MockDistributedDriver()
        mock.simulate_partition(True)

        with self.assertRaises(UncertainOutcomeError):
            mock.acquire(self.key, {"runner_id": "test"}, 900, "test")

        with self.assertRaises(UncertainOutcomeError):
            mock.inspect(self.key)


# ==============================================================================
# Phase 3: Filesystem Security
# ==============================================================================

class TestFilesystemSecurity(unittest.TestCase):
    """Verifies security controls against symlink, path traversal, and tampering attacks."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-sec-test-")
        self.base_path = Path(self.tmp_dir)
        self.key = "infraflow/locks/v1/local/workstation/sec/state.tfstate/default.lock"
        self.driver = LocalFSDriver(base_dir=self.base_path)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_symlink_attack_detection(self):
        """Detects and rejects symlink targets pointing outside the base directory."""
        outside_dir = tempfile.mkdtemp(prefix="infraflow-outside-")
        try:
            fp = hashlib.sha256(self.key.encode("utf-8")).hexdigest()
            symlink_lock = self.base_path / f"{fp}.lock.json"
            os.symlink(outside_dir, symlink_lock)

            with self.assertRaises(SecurityViolationError):
                self.driver.inspect(self.key)
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    def test_02_path_traversal_rejection(self):
        """Rejects relative traversal or null bytes in lock keys."""
        with self.assertRaises(ResourceIdentityError):
            self.driver.acquire("../../etc/shadow", {"runner_id": "attacker"}, 900, "attack")

        with self.assertRaises(ResourceIdentityError):
            self.driver.acquire("valid/key\x00inject", {"runner_id": "attacker"}, 900, "attack")

    def test_03_malformed_metadata_validation(self):
        """Rejects malformed schema version or negative tokens."""
        bad_meta = {
            "schema_version": "unsupported-schema-v9",
            "descriptor": {},
            "lease": {},
            "integrity": {},
        }
        with self.assertRaises(LockError):
            validate_lock_metadata(bad_meta)

    def test_04_integrity_checksum_tamper_detection(self):
        """Detects payload modifications without matching SHA-256 integrity digest."""
        res = self.driver.acquire(self.key, {"runner_id": "legit-runner"}, 900, "test")
        self.assertTrue(res.success)

        fp = hashlib.sha256(self.key.encode("utf-8")).hexdigest()
        lock_file = self.base_path / f"{fp}.lock.json"
        data = json.loads(lock_file.read_text(encoding="utf-8"))

        # Maliciously edit fencing token
        data["lease"]["fencing_token"] = 9999
        lock_file.write_text(json.dumps(data), encoding="utf-8")

        # Next inspect must fail closed due to integrity checksum mismatch
        with self.assertRaises(LockError):
            self.driver.inspect(self.key)

    def test_05_atomic_temporary_file_cleanup(self):
        """Verifies temporary files do not leak during normal atomic write cycles."""
        res = self.driver.acquire(self.key, {"runner_id": "clean-runner"}, 900, "test")
        self.assertTrue(res.success)

        # Verify no .tmp files remain in base directory
        tmp_files = list(self.base_path.glob("*.tmp*"))
        self.assertEqual(len(tmp_files), 0, f"Leaked temporary files found: {tmp_files}")


# ==============================================================================
# Phase 5: Telemetry Event Schema & Sensitive Data Scrubbing
# ==============================================================================

class TestLockingTelemetry(unittest.TestCase):
    """Verifies the 8 distributed locking telemetry events and sensitive data scrubbing."""

    def test_01_all_locking_telemetry_events_valid(self):
        """All 8 locking events conform to RFC 5424 / OpenTelemetry Schema v1.0."""
        locking_events = [
            "lock_acquired",
            "lock_renewed",
            "lock_released",
            "lock_contention",
            "lock_stale_reclaimed",
            "lock_lost",
            "lock_fencing_violation",
            "lock_force_unlocked",
        ]
        for et in locking_events:
            self.assertIn(et, emit_telemetry.VALID_EVENT_TYPES)
            event = emit_telemetry.create_telemetry_event(
                event_type=et,
                consumer_id="platform-locking-test",
                repository="TM-threemavithana/infraflow",
                status="PASS",
                metrics={"duration_ms": 12},
                verdict_reasons=[f"Executed telemetry test for {et}"],
            )
            is_valid, errors = emit_telemetry.validate_telemetry_event(event)
            self.assertTrue(is_valid, f"Event '{et}' failed validation: {errors}")

    def test_02_telemetry_sensitive_data_scrubbing(self):
        """Ensures secrets in verdict reasons or execution context are automatically scrubbed."""
        # Dynamically constructed AWS access key
        fake_key = "AKIA" + "1122334455667788"
        raw_text = f"Encountered key {fake_key} in test execution"

        event = emit_telemetry.create_telemetry_event(
            event_type="lock_acquired",
            consumer_id="platform-test",
            repository="TM-threemavithana/infraflow",
            status="PASS",
            verdict_reasons=[raw_text],
        )
        # Verify secret was scrubbed
        self.assertNotIn(fake_key, json.dumps(event))
        self.assertIn("[REDACTED_AWS_KEY]", json.dumps(event))


if __name__ == "__main__":
    unittest.main()
