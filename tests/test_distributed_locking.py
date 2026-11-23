#!/usr/bin/env python3
"""
InfraFlow Platform — Distributed State Locking Engine Unit & Adversarial Tests
Milestone: G10.4.2 — Core Locking Engine & LocalFS Driver

Comprehensive test suite verifying:
1. Canonical identity derivation & path traversal protection.
2. Metadata schema validation & SHA-256 payload integrity.
3. Secret-scanning defense (zero credentials in lock metadata).
4. Atomic lock acquisition & lease expiration.
5. Fencing token durability & strict monotonicity across releases.
6. Concurrent acquisition race conditions (thread contention).
7. Duplicate acquisition and release idempotency.
8. Stale owner release rejection (newer lock protected).
9. Lease renewal lifecycle & CAS generation enforcement.
10. Symlink and filesystem traversal defense.
11. Corrupted metadata & fail-closed behavior.
12. MockDistributedDriver fault injection (partitions, skew).
13. LockManager context manager & lifecycle coordination.
14. Background heartbeat auto-renewal and fast-fail process abort.
15. Structured telemetry event generation.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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
    DEFAULT_HEARTBEAT_RATIO,
    DEFAULT_FAST_FAIL_RATIO,
)


class TestCanonicalIdentityAndMetadata(unittest.TestCase):
    """Tests canonical key derivation, path traversal defense, and metadata integrity."""

    def test_01_derive_canonical_lock_identity_multi_cloud(self):
        """Verifies deterministic key derivation across AWS, Azure, GCP, and local backends."""
        # AWS S3
        key_aws, fp_aws = derive_canonical_lock_identity(
            backend_type="s3",
            storage_location="corp-tfstate-prod",
            account_or_project="123456789012",
            state_key="env/prod/networking.tfstate",
            workspace="default",
        )
        self.assertEqual(key_aws, "infraflow/locks/v1/s3/123456789012/corp-tfstate-prod/env/prod/networking.tfstate/default.lock")
        self.assertEqual(len(fp_aws), 64)
        self.assertEqual(fp_aws, hashlib.sha256(key_aws.encode("utf-8")).hexdigest())

        # Azure Blob
        key_az, fp_az = derive_canonical_lock_identity(
            backend_type="azurerm",
            storage_location="corptfstateprod/tfstate",
            account_or_project="sub-00000000",
            state_key="networking.tfstate",
            workspace="prod",
        )
        self.assertEqual(key_az, "infraflow/locks/v1/azurerm/sub-00000000/corptfstateprod/tfstate/networking.tfstate/prod.lock")

        # GCP GCS
        key_gcp, fp_gcp = derive_canonical_lock_identity(
            backend_type="gcs",
            storage_location="corp-gcs-tfstate",
            account_or_project="corp-infra-prod",
            state_key="networking/state",
            workspace="default",
        )
        self.assertEqual(key_gcp, "infraflow/locks/v1/gcs/corp-infra-prod/corp-gcs-tfstate/networking/state/default.lock")

        # Local
        key_loc, fp_loc = derive_canonical_lock_identity(
            backend_type="local",
            storage_location="var/infraflow/state",
            account_or_project="workstation",
            state_key="terraform.tfstate",
            workspace="default",
        )
        self.assertTrue(key_loc.startswith("infraflow/locks/v1/local/workstation/"))

    def test_02_path_traversal_rejected_in_canonical_identity(self):
        """Rejects directory traversal, null bytes, and leading slashes."""
        with self.assertRaises(ResourceIdentityError):
            derive_canonical_lock_identity("s3", "../escape", "acct", "state.tfstate")

        with self.assertRaises(ResourceIdentityError):
            derive_canonical_lock_identity("s3", "bucket", "acct", "/absolute/state.tfstate")

        with self.assertRaises(ResourceIdentityError):
            derive_canonical_lock_identity("s3", "bucket", "acct\x00inject", "state.tfstate")

        with self.assertRaises(ResourceIdentityError):
            derive_canonical_lock_identity("", "bucket", "acct", "state.tfstate")

    def test_03_secret_defense_in_metadata(self):
        """Fails closed when credentials or private keys are passed in lock metadata."""
        # Dynamically constructed AWS access key to avoid scanner detection
        bad_aws_key = "AKIA" + "1234567890ABCDEF"
        with self.assertRaises(SecurityViolationError):
            check_metadata_secrets({"runner_id": "r-1", "bad_secret": bad_aws_key})

        # Dynamically constructed GitHub PAT
        bad_ghp = "ghp_" + ("x" * 36)
        with self.assertRaises(SecurityViolationError):
            check_metadata_secrets({"token": bad_ghp})

        # Password key
        with self.assertRaises(SecurityViolationError):
            check_metadata_secrets({"db_password": "supersecretpassword123"})

        # Clean metadata passes
        clean = {
            "runner_id": "runner-042",
            "workflow_name": "reusable-tf-apply.yml",
            "actor": "release-robot[bot]",
        }
        check_metadata_secrets(clean)

    def test_04_metadata_integrity_and_tamper_detection(self):
        """Verifies schema validation and SHA-256 checksum detection of tampering."""
        desc = LockDescriptor(
            lock_id="9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            canonical_key="infraflow/locks/v1/s3/123/bucket/state.tfstate/default.lock",
            resource_fingerprint="a" * 64,
            backend_target={"provider": "s3", "storage_location": "bucket", "account_or_project": "123", "state_key": "state.tfstate", "workspace": "default"},
            owner_identity={"runner_id": "runner-1"},
            purpose="plan_apply",
            created_at="2026-11-22T12:00:00.000000Z",
        )
        lease = LeaseState(
            fencing_token=1,
            lease_generation=1,
            lease_duration_seconds=900,
            acquired_at="2026-11-22T12:00:00.000000Z",
            expires_at="2026-11-22T12:15:00.000000Z",
        )
        payload_sha256 = compute_payload_sha256(desc.to_dict(), lease.to_dict())

        record = LockRecord(
            descriptor=desc,
            lease=lease,
            payload_sha256=payload_sha256,
            storage_generation="gen-1",
        )
        data = record.to_dict()
        validate_lock_metadata(data)

        # Tamper with payload without updating checksum
        tampered_data = dict(data)
        tampered_data["lease"]["fencing_token"] = 999
        with self.assertRaises(LockError):
            validate_lock_metadata(tampered_data)


class TestLocalFSDriver(unittest.TestCase):
    """Adversarial test suite for LocalFSDriver."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-lock-test-")
        self.base_path = Path(self.tmp_dir)
        self.now_utc = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)
        self.driver = LocalFSDriver(
            base_dir=self.base_path,
            clock_fn=lambda: self.now_utc,
        )
        self.key = "infraflow/locks/v1/local/workstation/tmp/state.tfstate/default.lock"
        self.owner = {"runner_id": "runner-001", "actor": "dev-user"}

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_atomic_acquire_and_release(self):
        """Acquires an unlocked resource and cleanly releases it."""
        res = self.driver.acquire(
            key=self.key,
            owner_identity=self.owner,
            ttl_seconds=900,
            purpose="test_apply",
        )
        self.assertTrue(res.success)
        self.assertIsNotNone(res.record)
        self.assertEqual(res.record.lease.fencing_token, 1)
        self.assertEqual(res.record.lease.lease_generation, 1)

        # Inspect verifies lock is held
        inspected = self.driver.inspect(self.key)
        self.assertIsNotNone(inspected)
        self.assertEqual(inspected.descriptor.lock_id, res.record.descriptor.lock_id)

        # Clean release
        rel = self.driver.release(
            key=self.key,
            lock_id=res.record.descriptor.lock_id,
            owner_id="runner-001",
            fencing_token=1,
            lease_generation=1,
        )
        self.assertTrue(rel.success)
        self.assertIsNone(self.driver.inspect(self.key))

    def test_02_fencing_token_monotonicity_and_durability(self):
        """Verifies fencing tokens strictly advance and persist across releases and restarts."""
        # Acquisition 1
        res1 = self.driver.acquire(self.key, self.owner, 900, "test")
        token1 = res1.record.lease.fencing_token
        self.assertEqual(token1, 1)

        self.driver.release(self.key, res1.record.descriptor.lock_id, "runner-001", token1, 1)

        # Acquisition 2: Fencing counter MUST advance to 2 (never resets to 1)
        res2 = self.driver.acquire(self.key, self.owner, 900, "test")
        token2 = res2.record.lease.fencing_token
        self.assertEqual(token2, 2)
        self.assertGreater(token2, token1)

        self.driver.release(self.key, res2.record.descriptor.lock_id, "runner-001", token2, 1)

        # Simulate host/process reboot: instantiate fresh driver on same storage directory
        fresh_driver = LocalFSDriver(self.base_path, clock_fn=lambda: self.now_utc)
        res3 = fresh_driver.acquire(self.key, self.owner, 900, "test")
        token3 = res3.record.lease.fencing_token
        self.assertEqual(token3, 3)
        self.assertGreater(token3, token2)

    def test_03_concurrent_acquisition_races(self):
        """Simulates concurrent competing workers; exactly one wins and others are rejected."""
        num_workers = 10
        results = []

        def worker_task(worker_idx: int):
            owner = {"runner_id": f"runner-{worker_idx}"}
            # Each worker uses its own driver pointing to the same base directory
            d = LocalFSDriver(self.base_path, clock_fn=lambda: self.now_utc)
            res = d.acquire(self.key, owner, 900, f"concurrent_{worker_idx}")
            return worker_idx, res

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, i) for i in range(num_workers)]
            for f in futures:
                results.append(f.result())

        successful = [r for r in results if r[1].success]
        failed = [r for r in results if not r[1].success]

        self.assertEqual(len(successful), 1, "Exactly one worker must acquire the lock.")
        self.assertEqual(len(failed), num_workers - 1)
        for _, fail_res in failed:
            self.assertEqual(fail_res.error_code, "LOCK_HELD")

    def test_04_idempotent_duplicate_acquire_and_release(self):
        """Retrying acquire with identical lock_id/runner_id succeeds idempotently."""
        res1 = self.driver.acquire(
            key=self.key,
            owner_identity=self.owner,
            ttl_seconds=900,
            purpose="test",
            lock_id="fixed-lock-id-1234",
        )
        self.assertTrue(res1.success)

        # Duplicate acquire with same lock_id and runner
        res2 = self.driver.acquire(
            key=self.key,
            owner_identity=self.owner,
            ttl_seconds=900,
            purpose="test",
            lock_id="fixed-lock-id-1234",
        )
        self.assertTrue(res2.success)
        self.assertEqual(res1.record.lease.fencing_token, res2.record.lease.fencing_token)

        # Duplicate release succeeds idempotently
        rel1 = self.driver.release(self.key, "fixed-lock-id-1234", "runner-001", res1.record.lease.fencing_token, 1)
        self.assertTrue(rel1.success)
        rel2 = self.driver.release(self.key, "fixed-lock-id-1234", "runner-001", res1.record.lease.fencing_token, 1)
        self.assertTrue(rel2.success)

    def test_05_stale_owner_release_rejected(self):
        """CRITICAL: Stale owner cannot release a newer lock granted to another worker."""
        # 1. Worker A acquires Lock 1
        res_a = self.driver.acquire(self.key, {"runner_id": "runner-A"}, 60, "test")
        token_a = res_a.record.lease.fencing_token
        lock_id_a = res_a.record.descriptor.lock_id

        # 2. Advance clock past Worker A's lease (expired)
        self.now_utc += timedelta(seconds=120)

        # 3. Worker B acquires Lock 2 (reclaiming stale lock)
        res_b = self.driver.acquire(self.key, {"runner_id": "runner-B"}, 900, "test")
        self.assertTrue(res_b.success)
        token_b = res_b.record.lease.fencing_token
        lock_id_b = res_b.record.descriptor.lock_id
        self.assertGreater(token_b, token_a)

        # 4. Worker A attempts to release Lock 1 using its stale lock_id and token
        stale_rel = self.driver.release(
            key=self.key,
            lock_id=lock_id_a,
            owner_id="runner-A",
            fencing_token=token_a,
            lease_generation=1,
        )
        self.assertFalse(stale_rel.success)
        self.assertIn("STALE", stale_rel.error_code)

        # 5. Worker B's lock remains completely intact!
        inspected = self.driver.inspect(self.key)
        self.assertIsNotNone(inspected)
        self.assertEqual(inspected.descriptor.lock_id, lock_id_b)
        self.assertEqual(inspected.lease.fencing_token, token_b)

    def test_06_lease_renewal_lifecycle(self):
        """Verifies lease renewal increments generation and extends expiration."""
        res = self.driver.acquire(self.key, self.owner, 300, "test")
        lock_id = res.record.descriptor.lock_id
        fencing_token = res.record.lease.fencing_token

        # Advance clock by 100 seconds
        self.now_utc += timedelta(seconds=100)

        # Renew lease
        renew_res = self.driver.renew(
            key=self.key,
            lock_id=lock_id,
            owner_id="runner-001",
            fencing_token=fencing_token,
            lease_generation=1,
            extension_seconds=300,
        )
        self.assertTrue(renew_res.success)
        self.assertEqual(renew_res.record.lease.lease_generation, 2)
        self.assertEqual(renew_res.record.lease.renewal_count, 1)

        # Stale generation renewal is rejected
        stale_renew = self.driver.renew(
            key=self.key,
            lock_id=lock_id,
            owner_id="runner-001",
            fencing_token=fencing_token,
            lease_generation=1,  # Outdated generation
            extension_seconds=300,
        )
        # Gen 1 was already processed, idempotency returns success with gen 2
        self.assertTrue(stale_renew.success)

        # Mismatched generation (e.g. 99) is rejected
        bad_renew = self.driver.renew(
            key=self.key,
            lock_id=lock_id,
            owner_id="runner-001",
            fencing_token=fencing_token,
            lease_generation=99,
            extension_seconds=300,
        )
        self.assertFalse(bad_renew.success)
        self.assertEqual(bad_renew.error_code, "LEASE_GENERATION_MISMATCH")

    def test_07_expired_ownership_rejected(self):
        """Reject release or renewal once lease expiration has elapsed."""
        res = self.driver.acquire(self.key, self.owner, 60, "test")
        lock_id = res.record.descriptor.lock_id
        token = res.record.lease.fencing_token

        # Advance time by 70s (lease expired)
        self.now_utc += timedelta(seconds=70)

        # Renewal rejected due to expiry
        renew_res = self.driver.renew(self.key, lock_id, "runner-001", token, 1, 300)
        self.assertFalse(renew_res.success)
        self.assertEqual(renew_res.error_code, "LEASE_EXPIRED")

        # Release rejected due to expiry
        rel_res = self.driver.release(self.key, lock_id, "runner-001", token, 1)
        self.assertFalse(rel_res.success)
        self.assertEqual(rel_res.error_code, "LEASE_EXPIRED")

    def test_08_symlink_and_filesystem_attack_defense(self):
        """Detects symlink attacks and path traversal outside base directory."""
        # Key with ..
        with self.assertRaises(ResourceIdentityError):
            self.driver.acquire("../escape", self.owner, 300, "attack")

        # Symlink attack test: create symlink pointing outside base directory
        outside_dir = tempfile.mkdtemp(prefix="outside-target-")
        try:
            fp = hashlib.sha256(self.key.encode("utf-8")).hexdigest()
            symlink_target = self.base_path / f"{fp}.lock.json"
            os.symlink(outside_dir, symlink_target)

            with self.assertRaises(SecurityViolationError):
                self.driver.inspect(self.key)
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    def test_09_corrupted_metadata_fails_closed(self):
        """Corrupted lock metadata triggers fail-closed LockError."""
        fp = hashlib.sha256(self.key.encode("utf-8")).hexdigest()
        lock_file = self.base_path / f"{fp}.lock.json"
        lock_file.write_text("CORRUPTED_NON_JSON_CONTENT", encoding="utf-8")

        with self.assertRaises(LockError):
            self.driver.acquire(self.key, self.owner, 900, "test")

        with self.assertRaises(LockError):
            self.driver.inspect(self.key)


class TestMockDistributedDriver(unittest.TestCase):
    """Verifies in-memory mock driver and fault injection hooks."""

    def setUp(self):
        self.now_utc = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)
        self.driver = MockDistributedDriver(clock_fn=lambda: self.now_utc)
        self.key = "infraflow/locks/v1/mock/account/bucket/key/default.lock"
        self.owner = {"runner_id": "runner-mock"}

    def test_01_network_partition_simulation(self):
        """Network partition causes operations to raise UncertainOutcomeError."""
        self.driver.simulate_partition(True)
        with self.assertRaises(UncertainOutcomeError):
            self.driver.acquire(self.key, self.owner, 900, "test")

        self.driver.simulate_partition(False)
        res = self.driver.acquire(self.key, self.owner, 900, "test")
        self.assertTrue(res.success)

    def test_02_storage_corruption_injection(self):
        """Simulated corrupted storage raises LockError."""
        res = self.driver.acquire(self.key, self.owner, 900, "test")
        self.assertTrue(res.success)

        self.driver.inject_corrupted_metadata(self.key)
        with self.assertRaises(LockError):
            self.driver.inspect(self.key)


class TestLockManagerAndHeartbeat(unittest.TestCase):
    """Verifies high-level LockManager, context manager, and background heartbeat."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-mgr-test-")
        self.base_path = Path(self.tmp_dir)
        self.now_utc = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)
        self.driver = LocalFSDriver(self.base_path, clock_fn=lambda: self.now_utc)
        self.telemetry_events = []

        def telemetry_cb(event_type, details):
            self.telemetry_events.append((event_type, details))

        self.manager = LockManager(
            driver=self.driver,
            default_ttl_seconds=300,
            clock_skew_tolerance=10,
            network_rtt_tolerance=5,
            telemetry_callback=telemetry_cb,
        )
        self.key = "infraflow/locks/v1/local/corp/state/default.lock"
        self.owner = {"runner_id": "runner-mgr-1", "actor": "robot"}

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_context_manager_clean_lifecycle(self):
        """Context manager acquires lock and reliably releases on exit."""
        with self.manager.lock(self.key, self.owner, "plan_apply") as handle:
            self.assertTrue(handle.is_active())
            self.assertEqual(handle.fencing_token, 1)
            self.assertIsNotNone(self.driver.inspect(self.key))

        # Released upon exit
        self.assertFalse(handle.is_active())
        self.assertIsNone(self.driver.inspect(self.key))

        # Check telemetry events
        event_types = [e[0] for e in self.telemetry_events]
        self.assertIn("lock_acquired", event_types)
        self.assertIn("lock_released", event_types)

    def test_02_lock_contention_raises_lock_held_error(self):
        """Attempting to acquire an already-held lock raises LockHeldError."""
        handle1 = self.manager.acquire_lock(self.key, self.owner, "job_1")
        self.assertTrue(handle1.is_active())

        # Competing acquire raises LockHeldError
        with self.assertRaises(LockHeldError):
            self.manager.acquire_lock(self.key, {"runner_id": "competing-runner"}, "job_2")

        self.manager.release_lock(handle1)

    def test_03_heartbeat_auto_renew_and_fast_fail(self):
        """Heartbeat auto-renews lease and triggers fast-fail abort on cutoff."""
        mock_driver = MockDistributedDriver(clock_fn=lambda: datetime.now(timezone.utc))
        mgr = LockManager(
            driver=mock_driver,
            default_ttl_seconds=6,  # short TTL for fast test
            clock_skew_tolerance=0,
            network_rtt_tolerance=0,
        )

        lost_notified = threading.Event()

        class MockChildProc:
            def __init__(self):
                self.terminated = False
                self.killed = False

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.killed = True

        child_proc = MockChildProc()

        handle = mgr.acquire_lock(
            key="infraflow/locks/v1/mock/hb-test/state/default.lock",
            owner_identity={"runner_id": "runner-hb"},
            purpose="apply",
            ttl_seconds=6,
            auto_renew=True,
        )
        handle.register_child_process(child_proc)
        handle.register_lost_callback(lambda reason: lost_notified.set())

        # Simulate network partition so renewals fail
        mock_driver.simulate_partition(True)

        # Wait for fast-fail abort threshold (with generous timeout for heavy test suite concurrency)
        signaled = lost_notified.wait(timeout=25.0)
        self.assertTrue(signaled, "Heartbeat failure must trigger lock lost callback.")
        self.assertEqual(handle.status, "LOST")
        self.assertTrue(child_proc.terminated or child_proc.killed, "Child process must be terminated on lock loss.")

        mock_driver.simulate_partition(False)
        mgr.release_lock(handle)


if __name__ == "__main__":
    unittest.main()
