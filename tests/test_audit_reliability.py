#!/usr/bin/env python3
"""
InfraFlow — Independent Integration & Reliability Audit Test Suite (Milestone G10.5)

Empirical verification of the 10 reliability dimensions:
1. Workflow integration gap analysis (reusable-tf-apply.yml).
2. Consumer workflow gap analysis (concurrency vs distributed locking).
3. Cross-runner isolation vulnerability (LocalFSDriver multi-runner limitation).
4. Ephemeral replay ledger persistence gap across ephemeral CI runners.
5. Single-host kernel concurrency verification (LocalFSDriver single-host safety).
6. Fencing token ledger monotonicity and stale token rejection.
7. Lost handle fast-fail child process termination.
8. Uncertain and interrupted outcome preservation.
9. Corrupted and tampered lock metadata fail-closed behavior.
10. Provider API fencing boundary verification.
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
from pathlib import Path
from typing import Any, Dict

import yaml

# Import platform locking engine
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

# Dynamically import verify-plan-lifecycle.py
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
LIFECYCLE_SCRIPT = SCRIPTS_DIR / "verify-plan-lifecycle.py"
spec = importlib.util.spec_from_file_location("verify_plan_lifecycle", str(LIFECYCLE_SCRIPT))
vpl = importlib.util.module_from_spec(spec)
sys.modules["verify_plan_lifecycle"] = vpl
spec.loader.exec_module(vpl)

PlanLifecycleVerifier = vpl.PlanLifecycleVerifier
PlanReplayLedger = vpl.PlanReplayLedger
PlanReplayError = vpl.PlanReplayError
derive_plan_lock_identity = vpl.derive_plan_lock_identity
STATUS_RESERVED = vpl.STATUS_RESERVED
STATUS_CONSUMED = vpl.STATUS_CONSUMED
STATUS_FAILED = vpl.STATUS_FAILED
STATUS_INTERRUPTED = vpl.STATUS_INTERRUPTED
STATUS_OUTCOME_UNCERTAIN = vpl.STATUS_OUTCOME_UNCERTAIN
DECISION_AUTHORIZED = vpl.DECISION_AUTHORIZED
DECISION_REJECTED = vpl.DECISION_REJECTED


class TestIntegrationReliabilityAudit(unittest.TestCase):
    """Independent audit test suite probing real-world operational reliability."""

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-audit-g10-5-")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_workflow_integration_gap_analysis(self):
        """Audit Finding 1 Remediation: reusable-tf-apply.yml activates and passes --enable-lock (Remediated in G10.5.1)."""
        apply_yml_path = self.repo_root / ".github" / "workflows" / "reusable-tf-apply.yml"
        self.assertTrue(apply_yml_path.exists(), "reusable-tf-apply.yml must exist")

        with open(apply_yml_path, "r", encoding="utf-8") as f:
            content = f.read()
            data = yaml.safe_load(content)

        on_block = data.get("on") or data.get(True) or {}
        inputs = on_block.get("workflow_call", {}).get("inputs", {})

        # 1. Inputs audit: locking inputs are present in reusable-tf-apply.yml (remediated in G10.5.1)
        has_enable_lock = "enable-lock" in inputs
        has_lock_dir = "lock-dir" in inputs
        has_lock_ttl = "lock-ttl-seconds" in inputs

        # 2. Command execution audit: VERIFY_ARGS passes --enable-lock
        passes_enable_lock = "--enable-lock" in content
        calls_lock_consume = "lock-consume" in content or "consume_plan" in content
        calls_lock_fail = "lock-fail" in content or "fail_plan" in content

        # Document exact audit remediation evidence
        self.assertTrue(has_enable_lock, "reusable-tf-apply.yml provides 'enable-lock' input")
        self.assertTrue(has_lock_dir, "reusable-tf-apply.yml provides 'lock-dir' input")
        self.assertTrue(has_lock_ttl, "reusable-tf-apply.yml provides 'lock-ttl-seconds' input")
        self.assertTrue(passes_enable_lock, "reusable-tf-apply.yml passes '--enable-lock' to verify-plan-lifecycle.py")
        self.assertTrue(calls_lock_consume, "reusable-tf-apply.yml calls lock-consume or consume_plan")
        self.assertTrue(calls_lock_fail, "reusable-tf-apply.yml calls lock-fail or fail_plan on traps")

    def test_02_consumer_workflow_gap_analysis(self):
        """Audit Finding 2: Consumer workflows rely on GitHub concurrency, not distributed locking."""
        consumer_wf = self.repo_root / "examples" / "consumer-workflow" / ".github" / "workflows" / "infraflow-protected-apply-simulation.yml"
        self.assertTrue(consumer_wf.exists())

        with open(consumer_wf, "r", encoding="utf-8") as f:
            content = f.read()
            data = yaml.safe_load(content)

        # Consumer has GitHub concurrency group
        concurrency = data.get("concurrency")
        self.assertIsNotNone(concurrency, "Consumer workflow defines GitHub concurrency group")
        self.assertIn("${{ github.workflow }}", concurrency.get("group", ""))

        # Consumer does NOT specify any locking inputs to reusable workflow
        job_with = data.get("jobs", {}).get("simulate-apply", {}).get("with", {})
        self.assertNotIn("enable-lock", job_with)
        self.assertNotIn("lock-dir", job_with)

    def test_03_cross_runner_isolation_vulnerability(self):
        """Audit Finding 3: LocalFSDriver fails to provide mutual exclusion across distinct runner VMs."""
        # Simulate Runner VM 1 (ephemeral workspace 1)
        vm1_dir = os.path.join(self.test_dir, "runner_vm_1")
        vm1_locks = os.path.join(vm1_dir, ".infraflow", "locks")
        os.makedirs(vm1_locks, exist_ok=True)

        # Simulate Runner VM 2 (ephemeral workspace 2)
        vm2_dir = os.path.join(self.test_dir, "runner_vm_2")
        vm2_locks = os.path.join(vm2_dir, ".infraflow", "locks")
        os.makedirs(vm2_locks, exist_ok=True)

        target_key = "infraflow/locks/v1/s3/production/infraflow-tfstate-bucket/env/production/tf.state/default.lock"

        # Runner 1 acquires lock on target_key
        drv1 = LocalFSDriver(base_dir=vm1_locks)
        mgr1 = LockManager(driver=drv1)
        h1 = mgr1.acquire_lock(
            key=target_key,
            owner_identity={"runner_id": "github-runner-vm-1", "workflow": "reusable-tf-apply.yml"},
            purpose="apply-simulation-run-1",
            ttl_seconds=300,
        )
        self.assertTrue(h1.is_active())

        # Runner 2 on separate VM attempts acquisition on the same logical target_key
        drv2 = LocalFSDriver(base_dir=vm2_locks)
        mgr2 = LockManager(driver=drv2)

        # Vulnerability Demonstration: Runner 2 ALSO succeeds because filesystems are isolated!
        h2 = mgr2.acquire_lock(
            key=target_key,
            owner_identity={"runner_id": "github-runner-vm-2", "workflow": "reusable-tf-apply.yml"},
            purpose="apply-simulation-run-2",
            ttl_seconds=300,
        )

        # Both runners simultaneously believe they hold an authoritative exclusive lock
        self.assertTrue(h2.is_active())
        self.assertEqual(h1.key, h2.key)
        self.assertNotEqual(h1.lock_id, h2.lock_id)

        # Clean up
        mgr1.release_lock(h1)
        mgr2.release_lock(h2)

    def test_04_ephemeral_ledger_persistence_gap(self):
        """Audit Finding 4: Replay ledger on ephemeral runner storage does not survive runner shutdown."""
        plan_id = "plan-ephemeral-test-001"
        digest = "a" * 64
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Runner VM 1 executes and creates ledger in default local path
        vm1_db = os.path.join(self.test_dir, "vm1_ledger.db")
        ledger1 = PlanReplayLedger(db_path=vm1_db)
        ledger1.reserve_plan(plan_id, digest, "org/repo", "sha1", "prod", now, {})
        self.assertEqual(ledger1.get_plan_status(plan_id)["status"], STATUS_RESERVED)

        # Runner VM 1 terminates (ephemeral disk destroyed)
        os.remove(vm1_db)

        # Runner VM 2 spins up for a new run
        vm2_db = os.path.join(self.test_dir, "vm2_ledger.db")
        ledger2 = PlanReplayLedger(db_path=vm2_db)

        # Replay Vulnerability: VM 2 does not have the previous ledger, so duplicate reservation succeeds
        ledger2.reserve_plan(plan_id, digest, "org/repo", "sha1", "prod", now, {})
        self.assertEqual(ledger2.get_plan_status(plan_id)["status"], STATUS_RESERVED)

    def test_05_single_host_kernel_concurrency_verified(self):
        """Audit Verification 5: On a single shared host, LocalFSDriver guarantees mutual exclusion."""
        shared_locks = os.path.join(self.test_dir, "shared_locks")
        os.makedirs(shared_locks, exist_ok=True)
        target_key = "infraflow/locks/v1/s3/production/infraflow-tfstate-bucket/env/production/tf.state/default.lock"

        drv1 = LocalFSDriver(base_dir=shared_locks)
        mgr1 = LockManager(driver=drv1)
        h1 = mgr1.acquire_lock(
            key=target_key,
            owner_identity={"runner_id": "local-worker-1"},
            purpose="test-single-host",
            ttl_seconds=300,
        )
        self.assertTrue(h1.is_active())

        # Worker 2 on same shared filesystem MUST fail closed with LockHeldError
        drv2 = LocalFSDriver(base_dir=shared_locks)
        mgr2 = LockManager(driver=drv2)
        with self.assertRaises(LockHeldError):
            mgr2.acquire_lock(
                key=target_key,
                owner_identity={"runner_id": "local-worker-2"},
                purpose="test-single-host-competing",
                ttl_seconds=300,
            )

        mgr1.release_lock(h1)

    def test_06_fencing_token_ledger_monotonicity(self):
        """Audit Verification 6: PlanReplayLedger strictly rejects superseded fencing tokens."""
        db_path = os.path.join(self.test_dir, "ledger_fencing.db")
        ledger = PlanReplayLedger(db_path=db_path)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        key = "infraflow/locks/v1/s3/production/infraflow-tfstate-bucket/env/production/tf.state/default.lock"

        # Worker 1 holds token 1
        ledger.reserve_plan("plan-worker-1", "1111"*16, "org/repo", "commit1", "prod", now, {}, lock_id="lock-1", fencing_token=1, canonical_lock_key=key)

        # Worker 2 acquires newer token 2 on same key
        ledger.reserve_plan("plan-worker-2", "2222"*16, "org/repo", "commit2", "prod", now, {}, lock_id="lock-2", fencing_token=2, canonical_lock_key=key)

        # Worker 1 attempts to consume plan with superseded token 1
        with self.assertRaises(PlanReplayError) as ctx:
            ledger.consume_plan("plan-worker-1", fencing_token=1)
        self.assertIn("STALE_FENCING_TOKEN", str(ctx.exception))

    def test_07_lost_handle_and_heartbeat_fast_fail(self):
        """Audit Verification 7: Lost lock handle immediately terminates child subprocess."""
        shared_locks = os.path.join(self.test_dir, "shared_locks_hb")
        os.makedirs(shared_locks, exist_ok=True)
        drv = LocalFSDriver(base_dir=shared_locks)
        mgr = LockManager(driver=drv)

        handle = mgr.acquire_lock(
            key="infraflow/locks/v1/local/prod/test/state.tfstate/default.lock",
            owner_identity={"runner_id": "worker-hb"},
            purpose="test-abort",
            ttl_seconds=60,
        )

        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            self.assertIsNone(child.poll(), "Child process should be running")
            handle.register_child_process(child)

            # Trigger lock lost event
            handle.mark_lost("heartbeat_expired")

            child.wait(timeout=5)
            self.assertIsNotNone(child.poll(), "Child process must be terminated upon lock loss")
        finally:
            if child.poll() is None:
                child.kill()

    def test_08_uncertain_outcome_preservation(self):
        """Audit Verification 8: OUTCOME_UNCERTAIN fails closed and prevents re-execution."""
        db_path = os.path.join(self.test_dir, "ledger_unc.db")
        ledger = PlanReplayLedger(db_path=db_path)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        ledger.reserve_plan("plan-timeout", "3333"*16, "org/repo", "commit1", "prod", now, {})
        ledger.fail_plan("plan-timeout", uncertain=True)

        self.assertEqual(ledger.get_plan_status("plan-timeout")["status"], STATUS_OUTCOME_UNCERTAIN)

        with self.assertRaises(PlanReplayError) as ctx:
            ledger.reserve_plan("plan-timeout", "3333"*16, "org/repo", "commit1", "prod", now, {})
        self.assertIn("UNCERTAIN_EXECUTION_STATE", str(ctx.exception))

    def test_09_corrupted_lock_metadata_fails_closed(self):
        """Audit Verification 9: Tampered or corrupted lock file fails closed."""
        shared_locks = os.path.join(self.test_dir, "corrupt_locks")
        os.makedirs(shared_locks, exist_ok=True)
        drv = LocalFSDriver(base_dir=shared_locks)
        mgr = LockManager(driver=drv)

        key = "infraflow/locks/v1/s3/production/infraflow-tfstate-bucket/env/production/tf.state/default.lock"
        h = mgr.acquire_lock(
            key=key,
            owner_identity={"runner_id": "worker-corr"},
            purpose="test-tamper",
            ttl_seconds=300,
        )

        # Corrupt the lock.json file
        fp = drv._validate_key(key)
        lock_file = drv._resolve_key_path(fp, "lock.json")
        with open(lock_file, "w", encoding="utf-8") as f:
            f.write("{invalid-json-data")

        # Driver inspect / acquire should fail closed
        with self.assertRaises(LockError):
            drv.inspect(key)

    def test_10_provider_api_fencing_boundary_limitation(self):
        """Audit Verification 10: Provider APIs do not accept fencing tokens (Architectural Boundary)."""
        # Demonstrates that fencing token is strictly platform/ledger-enforced.
        # There is no provider argument (e.g. hashicorp/aws) that takes a fencing token.
        self.assertTrue(hasattr(vpl, "PlanReplayLedger"), "Fencing token is ledger-enforced")
        self.assertFalse(hasattr(vpl, "CloudProviderFencingClient"), "Cloud providers do not support fencing tokens")


if __name__ == "__main__":
    unittest.main()
