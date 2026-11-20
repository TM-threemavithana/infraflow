#!/usr/bin/env python3
"""
InfraFlow — Dedicated Adversarial Security & Integration Validation Suite
Milestone: G06.5 — Independent Adversarial Security Validation

Comprehensive 39-scenario adversarial test suite covering all four threat classes:
- Class A: Cryptographic Attacks (Tampering, Substitution, Forgery) — 8 tests
- Class B: Lifecycle & Replay Attacks (Time, State Drift, Replay, Races) — 9 tests
- Class C: Destructive Authorization & Blast-Radius Attacks (Scale, Elevation, Bypass) — 12 tests
- Class D: Workflow Contract & Filesystem Integrity Attacks (Symlinks, Workflow Bypass, Secrets) — 10 tests

Mandatory Invariants:
- Zero cloud spend ($0.00).
- Zero cloud credentials required.
- Fully offline simulation-only validation.
- Fail-closed security architecture.
"""

import base64
import copy
import datetime
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import yaml
from typing import Any, Dict, List, Optional

# Load platform modules dynamically from scripts directory
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
WORKFLOW_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "reusable-tf-apply.yml"))
TRUSTED_KEY_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policies", "trust", "trusted_signer.pub"))

if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

kms_mod = importlib.import_module("kms-envelope")
vpl_mod = importlib.import_module("verify-plan-lifecycle")
assess_mod = importlib.import_module("assess-destruction")
integrity_mod = importlib.import_module("verify-plan-integrity")

# Symbols from kms-envelope
encrypt_plan = kms_mod.encrypt_plan
decrypt_plan = kms_mod.decrypt_plan
safe_read_file = kms_mod.safe_read_file
safe_write_file = kms_mod.safe_write_file
canonicalize_aad = kms_mod.canonicalize_aad
EnvelopeError = kms_mod.EnvelopeError
EnvelopeAuthenticationError = kms_mod.EnvelopeAuthenticationError
EnvelopeContextMismatchError = kms_mod.EnvelopeContextMismatchError
EnvelopeDigestMismatchError = kms_mod.EnvelopeDigestMismatchError
EnvelopeKeyError = kms_mod.EnvelopeKeyError
PlanEnvelope = kms_mod.PlanEnvelope
MockKMSClient = kms_mod.MockKMSClient
KEK_BYTES = kms_mod.KEK_BYTES

# Symbols from verify-plan-lifecycle
PlanLifecycleVerifier = vpl_mod.PlanLifecycleVerifier
PlanReplayLedger = vpl_mod.PlanReplayLedger
PlanReplayError = vpl_mod.PlanReplayError
DECISION_AUTHORIZED = vpl_mod.DECISION_AUTHORIZED
DECISION_REJECTED = vpl_mod.DECISION_REJECTED
STATUS_RESERVED = vpl_mod.STATUS_RESERVED
STATUS_CONSUMED = vpl_mod.STATUS_CONSUMED
STATUS_FAILED = vpl_mod.STATUS_FAILED
STATUS_INTERRUPTED = vpl_mod.STATUS_INTERRUPTED
ENVELOPE_SCHEMA_VERSION = vpl_mod.ENVELOPE_SCHEMA_VERSION

# Symbols from assess-destruction
DestructivePlanAssessmentEngine = assess_mod.DestructivePlanAssessmentEngine
DestructivePlanClassifier = assess_mod.DestructivePlanClassifier
BlastRadiusPolicy = assess_mod.BlastRadiusPolicy
DestructionAssessmentError = assess_mod.DestructionAssessmentError
MalformedPlanError = assess_mod.MalformedPlanError
UnknownActionError = assess_mod.UnknownActionError
DestructionConfirmationValidator = assess_mod.DestructionConfirmationValidator
ExecutionRecoveryManager = assess_mod.ExecutionRecoveryManager
ConfirmationError = assess_mod.ConfirmationError
STATE_NOT_STARTED = assess_mod.STATE_NOT_STARTED
STATE_RESERVED = assess_mod.STATE_RESERVED
STATE_OUTCOME_UNCERTAIN = assess_mod.STATE_OUTCOME_UNCERTAIN
PLATFORM_MAX_DELETIONS_CEILING = assess_mod.PLATFORM_MAX_DELETIONS_CEILING
PLATFORM_MAX_REPLACEMENTS_CEILING = assess_mod.PLATFORM_MAX_REPLACEMENTS_CEILING

# Symbols from verify-plan-integrity
verify_provenance = integrity_mod.verify_provenance
sign_provenance = integrity_mod.sign_provenance


# ==============================================================================
# CLASS A: Cryptographic Attacks (Tampering, Substitution, Forgery)
# ==============================================================================

class TestAdversarialClassA(unittest.TestCase):
    """Class A: Cryptographic tampering, substitution, and forgery defenses."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-adv-class-a-")
        self.kek = os.urandom(KEK_BYTES)
        self.raw_plan = b"TERRAFORM_BINARY_PLAN_SECURE_PAYLOAD_TEST_DATA\x01\x02\x03\x04"
        self.plan_digest = hashlib.sha256(self.raw_plan).hexdigest()
        self.repo = "TM-threemavithana/infraflow-consumer-test"
        self.commit = "d0660de837ca07d5bdd56f04b0e50691ce98bd28"
        self.workflow = ".github/workflows/reusable-tf-plan.yml"
        self.env = "production"
        self.ref_now = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_valid_envelope(self) -> PlanEnvelope:
        return encrypt_plan(
            plan_bytes=self.raw_plan,
            kek=self.kek,
            repository=self.repo,
            commit_sha=self.commit,
            workflow=self.workflow,
            environment=self.env,
        )

    def test_a01_ciphertext_bitflip_tampering_rejected(self):
        """A01: Bit-flip in encrypted payload ciphertext is rejected by GCM tag verification."""
        envelope = self._create_valid_envelope()
        corrupted_ct = bytearray(envelope.ciphertext)
        corrupted_ct[0] ^= 0x01  # Flip 1 bit
        envelope.ciphertext = bytes(corrupted_ct)

        with self.assertRaises(EnvelopeAuthenticationError):
            decrypt_plan(
                envelope=envelope,
                kek=self.kek,
                expected_repo=self.repo,
                expected_commit=self.commit,
                expected_environment=self.env,
            )

    def test_a02_auth_tag_corruption_rejected(self):
        """A02: Corrupted authentication tag causes decryption to fail closed."""
        envelope = self._create_valid_envelope()
        corrupted_ct = bytearray(envelope.ciphertext)
        corrupted_ct[-1] ^= 0x80  # Corrupt auth tag (last 16 bytes)
        envelope.ciphertext = bytes(corrupted_ct)

        with self.assertRaises(EnvelopeAuthenticationError):
            decrypt_plan(
                envelope=envelope,
                kek=self.kek,
                expected_repo=self.repo,
                expected_commit=self.commit,
                expected_environment=self.env,
            )

    def test_a03_wrapped_key_modification_rejected(self):
        """A03: Modified wrapped DEK ciphertext prevents key unwrapping."""
        envelope = self._create_valid_envelope()
        corrupted_wdek = bytearray(envelope.wrapped_dek)
        corrupted_wdek[2] ^= 0xFF
        envelope.wrapped_dek = bytes(corrupted_wdek)

        with self.assertRaises((EnvelopeAuthenticationError, EnvelopeKeyError)):
            decrypt_plan(
                envelope=envelope,
                kek=self.kek,
                expected_repo=self.repo,
                expected_commit=self.commit,
                expected_environment=self.env,
            )

    def test_a04_encryption_context_aad_mismatch_rejected(self):
        """A04: Decrypting with altered AAD context (repository/env) is rejected."""
        envelope = self._create_valid_envelope()

        # Context altered: wrong expected environment
        with self.assertRaises(EnvelopeContextMismatchError):
            decrypt_plan(
                envelope=envelope,
                kek=self.kek,
                expected_repo=self.repo,
                expected_commit=self.commit,
                expected_environment="staging",  # Discrepancy
            )

    def test_a05_plan_digest_tampering_rejected(self):
        """A05: Forged or modified plan digest in envelope context fails integrity check."""
        envelope = self._create_valid_envelope()
        envelope.plan_digest = "0" * 64

        with self.assertRaises(EnvelopeDigestMismatchError):
            decrypt_plan(
                envelope=envelope,
                kek=self.kek,
                expected_repo=self.repo,
                expected_commit=self.commit,
                expected_environment=self.env,
            )

    def test_a06_repo_commit_identity_substitution_rejected(self):
        """A06: In-flight repository or commit identity substitution fails static and dynamic checks."""
        envelope = self._create_valid_envelope()
        state = {
            "version": 4,
            "terraform_version": "1.10.4",
            "serial": 10,
            "lineage": "3f2e1d0c-4b5a-6789-0123-abcdef456789",
            "outputs": {},
            "resources": [],
        }

        verifier = PlanLifecycleVerifier()
        # Verify with spoofed repository
        decision = verifier.verify_authorization(
            envelope_data=envelope.to_dict(),
            state_data=state,
            expected_repo="untrusted-attacker/rogue-repo",
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage="3f2e1d0c-4b5a-6789-0123-abcdef456789",
            expected_serial=10,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "REPO_MISMATCH")

    def test_a07_forged_provenance_rejected(self):
        """A07: Forged in-toto provenance signed by unpinned key is rejected."""
        plan_json_path = os.path.join(self.test_dir, "plan.json")
        with open(plan_json_path, "w", encoding="utf-8") as f:
            json.dump({"format_version": "1.2", "resource_changes": []}, f)

        forged_prov_path = os.path.join(self.test_dir, "forged_prov.json")

        # Generate provenance with self-signed unpinned key
        sign_provenance(
            plan_json_path=plan_json_path,
            output_path=forged_prov_path,
            repository=self.repo,
            commit_sha=self.commit,
            workflow="test.yml",
            policy_result="passed",
            signing_tier="preview",
        )

        # Verification against pinned platform trust root must FAIL
        success, errors = verify_provenance(
            provenance_path=forged_prov_path,
            trusted_public_key_path=TRUSTED_KEY_FILE,
            expected_repository=self.repo,
            expected_commit_sha=self.commit,
        )
        self.assertFalse(success)
        self.assertTrue(any("Untrusted signer key" in err or "Untrusted public key" in err for err in errors))

    def test_a08_missing_provenance_in_production_rejected(self):
        """A08: Missing or unverified provenance in production fails closed."""
        envelope = self._create_valid_envelope()
        state = {
            "version": 4,
            "terraform_version": "1.10.4",
            "serial": 10,
            "lineage": "3f2e1d0c-4b5a-6789-0123-abcdef456789",
            "outputs": {},
            "resources": [],
        }

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope.to_dict(),
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment="production",
            expected_lineage="3f2e1d0c-4b5a-6789-0123-abcdef456789",
            expected_serial=10,
            provenance_status="UNVERIFIED",
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "UNVERIFIED_PROVENANCE")


# ==============================================================================
# CLASS B: Lifecycle & Replay Attacks (Time, State Drift, Replay, Races)
# ==============================================================================

class TestAdversarialClassB(unittest.TestCase):
    """Class B: Lifecycle expiration, state drift, replay, and concurrency attacks."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-adv-class-b-")
        self.ref_now = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.repo = "TM-threemavithana/infraflow-consumer-test"
        self.commit = "d0660de837ca07d5bdd56f04b0e50691ce98bd28"
        self.env = "production"
        self.lineage = "3f2e1d0c-4b5a-6789-0123-abcdef456789"
        self.serial = 42
        self.digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_envelope(self, created_at: str, expires_at: str, plan_id: str = "plan-b-001") -> Dict[str, Any]:
        return {
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "algorithm": "AES-256-GCM",
            "plan_id": plan_id,
            "created_at": created_at,
            "expires_at": expires_at,
            "context": {
                "repository": self.repo,
                "commit_sha": self.commit,
                "environment": self.env,
                "plan_digest_sha256": self.digest,
                "workflow_sha": "484b067aa500d5523d1bccc06ce111cfe736a8af",
            },
            "wrapped_dek": {"algorithm": "AES-256-GCM"},
            "payload": {"nonce": "AAAA", "ciphertext": "BBBB"},
        }

    def _make_state(self, serial: Optional[int] = None, lineage: Optional[str] = None) -> Dict[str, Any]:
        return {
            "version": 4,
            "terraform_version": "1.10.4",
            "serial": self.serial if serial is None else serial,
            "lineage": self.lineage if lineage is None else lineage,
            "outputs": {},
            "resources": [],
        }

    def test_b01_expired_plan_rejected(self):
        """B01: Plan past its TTL expiration is rejected."""
        created_at = (self.ref_now - datetime.timedelta(hours=6)).isoformat()
        expires_at = (self.ref_now - datetime.timedelta(minutes=5)).isoformat()
        envelope = self._make_envelope(created_at, expires_at)
        state = self._make_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage=self.lineage,
            expected_serial=self.serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "PLAN_EXPIRED")

    def test_b02_future_dated_plan_rejected(self):
        """B02: Future-dated plan beyond clock skew threshold is rejected."""
        created_at = (self.ref_now + datetime.timedelta(minutes=15)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=2)).isoformat()
        envelope = self._make_envelope(created_at, expires_at)
        state = self._make_state()

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage=self.lineage,
            expected_serial=self.serial,
            clock_skew_seconds=60,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "FUTURE_CREATED_PLAN")

    def test_b03_state_serial_mismatch_rejected(self):
        """B03: Drifted state serial (newer or older) causes stale plan rejection."""
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=1)).isoformat()
        envelope = self._make_envelope(created_at, expires_at)
        state = self._make_state(serial=43)  # State advanced to serial 43

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage=self.lineage,
            expected_serial=42,  # Planning was at serial 42
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "STALE_STATE_SERIAL")

    def test_b04_state_lineage_mismatch_rejected(self):
        """B04: Different state lineage UUID causes immediate rejection."""
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=1)).isoformat()
        envelope = self._make_envelope(created_at, expires_at)
        state = self._make_state(lineage="99999999-9999-9999-9999-999999999999")

        verifier = PlanLifecycleVerifier()
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage=self.lineage,
            expected_serial=self.serial,
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "STATE_LINEAGE_MISMATCH")

    def test_b05_wrong_backend_or_workspace_rejected(self):
        """B05: Plan bound to specific backend or workspace is rejected on mismatch."""
        created_at = (self.ref_now - datetime.timedelta(hours=1)).isoformat()
        expires_at = (self.ref_now + datetime.timedelta(hours=1)).isoformat()
        envelope = self._make_envelope(created_at, expires_at)
        state = self._make_state()

        verifier = PlanLifecycleVerifier()
        # Workspace mismatch
        decision = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage=self.lineage,
            expected_serial=self.serial,
            expected_workspace="production",
            actual_workspace="staging",
            current_time=self.ref_now,
        )
        self.assertEqual(decision.decision, DECISION_REJECTED)
        self.assertEqual(decision.decision_code, "WORKSPACE_MISMATCH")

        # Backend mismatch
        decision_b = verifier.verify_authorization(
            envelope_data=envelope,
            state_data=state,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_lineage=self.lineage,
            expected_serial=self.serial,
            expected_backend="s3://bucket/tfstate",
            actual_backend="s3://other-bucket/tfstate",
            current_time=self.ref_now,
        )
        self.assertEqual(decision_b.decision, DECISION_REJECTED)
        self.assertEqual(decision_b.decision_code, "BACKEND_MISMATCH")

    def test_b06_replayed_plan_id_rejected(self):
        """B06: Consumed plan cannot be re-reserved or re-executed."""
        db_path = os.path.join(self.test_dir, "ledger_replay.db")
        ledger = PlanReplayLedger(db_path=db_path)
        plan_id = "plan-replay-test-01"
        expires_at = (self.ref_now + datetime.timedelta(hours=1)).isoformat()

        ledger.reserve_plan(
            plan_id=plan_id,
            plan_digest_sha256=self.digest,
            repository=self.repo,
            commit_sha=self.commit,
            environment=self.env,
            expires_at=expires_at,
            execution_context={},
            current_time=self.ref_now,
        )
        ledger.consume_plan(plan_id=plan_id, current_time=self.ref_now)

        with self.assertRaises(PlanReplayError) as ctx:
            ledger.reserve_plan(
                plan_id=plan_id,
                plan_digest_sha256=self.digest,
                repository=self.repo,
                commit_sha=self.commit,
                environment=self.env,
                expires_at=expires_at,
                execution_context={},
                current_time=self.ref_now,
            )
        self.assertIn("ALREADY_CONSUMED", str(ctx.exception))

    def test_b07_concurrent_duplicate_reservations_prevented(self):
        """B07: Atomic SQLite locking prevents race condition on duplicate reservation."""
        db_path = os.path.join(self.test_dir, "ledger_race.db")
        ledger = PlanReplayLedger(db_path=db_path)
        plan_id = "plan-race-test-01"
        expires_at = (self.ref_now + datetime.timedelta(hours=1)).isoformat()

        successes = []
        failures = []

        def worker():
            try:
                ledger.reserve_plan(
                    plan_id=plan_id,
                    plan_digest_sha256=self.digest,
                    repository=self.repo,
                    commit_sha=self.commit,
                    environment=self.env,
                    expires_at=expires_at,
                    execution_context={"thread": threading.get_ident()},
                    current_time=self.ref_now,
                )
                successes.append(1)
            except PlanReplayError:
                failures.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 7)

    def test_b08_retry_after_uncertain_outcome_blocked(self):
        """B08: An active or uncertain plan blocks automated re-reservation."""
        mgr = ExecutionRecoveryManager(db_path=os.path.join(self.test_dir, "recovery.db"))
        mgr.transition_state(
            plan_id="plan-uncertain-01",
            plan_digest_sha256=self.digest,
            repository=self.repo,
            environment=self.env,
            new_state=STATE_OUTCOME_UNCERTAIN,
            details="Process timed out during execution",
        )
        with self.assertRaises(DestructionAssessmentError) as ctx:
            mgr.transition_state(
                plan_id="plan-uncertain-01",
                plan_digest_sha256=self.digest,
                repository=self.repo,
                environment=self.env,
                new_state=STATE_RESERVED,
            )
        self.assertEqual(ctx.exception.decision_code, "UNCERTAIN_STATE_LOCKED")

    def test_b09_interrupted_execution_marked_uncertain(self):
        """B09: Interrupted execution marks ledger entry as uncertain and records audit trail."""
        mgr = ExecutionRecoveryManager(db_path=os.path.join(self.test_dir, "recovery_int.db"))
        mgr.transition_state(
            plan_id="plan-int-01",
            plan_digest_sha256=self.digest,
            repository=self.repo,
            environment=self.env,
            new_state=STATE_RESERVED,
        )
        mgr.transition_state(
            plan_id="plan-int-01",
            plan_digest_sha256=self.digest,
            repository=self.repo,
            environment=self.env,
            new_state=STATE_OUTCOME_UNCERTAIN,
            decision_code="EXECUTION_INTERRUPTED",
            details="SIGINT received: execution simulation interrupted",
        )
        state_record = mgr.get_state("plan-int-01")
        self.assertIsNotNone(state_record)
        self.assertEqual(state_record["state"], STATE_OUTCOME_UNCERTAIN)
        self.assertEqual(state_record["decision_code"], "EXECUTION_INTERRUPTED")
        self.assertIn("SIGINT", state_record["details"])


# ==============================================================================
# CLASS C: Destructive Authorization & Blast-Radius Attacks (Scale, Elevation, Bypass)
# ==============================================================================

class TestAdversarialClassC(unittest.TestCase):
    """Class C: Destructive change assessment, ceiling enforcement, and confirmation tokens."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-adv-class-c-")
        self.ref_now = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.plan_id = "plan-destroy-adv-001"
        self.plan_digest = "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123"
        self.repo = "TM-threemavithana/infraflow-consumer-test"
        self.env = "production"
        self.authorizer = "admin@infraflow.security"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_plan(self, changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "format_version": "1.2",
            "terraform_version": "1.10.4",
            "resource_changes": changes,
        }

    def _make_resource_change(self, address: str, res_type: str, actions: List[str]) -> Dict[str, Any]:
        return {
            "address": address,
            "type": res_type,
            "name": "example",
            "module_address": "",
            "change": {
                "actions": actions,
                "before": {"id": "123"},
                "after": None if "delete" in actions else {"id": "123"},
            },
        }

    def test_c01_consumer_policy_ceiling_elevation_blocked(self):
        """C01: Consumer policy exceeding platform deletion ceiling (25) is blocked."""
        policy_data = {
            "schema_version": "infraflow-destruction-policy-v1",
            "environment": "production",
            "max_deletions": 50,  # Exceeds PLATFORM_MAX_DELETIONS_CEILING (25)
            "max_replacements": 10,
        }
        policy_path = os.path.join(self.test_dir, "elevated_policy.json")
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(policy_data, f)

        with self.assertRaises(DestructionAssessmentError) as ctx:
            BlastRadiusPolicy.from_file(policy_path)
        self.assertEqual(ctx.exception.decision_code, "POLICY_CEILING_EXCEEDED")

    def test_c02_consumer_statewide_destroy_elevation_blocked(self):
        """C02: Consumer policy attempting allow_state_wide_destroy in production is blocked."""
        policy_data = {
            "schema_version": "infraflow-destruction-policy-v1",
            "environment": "production",
            "max_deletions": 10,
            "max_replacements": 10,
            "allow_state_wide_destroy": True,  # Strictly prohibited in production
        }
        policy_path = os.path.join(self.test_dir, "statewide_policy.json")
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(policy_data, f)

        with self.assertRaises(DestructionAssessmentError) as ctx:
            BlastRadiusPolicy.from_file(policy_path)
        self.assertEqual(ctx.exception.decision_code, "POLICY_CEILING_EXCEEDED")

    def test_c03_consumer_increasing_deletion_threshold_prevented(self):
        """C03: Caller CLI argument cannot loosen a stricter policy deletion limit."""
        policy_data = {
            "schema_version": "infraflow-destruction-policy-v1",
            "environment": "production",
            "max_deletions": 2,
            "max_replacements": 5,
        }
        policy_path = os.path.join(self.test_dir, "strict_policy.json")
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(policy_data, f)

        policy = BlastRadiusPolicy.from_file(policy_path)
        bounded_policy = policy.apply_caller_bounds(caller_max_del=10, caller_max_rep=None)
        self.assertEqual(bounded_policy.max_deletions, 2)  # Capped at stricter limit

        changes = [
            self._make_resource_change(f"aws_s3_bucket.b{i}", "aws_s3_bucket", ["delete"]) for i in range(3)
        ]
        changes.append(self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]))
        plan = self._make_plan(changes)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env,
            policy=bounded_policy,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "DELETION_LIMIT_EXCEEDED")

    def test_c04_missing_destruction_confirmation_rejected(self):
        """C04: Plan with destructive changes lacking confirmation token is rejected."""
        changes = [
            self._make_resource_change("aws_s3_bucket.temp", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]),
        ]
        plan = self._make_plan(changes)

        policy = BlastRadiusPolicy(environment=self.env, max_deletions=5)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env,
            policy=policy,
            confirmation_token=None,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "MISSING_DESTRUCTION_CONFIRMATION")

    def test_c05_generic_token_confirmation_rejected(self):
        """C05: Generic confirmation tokens ('yes', 'CONFIRM', 'proceed') are rejected."""
        changes = [
            self._make_resource_change("aws_s3_bucket.temp", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]),
        ]
        plan = self._make_plan(changes)

        policy = BlastRadiusPolicy(environment=self.env, max_deletions=5)

        for generic_token in ["yes", "YES", "confirm", "PROCEED", "true", "override"]:
            decision = DestructivePlanAssessmentEngine.assess(
                plan_data=plan,
                expected_plan_id=self.plan_id,
                expected_plan_digest=self.plan_digest,
                repository=self.repo,
                environment=self.env,
                policy=policy,
                confirmation_token=generic_token,
                current_time=self.ref_now,
            )
            self.assertEqual(decision["decision"], DECISION_REJECTED)
            self.assertEqual(decision["decision_code"], "INVALID_CONFIRMATION_TOKEN")
            self.assertIn("Generic token", decision["reason"])

    def test_c06_untrusted_authorizer_confirmation_rejected(self):
        """C06: Confirmation token authorized by identity not in trusted authorizers allowlist is rejected."""
        token = DestructionConfirmationValidator.create_token(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            source_repository=self.repo,
            target_environment=self.env,
            pure_deletions=1,
            replacements=0,
            authorized_by="mallory@untrusted.attacker",  # Untrusted
            validity_seconds=3600,
            current_time=self.ref_now,
        )

        changes = [
            self._make_resource_change("aws_s3_bucket.temp", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]),
        ]
        plan = self._make_plan(changes)

        policy = BlastRadiusPolicy(
            environment=self.env,
            max_deletions=5,
            trusted_authorizers={"alice@infraflow.security", "bob@infraflow.security"},
        )

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env,
            policy=policy,
            confirmation_token=token,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "UNAUTHORIZED_AUTHORIZER")

    def test_c07_confirmation_replayed_for_different_plan_rejected(self):
        """C07: Confirmation token bound to plan A presented for plan B is rejected."""
        token = DestructionConfirmationValidator.create_token(
            plan_id="plan-A",
            plan_digest_sha256="0" * 64,
            source_repository=self.repo,
            target_environment=self.env,
            pure_deletions=1,
            replacements=0,
            authorized_by=self.authorizer,
            validity_seconds=3600,
            current_time=self.ref_now,
        )

        changes = [
            self._make_resource_change("aws_s3_bucket.temp", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]),
        ]
        plan = self._make_plan(changes)

        policy = BlastRadiusPolicy(environment=self.env, max_deletions=5)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id="plan-B",  # Discrepancy
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env,
            policy=policy,
            confirmation_token=token,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "CONFIRMATION_PLAN_MISMATCH")

    def test_c08_confirmation_bound_to_different_repo_env_rejected(self):
        """C08: Confirmation token bound to staging presented in production is rejected."""
        token = DestructionConfirmationValidator.create_token(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            source_repository=self.repo,
            target_environment="staging",  # Staging confirmation
            pure_deletions=1,
            replacements=0,
            authorized_by=self.authorizer,
            validity_seconds=3600,
            current_time=self.ref_now,
        )

        changes = [
            self._make_resource_change("aws_s3_bucket.temp", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]),
        ]
        plan = self._make_plan(changes)

        policy = BlastRadiusPolicy(environment="production", max_deletions=5)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment="production",  # Production execution
            policy=policy,
            confirmation_token=token,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "CONFIRMATION_ENV_MISMATCH")

    def test_c09_security_critical_deletion_blocked(self):
        """C09: Deletion of protected security-critical resources (e.g. KMS, IAM) is blocked."""
        token = DestructionConfirmationValidator.create_token(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            source_repository=self.repo,
            target_environment=self.env,
            pure_deletions=1,
            replacements=0,
            authorized_by=self.authorizer,
            validity_seconds=3600,
            current_time=self.ref_now,
        )

        changes = [
            self._make_resource_change("aws_kms_key.root_key", "aws_kms_key", ["delete"]),
            self._make_resource_change("aws_s3_bucket.main", "aws_s3_bucket", ["update"]),
        ]
        plan = self._make_plan(changes)

        policy = BlastRadiusPolicy(environment=self.env, max_deletions=5, allow_security_critical_destruction=False)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env,
            policy=policy,
            confirmation_token=token,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "SECURITY_CRITICAL_DESTRUCTION_BLOCKED")

    def test_c10_state_wide_destroy_blocked(self):
        """C10: Complete destruction of all managed resources is blocked in production."""
        changes = [
            self._make_resource_change(f"aws_s3_bucket.b{i}", "aws_s3_bucket", ["delete"]) for i in range(5)
        ]
        plan = self._make_plan(changes)

        token = DestructionConfirmationValidator.create_token(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            source_repository=self.repo,
            target_environment=self.env,
            pure_deletions=5,
            replacements=0,
            authorized_by=self.authorizer,
            validity_seconds=3600,
            current_time=self.ref_now,
        )

        policy = BlastRadiusPolicy(environment="production", max_deletions=10, allow_state_wide_destroy=False)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment="production",
            policy=policy,
            confirmation_token=token,
            current_time=self.ref_now,
        )
        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "STATE_WIDE_DESTROY_BLOCKED")

    def test_c11_unknown_action_combination_fails_closed(self):
        """C11: Unknown or malformed action array fails closed with evaluation error."""
        with self.assertRaises(UnknownActionError):
            DestructivePlanClassifier.classify_resource_action(["delete", "unrecognized_action"])

    def test_c12_destroy_before_create_replacement_classified(self):
        """C12: destroy-before-create action combination is correctly classified as replacement."""
        cat, direction = DestructivePlanClassifier.classify_resource_action(["delete", "create"])
        self.assertEqual(cat, "replace")
        self.assertEqual(direction, "destroy_before_create")

        cat_rev, direction_rev = DestructivePlanClassifier.classify_resource_action(["create", "delete"])
        self.assertEqual(cat_rev, "replace")
        self.assertEqual(direction_rev, "create_before_destroy")


# ==============================================================================
# CLASS D: Workflow Contract & Filesystem Integrity Attacks
# ==============================================================================

class TestAdversarialClassD(unittest.TestCase):
    """Class D: Workflow contract, symlink attacks, and zero-execution verification."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-adv-class-d-")
        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            self.workflow_yaml = yaml.safe_load(f)
            f.seek(0)
            self.workflow_content = f.read()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_d01_symlink_plan_file_rejected(self):
        """D01: Symlinked plan envelope pointing outside workspace is rejected."""
        real_file = os.path.join(self.test_dir, "real_plan.txt")
        with open(real_file, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL_SYSTEM_DATA")

        symlink_path = os.path.join(self.test_dir, "plan_link.json")
        os.symlink(real_file, symlink_path)

        # 1. kms-envelope rejects symlink
        with self.assertRaises(EnvelopeError) as ctx:
            safe_read_file(symlink_path)
        self.assertIn("Symlinks are strictly prohibited", str(ctx.exception))

        # 2. assess-destruction rejects symlink
        with self.assertRaises(MalformedPlanError):
            DestructivePlanClassifier.analyze_plan_file(symlink_path)

    def test_d02_symlink_state_file_rejected(self):
        """D02: Symlink rejection is enforced for state snapshot files."""
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        self.assertIn('if [[ -L "${file_var}" ]]', guard_script)
        self.assertIn("Symbolic links are strictly prohibited", guard_script)

    def test_d03_symlink_policy_file_rejected(self):
        """D03: Symlinked destruction blast-radius policy is rejected."""
        real_policy = os.path.join(self.test_dir, "real_policy.json")
        with open(real_policy, "w", encoding="utf-8") as f:
            json.dump({"schema_version": "1.0", "max_deletions": 5}, f)

        symlink_policy = os.path.join(self.test_dir, "policy_link.json")
        os.symlink(real_policy, symlink_policy)

        with self.assertRaises(DestructionAssessmentError) as ctx:
            BlastRadiusPolicy.from_file(symlink_policy)
        self.assertEqual(ctx.exception.decision_code, "SYMLINK_PROHIBITED")

    def test_d04_symlink_confirmation_file_rejected(self):
        """D04: Workflow validate-inputs rejects symlinked optional confirmation and policy files."""
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        self.assertIn('for opt_file in "${INPUT_DESTRUCTION_POLICY}" "${INPUT_DESTRUCTION_CONF_FILE}" "${INPUT_PLAN_JSON}"', guard_script)
        self.assertIn('if [[ -L "${opt_file}" ]]', guard_script)

    def test_d05_untrusted_pr_event_rejected(self):
        """D05: pull_request and pull_request_target events are strictly rejected."""
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        self.assertIn('"${EVENT_NAME}" == "pull_request"', guard_script)
        self.assertIn('"${EVENT_NAME}" == "pull_request_target"', guard_script)
        self.assertIn("strictly prohibited from requesting execution or apply authorization", guard_script)

    def test_d06_mutable_workflow_ref_rejected(self):
        """D06: Platform workflow references must be immutable 40-character commit SHAs."""
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        self.assertIn('^[0-9a-f]{40}$', guard_script)
        self.assertIn("Platform reusable workflow must be referenced by an immutable 40-character commit SHA", guard_script)

    def test_d07_unauthorized_platform_repo_rejected(self):
        """D07: Untrusted fork or unauthorized repository is rejected as platform source."""
        guard_script = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]["run"]
        self.assertIn('TRUSTED_PLATFORM_REPO="TM-threemavithana/infraflow"', guard_script)
        self.assertIn('if [[ "${WORKFLOW_REPO}" != "${TRUSTED_PLATFORM_REPO}" ]]', guard_script)

    def test_d08_missing_mandatory_outputs_fails_closed(self):
        """D08: All 8 contract outputs are defined and summary step defaults to failure/rejected."""
        on_block = self.workflow_yaml.get("on") or self.workflow_yaml.get(True, {})
        outputs = on_block.get("workflow_call", {}).get("outputs", {})
        expected_outputs = {
            "plan-verification-status",
            "provenance-status",
            "state-consistency-status",
            "replay-status",
            "destruction-status",
            "destruction-summary",
            "authorization-status",
            "simulation-status",
        }
        self.assertTrue(expected_outputs.issubset(set(outputs.keys())))

    def test_d09_non_fail_closed_destruct_status_rejected(self):
        """D09: Summary job requires positive membership in ('authorized' | 'safe' | 'not-applicable')."""
        summary_script = self.workflow_yaml["jobs"]["summary"]["steps"][0]["run"]
        self.assertIn('"authorized"', summary_script)
        self.assertIn('"safe"', summary_script)
        self.assertIn('"not-applicable"', summary_script)
        # Ensure fail-closed: != "rejected" was removed
        self.assertNotIn('"${DESTRUCT_STATUS}" != "rejected"', summary_script)

    def test_d10_strict_absence_of_live_apply_destroy(self):
        """D10: Static audit confirms strict absence of live apply/destroy commands and unmocked cloud calls."""
        # Check workflow file
        self.assertNotIn("terraform apply", self.workflow_content.lower())
        self.assertNotIn("terraform destroy", self.workflow_content.lower())
        self.assertNotIn("force-unlock", self.workflow_content.lower())

        # Check python scripts
        scripts_to_check = [
            "kms-envelope.py",
            "verify-plan-lifecycle.py",
            "assess-destruction.py",
        ]
        for script_name in scripts_to_check:
            script_path = os.path.join(SCRIPTS_DIR, script_name)
            with open(script_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Disallow live subprocess terraform apply/destroy
            self.assertNotIn('["terraform", "apply"', content)
            self.assertNotIn('["terraform", "destroy"', content)
            self.assertNotIn('boto3.client("kms")', content)
            self.assertNotIn("boto3.client('kms')", content)


if __name__ == "__main__":
    unittest.main()
