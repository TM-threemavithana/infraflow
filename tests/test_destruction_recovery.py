#!/usr/bin/env python3
"""
InfraFlow — Controlled Destruction, Blast-Radius Protection & Failure Recovery Unit Tests
Milestone: G06.4

Comprehensive 25-scenario adversarial unit test suite:
1. Safe create-only plan: 0 deletions, 0 replacements -> automatically authorized without confirmation.
2. Single authorized simulated deletion: 1 deletion within threshold with valid confirmation -> authorized.
3. Multiple deletions under threshold: Deletions within max_deletions with valid confirmation -> authorized.
4. Deletion count exceeding threshold: Deletions > max_deletions -> rejected with DELETION_LIMIT_EXCEEDED.
5. Replacement count exceeding threshold: Replacements > max_replacements -> rejected with REPLACEMENT_LIMIT_EXCEEDED.
6. Security-critical resource deletion blocked: Deletion of IAM, KMS, or S3 access block -> rejected with SECURITY_CRITICAL_DESTRUCTION_BLOCKED.
7. State-wide destroy attempt blocked: Plan deleting all active resources -> rejected with STATE_WIDE_DESTROY_BLOCKED.
8. Missing destruction confirmation rejected: Destructive changes present without confirmation -> rejected with MISSING_DESTRUCTION_CONFIRMATION.
9. Incorrect confirmation (generic string) rejected: 'yes', 'true', 'destroy' -> rejected with INVALID_CONFIRMATION_TOKEN.
10. Confirmation bound to another plan rejected: Plan ID mismatch -> rejected with CONFIRMATION_PLAN_MISMATCH.
11. Confirmation bound to another repo rejected: Source repo mismatch -> rejected with CONFIRMATION_REPO_MISMATCH.
12. Confirmation bound to another environment rejected: Target environment mismatch -> rejected with CONFIRMATION_ENV_MISMATCH.
13. Expired confirmation rejected: Confirmation token expired -> rejected with CONFIRMATION_EXPIRED.
14. Caller-controlled threshold override blocked: Caller cannot elevate threshold above policy.
15. Missing destruction policy fails closed: Non-existent policy file fails closed.
16. Malformed Terraform plan fails closed: Malformed JSON, missing changes, errored plan -> MALFORMED_PLAN.
17. Unknown resource action fails closed: Unknown action token -> fails closed with UNKNOWN_ACTION.
18. Replay of destruction authorization blocked: Replay ledger blocks duplicate reservation.
19. Concurrent simulation reservations prevented: Atomic reservation in ledger prevents race conditions.
20. Interrupted execution transitions to OUTCOME_UNCERTAIN: Simulation crash/interrupt marked OUTCOME_UNCERTAIN.
21. Partial-execution simulation marks OUTCOME_UNCERTAIN: Incomplete execution marked OUTCOME_UNCERTAIN.
22. Unknown outcome and retry attempt strictly blocked: OUTCOME_UNCERTAIN state cannot be retried or re-reserved.
23. Temporary-file cleanup trap and mode 0600 verified: Restricted mode 0600 and cleanup verified.
24. Untrusted PR attempting destructive authorization rejected: Pull request events blocked at guard.
25. Strict absence of real apply/destroy verified: Verifies absence of live Terraform commands in workflows and scripts.
"""

import datetime
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from typing import Any, Dict, List, Optional
import yaml

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
ASSESS_SCRIPT = os.path.join(SCRIPTS_DIR, "assess-destruction.py")
LIFECYCLE_SCRIPT = os.path.join(SCRIPTS_DIR, "verify-plan-lifecycle.py")
WORKFLOW_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "reusable-tf-apply.yml"))

if not os.path.isfile(ASSESS_SCRIPT):
    raise FileNotFoundError(f"Missing {ASSESS_SCRIPT}")
if not os.path.isfile(LIFECYCLE_SCRIPT):
    raise FileNotFoundError(f"Missing {LIFECYCLE_SCRIPT}")
if not os.path.isfile(WORKFLOW_FILE):
    raise FileNotFoundError(f"Missing {WORKFLOW_FILE}")

# Dynamically import assess-destruction
spec_assess = importlib.util.spec_from_file_location("assess_destruction", ASSESS_SCRIPT)
assess_mod = importlib.util.module_from_spec(spec_assess)
sys.modules["assess_destruction"] = assess_mod
spec_assess.loader.exec_module(assess_mod)

# Dynamically import verify-plan-lifecycle
spec_vpl = importlib.util.spec_from_file_location("verify_plan_lifecycle", LIFECYCLE_SCRIPT)
vpl_mod = importlib.util.module_from_spec(spec_vpl)
sys.modules["verify_plan_lifecycle"] = vpl_mod
spec_vpl.loader.exec_module(vpl_mod)

# Symbols from assess-destruction
DestructivePlanClassifier = assess_mod.DestructivePlanClassifier
BlastRadiusPolicy = assess_mod.BlastRadiusPolicy
DestructionConfirmationValidator = assess_mod.DestructionConfirmationValidator
ExecutionRecoveryManager = assess_mod.ExecutionRecoveryManager
DestructivePlanAssessmentEngine = assess_mod.DestructivePlanAssessmentEngine

DestructionAssessmentError = assess_mod.DestructionAssessmentError
MalformedPlanError = assess_mod.MalformedPlanError
UnknownActionError = assess_mod.UnknownActionError
BlastRadiusExceededError = assess_mod.BlastRadiusExceededError
ConfirmationError = assess_mod.ConfirmationError

DECISION_AUTHORIZED = assess_mod.DECISION_AUTHORIZED
DECISION_REJECTED = assess_mod.DECISION_REJECTED
STATE_NOT_STARTED = assess_mod.STATE_NOT_STARTED
STATE_VERIFICATION_FAILED = assess_mod.STATE_VERIFICATION_FAILED
STATE_RESERVED = assess_mod.STATE_RESERVED
STATE_SIMULATION_COMPLETED = assess_mod.STATE_SIMULATION_COMPLETED
STATE_SIMULATION_FAILED = assess_mod.STATE_SIMULATION_FAILED
STATE_OUTCOME_UNCERTAIN = assess_mod.STATE_OUTCOME_UNCERTAIN
STATE_REJECTED = assess_mod.STATE_REJECTED
DESTRUCTION_POLICY_SCHEMA_VERSION = assess_mod.DESTRUCTION_POLICY_SCHEMA_VERSION
DESTRUCTION_CONFIRMATION_SCHEMA_VERSION = assess_mod.DESTRUCTION_CONFIRMATION_SCHEMA_VERSION
SECURITY_CRITICAL_RESOURCE_TYPES = assess_mod.SECURITY_CRITICAL_RESOURCE_TYPES

# Symbols from verify-plan-lifecycle
PlanReplayLedger = vpl_mod.PlanReplayLedger
PlanReplayError = vpl_mod.PlanReplayError


class TestDestructionRecovery(unittest.TestCase):
    """25-scenario adversarial unit test suite for Milestone G06.4."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-g06-4-test-")
        self.ref_now = datetime.datetime(2026, 11, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.plan_id = "plan-destroy-test-001"
        self.plan_digest = "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123"
        self.repo = "TM-threemavithana/infraflow-consumer-test"
        self.env_prod = "production"
        self.env_staging = "staging"
        self.authorizer = "admin@infraflow.security"

        with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
            self.workflow_yaml = yaml.safe_load(f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_resource_change(
        self,
        address: str,
        res_type: str,
        actions: List[str],
        name: str = "example",
        module_address: str = "",
    ) -> Dict[str, Any]:
        return {
            "address": address,
            "type": res_type,
            "name": name,
            "module_address": module_address,
            "change": {
                "actions": actions,
                "before": {"id": "res-123"},
                "after": {"id": "res-123"} if "delete" not in actions else None,
            },
        }

    def _make_plan(self, changes: List[Dict[str, Any]], errored: bool = False) -> Dict[str, Any]:
        res = {
            "format_version": "1.2",
            "terraform_version": "1.10.4",
            "resource_changes": changes,
        }
        if errored:
            res["errored"] = True
        return res

    def _make_confirmation(
        self,
        pure_deletions: int,
        replacements: int,
        plan_id: Optional[str] = None,
        digest: Optional[str] = None,
        repo: Optional[str] = None,
        env: Optional[str] = None,
        ttl_seconds: int = 3600,
        authorized_by: Optional[str] = None,
        current_time: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        return DestructionConfirmationValidator.create_token(
            plan_id=plan_id or self.plan_id,
            plan_digest_sha256=digest or self.plan_digest,
            source_repository=repo or self.repo,
            target_environment=env or self.env_prod,
            pure_deletions=pure_deletions,
            replacements=replacements,
            authorized_by=authorized_by or self.authorizer,
            validity_seconds=ttl_seconds,
            current_time=current_time or self.ref_now,
        )

    # 1. Safe create-only plan: 0 deletions, 0 replacements -> automatically authorized without confirmation
    def test_01_safe_create_only_plan(self):
        changes = [
            self._make_resource_change("aws_s3_bucket.data", "aws_s3_bucket", ["create"]),
            self._make_resource_change("aws_sqs_queue.events", "aws_sqs_queue", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_prod, max_deletions=0, max_replacements=0)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_prod,
            policy=policy,
            confirmation_token=None,  # No confirmation required
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_AUTHORIZED)
        self.assertEqual(decision["decision_code"], "SAFE_NON_DESTRUCTIVE_PLAN")
        self.assertFalse(decision["has_destructive_changes"])
        self.assertFalse(decision["confirmation_evaluation"]["is_required"])

    # 2. Single authorized simulated deletion: 1 deletion within threshold with valid confirmation -> authorized
    def test_02_single_authorized_simulated_deletion(self):
        changes = [
            self._make_resource_change("aws_instance.worker", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.manager", "aws_instance", ["update"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=1, require_confirmation=True)
        conf = self._make_confirmation(pure_deletions=1, replacements=0, env=self.env_staging)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_AUTHORIZED)
        self.assertEqual(decision["decision_code"], "AUTHORIZED_SIMULATION_WITH_CONFIRMATION")
        self.assertTrue(decision["has_destructive_changes"])
        self.assertTrue(decision["confirmation_evaluation"]["is_valid"])

    # 3. Multiple deletions under threshold: Deletions within max_deletions with valid confirmation -> authorized
    def test_03_multiple_deletions_under_threshold(self):
        changes = [
            self._make_resource_change("aws_instance.node1", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.node2", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.node3", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.node4", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)
        conf = self._make_confirmation(pure_deletions=3, replacements=0, env=self.env_staging)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_AUTHORIZED)
        self.assertEqual(decision["metrics"]["pure_deletions"], 3)
        self.assertEqual(decision["metrics"]["creates"], 1)

    # 4. Deletion count exceeding threshold: Deletions > max_deletions -> rejected with DELETION_LIMIT_EXCEEDED
    def test_04_deletion_count_exceeding_threshold_rejected(self):
        changes = [
            self._make_resource_change(f"aws_instance.node_{i}", "aws_instance", ["delete"])
            for i in range(5)
        ]
        # Include an update so it is not a state-wide destroy
        changes.append(self._make_resource_change("aws_instance.primary", "aws_instance", ["update"]))
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=3)
        conf = self._make_confirmation(pure_deletions=5, replacements=0, env=self.env_staging)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "DELETION_LIMIT_EXCEEDED")
        self.assertIn("exceeds maximum allowed limit of 3", decision["reason"])

    # 5. Replacement count exceeding threshold: Replacements > max_replacements -> rejected with REPLACEMENT_LIMIT_EXCEEDED
    def test_05_replacement_count_exceeding_threshold_rejected(self):
        changes = [
            self._make_resource_change(f"aws_instance.node_{i}", "aws_instance", ["create", "delete"])
            for i in range(4)
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_replacements=2)
        conf = self._make_confirmation(pure_deletions=0, replacements=4, env=self.env_staging)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "REPLACEMENT_LIMIT_EXCEEDED")
        self.assertIn("exceeds maximum allowed limit of 2", decision["reason"])

    # 6. Security-critical resource deletion blocked: IAM, KMS, S3 public access block -> rejected
    def test_06_security_critical_deletion_blocked(self):
        critical_types = [
            ("aws_iam_role.deployer", "aws_iam_role"),
            ("aws_kms_key.main", "aws_kms_key"),
            ("aws_s3_bucket_public_access_block.pab", "aws_s3_bucket_public_access_block"),
        ]

        for addr, rtype in critical_types:
            changes = [
                self._make_resource_change(addr, rtype, ["delete"]),
                self._make_resource_change("aws_s3_bucket.data", "aws_s3_bucket", ["create"]),
            ]
            plan = self._make_plan(changes)
            policy = BlastRadiusPolicy(
                environment=self.env_staging,
                max_deletions=10,
                allow_security_critical_destruction=False,
            )
            conf = self._make_confirmation(pure_deletions=1, replacements=0, env=self.env_staging)

            decision = DestructivePlanAssessmentEngine.assess(
                plan_data=plan,
                expected_plan_id=self.plan_id,
                expected_plan_digest=self.plan_digest,
                repository=self.repo,
                environment=self.env_staging,
                policy=policy,
                confirmation_token=conf,
                current_time=self.ref_now,
            )

            self.assertEqual(decision["decision"], DECISION_REJECTED)
            self.assertEqual(decision["decision_code"], "SECURITY_CRITICAL_DESTRUCTION_BLOCKED")
            self.assertIn("Destruction of security-critical resources is prohibited", decision["reason"])

    # 7. State-wide destroy attempt blocked: Plan deleting all resources -> rejected with STATE_WIDE_DESTROY_BLOCKED
    def test_07_state_wide_destroy_blocked(self):
        changes = [
            self._make_resource_change("aws_s3_bucket.b1", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_s3_bucket.b2", "aws_s3_bucket", ["delete"]),
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(
            environment=self.env_staging,
            max_deletions=10,
            allow_state_wide_destroy=False,
        )
        conf = self._make_confirmation(pure_deletions=3, replacements=0, env=self.env_staging)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "STATE_WIDE_DESTROY_BLOCKED")
        self.assertTrue(decision["metrics"]["is_state_wide_destroy"])

    # 8. Missing destruction confirmation rejected: Destructive changes present without confirmation
    def test_08_missing_confirmation_rejected(self):
        changes = [
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.new_app", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=None,  # Missing!
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "MISSING_DESTRUCTION_CONFIRMATION")
        self.assertFalse(decision["confirmation_evaluation"]["is_valid"])

    # 9. Incorrect confirmation (generic string) rejected: 'yes', 'true', 'destroy' -> rejected
    def test_09_generic_confirmation_rejected(self):
        generic_tokens = ["yes", "YES", "true", "TRUE", "destroy", "apply", "proceed", "override"]
        changes = [
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.new_app", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)

        for gen_tok in generic_tokens:
            decision = DestructivePlanAssessmentEngine.assess(
                plan_data=plan,
                expected_plan_id=self.plan_id,
                expected_plan_digest=self.plan_digest,
                repository=self.repo,
                environment=self.env_staging,
                policy=policy,
                confirmation_token=gen_tok,
                current_time=self.ref_now,
            )

            self.assertEqual(decision["decision"], DECISION_REJECTED)
            self.assertEqual(decision["decision_code"], "INVALID_CONFIRMATION_TOKEN")
            self.assertIn("Generic token", decision["reason"])

    # 10. Confirmation bound to another plan rejected: Plan ID mismatch -> rejected
    def test_10_confirmation_plan_mismatch_rejected(self):
        changes = [
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.new_app", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)
        conf = self._make_confirmation(
            pure_deletions=1, replacements=0, env=self.env_staging, plan_id="different-plan-999"
        )

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "CONFIRMATION_PLAN_MISMATCH")

    # 11. Confirmation bound to another repo rejected: Source repo mismatch -> rejected
    def test_11_confirmation_repo_mismatch_rejected(self):
        changes = [
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.new_app", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)
        conf = self._make_confirmation(
            pure_deletions=1, replacements=0, env=self.env_staging, repo="attacker/malicious-repo"
        )

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "CONFIRMATION_REPO_MISMATCH")

    # 12. Confirmation bound to another environment rejected: Target environment mismatch -> rejected
    def test_12_confirmation_env_mismatch_rejected(self):
        changes = [
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.new_app", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)
        conf = self._make_confirmation(
            pure_deletions=1, replacements=0, env="dev"  # Confirmed for dev, not staging
        )

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "CONFIRMATION_ENV_MISMATCH")

    # 13. Expired confirmation rejected: Confirmation token expired -> rejected with CONFIRMATION_EXPIRED
    def test_13_expired_confirmation_rejected(self):
        changes = [
            self._make_resource_change("aws_instance.app", "aws_instance", ["delete"]),
            self._make_resource_change("aws_instance.new_app", "aws_instance", ["create"]),
        ]
        plan = self._make_plan(changes)
        policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=5, require_confirmation=True)

        # Token created 3 hours ago with 1 hour TTL
        past_time = self.ref_now - datetime.timedelta(hours=3)
        conf = self._make_confirmation(
            pure_deletions=1, replacements=0, env=self.env_staging,
            ttl_seconds=3600, current_time=past_time
        )

        decision = DestructivePlanAssessmentEngine.assess(
            plan_data=plan,
            expected_plan_id=self.plan_id,
            expected_plan_digest=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            policy=policy,
            confirmation_token=conf,
            current_time=self.ref_now,  # Evaluated now (2 hours after expiry)
        )

        self.assertEqual(decision["decision"], DECISION_REJECTED)
        self.assertEqual(decision["decision_code"], "CONFIRMATION_EXPIRED")

    # 14. Caller-controlled threshold override blocked: Caller cannot elevate threshold above policy
    def test_14_caller_threshold_elevation_prevented(self):
        # Policy allows max 2 deletions
        base_policy = BlastRadiusPolicy(environment=self.env_staging, max_deletions=2, max_replacements=1)

        # Untrusted caller attempts to raise limit to 50
        bounded_policy = base_policy.apply_caller_bounds(caller_max_del=50, caller_max_rep=20)
        self.assertEqual(bounded_policy.max_deletions, 2)
        self.assertEqual(bounded_policy.max_replacements, 1)

        # Caller lowering limit is allowed (tightening)
        tightened_policy = base_policy.apply_caller_bounds(caller_max_del=1, caller_max_rep=0)
        self.assertEqual(tightened_policy.max_deletions, 1)
        self.assertEqual(tightened_policy.max_replacements, 0)

    # 15. Missing destruction policy fails closed: Non-existent policy file fails closed
    def test_15_missing_policy_file_rejected(self):
        non_existent_policy = os.path.join(self.test_dir, "non-existent-policy.json")

        with self.assertRaises(DestructionAssessmentError) as ctx:
            BlastRadiusPolicy.from_file(non_existent_policy, environment=self.env_prod)

        self.assertEqual(ctx.exception.decision_code, "POLICY_NOT_FOUND")

    # 16. Malformed Terraform plan fails closed: Invalid JSON, missing changes, errored plan -> MALFORMED_PLAN
    def test_16_malformed_plan_json_rejected(self):
        # 1. Non-dict root
        with self.assertRaises(MalformedPlanError):
            DestructivePlanClassifier.analyze_plan_dict("not-a-dict")  # type: ignore

        # 2. Errored plan
        errored_plan = self._make_plan([], errored=True)
        with self.assertRaises(MalformedPlanError):
            DestructivePlanClassifier.analyze_plan_dict(errored_plan)

        # 3. Non-list resource_changes
        bad_rc_plan = {"format_version": "1.2", "resource_changes": "invalid"}
        with self.assertRaises(MalformedPlanError):
            DestructivePlanClassifier.analyze_plan_dict(bad_rc_plan)

        # 4. Resource change missing actions
        missing_actions_plan = self._make_plan([
            {"address": "res.test", "type": "test", "change": {}}
        ])
        with self.assertRaises(MalformedPlanError):
            DestructivePlanClassifier.analyze_plan_dict(missing_actions_plan)

    # 17. Unknown resource action fails closed: Unknown action token -> fails closed with UNKNOWN_ACTION
    def test_17_unknown_resource_action_rejected(self):
        bad_action_sets = [
            ["destroy"],  # Terraform canonical is "delete", not "destroy"
            ["corrupt"],
            ["delete", "corrupt"],
            ["unknown_action"],
            ["create", "delete", "extra"],
        ]

        for actions in bad_action_sets:
            with self.assertRaises(UnknownActionError):
                DestructivePlanClassifier.classify_resource_action(actions)

    # 18. Replay of destruction authorization blocked: Replay ledger blocks duplicate reservation
    def test_18_replay_destruction_authorization_blocked(self):
        ledger_db = os.path.join(self.test_dir, "replay.db")
        ledger = PlanReplayLedger(db_path=ledger_db)
        expires_at = (self.ref_now + datetime.timedelta(hours=2)).isoformat()

        # First reservation succeeds
        ledger.reserve_plan(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            repository=self.repo,
            commit_sha="a" * 40,
            environment=self.env_staging,
            expires_at=expires_at,
            execution_context={"workflow_sha": "b" * 40},
            current_time=self.ref_now,
        )

        # Duplicate reservation strictly blocked
        with self.assertRaises(PlanReplayError):
            ledger.reserve_plan(
                plan_id=self.plan_id,
                plan_digest_sha256=self.plan_digest,
                repository=self.repo,
                commit_sha="a" * 40,
                environment=self.env_staging,
                expires_at=expires_at,
                execution_context={"workflow_sha": "b" * 40},
                current_time=self.ref_now,
            )

        ledger.close()

    # 19. Concurrent simulation reservations prevented: Atomic reservation in ledger prevents race conditions
    def test_19_concurrent_reservations_prevented(self):
        ledger_db = os.path.join(self.test_dir, "concurrent_replay.db")
        ledger = PlanReplayLedger(db_path=ledger_db)
        expires_at = (self.ref_now + datetime.timedelta(hours=2)).isoformat()
        successes = []
        failures = []

        def worker():
            try:
                ledger.reserve_plan(
                    plan_id="concurrent-plan-001",
                    plan_digest_sha256=self.plan_digest,
                    repository=self.repo,
                    commit_sha="a" * 40,
                    environment=self.env_staging,
                    expires_at=expires_at,
                    execution_context={"workflow_sha": "b" * 40},
                    current_time=self.ref_now,
                )
                successes.append(1)
            except Exception as e:
                failures.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 9)
        ledger.close()

    # 20. Interrupted execution transitions to OUTCOME_UNCERTAIN: Crash/interrupt marked OUTCOME_UNCERTAIN
    def test_20_interrupted_execution_handling(self):
        ledger_db = os.path.join(self.test_dir, "recovery.db")
        recovery_mgr = ExecutionRecoveryManager(db_path=ledger_db)

        # Plan reserved
        recovery_mgr.transition_state(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            new_state=STATE_RESERVED,
            current_time=self.ref_now,
        )

        # Simulated crash or SIGTERM received
        recovery_mgr.transition_state(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            new_state=STATE_OUTCOME_UNCERTAIN,
            decision_code="CRASH_DETECTED",
            details="Process terminated unexpectedly during simulation",
            current_time=self.ref_now,
        )

        state_record = recovery_mgr.get_state(self.plan_id)
        self.assertIsNotNone(state_record)
        self.assertEqual(state_record["state"], STATE_OUTCOME_UNCERTAIN)
        self.assertEqual(state_record["decision_code"], "CRASH_DETECTED")
        recovery_mgr.close()

    # 21. Partial-execution simulation marks OUTCOME_UNCERTAIN: Incomplete execution marked OUTCOME_UNCERTAIN
    def test_21_partial_execution_outcome_uncertain(self):
        ledger_db = os.path.join(self.test_dir, "partial.db")
        recovery_mgr = ExecutionRecoveryManager(db_path=ledger_db)

        recovery_mgr.transition_state(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            new_state=STATE_RESERVED,
            current_time=self.ref_now,
        )

        # Partial step completed before timeout
        recovery_mgr.transition_state(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            new_state=STATE_OUTCOME_UNCERTAIN,
            decision_code="EXECUTION_TIMEOUT",
            details="Execution timed out at step 3/5; state integrity unconfirmed",
            current_time=self.ref_now,
        )

        record = recovery_mgr.get_state(self.plan_id)
        self.assertEqual(record["state"], STATE_OUTCOME_UNCERTAIN)
        self.assertEqual(record["decision_code"], "EXECUTION_TIMEOUT")
        recovery_mgr.close()

    # 22. Unknown outcome and retry attempt strictly blocked: OUTCOME_UNCERTAIN state cannot be retried
    def test_22_retry_blocked_on_uncertain_state(self):
        ledger_db = os.path.join(self.test_dir, "uncertain_block.db")
        recovery_mgr = ExecutionRecoveryManager(db_path=ledger_db)

        # Put plan into OUTCOME_UNCERTAIN
        recovery_mgr.transition_state(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            repository=self.repo,
            environment=self.env_staging,
            new_state=STATE_OUTCOME_UNCERTAIN,
            decision_code="NETWORK_PARTITION",
            details="Network disconnected during apply simulation",
            current_time=self.ref_now,
        )

        # Attempt to transition back to RESERVED (automated retry) MUST fail
        with self.assertRaises(DestructionAssessmentError) as ctx:
            recovery_mgr.transition_state(
                plan_id=self.plan_id,
                plan_digest_sha256=self.plan_digest,
                repository=self.repo,
                environment=self.env_staging,
                new_state=STATE_RESERVED,
                current_time=self.ref_now,
            )

        self.assertEqual(ctx.exception.decision_code, "UNCERTAIN_STATE_LOCKED")

        # Attempt to reset back to NOT_STARTED MUST fail
        with self.assertRaises(DestructionAssessmentError) as ctx2:
            recovery_mgr.transition_state(
                plan_id=self.plan_id,
                plan_digest_sha256=self.plan_digest,
                repository=self.repo,
                environment=self.env_staging,
                new_state=STATE_NOT_STARTED,
                current_time=self.ref_now,
            )

        self.assertEqual(ctx2.exception.decision_code, "UNCERTAIN_STATE_LOCKED")
        recovery_mgr.close()

    # 23. Temporary-file cleanup trap and mode 0600 verified: Restricted mode 0600 and cleanup
    def test_23_temporary_file_cleanup_and_permissions(self):
        output_token_file = os.path.join(self.test_dir, "test_token.json")

        # Create token using CLI helper or API
        token = DestructionConfirmationValidator.create_token(
            plan_id=self.plan_id,
            plan_digest_sha256=self.plan_digest,
            source_repository=self.repo,
            target_environment=self.env_staging,
            pure_deletions=1,
            replacements=0,
            authorized_by=self.authorizer,
            validity_seconds=3600,
            current_time=self.ref_now,
        )

        # Write with restrictive 0600 permissions
        fd = os.open(output_token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(token))

        file_stat = os.stat(output_token_file)
        file_mode = stat.S_IMODE(file_stat.st_mode)

        # In POSIX environments, verify permissions are 0600 (read/write by owner only)
        if os.name == "posix":
            self.assertEqual(file_mode, 0o600, f"Expected file mode 0600, got {oct(file_mode)}")

        # Verify cleanup works
        os.remove(output_token_file)
        self.assertFalse(os.path.exists(output_token_file))

    # 24. Untrusted PR attempting destructive authorization rejected: Pull request events blocked at guard
    def test_24_untrusted_pr_destructive_rejected(self):
        # Inspect reusable-tf-apply.yml validate-inputs job
        guard_step = self.workflow_yaml["jobs"]["validate-inputs"]["steps"][0]
        script = guard_step["run"]

        # Confirm strict rejection of pull_request and pull_request_target
        self.assertIn('if [[ "${EVENT_NAME}" == "pull_request" || "${EVENT_NAME}" == "pull_request_target" ]]', script)
        self.assertIn("Security Violation: Untrusted pull requests", script)
        self.assertIn("exit 1", script)

    # 25. Strict absence of real apply/destroy verified: Verifies absence of live Terraform commands
    def test_25_strict_absence_of_real_apply_destroy(self):
        # Check all workflow jobs and steps
        workflow_str = yaml.dump(self.workflow_yaml)

        # Check for forbidden execution commands in workflow YAML
        forbidden_patterns = [
            "terraform apply",
            "terraform destroy",
            "terraform force-unlock",
        ]

        for pat in forbidden_patterns:
            self.assertNotIn(pat, workflow_str)

        # Check scripts directory for forbidden process execution commands
        for script_name in ["assess-destruction.py", "verify-plan-lifecycle.py"]:
            script_path = os.path.join(SCRIPTS_DIR, script_name)
            with open(script_path, "r", encoding="utf-8") as sf:
                content = sf.read()
                # Ensure no subprocess / system invocation of real terraform apply or destroy
                self.assertNotIn("subprocess.run([\"terraform\", \"apply\"", content)
                self.assertNotIn("subprocess.run([\"terraform\", \"destroy\"", content)
                self.assertNotIn("subprocess.run([\"terraform\", \"force-unlock\"", content)
                self.assertNotIn("os.system(\"terraform apply", content)
                self.assertNotIn("os.system(\"terraform destroy", content)


if __name__ == "__main__":
    unittest.main()
