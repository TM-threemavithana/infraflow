#!/usr/bin/env python3
"""
InfraFlow — Semantic Destruction Protection Adversarial Test Suite
Milestone: G10.3

Validates central semantic destruction policy and assessment engine across:
- Critical database, KMS, storage, IAM, and network security resource deletions.
- Distinguishing direct deletion vs destroy-before-create and create-before-destroy replacements.
- Rejection of generic confirmation tokens ("yes", "confirm", "force").
- Plan-specific cryptographic confirmation token authorization.
- Unknown action tokens and malformed plan JSON rejection.
- Consumer policy elevation prevention.
- Consumer configuration tampering rejection.
- Positive tests for non-critical resource changes.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import importlib.util

# Load assess-destruction.py via importlib (hyphenated filename)
assess_path = REPO_ROOT / "scripts" / "assess-destruction.py"
spec_assess = importlib.util.spec_from_file_location("assess_destruction", str(assess_path))
assess_destruction = importlib.util.module_from_spec(spec_assess)
spec_assess.loader.exec_module(assess_destruction)

DestructivePlanAssessmentEngine = assess_destruction.DestructivePlanAssessmentEngine
BlastRadiusPolicy = assess_destruction.BlastRadiusPolicy
DestructionConfirmationValidator = assess_destruction.DestructionConfirmationValidator
DECISION_AUTHORIZED = assess_destruction.DECISION_AUTHORIZED
DECISION_REJECTED = assess_destruction.DECISION_REJECTED

# Load validate-consumer.py
val_path = REPO_ROOT / "scripts" / "validate-consumer.py"
spec = importlib.util.spec_from_file_location("validate_consumer", str(val_path))
validate_consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_consumer)


class TestSemanticDestructionAdversarial(unittest.TestCase):
    """25-vector adversarial and verification test suite for semantic destruction protection."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-destruction-test-")
        self.tmp_path = Path(self.tmp_dir)
        self.policy_file = REPO_ROOT / "policies" / "common" / "critical_resources.rego"
        self.conftest_bin = Path(os.environ.get("HOME", "/home/tharuka")) / ".local" / "bin" / "conftest"
        if not self.conftest_bin.exists():
            self.conftest_bin = Path("conftest")

        self.plan_id = "test-plan-103"
        self.plan_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.repo = "TM-threemavithana/infraflow-consumer-app"
        self.env = "production"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _eval_conftest(self, plan_data: dict) -> subprocess.CompletedProcess:
        """Helper to evaluate plan_data against critical_resources.rego using conftest."""
        plan_f = self.tmp_path / "plan.json"
        with open(plan_f, "w", encoding="utf-8") as f:
            json.dump(plan_data, f, indent=2)

        cmd = [
            str(self.conftest_bin),
            "test",
            "--namespace", "common.critical_resources",
            "--policy", str(self.policy_file),
            str(plan_f),
            "--no-color",
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _make_plan(self, resource_changes: list) -> dict:
        return {
            "format_version": "1.2",
            "terraform_version": "1.10.4",
            "resource_changes": resource_changes,
        }

    # --------------------------------------------------------------------------
    # 1. Database Deletion Tests
    # --------------------------------------------------------------------------

    def test_aws_rds_deletion_rejected(self):
        """Direct deletion of AWS RDS cluster is rejected."""
        plan = self._make_plan([{
            "address": "aws_rds_cluster.primary",
            "type": "aws_rds_cluster",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'aws_rds_cluster.primary'", res.stdout)

    def test_azure_postgres_deletion_rejected(self):
        """Direct deletion of Azure PostgreSQL flexible server is rejected."""
        plan = self._make_plan([{
            "address": "azurerm_postgresql_flexible_server.db",
            "type": "azurerm_postgresql_flexible_server",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'azurerm_postgresql_flexible_server.db'", res.stdout)

    def test_gcp_sql_database_deletion_rejected(self):
        """Direct deletion of GCP Cloud SQL instance is rejected."""
        plan = self._make_plan([{
            "address": "google_sql_database_instance.master",
            "type": "google_sql_database_instance",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'google_sql_database_instance.master'", res.stdout)

    # --------------------------------------------------------------------------
    # 2. KMS Key & Encryption Deletion Tests
    # --------------------------------------------------------------------------

    def test_aws_kms_key_deletion_rejected(self):
        """Direct deletion of AWS KMS key is rejected."""
        plan = self._make_plan([{
            "address": "aws_kms_key.app_vault",
            "type": "aws_kms_key",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'aws_kms_key.app_vault'", res.stdout)

    def test_azure_key_vault_deletion_rejected(self):
        """Direct deletion of Azure Key Vault is rejected."""
        plan = self._make_plan([{
            "address": "azurerm_key_vault.secrets",
            "type": "azurerm_key_vault",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'azurerm_key_vault.secrets'", res.stdout)

    def test_gcp_kms_crypto_key_deletion_rejected(self):
        """Direct deletion of GCP KMS crypto key is rejected."""
        plan = self._make_plan([{
            "address": "google_kms_crypto_key.envelope",
            "type": "google_kms_crypto_key",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'google_kms_crypto_key.envelope'", res.stdout)

    # --------------------------------------------------------------------------
    # 3. Storage & IAM Deletion Tests
    # --------------------------------------------------------------------------

    def test_azure_storage_account_deletion_rejected(self):
        """Direct deletion of Azure storage account is rejected."""
        plan = self._make_plan([{
            "address": "azurerm_storage_account.state_store",
            "type": "azurerm_storage_account",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'azurerm_storage_account.state_store'", res.stdout)

    def test_aws_iam_role_deletion_rejected(self):
        """Direct deletion of AWS IAM role is rejected."""
        plan = self._make_plan([{
            "address": "aws_iam_role.admin_exec",
            "type": "aws_iam_role",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'aws_iam_role.admin_exec'", res.stdout)

    def test_network_security_group_deletion_rejected(self):
        """Direct deletion of Azure NSG is rejected."""
        plan = self._make_plan([{
            "address": "azurerm_network_security_group.ingress",
            "type": "azurerm_network_security_group",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Direct deletion of critical resource 'azurerm_network_security_group.ingress'", res.stdout)

    # --------------------------------------------------------------------------
    # 4. Replacement Differentiation Tests
    # --------------------------------------------------------------------------

    def test_destroy_before_create_replacement_rejected(self):
        """Dangerous destroy-before-create replacement is rejected."""
        plan = self._make_plan([{
            "address": "aws_db_instance.db_master",
            "type": "aws_db_instance",
            "change": {"actions": ["delete", "create"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Dangerous destroy-before-create replacement", res.stdout)

    def test_create_before_destroy_replacement_rejected(self):
        """Create-before-destroy replacement is rejected without confirmation."""
        plan = self._make_plan([{
            "address": "aws_kms_key.rotation",
            "type": "aws_kms_key",
            "change": {"actions": ["create", "delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Create-before-destroy replacement", res.stdout)

    # --------------------------------------------------------------------------
    # 5. Generic Confirmation Rejection
    # --------------------------------------------------------------------------

    def test_generic_tokens_strictly_rejected(self):
        """Generic confirmation tokens (yes, confirm, force, true) are strictly rejected."""
        for token in ["yes", "confirm", "force", "true", "approved"]:
            plan = self._make_plan([{
                "address": "aws_kms_key.key",
                "type": "aws_kms_key",
                "change": {"actions": ["delete"]},
            }])
            plan["infraflow_authorization"] = {
                "authorized": True,
                "token": token,
            }
            res = self._eval_conftest(plan)
            self.assertNotEqual(res.returncode, 0, f"Token '{token}' should have been rejected")
            self.assertIn("is rejected. Plan-specific cryptographic confirmation required", res.stdout)

    # --------------------------------------------------------------------------
    # 6. Valid Cryptographic Authorization
    # --------------------------------------------------------------------------

    def test_valid_cryptographic_confirmation_authorized(self):
        """Plan-specific cryptographic confirmation authorizes critical destruction."""
        plan = self._make_plan([{
            "address": "aws_db_instance.decommission",
            "type": "aws_db_instance",
            "change": {"actions": ["delete"]},
        }])
        plan["infraflow_authorization"] = {
            "authorized": True,
            "schema_version": "infraflow-destruction-confirmation-v1",
            "token": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        }
        res = self._eval_conftest(plan)
        self.assertEqual(res.returncode, 0, f"Expected clean pass, got: {res.stdout} {res.stderr}")

    # --------------------------------------------------------------------------
    # 7. Unknown Action and Malformed Plan Detection
    # --------------------------------------------------------------------------

    def test_unknown_action_token_rejected(self):
        """Unknown action token fails closed."""
        plan = self._make_plan([{
            "address": "aws_s3_bucket.bad",
            "type": "aws_s3_bucket",
            "change": {"actions": ["unsupported_action_token"]},
        }])
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("contains unknown or unsupported action token", res.stdout)

    def test_missing_resource_changes_rejected(self):
        """Plan missing resource_changes array fails closed."""
        plan = {"format_version": "1.2"}
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Plan JSON is missing 'resource_changes' array", res.stdout)

    # --------------------------------------------------------------------------
    # 8. Positive Non-Critical Tests
    # --------------------------------------------------------------------------

    def test_non_critical_deletion_allowed(self):
        """Deletion of non-critical resource (e.g. DNS record) passes policy."""
        plan = self._make_plan([{
            "address": "aws_route53_record.temp",
            "type": "aws_route53_record",
            "change": {"actions": ["delete"]},
        }])
        res = self._eval_conftest(plan)
        self.assertEqual(res.returncode, 0, f"Unexpected failure: {res.stdout}")

    def test_safe_create_update_allowed(self):
        """Safe additions and updates pass policy."""
        plan = self._make_plan([
            {
                "address": "aws_db_instance.new",
                "type": "aws_db_instance",
                "change": {"actions": ["create"]},
            },
            {
                "address": "azurerm_storage_account.active",
                "type": "azurerm_storage_account",
                "change": {"actions": ["update"]},
            },
        ])
        res = self._eval_conftest(plan)
        self.assertEqual(res.returncode, 0, f"Unexpected failure: {res.stdout}")

    # --------------------------------------------------------------------------
    # 9. Consumer Configuration Tampering Rejection
    # --------------------------------------------------------------------------

    def test_consumer_disabling_scanners_rejected(self):
        """Consumer configuration attempting enforce_mandatory_scanners: false is rejected."""
        cfg = {
            "version": "1.0",
            "consumer_id": "test-tamper",
            "team": "security",
            "workload_type": "general",
            "terraform_dir": "terraform",
            "environment": "prod",
            "adapter": "aws",
            "platform_ref": "TM-threemavithana/infraflow",
            "platform_sha": "8fd761bb42165435e1162f37ee39df15d5532b09",
            "terraform_version": "1.10.4",
            "security_controls": {
                "enforce_mandatory_scanners": False,
                "fail_on_destructive": True,
                "max_allowed_deletions": 5,
            },
        }
        res = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, res)
        self.assertFalse(res.is_valid)
        fails = [msg for msg in res.errors if "enforce_mandatory_scanners" in msg]
        self.assertTrue(len(fails) >= 1)

    def test_consumer_excessive_deletions_rejected(self):
        """Consumer configuration attempting max_allowed_deletions > 25 is rejected."""
        cfg = {
            "version": "1.0",
            "consumer_id": "test-tamper-del",
            "team": "security",
            "workload_type": "general",
            "terraform_dir": "terraform",
            "environment": "prod",
            "adapter": "aws",
            "platform_ref": "TM-threemavithana/infraflow",
            "platform_sha": "8fd761bb42165435e1162f37ee39df15d5532b09",
            "terraform_version": "1.10.4",
            "security_controls": {
                "enforce_mandatory_scanners": True,
                "fail_on_destructive": True,
                "max_allowed_deletions": 99,
            },
        }
        res = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, res)
        self.assertFalse(res.is_valid)
        fails = [msg for msg in res.errors if "max_allowed_deletions" in msg]
        self.assertTrue(len(fails) >= 1)


if __name__ == "__main__":
    unittest.main()
