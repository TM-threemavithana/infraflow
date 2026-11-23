#!/usr/bin/env python3
"""
InfraFlow Security Integration Assurance Test Suite (Milestone G10.3.1)

Validates end-to-end security integration across all consumer execution paths:
1. Mandatory secret scanning enforcement across AWS, Azure, GCP, and provider-neutral workflows.
2. Semantic critical destruction protection (critical_resources.rego) on actual Terraform plan JSON.
3. Rejection of unauthorized decommissioning (closing heuristic substring bypasses).
4. Platform-controlled, plan-bound destruction authorization.
5. Prevention of consumer policy weakening (enforce_mandatory_scanners, enable-policy-evaluation, enable-trivy).
6. Fail-closed behavior on scanner, OPA, or parser failures.
7. Zero raw secret leakage in logs, reports, or step summaries.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFTEST_BIN = shutil.which("conftest") or str(Path.home() / ".local" / "bin" / "conftest")
POLICIES_DIR = REPO_ROOT / "policies"
CRITICAL_REGO = POLICIES_DIR / "common" / "critical_resources.rego"
SCAN_SECRETS_PY = REPO_ROOT / "scripts" / "scan-secrets.py"
VALIDATE_CONSUMER_PY = REPO_ROOT / "scripts" / "validate-consumer.py"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


class TestSecurityIntegrationAssurance(unittest.TestCase):
    """End-to-end assurance tests for G10.3.1 security integration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="infraflow-g10-sec-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _eval_conftest(self, plan_data: dict, namespace: str = "common.critical_resources") -> subprocess.CompletedProcess:
        """Helper to evaluate Conftest against plan data."""
        plan_path = Path(self.temp_dir) / "plan.json"
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan_data, f)

        cmd = [
            CONFTEST_BIN,
            "test",
            "--namespace", namespace,
            "--policy", str(CRITICAL_REGO),
            str(plan_path),
            "--no-color",
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    # --------------------------------------------------------------------------
    # Positive Scenarios
    # --------------------------------------------------------------------------

    def test_safe_terraform_changes_pass(self):
        """Positive: Safe Terraform resource additions pass secret scan and OPA critical policy."""
        # 1. Clean directory passes secret scan
        main_tf = Path(self.temp_dir) / "main.tf"
        main_tf.write_text('resource "terraform_data" "safe" {\n  input = "clean_value"\n}\n')
        res_scan = subprocess.run(
            ["python3", str(SCAN_SECRETS_PY), "--target-dir", self.temp_dir, "--strict", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_scan.returncode, 0, f"Clean repo failed secret scan: {res_scan.stdout}")
        data = json.loads(res_scan.stdout)
        self.assertEqual(data.get("status"), "PASS")
        self.assertEqual(data.get("total_secrets_found"), 0)

        # 2. Plan creating new resource passes critical_resources policy
        safe_plan = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_db_instance.new_db",
                    "type": "aws_db_instance",
                    "change": {"actions": ["create"]},
                }
            ],
        }
        res_opa = self._eval_conftest(safe_plan)
        self.assertEqual(res_opa.returncode, 0, f"Safe plan creation rejected: {res_opa.stdout}")

    def test_non_critical_resource_updates_pass(self):
        """Positive: In-place update or deletion of non-critical resources (e.g. cloudwatch alarm) passes."""
        plan = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_cloudwatch_metric_alarm.cpu",
                    "type": "aws_cloudwatch_metric_alarm",
                    "change": {"actions": ["delete"]},
                },
                {
                    "address": "terraform_data.helper",
                    "type": "terraform_data",
                    "change": {"actions": ["update"]},
                },
            ],
        }
        res = self._eval_conftest(plan)
        self.assertEqual(res.returncode, 0, f"Non-critical change unexpectedly denied: {res.stdout}")

    def test_authorized_decommission_passes(self):
        """Positive: Decommissioning critical resource WITH valid plan-bound token is permitted."""
        plan = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.decommissioned_bucket",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["delete"]},
                }
            ],
            "infraflow_authorization": {
                "authorized": True,
                "schema_version": "infraflow-destruction-confirmation-v1",
                "token": "infraflow-valid-auth-token-hash-2026",
            },
        }
        res = self._eval_conftest(plan)
        self.assertEqual(res.returncode, 0, f"Authorized decommission rejected: {res.stdout}")

    def test_authorized_database_deletion_passes(self):
        """Positive: Production database deletion WITH valid platform token is permitted."""
        plan = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_db_instance.primary",
                    "type": "aws_db_instance",
                    "change": {"actions": ["delete"]},
                }
            ],
            "infraflow_authorization": {
                "authorized": True,
                "schema_version": "infraflow-destruction-confirmation-v1",
                "token": "dGhpcy1pcy1hLXZhbGlkLXBsYW4tc3BlY2lmaWMtdG9rZW4=",
            },
        }
        res = self._eval_conftest(plan)
        self.assertEqual(res.returncode, 0, f"Authorized DB deletion rejected: {res.stdout}")

    # --------------------------------------------------------------------------
    # Negative Scenarios: Critical Destruction & Decommissioning
    # --------------------------------------------------------------------------

    def test_database_deletion_rejected(self):
        """Negative: Direct database deletion without authorization is strictly blocked."""
        for db_type, address in [
            ("aws_db_instance", "aws_db_instance.primary"),
            ("azurerm_mssql_database", "azurerm_mssql_database.app_db"),
            ("google_sql_database_instance", "google_sql_database_instance.postgres"),
        ]:
            plan = {
                "format_version": "1.2",
                "resource_changes": [
                    {
                        "address": address,
                        "type": db_type,
                        "change": {"actions": ["delete"]},
                    }
                ],
            }
            res = self._eval_conftest(plan)
            self.assertNotEqual(res.returncode, 0, f"Expected {db_type} deletion to fail")
            self.assertIn("Direct deletion of critical resource", res.stdout)

    def test_kms_deletion_rejected(self):
        """Negative: Direct KMS key or key vault deletion without authorization is strictly blocked."""
        for kms_type, address in [
            ("aws_kms_key", "aws_kms_key.app_key"),
            ("azurerm_key_vault", "azurerm_key_vault.vault"),
            ("google_kms_crypto_key", "google_kms_crypto_key.key"),
        ]:
            plan = {
                "format_version": "1.2",
                "resource_changes": [
                    {
                        "address": address,
                        "type": kms_type,
                        "change": {"actions": ["delete"]},
                    }
                ],
            }
            res = self._eval_conftest(plan)
            self.assertNotEqual(res.returncode, 0, f"Expected {kms_type} deletion to fail")
            self.assertIn("Direct deletion of critical resource", res.stdout)

    def test_unauthorized_decommission_rejected(self):
        """Negative: Naming a resource 'decommission' without a token is strictly REJECTED (closes heuristic bypass)."""
        plan = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.decommissioned_bucket",
                    "type": "aws_s3_bucket",
                    "name": "decommissioned_bucket",
                    "change": {
                        "actions": ["delete"],
                        "before": {"bucket": "decommissioned-prod-data"},
                    },
                }
            ],
        }
        res = self._eval_conftest(plan)
        self.assertNotEqual(res.returncode, 0, "Unauthorized decommission unexpectedly succeeded")
        self.assertIn("Direct deletion of critical resource 'aws_s3_bucket.decommissioned_bucket'", res.stdout)

    def test_generic_tokens_rejected(self):
        """Negative: Trivial or generic approval tokens ('confirm', 'true', 'approved', 'force') are rejected."""
        for generic_token in ["confirm", "true", "yes", "approved", "force", "ok", "1"]:
            plan = {
                "format_version": "1.2",
                "resource_changes": [
                    {
                        "address": "aws_kms_key.master",
                        "type": "aws_kms_key",
                        "change": {"actions": ["delete"]},
                    }
                ],
                "infraflow_authorization": {
                    "authorized": True,
                    "schema_version": "infraflow-destruction-confirmation-v1",
                    "token": generic_token,
                },
            }
            res = self._eval_conftest(plan)
            self.assertNotEqual(res.returncode, 0, f"Generic token '{generic_token}' was accepted")
            self.assertIn("Generic confirmation token", res.stdout)

    def test_replacement_actions_rejected(self):
        """Negative: Destroy-before-create and create-before-destroy replacements on critical resources are rejected."""
        for actions, desc in [
            (["delete", "create"], "destroy-before-create"),
            (["create", "delete"], "create-before-destroy"),
        ]:
            plan = {
                "format_version": "1.2",
                "resource_changes": [
                    {
                        "address": "azurerm_key_vault.secrets",
                        "type": "azurerm_key_vault",
                        "change": {"actions": actions},
                    }
                ],
            }
            res = self._eval_conftest(plan)
            self.assertNotEqual(res.returncode, 0, f"Replacement {desc} was unexpectedly accepted")

    def test_opa_malformed_plan_blocks_execution(self):
        """Negative: Malformed plan JSON (null change, unknown action, missing resource_changes) fails closed."""
        # 1. Missing resource_changes
        res1 = self._eval_conftest({"format_version": "1.2"})
        self.assertNotEqual(res1.returncode, 0)
        self.assertIn("missing 'resource_changes' array", res1.stdout)

        # 2. Unknown action token
        res2 = self._eval_conftest({
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.test",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["obliterate"]},
                }
            ],
        })
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("unknown or unsupported action token 'obliterate'", res2.stdout)

    # --------------------------------------------------------------------------
    # Negative Scenarios: Consumer Policy Weakening & Scanner Bypasses
    # --------------------------------------------------------------------------

    def test_consumer_policy_weakening_rejected(self):
        """Negative: Setting enforce_mandatory_scanners: false is rejected by validate-consumer.py."""
        cfg_path = Path(self.temp_dir) / "infraflow.config.yaml"
        cfg_path.write_text("""version: "1.0"
consumer_id: "sec-bypass-test"
team: "unauthorized"
workload_type: "general"
terraform_dir: "terraform"
environment: "dev"
adapter: "aws"
platform_ref: "TM-threemavithana/infraflow"
platform_sha: "8fd761bb42165435e1162f37ee39df15d5532b09"
terraform_version: "1.10.4"
security_controls:
  enforce_mandatory_scanners: false
  fail_on_destructive: true
  max_allowed_deletions: 5
""")
        tf_dir = Path(self.temp_dir) / "terraform"
        tf_dir.mkdir(parents=True, exist_ok=True)
        (tf_dir / "main.tf").write_text('resource "terraform_data" "x" {}\n')

        res = subprocess.run(
            ["python3", str(VALIDATE_CONSUMER_PY), "--config", str(cfg_path), "--repo-dir", self.temp_dir],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("enforce_mandatory_scanners must be strictly", res.stdout)

    def test_workflow_guard_rejects_disabling_security(self):
        """Negative: Platform workflow guards reject disabling Trivy or OPA policy evaluation."""
        for wf_file in ["reusable-tf-plan.yml", "reusable-tf-aws.yml", "reusable-tf-azure.yml", "reusable-tf-gcp.yml", "reusable-tf-security.yml"]:
            wf_path = WORKFLOWS_DIR / wf_file
            content = wf_path.read_text(encoding="utf-8")
            # Guard must check ENABLE_POLICY_EVAL / ENABLE_TRIVY / ENABLE_CONFTEST
            self.assertTrue(
              "Disabling mandatory" in content,
              f"{wf_file} missing defensive input guard against disabling mandatory scanners"
            )

    # --------------------------------------------------------------------------
    # Secret Scanner Enforcement & Zero Leakage
    # --------------------------------------------------------------------------

    def test_secret_scanner_failure_blocks_execution(self):
        """Negative: Dirty consumer repo with real credentials causes scanner to exit 1."""
        dirty_file = Path(self.temp_dir) / "creds.tf"
        dirty_file.write_text('provider "aws" {\n  access_key = "AKIAIOSFODNN7MINEKEY"\n}\n')
        res = subprocess.run(
            ["python3", str(SCAN_SECRETS_PY), "--target-dir", self.temp_dir, "--strict", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1, "Dirty repo did not trigger exit code 1")
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "FAIL")
        self.assertGreater(data.get("total_secrets_found"), 0)

    def test_secret_values_never_leak_in_reports(self):
        """Security Invariant: Detected credentials must never appear unredacted in outputs/reports."""
        raw_key = "AKIAIOSFODNN7MINEKEY"
        dirty_file = Path(self.temp_dir) / "secrets.tf"
        dirty_file.write_text(f'variable "aws_key" {{\n  default = "{raw_key}"\n}}\n')
        res = subprocess.run(
            ["python3", str(SCAN_SECRETS_PY), "--target-dir", self.temp_dir, "--strict", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertNotIn(raw_key, res.stdout, "Raw credential leaked into stdout JSON report!")
        self.assertIn("AKIA", res.stdout, "Rule prefix should be present for rule identification")
        self.assertIn("****", res.stdout, "Masking asterisks should conceal sensitive characters")

    # --------------------------------------------------------------------------
    # Cloud Adapter Enforcement Verification
    # --------------------------------------------------------------------------

    def test_cloud_adapter_secret_scan_enforcement(self):
        """Assurance: All reusable workflows declare and enforce mandatory secret scanning step."""
        required_workflows = [
            "reusable-tf-plan.yml",
            "reusable-tf-aws.yml",
            "reusable-tf-azure.yml",
            "reusable-tf-gcp.yml",
            "reusable-tf-security.yml",
            "reusable-tf-governance.yml",
        ]
        for wf_name in required_workflows:
            wf_path = WORKFLOWS_DIR / wf_name
            self.assertTrue(wf_path.is_file(), f"Workflow {wf_name} missing")
            content = wf_path.read_text(encoding="utf-8")
            self.assertIn("Execute Mandatory Consumer Secret Scanner", content, f"{wf_name} missing secret scanner step")
            self.assertIn("secret-scan-status", content, f"{wf_name} missing secret-scan-status output")

    def test_azure_and_gcp_use_all_namespaces(self):
        """Assurance: Azure and GCP adapters invoke Conftest with --all-namespaces to evaluate critical_resources."""
        for adapter in ["reusable-tf-azure.yml", "reusable-tf-gcp.yml"]:
            content = (WORKFLOWS_DIR / adapter).read_text(encoding="utf-8")
            self.assertIn("--all-namespaces", content, f"{adapter} missing --all-namespaces in Conftest invocation")


if __name__ == "__main__":
    unittest.main()
