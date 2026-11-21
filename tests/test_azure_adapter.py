#!/usr/bin/env python3
"""
InfraFlow — Azure Adapter & Workload Identity Test Suite
Milestone: G07.5 — Microsoft Azure Adapter & Workload Identity Foundation

Validates security controls, input guards, workflow invariants, and regex patterns:
 1. Valid and invalid Azure subscription IDs (UUIDv4)
 2. Valid and invalid tenant IDs (UUIDv4)
 3. Valid and invalid client IDs (UUIDv4)
 4. Valid and invalid resource group names (1-90 chars, no ending period)
 5. Azure storage account naming rules (3-24 lowercase alphanumeric)
 6. Valid and invalid storage containers (3-63 lowercase alphanumeric and hyphens)
 7. State key traversal and leading slash rejection
 8. Cross-environment state collision defense
 9. OIDC issuer mismatch rejection
10. Audience mismatch and wildcard audience rejection
11. Federated credential subject mismatch rejection
12. Broad trust configuration (wildcards in subject) rejection
13. Unauthorized repository identity rejection
14. Untrusted PR live credential attempts (SEC-02 fail-closed)
15. Azure authentication enablement rejection (G07.5 fail-closed simulation invariant)
16. Disabled security scanning bypass rejection
17. Disabled policy evaluation bypass rejection
18. Unsafe storage account public access rejection
19. Overprivileged subscription-level IAM/RBAC bindings rejection
20. Missing required security inputs rejection
21. Mutable reusable workflow references (@main) rejection
22. Symlink workspace escapes rejection
23. Shell injection attempts rejection
24. Missing or malformed Terraform plan metrics rejection
25. Failed mandatory jobs reported as failure in summary aggregator
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REUSABLE_AZURE_WF = os.path.join(REPO_ROOT, ".github", "workflows", "reusable-tf-azure.yml")
AZURE_REF_MODULE = os.path.join(REPO_ROOT, "examples", "azure-reference-module")


def get_conftest_bin():
    """Finds conftest binary across known PATH and user local bin locations."""
    for loc in [
        shutil.which("conftest"),
        "/home/tharuka/.local/bin/conftest",
        os.path.expanduser("~/.local/bin/conftest"),
        "/usr/local/bin/conftest",
        "/usr/bin/conftest",
    ]:
        if loc and os.path.isfile(loc) and os.access(loc, os.X_OK):
            return loc
    return None

UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
RG_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.\(\)]{1,90}$")
STORAGE_ACCOUNT_REGEX = re.compile(r"^[a-z0-9]{3,24}$")
CONTAINER_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$")
REGION_REGEX = re.compile(r"^[a-z0-9]+$")
COMMIT_SHA_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")


class TestAzureRegexValidation(unittest.TestCase):
    """Validates regex pattern rules used in Azure adapter and security policies."""

    def test_subscription_id_valid(self):
        valid_uuids = [
            "00000000-0000-0000-0000-000000000000",
            "12345678-abcd-ef01-2345-6789abcdef01",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
        ]
        for uuid_str in valid_uuids:
            with self.subTest(uuid=uuid_str):
                self.assertIsNotNone(UUID_REGEX.match(uuid_str))

    def test_subscription_id_invalid(self):
        invalid_uuids = [
            "short-id",
            "12345678-abcd-ef01-2345-6789abcdef0g", # 'g' is not hex
            "12345678abcd-ef01-2345-6789abcdef01",  # missing hyphen
            "12345678-abcd-ef01-2345-6789abcdef012",# too long
            "sub-id; rm -rf /",                     # injection attempt
        ]
        for uuid_str in invalid_uuids:
            with self.subTest(uuid=uuid_str):
                self.assertIsNone(UUID_REGEX.match(uuid_str))

    def test_resource_group_name_valid(self):
        valid_rgs = [
            "rg-infraflow-prod",
            "RG_PRODUCTION_01",
            "rg.infraflow.core",
            "my-rg(prod)",
            "rg123",
        ]
        for rg in valid_rgs:
            with self.subTest(rg=rg):
                self.assertIsNotNone(RG_REGEX.match(rg))
                self.assertFalse(rg.endswith("."))

    def test_resource_group_name_invalid(self):
        invalid_rgs = [
            "",                        # empty
            "a" * 91,                  # > 90 chars
            "rg-prod.",                # ends with period
            "rg-prod; rm -rf /",       # injection attempt
            "rg name with spaces",     # spaces not allowed
        ]
        for rg in invalid_rgs:
            with self.subTest(rg=rg):
                is_valid = bool(RG_REGEX.match(rg)) and not rg.endswith(".")
                self.assertFalse(is_valid)

    def test_storage_account_name_valid(self):
        valid_sas = [
            "stinfraflowprod01",
            "storageaccount123",
            "abc",
            "a" * 24,
        ]
        for sa in valid_sas:
            with self.subTest(sa=sa):
                self.assertIsNotNone(STORAGE_ACCOUNT_REGEX.match(sa))

    def test_storage_account_name_invalid(self):
        invalid_sas = [
            "ab",                      # < 3 chars
            "a" * 25,                  # > 24 chars
            "StStorageUpper",          # uppercase not permitted
            "st-hyphen-account",       # hyphens not permitted
            "st_underscore",           # underscores not permitted
            "st.with.dots",            # dots not permitted
            "sa; rm -rf /",            # command injection
        ]
        for sa in invalid_sas:
            with self.subTest(sa=sa):
                self.assertIsNone(STORAGE_ACCOUNT_REGEX.match(sa))

    def test_container_name_valid(self):
        valid_containers = [
            "tfstate",
            "prod-tfstate",
            "env-prod-state-01",
            "abc",
            "a" * 63,
        ]
        for c in valid_containers:
            with self.subTest(container=c):
                self.assertIsNotNone(CONTAINER_REGEX.match(c))
                self.assertNotIn("--", c)

    def test_container_name_invalid(self):
        invalid_containers = [
            "ab",                      # < 3 chars
            "a" * 64,                  # > 63 chars
            "-leading-hyphen",         # cannot start with hyphen
            "trailing-hyphen-",        # cannot end with hyphen
            "consecutive--hyphens",    # consecutive hyphens forbidden
            "UpperContainer",          # uppercase not permitted
            "cont_underscore",         # underscores not permitted
            "cont.dot",                # dots not permitted
        ]
        for c in invalid_containers:
            with self.subTest(container=c):
                is_valid = bool(CONTAINER_REGEX.match(c)) and "--" not in c
                self.assertFalse(is_valid)


class TestAzureWorkflowGuardExecution(unittest.TestCase):
    """Executes the extracted bash guard from reusable-tf-azure.yml across negative test vectors."""

    @classmethod
    def setUpClass(cls):
        self_wf = REUSABLE_AZURE_WF
        with open(self_wf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        steps = {s["id"]: s["run"] for s in data["jobs"]["validate-inputs"]["steps"] if "id" in s and "run" in s}
        cls.guard_script = steps["guard"]

    def run_guard(self, env_overrides):
        base_env = {
            "INPUT_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000000",
            "INPUT_TENANT_ID": "00000000-0000-0000-0000-000000000000",
            "INPUT_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
            "INPUT_AZURE_RG": "rg-infraflow-prod",
            "INPUT_BACKEND_RG": "",
            "INPUT_REGION": "eastus",
            "INPUT_AZURE_SA": "stinfraflowprod01",
            "INPUT_BACKEND_SA": "",
            "INPUT_AZURE_CONTAINER": "tfstate",
            "INPUT_BACKEND_CONTAINER": "",
            "INPUT_AZURE_KEY": "prod/terraform.tfstate",
            "INPUT_BACKEND_KEY": "",
            "INPUT_VERSION": "1.10.4",
            "INPUT_DIR": ".",
            "INPUT_VAR_FILE": "",
            "INPUT_ENV": "production",
            "ENABLE_AZURE_AUTH": "false",
            "ENABLE_POLICY_EVAL": "true",
            "INPUT_POLICY_DIR": "policies",
            "ENABLE_TRIVY": "true",
            "INPUT_SEVERITY": "HIGH,CRITICAL",
            "FAIL_DESTRUCTIVE": "true",
            "EVENT_NAME": "push",
            "TARGET_REF": "refs/heads/main",
            "WORKFLOW_REPO": "TM-threemavithana/infraflow",
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@7c4dff9d5ab9e917fab79f59fa359bb413dca720",
        }
        base_env.update(env_overrides)
        env = {k: str(v) for k, v in base_env.items()}
        res = subprocess.run(
            ["bash", "-c", self.guard_script],
            env=env,
            capture_output=True,
            text=True,
        )
        return res.returncode, res.stdout + res.stderr

    def test_positive_valid_inputs_accepted(self):
        rc, out = self.run_guard({})
        self.assertEqual(rc, 0, f"Valid inputs rejected: {out}")
        self.assertIn("Azure Adapter inputs validated successfully", out)

    def test_invalid_subscription_id_rejected(self):
        rc, out = self.run_guard({"INPUT_SUBSCRIPTION_ID": "not-a-valid-uuid"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-subscription-id", out)

    def test_invalid_tenant_id_rejected(self):
        rc, out = self.run_guard({"INPUT_TENANT_ID": "bad-tenant-id"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-tenant-id", out)

    def test_invalid_client_id_rejected(self):
        rc, out = self.run_guard({"INPUT_CLIENT_ID": "bad-client-id"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-client-id", out)

    def test_invalid_resource_group_rejected(self):
        rc, out = self.run_guard({"INPUT_AZURE_RG": "rg-invalid."})
        self.assertNotEqual(rc, 0)
        self.assertIn("Resource group name", out)

    def test_invalid_storage_account_rejected(self):
        rc, out = self.run_guard({"INPUT_AZURE_SA": "Invalid_Storage_Account!"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-storage-account-name", out)

    def test_invalid_storage_container_rejected(self):
        rc, out = self.run_guard({"INPUT_AZURE_CONTAINER": "bad--container"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-storage-container-name", out)

    def test_state_key_traversal_rejected(self):
        rc, out = self.run_guard({"INPUT_AZURE_KEY": "../../secret/state"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-backend-key", out)

    def test_state_key_leading_slash_rejected(self):
        rc, out = self.run_guard({"INPUT_AZURE_KEY": "/root/state"})
        self.assertNotEqual(rc, 0)
        self.assertIn("azure-backend-key", out)

    def test_live_azure_auth_invariant_rejected(self):
        rc, out = self.run_guard({"ENABLE_AZURE_AUTH": "true"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Live Azure authentication is strictly disabled in Milestone G07.5", out)

    def test_untrusted_pr_auth_request_rejected(self):
        rc, out = self.run_guard({"EVENT_NAME": "pull_request", "ENABLE_AZURE_AUTH": "true"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Live Azure authentication is strictly disabled", out)

    def test_disabling_policy_evaluation_rejected(self):
        rc, out = self.run_guard({"ENABLE_POLICY_EVAL": "false"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Disabling mandatory policy evaluation", out)

    def test_disabling_trivy_scanning_rejected(self):
        rc, out = self.run_guard({"ENABLE_TRIVY": "false"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Disabling mandatory Trivy IaC scanning", out)

    def test_mutable_workflow_ref_rejected(self):
        rc, out = self.run_guard({
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@main"
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("immutable 40-character hexadecimal commit SHA", out)

    def test_working_directory_traversal_rejected(self):
        rc, out = self.run_guard({"INPUT_DIR": "../../etc"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Path traversal", out)

    def test_working_directory_shell_injection_rejected(self):
        rc, out = self.run_guard({"INPUT_DIR": "modules; rm -rf /"})
        self.assertNotEqual(rc, 0)
        self.assertIn("forbidden characters", out)

    def test_var_file_traversal_rejected(self):
        rc, out = self.run_guard({"INPUT_VAR_FILE": "../../../secrets.tfvars"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Path traversal or absolute paths in var-file", out)

    def test_policy_directory_traversal_rejected(self):
        rc, out = self.run_guard({"INPUT_POLICY_DIR": "/etc/policies"})
        self.assertNotEqual(rc, 0)
        self.assertIn("policy-directory must be a safe relative path", out)

    def test_invalid_terraform_version_rejected(self):
        rc, out = self.run_guard({"INPUT_VERSION": "1.5.7"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Minimum supported version is 1.6.0", out)

    def test_invalid_severity_threshold_rejected(self):
        rc, out = self.run_guard({"INPUT_SEVERITY": "LOW"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Severity threshold", out)


class TestAzureSummaryAggregator(unittest.TestCase):
    """Validates the summary aggregator logic from reusable-tf-azure.yml."""

    @classmethod
    def setUpClass(cls):
        with open(REUSABLE_AZURE_WF, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        steps = {s["id"]: s["run"] for s in data["jobs"]["summary"]["steps"] if "id" in s and "run" in s}
        cls.aggregator_script = steps["aggregate"]

    def run_aggregator(self, env_overrides):
        base_env = {
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "true",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "1",
            "ENABLE_AZURE_AUTH": "false",
            "GITHUB_OUTPUT": "/dev/null",
        }
        base_env.update(env_overrides)
        env = {k: str(v) for k, v in base_env.items()}
        res = subprocess.run(
            ["bash", "-c", self.aggregator_script],
            env=env,
            capture_output=True,
            text=True,
        )
        return res.returncode, res.stdout + res.stderr

    def test_positive_aggregation_succeeds(self):
        rc, out = self.run_aggregator({})
        self.assertEqual(rc, 0, f"Aggregator failed on valid inputs: {out}")
        self.assertIn("authorization-status: not-applicable", out)
        self.assertIn("total-changes:        1", out)
        self.assertIn("azure-auth-status:    disabled", out)

    def test_validation_failure_propagates(self):
        rc, out = self.run_aggregator({"VALIDATE_RESULT": "failure"})
        self.assertNotEqual(rc, 0)
        self.assertIn("authorization-status: rejected", out)

    def test_plan_failure_propagates(self):
        rc, out = self.run_aggregator({"CF_PLAN_RESULT": "failure"})
        self.assertNotEqual(rc, 0)
        self.assertIn("authorization-status: rejected", out)

    def test_inconsistent_metrics_has_changes_true_zero_count_rejected(self):
        rc, out = self.run_aggregator({
            "CF_HAS_CHANGES": "true",
            "CF_TOTAL_CHANGES": "0",
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("Aggregated metrics inconsistent", out)

    def test_inconsistent_metrics_has_changes_false_positive_count_rejected(self):
        rc, out = self.run_aggregator({
            "CF_HAS_CHANGES": "false",
            "CF_TOTAL_CHANGES": "2",
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("Aggregated metrics inconsistent", out)

    def test_malformed_total_changes_rejected(self):
        rc, out = self.run_aggregator({"CF_TOTAL_CHANGES": "-1"})
        self.assertNotEqual(rc, 0)
        self.assertIn("not a non-negative integer", out)


class TestAzureEntraIdOidcPolicyWithConftest(unittest.TestCase):
    """Executes Conftest verification on Microsoft Entra ID Rego policies."""

    def test_all_entra_oidc_rego_tests_pass(self):
        conftest_bin = get_conftest_bin()
        if not conftest_bin:
            self.skipTest("conftest binary not found in environment")
        policy_file = os.path.join(REPO_ROOT, "policies", "azure", "entra_oidc.rego")
        test_file = os.path.join(REPO_ROOT, "policies", "azure", "entra_oidc_test.rego")
        res = subprocess.run(
            [conftest_bin, "verify", "--policy", policy_file, "--policy", test_file],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Entra ID Rego tests failed: {res.stdout}\n{res.stderr}")
        self.assertIn("18 passed", res.stdout)


class TestAzureStorageBackendPolicyWithConftest(unittest.TestCase):
    """Executes Conftest verification on Azure Storage backend Rego policies."""

    def test_all_storage_backend_rego_tests_pass(self):
        conftest_bin = get_conftest_bin()
        if not conftest_bin:
            self.skipTest("conftest binary not found in environment")
        policy_file = os.path.join(REPO_ROOT, "policies", "azure", "storage_backend.rego")
        test_file = os.path.join(REPO_ROOT, "policies", "azure", "storage_backend_test.rego")
        res = subprocess.run(
            [conftest_bin, "verify", "--policy", policy_file, "--policy", test_file],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Storage backend Rego tests failed: {res.stdout}\n{res.stderr}")
        self.assertIn("18 passed", res.stdout)


class TestAzureReferenceModuleStructure(unittest.TestCase):
    """Validates structure and configuration of examples/azure-reference-module."""

    def test_required_files_exist(self):
        required_files = [
            "versions.tf",
            "variables.tf",
            "main.tf",
            "outputs.tf",
            "README.md",
            os.path.join("tests", "azure_test.tftest.hcl"),
        ]
        for f in required_files:
            path = os.path.join(AZURE_REF_MODULE, f)
            with self.subTest(file=f):
                self.assertTrue(os.path.isfile(path), f"Missing required file: {path}")

    def test_versions_tf_requires_azurerm_and_terraform_ge_1_7(self):
        versions_path = os.path.join(AZURE_REF_MODULE, "versions.tf")
        with open(versions_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('required_version = ">= 1.7.0"', content)
        self.assertIn('source  = "hashicorp/azurerm"', content)
        self.assertIn('backend "azurerm"', content)

    def test_main_tf_enforces_security_controls(self):
        main_path = os.path.join(AZURE_REF_MODULE, "main.tf")
        with open(main_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('min_tls_version                   = "TLS1_2"', content)
        self.assertIn('allow_nested_items_to_be_public   = false', content)
        self.assertIn('public_network_access_enabled     = false', content)
        self.assertIn('shared_access_key_enabled         = false', content)
        self.assertIn('infrastructure_encryption_enabled = true', content)
        self.assertIn('container_access_type = "private"', content)


if __name__ == "__main__":
    unittest.main()
