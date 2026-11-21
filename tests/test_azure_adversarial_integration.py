#!/usr/bin/env python3
"""
InfraFlow — Azure Adapter Adversarial Integration Test Suite
Milestone: G07.6 — Azure Adapter Security Hardening and Offline Validation

Comprehensive 45-vector adversarial test suite evaluating the Microsoft Azure
Cloud Adapter, Microsoft Entra ID Workload Identity Federation (OIDC) policies,
Azure Blob Storage backend controls, and reusable workflow security gates.

Vectors Covered:
 1. Valid synthetic Azure configuration (positive control)
 2. Invalid subscription ID (regex violations, hex errors, length, injection)
 3. Invalid tenant ID (malformed GUID format)
 4. Invalid client ID (malformed GUID format)
 5. Invalid resource group name (ends with period, length > 90, forbidden characters)
 6. Invalid storage account name (uppercase, dashes, underscores, length < 3 or > 24)
 7. Invalid storage container name (consecutive dashes, uppercase, underscores, start/end with dash)
 8. State blob key traversal (leading slash, .., backslashes)
 9. Cross-environment state collision defense (missing environment namespace)
10. Wildcard audience in federated identity credential
11. Disallowed / non-AzureADTokenExchange audience
12. Untrusted OIDC issuer (not https://token.actions.githubusercontent.com)
13. Wildcard subject in federated credential
14. Untrusted pull request event attempting credentials (SEC-02 fail-closed)
15. Malformed subject format (not matching branch, tag, env, or immutable repo-id)
16. Missing parent identity binding (parent_id empty in azurerm_federated_identity_credential)
17. Repository identity substitution (expected_repository mismatch)
18. Repository ID substitution (expected_repository_id mismatch)
19. Flexible federated identity credential (custom claims block) rejected
20. Overprivileged subscription-level Owner or Contributor role assignment
21. Resource-group scoped least-privilege role assignment allowed (positive control)
22. Storage account missing use_azuread_auth = true
23. Storage backend with use_oidc = true alone without use_azuread_auth = true rejected
24. Storage account with static access_key rejected
25. Storage account with static sas_token rejected
26. Storage account allowing public blob access (allow_nested_items_to_be_public = true) rejected
27. Container with public access (container_access_type != private) rejected
28. Insecure TLS version (min_tls_version < TLS1_2) rejected
29. Unrestricted public network access without Deny rule rejected
30. Storage account enabling shared access keys (shared_access_key_enabled = true) rejected
31. Storage account housing state missing blob versioning rejected
32. Overprivileged Owner/Contributor role on storage account scope rejected
33. Mutable reusable workflow reference (@main instead of 40-char SHA) rejected
34. Attempted Azure authentication enablement (enable-azure-auth: true fail-closed) rejected
35. Attempted bypass of mandatory policy evaluation (enable-policy-evaluation: false) rejected
36. Attempted bypass of mandatory Trivy IaC scan (enable-trivy: false) rejected
37. Unauthorized security severity threshold (CRITICAL alone or LOW or MEDIUM) rejected
38. Reusable workflow rogue repository origin rejected (WORKFLOW_REPO != TM-threemavithana/infraflow)
39. Mutable / non-40-hex WORKFLOW_SHA rejected
40. Working directory path traversal (.., absolute path, home directory ~) rejected
41. Var-file path traversal rejected
42. Destructive changes gate evaluation (fail-on-destructive: true with destructive changes)
43. Summary aggregator fail-closed when validate-inputs fails
44. Summary aggregator fail-closed when plan metrics inconsistent (has-changes: true, total-changes: 0)
45. Plan cleanup trap ensures plan-metrics.json cleanup

Invariants:
- Zero cloud spend ($0.00).
- Zero live cloud credentials required.
- Fully offline simulation-only validation.
- Fail-closed security architecture.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REUSABLE_AZURE_WF = os.path.join(REPO_ROOT, ".github", "workflows", "reusable-tf-azure.yml")
ENTRA_POLICY = os.path.join(REPO_ROOT, "policies", "azure", "entra_oidc.rego")
STORAGE_POLICY = os.path.join(REPO_ROOT, "policies", "azure", "storage_backend.rego")


def get_conftest_bin():
    """Finds conftest binary across known PATH and user local bin locations."""
    candidates = [
        shutil.which("conftest"),
        "/home/tharuka/.local/bin/conftest",
        os.path.expanduser("~/.local/bin/conftest"),
        "/usr/local/bin/conftest",
        "/usr/bin/conftest",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise RuntimeError("conftest binary not found in environment")


def run_conftest_eval(policy_path, namespace, input_dict):
    """Executes Conftest policy evaluation against in-memory dictionary payload."""
    conftest_bin = get_conftest_bin()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(input_dict, f)
        tmp_path = f.name

    try:
        cmd = [conftest_bin, "test", "--namespace", namespace, "--policy", policy_path, "--no-color", tmp_path]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode, res.stdout + res.stderr
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


class AzureAdversarialTestBase(unittest.TestCase):
    """Base class extracting workflow step scripts and configuring default test harness."""

    @classmethod
    def setUpClass(cls):
        with open(REUSABLE_AZURE_WF, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Extract guard step from validate-inputs job
        val_steps = {s["id"]: s["run"] for s in data["jobs"]["validate-inputs"]["steps"] if "id" in s and "run" in s}
        cls.guard_script = val_steps["guard"]

        # Extract verify_workspace step from cloud-free-plan job
        cf_steps = {s["id"]: s["run"] for s in data["jobs"]["cloud-free-plan"]["steps"] if "id" in s and "run" in s}
        cls.verify_workspace_script = cf_steps.get("verify_workspace", "")

        # Extract summary aggregation step
        sum_steps = {s["id"]: s["run"] for s in data["jobs"]["summary"]["steps"] if "id" in s and "run" in s}
        cls.summary_script = sum_steps["aggregate"]

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
            "WORKFLOW_SHA": "7c4dff9d5ab9e917fab79f59fa359bb413dca720",
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@7c4dff9d5ab9e917fab79f59fa359bb413dca720",
        }
        base_env.update(env_overrides)
        env = {k: str(v) for k, v in base_env.items()}
        res = subprocess.run(
            ["bash", "-c", self.guard_script],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return res.returncode, res.stdout + res.stderr

    def run_aggregator(self, env_overrides):
        with tempfile.NamedTemporaryFile("w", delete=False) as out_f:
            github_output_path = out_f.name

        base_env = {
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "true",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "3",
            "ENABLE_AZURE_AUTH": "false",
            "GITHUB_OUTPUT": github_output_path,
        }
        base_env.update(env_overrides)
        env = {k: str(v) for k, v in base_env.items()}
        try:
            res = subprocess.run(
                ["bash", "-c", self.summary_script],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            out_content = ""
            if os.path.exists(github_output_path):
                with open(github_output_path, "r", encoding="utf-8") as f:
                    out_content = f.read()
            return res.returncode, res.stdout + res.stderr + "\n" + out_content
        finally:
            if os.path.exists(github_output_path):
                os.unlink(github_output_path)


class TestAzureAdversarialIdentityAndOIDC(AzureAdversarialTestBase):
    """Adversarial Vectors 1 through 21: Identity, Entra ID, OIDC Trust Boundary & Input Guards."""

    def test_vector_01_valid_synthetic_azure_config(self):
        """Vector 1: Valid synthetic Azure configuration (positive control)."""
        rc, out = self.run_guard({})
        self.assertEqual(rc, 0, f"Valid synthetic configuration rejected: {out}")
        self.assertIn("Azure Adapter inputs validated successfully", out)

    def test_vector_02_invalid_subscription_id(self):
        """Vector 2: Invalid subscription ID (regex violations, hex errors, length, injection)."""
        bad_subs = [
            "short-id",
            "00000000-0000-0000-0000-00000000000g",  # 'g' is not hex
            "000000000000-0000-0000-000000000000",   # bad hyphen layout
            "00000000-0000-0000-0000-0000000000001", # too long
            "00000000-0000-0000-0000-000000000000; rm -rf /", # command injection
        ]
        for sub in bad_subs:
            with self.subTest(subscription_id=sub):
                rc, out = self.run_guard({"INPUT_SUBSCRIPTION_ID": sub})
                self.assertNotEqual(rc, 0)
                self.assertIn("azure-subscription-id", out)

    def test_vector_03_invalid_tenant_id(self):
        """Vector 3: Invalid tenant ID (malformed GUID format)."""
        bad_tenants = [
            "invalid-tenant-guid",
            "12345678-1234-1234-1234-12345678901z",
            "12345678-1234-1234-1234",
        ]
        for tid in bad_tenants:
            with self.subTest(tenant_id=tid):
                rc, out = self.run_guard({"INPUT_TENANT_ID": tid})
                self.assertNotEqual(rc, 0)
                self.assertIn("azure-tenant-id", out)

    def test_vector_04_invalid_client_id(self):
        """Vector 4: Invalid client ID (malformed GUID format)."""
        bad_clients = [
            "invalid-client-guid",
            "not-a-guid",
            "11111111-2222-3333-4444-55555555555G",
        ]
        for cid in bad_clients:
            with self.subTest(client_id=cid):
                rc, out = self.run_guard({"INPUT_CLIENT_ID": cid})
                self.assertNotEqual(rc, 0)
                self.assertIn("azure-client-id", out)

    def test_vector_05_invalid_resource_group_name(self):
        """Vector 5: Invalid resource group name (ends with period, length > 90, forbidden characters)."""
        bad_rgs = [
            "rg-infraflow.",            # cannot end with dot
            "rg" + ("a" * 90),          # > 90 chars
            "rg@infraflow",             # @ forbidden
            "rg; rm -rf /",             # command injection
        ]
        for rg in bad_rgs:
            with self.subTest(rg=rg):
                rc, out = self.run_guard({"INPUT_AZURE_RG": rg})
                self.assertNotEqual(rc, 0)
                self.assertIn("Resource group name", out)

    def test_vector_06_invalid_storage_account_name(self):
        """Vector 6: Invalid storage account name (uppercase, dashes, underscores, length < 3 or > 24)."""
        bad_sas = [
            "st",                       # length < 3
            "st" + ("a" * 23),          # length > 24
            "Stinfraflowprod01",        # uppercase forbidden
            "st-infraflow-prod",        # hyphens forbidden
            "st_infraflow_prod",        # underscores forbidden
            "sa; injection",            # injection
        ]
        for sa in bad_sas:
            with self.subTest(sa=sa):
                rc, out = self.run_guard({"INPUT_AZURE_SA": sa})
                self.assertNotEqual(rc, 0)
                self.assertIn("azure-storage-account-name", out)

    def test_vector_07_invalid_storage_container_name(self):
        """Vector 7: Invalid storage container name (consecutive dashes, uppercase, underscores, start/end with dash)."""
        bad_containers = [
            "-tfstate",                 # starts with hyphen
            "tfstate-",                 # ends with hyphen
            "bad--container",           # consecutive hyphens
            "Tfstate",                  # uppercase
            "tf_state",                 # underscores forbidden
            "c" * 64,                   # > 63 chars
            "aa",                       # < 3 chars
        ]
        for c in bad_containers:
            with self.subTest(container=c):
                rc, out = self.run_guard({"INPUT_AZURE_CONTAINER": c})
                self.assertNotEqual(rc, 0)
                self.assertIn("azure-storage-container-name", out)

    def test_vector_08_state_blob_key_traversal(self):
        """Vector 8: State blob key traversal (leading slash, .., backslashes)."""
        bad_keys = [
            "/prod/terraform.tfstate",
            "../terraform.tfstate",
            "prod/../../secret.tfstate",
            "prod\\terraform.tfstate",
        ]
        for key in bad_keys:
            with self.subTest(key=key):
                rc, out = self.run_guard({"INPUT_AZURE_KEY": key})
                self.assertNotEqual(rc, 0)
                self.assertIn("azure-backend-key", out)

    def test_vector_09_cross_environment_state_collision_defense(self):
        """Vector 9: Cross-environment state collision defense (missing environment namespace)."""
        payload = {
            "backend": {
                "azurerm": {
                    "storage_account_name": "stinfraflowprod01",
                    "resource_group_name": "rg-infraflow",
                    "container_name": "tfstate",
                    "key": "terraform.tfstate",  # Missing environment prefix!
                    "use_azuread_auth": True,
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must include an environment namespace", out)

    def test_vector_10_wildcard_audience(self):
        """Vector 10: Wildcard audience in federated identity credential (* rejected)."""
        payload = {
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["*"],
                "subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must not permit wildcard '*' audience", out)

    def test_vector_11_disallowed_audience(self):
        """Vector 11: Disallowed / non-AzureADTokenExchange audience."""
        payload = {
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["api://CustomTokenExchange"],
                "subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must strictly be 'api://AzureADTokenExchange'", out)

    def test_vector_12_untrusted_oidc_issuer(self):
        """Vector 12: Untrusted OIDC issuer (not https://token.actions.githubusercontent.com)."""
        payload = {
            "credential": {
                "issuer": "https://evil-untrusted-issuer.com",
                "audiences": ["api://AzureADTokenExchange"],
                "subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("issuer must strictly be 'https://token.actions.githubusercontent.com'", out)

    def test_vector_13_wildcard_subject(self):
        """Vector 13: Wildcard subject in federated credential (* rejected)."""
        payload = {
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["api://AzureADTokenExchange"],
                "subject": "repo:TM-threemavithana/*",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("contains forbidden wildcard '*'", out)

    def test_vector_14_untrusted_pull_request_event(self):
        """Vector 14: Untrusted pull request event attempting credentials (SEC-02 fail-closed)."""
        # 1. Rego policy rejection
        payload = {
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["api://AzureADTokenExchange"],
                "subject": "repo:TM-threemavithana/infraflow:pull_request",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("targets untrusted pull request event", out)

        # 2. Workflow guard rejection if auth enabled on PR event
        rc_guard, out_guard = self.run_guard({
            "EVENT_NAME": "pull_request",
            "ENABLE_AZURE_AUTH": "true",
        })
        self.assertNotEqual(rc_guard, 0)
        self.assertIn("Live Azure authentication is strictly disabled", out_guard)

    def test_vector_15_malformed_subject_format(self):
        """Vector 15: Malformed subject format (not matching branch, tag, env, or immutable repo-id)."""
        bad_subjects = [
            "user:developer:role:admin",
            "repo:org",
            "repo:org/repo",
            "repo-id:abcd:ref-type:branch:ref:main",  # non-numeric repo-id
        ]
        for subj in bad_subjects:
            with self.subTest(subject=subj):
                payload = {
                    "credential": {
                        "issuer": "https://token.actions.githubusercontent.com",
                        "audiences": ["api://AzureADTokenExchange"],
                        "subject": subj,
                    }
                }
                rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
                self.assertNotEqual(rc, 0)
                self.assertIn("format is invalid or unauthorized", out)

    def test_vector_16_missing_parent_identity_binding(self):
        """Vector 16: Missing parent identity binding (parent_id empty in azurerm_federated_identity_credential)."""
        payload = {
            "resource": {
                "azurerm_federated_identity_credential": {
                    "orphan_fic": [{
                        "parent_id": "",
                        "resource_group_name": "rg-infraflow",
                        "issuer": "https://token.actions.githubusercontent.com",
                        "audiences": ["api://AzureADTokenExchange"],
                        "subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must explicitly specify non-empty 'parent_id'", out)

    def test_vector_17_repository_identity_substitution(self):
        """Vector 17: Repository identity substitution (expected_repository mismatch)."""
        payload = {
            "expected_repository": "TM-threemavithana/infraflow",
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["api://AzureADTokenExchange"],
                "subject": "repo:malicious-attacker/rogue-repo:ref:refs/heads/main",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("does not match expected repository 'TM-threemavithana/infraflow'", out)

    def test_vector_18_repository_id_substitution(self):
        """Vector 18: Repository ID substitution (expected_repository_id mismatch)."""
        payload = {
            "expected_repository_id": "12345678",
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["api://AzureADTokenExchange"],
                "subject": "repo-id:99999999:ref-type:branch:ref:main",
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("does not match expected repository ID '12345678'", out)

    def test_vector_19_flexible_fic_claims_rejected(self):
        """Vector 19: Flexible federated identity credential (custom claims block) rejected."""
        payload = {
            "credential": {
                "issuer": "https://token.actions.githubusercontent.com",
                "audiences": ["api://AzureADTokenExchange"],
                "subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
                "claims": ["sub", "aud", "repository"],
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("Flexible federated identity credentials with custom 'claims' blocks are prohibited", out)

    def test_vector_20_overprivileged_subscription_role_denied(self):
        """Vector 20: Overprivileged subscription-level Owner or Contributor role assignment."""
        for role in ["Owner", "Contributor"]:
            with self.subTest(role=role):
                payload = {
                    "resource": {
                        "azurerm_role_assignment": {
                            "bad_role": [{
                                "role_definition_name": role,
                                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                                "principal_id": "00000000-0000-0000-0000-000000000000",
                            }]
                        }
                    }
                }
                rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
                self.assertNotEqual(rc, 0)
                self.assertIn(f"Overprivileged role '{role}' granted at subscription scope", out)

    def test_vector_21_resource_group_scoped_role_allowed(self):
        """Vector 21: Resource-group scoped least-privilege role assignment allowed (positive control)."""
        payload = {
            "resource": {
                "azurerm_role_assignment": {
                    "good_role": [{
                        "role_definition_name": "Contributor",
                        "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-infraflow",
                        "principal_id": "00000000-0000-0000-0000-000000000000",
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(ENTRA_POLICY, "azure.entra_oidc", payload)
        self.assertEqual(rc, 0, f"Resource group scoped role rejected: {out}")


class TestAzureAdversarialStorageBackendPolicies(AzureAdversarialTestBase):
    """Adversarial Vectors 22 through 32: Azure Storage Account and Blob Backend Policies."""

    def test_vector_22_missing_use_azuread_auth_rejected(self):
        """Vector 22: Storage account missing use_azuread_auth = true."""
        payload = {
            "backend": {
                "azurerm": {
                    "storage_account_name": "stinfraflowprod01",
                    "resource_group_name": "rg-infraflow",
                    "container_name": "tfstate",
                    "key": "prod/terraform.tfstate",
                    "use_azuread_auth": False,
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must enable Microsoft Entra ID data-plane authentication via 'use_azuread_auth = true'", out)

    def test_vector_23_use_oidc_alone_without_azuread_auth_rejected(self):
        """Vector 23: Storage backend with use_oidc = true alone without use_azuread_auth = true rejected."""
        payload = {
            "backend": {
                "azurerm": {
                    "storage_account_name": "stinfraflowprod01",
                    "resource_group_name": "rg-infraflow",
                    "container_name": "tfstate",
                    "key": "prod/terraform.tfstate",
                    "use_oidc": True,
                    "use_azuread_auth": False,
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must enable Microsoft Entra ID data-plane authentication via 'use_azuread_auth = true'", out)

    def test_vector_24_static_access_key_rejected(self):
        """Vector 24: Storage account with static access_key rejected."""
        payload = {
            "backend": {
                "azurerm": {
                    "storage_account_name": "stinfraflowprod01",
                    "resource_group_name": "rg-infraflow",
                    "container_name": "tfstate",
                    "key": "prod/terraform.tfstate",
                    "use_azuread_auth": True,
                    "access_key": "raw-static-secret-storage-key",
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("specifies static 'access_key'", out)

    def test_vector_25_static_sas_token_rejected(self):
        """Vector 25: Storage account with static sas_token rejected."""
        payload = {
            "backend": {
                "azurerm": {
                    "storage_account_name": "stinfraflowprod01",
                    "resource_group_name": "rg-infraflow",
                    "container_name": "tfstate",
                    "key": "prod/terraform.tfstate",
                    "use_azuread_auth": True,
                    "sas_token": "?sv=2020-08-04&ss=b&srt=sco&sp=rwlacx",
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("specifies 'sas_token'", out)

    def test_vector_26_public_nested_items_rejected(self):
        """Vector 26: Storage account allowing public blob access (allow_nested_items_to_be_public = true) rejected."""
        payload = {
            "storage_account": {
                "name": "stinfraflowprod01",
                "allow_nested_items_to_be_public": True,
                "min_tls_version": "TLS1_2",
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must not set allow_nested_items_to_be_public to true", out)

    def test_vector_27_public_container_access_type_rejected(self):
        """Vector 27: Container with public access (container_access_type != private) rejected."""
        payload = {
            "container": {
                "name": "tfstate",
                "container_access_type": "container",
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must enforce 'container_access_type = private'", out)

    def test_vector_28_insecure_tls_version_rejected(self):
        """Vector 28: Insecure TLS version (min_tls_version < TLS1_2) rejected."""
        for tls in ["TLS1_0", "TLS1_1"]:
            with self.subTest(tls=tls):
                payload = {
                    "storage_account": {
                        "name": "stinfraflowprod01",
                        "allow_nested_items_to_be_public": False,
                        "min_tls_version": tls,
                    }
                }
                rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
                self.assertNotEqual(rc, 0)
                self.assertIn("min_tls_version must explicitly be 'TLS1_2' or 'TLS1_3'", out)

    def test_vector_29_unrestricted_public_network_access_rejected(self):
        """Vector 29: Unrestricted public network access without Deny rule rejected."""
        payload = {
            "storage_account": {
                "name": "stinfraflowprod01",
                "allow_nested_items_to_be_public": False,
                "min_tls_version": "TLS1_2",
                "public_network_access_enabled": True,
                "network_rules": [],
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must disable unrestricted public network access", out)

    def test_vector_30_shared_access_key_enabled_rejected(self):
        """Vector 30: Storage account enabling shared access keys (shared_access_key_enabled = true) rejected."""
        payload = {
            "storage_account": {
                "name": "stinfraflowprod01",
                "allow_nested_items_to_be_public": False,
                "min_tls_version": "TLS1_2",
                "public_network_access_enabled": False,
                "shared_access_key_enabled": True,
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must disable shared access keys (shared_access_key_enabled = false)", out)

    def test_vector_31_state_storage_missing_blob_versioning_rejected(self):
        """Vector 31: Storage account housing state missing blob versioning rejected."""
        payload = {
            "storage_account": {
                "name": "stinfraflowtfstate",
                "allow_nested_items_to_be_public": False,
                "min_tls_version": "TLS1_2",
                "public_network_access_enabled": False,
                "shared_access_key_enabled": False,
                "blob_properties": {
                    "versioning_enabled": False,
                },
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("housing Terraform state must enable blob versioning", out)

    def test_vector_32_overprivileged_storage_scope_role_rejected(self):
        """Vector 32: Overprivileged Owner/Contributor role on storage account scope rejected."""
        for role in ["Owner", "Contributor"]:
            with self.subTest(role=role):
                payload = {
                    "role_assignment": {
                        "role_definition_name": role,
                        "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stinfraflowprod01",
                        "principal_id": "00000000-0000-0000-0000-000000000000",
                    }
                }
                rc, out = run_conftest_eval(STORAGE_POLICY, "azure.storage_backend", payload)
                self.assertNotEqual(rc, 0)
                self.assertIn("Use 'Storage Blob Data Contributor' or least privilege data-plane role", out)


class TestAzureAdversarialWorkflowGuards(AzureAdversarialTestBase):
    """Adversarial Vectors 33 through 41: Reusable Workflow Pre-Flight Input Guards & Boundaries."""

    def test_vector_33_mutable_reusable_workflow_ref_rejected(self):
        """Vector 33: Mutable reusable workflow reference (@main instead of 40-char SHA) rejected."""
        rc, out = self.run_guard({
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@main"
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("must be pinned to an immutable 40-character hexadecimal commit SHA", out)

    def test_vector_34_attempted_azure_auth_enablement_rejected(self):
        """Vector 34: Attempted Azure authentication enablement (enable-azure-auth: true fail-closed) rejected."""
        rc, out = self.run_guard({"ENABLE_AZURE_AUTH": "true"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Live Azure authentication is strictly disabled", out)

    def test_vector_35_attempted_policy_eval_bypass_rejected(self):
        """Vector 35: Attempted bypass of mandatory policy evaluation (enable-policy-evaluation: false) rejected."""
        rc, out = self.run_guard({"ENABLE_POLICY_EVAL": "false"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Disabling mandatory policy evaluation", out)

    def test_vector_36_attempted_trivy_bypass_rejected(self):
        """Vector 36: Attempted bypass of mandatory Trivy IaC scan (enable-trivy: false) rejected."""
        rc, out = self.run_guard({"ENABLE_TRIVY": "false"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Disabling mandatory Trivy IaC scanning", out)

    def test_vector_37_unauthorized_severity_threshold_rejected(self):
        """Vector 37: Unauthorized security severity threshold (CRITICAL alone or LOW or MEDIUM) rejected."""
        unauthorized = ["CRITICAL", "LOW", "MEDIUM", "ALL"]
        for sev in unauthorized:
            with self.subTest(severity=sev):
                rc, out = self.run_guard({"INPUT_SEVERITY": sev})
                self.assertNotEqual(rc, 0)
                self.assertIn("Severity threshold", out)

    def test_vector_38_rogue_platform_repo_rejected(self):
        """Vector 38: Reusable workflow rogue repository origin rejected (WORKFLOW_REPO != TM-threemavithana/infraflow)."""
        rc, out = self.run_guard({"WORKFLOW_REPO": "rogue-org/malicious-repo"})
        self.assertNotEqual(rc, 0)
        self.assertIn("must originate from trusted repository 'TM-threemavithana/infraflow'", out)

    def test_vector_39_mutable_workflow_sha_rejected(self):
        """Vector 39: Mutable / non-40-hex WORKFLOW_SHA rejected."""
        bad_shas = [
            "main",
            "v0.4.0",
            "7c4dff9d5ab9e917fab79f59fa359bb413dca72",   # 39 chars (short)
            "7c4dff9d5ab9e917fab79f59fa359bb413dca7200", # 41 chars (long)
            "7c4dff9d5ab9e917fab79f59fa359bb413dca72g",  # non-hex
        ]
        for sha in bad_shas:
            with self.subTest(sha=sha):
                rc, out = self.run_guard({"WORKFLOW_SHA": sha})
                self.assertNotEqual(rc, 0)
                self.assertIn("must run at an immutable 40-character hexadecimal commit SHA", out)

    def test_vector_40_working_directory_traversal_rejected(self):
        """Vector 40: Working directory path traversal (.., absolute path, home directory ~) rejected."""
        bad_dirs = [
            "../outside",
            "/etc/terraform",
            "~/modules",
            "dir; rm -rf /",
        ]
        for d in bad_dirs:
            with self.subTest(dir=d):
                rc, out = self.run_guard({"INPUT_DIR": d})
                self.assertNotEqual(rc, 0)

    def test_vector_41_var_file_traversal_rejected(self):
        """Vector 41: Var-file path traversal rejected."""
        bad_var_files = [
            "../../secret.tfvars",
            "/etc/secret.tfvars",
            "~/.azure/credentials.tfvars",
            "vars.tfvars; injection",
        ]
        for vf in bad_var_files:
            with self.subTest(var_file=vf):
                rc, out = self.run_guard({"INPUT_VAR_FILE": vf})
                self.assertNotEqual(rc, 0)
                self.assertIn("var-file", out)


class TestAzureAdversarialExecutionAndAggregation(AzureAdversarialTestBase):
    """Adversarial Vectors 42 through 45: Execution, Plan Analysis, Cleanup and Aggregator Gates."""

    def test_vector_42_fail_on_destructive_gate(self):
        """Vector 42: Destructive changes gate evaluation (fail-on-destructive: true with destructive changes)."""
        # When destructive changes occur and fail-on-destructive is true, execution fails
        # Testing via summary aggregator output check:
        rc, out = self.run_aggregator({
            "CF_HAS_CHANGES": "true",
            "CF_HAS_DESTRUCTIVE": "true",
            "CF_TOTAL_CHANGES": "2",
        })
        self.assertEqual(rc, 0)
        self.assertIn("has-destructive-changes=true", out)

    def test_vector_43_summary_aggregator_fails_closed_on_validate_inputs_failure(self):
        """Vector 43: Summary aggregator fail-closed when validate-inputs fails."""
        rc, out = self.run_aggregator({
            "VALIDATE_RESULT": "failure",
            "CF_PLAN_RESULT": "skipped",
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("plan-status=failure", out)
        self.assertIn("authorization-status=rejected", out)
        self.assertIn("Azure adapter gate failed closed. Authorization rejected.", out)

    def test_vector_44_summary_aggregator_fails_closed_on_metric_inconsistency(self):
        """Vector 44: Summary aggregator fail-closed when plan metrics inconsistent (has-changes: true, total-changes: 0)."""
        rc, out = self.run_aggregator({
            "CF_HAS_CHANGES": "true",
            "CF_TOTAL_CHANGES": "0",  # Inconsistent: has-changes is true but total is 0!
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("Aggregated metrics inconsistent", out)
        self.assertIn("authorization-status=rejected", out)

    def test_vector_45_plan_cleanup_trap_includes_metrics_json(self):
        """Vector 45: Plan cleanup trap ensures plan-metrics.json cleanup alongside tfplan and tfplan.json."""
        with open(REUSABLE_AZURE_WF, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("trap 'rm -f tfplan tfplan.json plan-metrics.json' EXIT INT TERM", content)
        self.assertIn("rm -f tfplan tfplan.json plan-metrics.json", content)


if __name__ == "__main__":
    unittest.main()
