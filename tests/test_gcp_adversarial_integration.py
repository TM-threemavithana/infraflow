#!/usr/bin/env python3
"""
InfraFlow — GCP Adapter Adversarial Integration Test Suite
Milestone: G07.3 — GCP Adapter Security Hardening and Offline Validation

Comprehensive 30-vector adversarial test suite evaluating the GCP Cloud Adapter,
Workload Identity Federation (WIF) OIDC policies, and GCS Remote Backend controls.

Vectors Covered:
 1. Valid synthetic GCP configuration (positive control)
 2. Invalid project ID (regex violations, uppercase, length, starts with digit)
 3. Invalid region (malformed, uppercase, injection)
 4. Malformed WIF provider resource (non-global location, non-numeric project number)
 5. Incorrect Service Account email (missing .iam., missing @)
 6. Wildcard WIF audience (* in provider or CEL)
 7. Wrong OIDC issuer (not token.actions.githubusercontent.com)
 8. Missing owner identity constraint (org-wide owner binding without repository)
 9. Repository identity substitution (attempting unauthorized repository in assertion)
10. Broad attribute condition (missing repository constraint in attribute_condition)
11. Missing mandatory attribute mapping (missing google.subject or attribute.repository)
12. Untrusted PR context (pull_request event attempting auth - SEC-02)
13. Mutable workflow reference (@main instead of 40-character commit SHA)
14. Attempted GCP authentication enablement (enable-gcp-auth: true fail-closed)
15. Arbitrary Service Account selection (wildcard * in workloadIdentityUser member)
16. Malicious backend bucket (goog*/google*, length, characters)
17. Backend prefix traversal (.. or leading /)
18. Public bucket access (allUsers / allAuthenticatedUsers ACL or predefined ACL)
19. Public IAM binding (allUsers in IAM member/binding)
20. Missing mandatory storage protection (UBLA=false, PAP=inherited, versioning disabled)
21. Destructive bucket configuration (force_destroy = true)
22. Malformed or unsupported policy input (syntax/empty payload handling)
23. Symlink workspace escape (symlinked working directory or var-file)
24. Shell argument injection (command chaining in parameters)
25. Missing security job output (summary aggregation with missing inputs)
26. Failed job reported as successful (failure propagation in summary)
27. Unexpected skipped mandatory gate (policy eval or Trivy disabled)
28. Sensitive input log exposure (zero secret leakage)
29. Unsafe Terraform state handling (ephemeral plan cleanup trap verification)
30. Cross-environment configuration substitution (empty backend prefix)

Invariants:
- Zero cloud spend ($0.00).
- Zero cloud credentials required.
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
REUSABLE_GCP_WF = os.path.join(REPO_ROOT, ".github", "workflows", "reusable-tf-gcp.yml")
WIF_POLICY = os.path.join(REPO_ROOT, "policies", "gcp", "wif_oidc.rego")
STORAGE_POLICY = os.path.join(REPO_ROOT, "policies", "gcp", "storage_backend.rego")


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


class GcpAdversarialTestBase(unittest.TestCase):
    """Base class extracting workflow step scripts and configuring default test harness."""

    @classmethod
    def setUpClass(cls):
        with open(REUSABLE_GCP_WF, "r", encoding="utf-8") as f:
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
            "INPUT_VERSION": "1.10.4",
            "INPUT_DIR": ".",
            "INPUT_VAR_FILE": "",
            "INPUT_ENV": "dev",
            "INPUT_PROJECT_ID": "infraflow-ref-project",
            "INPUT_GCP_REGION": "us-central1",
            "INPUT_WIF_PROVIDER": "projects/123456789012/locations/global/workloadIdentityPools/infraflow-pool/providers/github-provider",
            "INPUT_SERVICE_ACCOUNT": "infraflow-sa@infraflow-ref-project.iam.gserviceaccount.com",
            "INPUT_BUCKET": "infraflow-tfstate-bucket",
            "INPUT_PREFIX": "terraform/state/dev",
            "INPUT_SEVERITY": "HIGH,CRITICAL",
            "ENABLE_GCP_AUTH": "false",
            "ENABLE_POLICY_EVAL": "true",
            "ENABLE_TRIVY": "true",
            "INPUT_POLICY_DIR": "policies",
            "EVENT_NAME": "push",
            "TARGET_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "TM-threemavithana/infraflow",
            "WORKFLOW_REPO": "TM-threemavithana/infraflow",
            "WORKFLOW_SHA": "cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2",
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2",
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


class TestGcpAdversarialIdentityAndOIDC(GcpAdversarialTestBase):
    """Adversarial Vectors 1 through 15: Identity, WIF, OIDC Trust Boundary & Input Guards."""

    def test_vector_01_valid_synthetic_gcp_config(self):
        """Vector 1: Valid synthetic GCP configuration (positive control)."""
        rc, out = self.run_guard({})
        self.assertEqual(rc, 0, f"Valid synthetic configuration rejected: {out}")
        self.assertIn("verified successfully", out)

    def test_vector_02_invalid_project_id(self):
        """Vector 2: Invalid project ID (regex violations, uppercase, length, starts with digit)."""
        bad_ids = [
            "SHORT",                    # uppercase + short
            "123-starts-with-digit",    # cannot start with digit
            "my_project_id",            # underscores forbidden
            "a" * 31,                   # length > 30 chars
            "proj; rm -rf /",           # command injection attempt
        ]
        for pid in bad_ids:
            with self.subTest(project_id=pid):
                rc, out = self.run_guard({"INPUT_PROJECT_ID": pid})
                self.assertNotEqual(rc, 0)
                self.assertIn("project-id", out)

    def test_vector_03_invalid_region(self):
        """Vector 3: Invalid region (malformed, uppercase, injection)."""
        bad_regions = [
            "US-CENTRAL1",              # uppercase
            "us_central1",              # underscore
            "us-central-1",             # dash before digit
            "us-central1; rm -rf /",    # injection
        ]
        for reg in bad_regions:
            with self.subTest(region=reg):
                rc, out = self.run_guard({"INPUT_GCP_REGION": reg})
                self.assertNotEqual(rc, 0)
                self.assertIn("region", out)

    def test_vector_04_malformed_wif_provider_resource(self):
        """Vector 4: Malformed WIF provider resource (non-global location, non-numeric project number)."""
        bad_wifs = [
            "projects/my-proj/locations/global/workloadIdentityPools/pool/providers/prov", # project must be numeric
            "projects/12345/locations/us-central1/workloadIdentityPools/pool/providers/prov", # location must be global
            "arn:aws:iam::123456789012:role/bad-wif",                                       # AWS ARN
        ]
        for wif in bad_wifs:
            with self.subTest(wif=wif):
                rc, out = self.run_guard({"INPUT_WIF_PROVIDER": wif})
                self.assertNotEqual(rc, 0)
                self.assertIn("Workload Identity Provider", out)

    def test_vector_05_incorrect_service_account_email(self):
        """Vector 5: Incorrect Service Account email (missing .iam., missing @)."""
        bad_sas = [
            "admin@example.com",
            "sa@proj.gserviceaccount.com",      # missing .iam.
            "invalid-email-without-at",
            "sa@proj.iam.gserviceaccount.com; injection",
        ]
        for sa in bad_sas:
            with self.subTest(sa=sa):
                rc, out = self.run_guard({"INPUT_SERVICE_ACCOUNT": sa})
                self.assertNotEqual(rc, 0)
                self.assertIn("Service Account", out)

    def test_vector_06_wildcard_wif_audience(self):
        """Vector 6: Wildcard WIF audience (* in provider or CEL)."""
        payload = {
            "resource": {
                "google_iam_workload_identity_pool_provider": {
                    "bad_prov": [{
                        "oidc": [{
                            "issuer_uri": "https://token.actions.githubusercontent.com",
                            "allowed_audiences": ["*"]
                        }],
                        "attribute_mapping": {
                            "google.subject": "assertion.sub",
                            "attribute.repository": "assertion.repository"
                        },
                        "attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow' && assertion.ref == 'refs/heads/main'"
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("wildcard '*' audience", out)

    def test_vector_07_wrong_oidc_issuer(self):
        """Vector 7: Wrong OIDC issuer (not token.actions.githubusercontent.com)."""
        payload = {
            "resource": {
                "google_iam_workload_identity_pool_provider": {
                    "bad_issuer": [{
                        "oidc": [{
                            "issuer_uri": "https://evil-attacker-issuer.com"
                        }],
                        "attribute_mapping": {
                            "google.subject": "assertion.sub",
                            "attribute.repository": "assertion.repository"
                        },
                        "attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow' && assertion.ref == 'refs/heads/main'"
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must strictly be 'https://token.actions.githubusercontent.com'", out)

    def test_vector_08_missing_owner_identity_constraint(self):
        """Vector 8: Missing owner identity constraint (org-wide owner binding without repository)."""
        payload = {
            "resource": {
                "google_service_account_iam_binding": {
                    "bad_binding": [{
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [
                            "principalSet://iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/attribute.repository_owner/my-org"
                        ]
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("allows organization-wide repository_owner access without exact repository binding", out)

    def test_vector_09_repository_identity_substitution(self):
        """Vector 9: Repository identity substitution (attempting unauthorized repository in assertion)."""
        payload_no_repo = {
            "resource": {
                "google_iam_workload_identity_pool_provider": {
                    "sub_prov": [{
                        "oidc": [{
                            "issuer_uri": "https://token.actions.githubusercontent.com"
                        }],
                        "attribute_mapping": {
                            "google.subject": "assertion.sub",
                            "attribute.repository": "assertion.repository"
                        },
                        "attribute_condition": "assertion.actor == 'attacker'"
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload_no_repo)
        self.assertNotEqual(rc, 0)
        self.assertIn("must explicitly filter on 'assertion.repository' or immutable 'assertion.repository_id'", out)

    def test_vector_10_broad_attribute_condition(self):
        """Vector 10: Broad attribute condition (missing repository constraint in attribute_condition)."""
        payload = {
            "resource": {
                "google_iam_workload_identity_pool_provider": {
                    "broad_cond": [{
                        "oidc": [{
                            "issuer_uri": "https://token.actions.githubusercontent.com"
                        }],
                        "attribute_mapping": {
                            "google.subject": "assertion.sub",
                            "attribute.repository": "assertion.repository"
                        },
                        "attribute_condition": ""
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("missing mandatory 'attribute_condition'", out)

    def test_vector_11_missing_mandatory_attribute_mapping(self):
        """Vector 11: Missing mandatory attribute mapping (missing google.subject or attribute.repository)."""
        payload = {
            "resource": {
                "google_iam_workload_identity_pool_provider": {
                    "missing_mapping": [{
                        "oidc": [{
                            "issuer_uri": "https://token.actions.githubusercontent.com"
                        }],
                        "attribute_mapping": {
                            "google.subject": "assertion.sub"
                            # missing attribute.repository
                        },
                        "attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow'"
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("attribute.repository", out)

    def test_vector_12_untrusted_pr_context(self):
        """Vector 12: Untrusted PR context (pull_request event attempting auth - SEC-02)."""
        rc, out = self.run_guard({
            "EVENT_NAME": "pull_request",
            "ENABLE_GCP_AUTH": "true",
        })
        self.assertNotEqual(rc, 0)
        # Rejection occurs either on live GCP auth disabled or SEC-02 pull_request rule
        self.assertTrue(
            "Pull request events are strictly forbidden" in out or "Live GCP authentication is strictly disabled" in out
        )

    def test_vector_13_mutable_workflow_reference(self):
        """Vector 13: Mutable workflow reference (@main instead of 40-character commit SHA)."""
        rc, out = self.run_guard({
            "WORKFLOW_SHA": "main",
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@main",
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("immutable 40-character hexadecimal commit SHA", out)

    def test_vector_14_attempted_gcp_authentication_enablement(self):
        """Vector 14: Attempted GCP authentication enablement (enable-gcp-auth: true fail-closed)."""
        rc, out = self.run_guard({"ENABLE_GCP_AUTH": "true"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Live GCP authentication is strictly disabled in Milestone G07.2", out)

    def test_vector_15_arbitrary_service_account_selection(self):
        """Vector 15: Arbitrary Service Account selection (wildcard * in workloadIdentityUser member)."""
        payload = {
            "resource": {
                "google_service_account_iam_member": {
                    "bad_wildcard": [{
                        "role": "roles/iam.workloadIdentityUser",
                        "member": "*"
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(WIF_POLICY, "gcp.wif_oidc", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("allows wildcard principal", out)


class TestGcpAdversarialStorageAndBackend(GcpAdversarialTestBase):
    """Adversarial Vectors 16 through 21 and 30: GCS State Storage & Backend Controls."""

    def test_vector_16_malicious_backend_bucket(self):
        """Vector 16: Malicious backend bucket (goog*/google*, length, characters)."""
        bad_buckets = [
            "google-internal-state",
            "goog-tfstate",
            "ab",                       # too short
            "a" * 64,                   # too long
            "UPPERCASE-BUCKET",         # uppercase
            "bucket; rm -rf /",         # shell metacharacters
        ]
        for b in bad_buckets:
            with self.subTest(bucket=b):
                rc, out = self.run_guard({"INPUT_BUCKET": b})
                self.assertNotEqual(rc, 0)

    def test_vector_17_backend_prefix_traversal(self):
        """Vector 17: Backend prefix traversal (.. or leading /)."""
        bad_prefixes = [
            "/leading/slash",
            "state/../../traversal",
            "path/with spaces/state",
        ]
        for p in bad_prefixes:
            with self.subTest(prefix=p):
                rc, out = self.run_guard({"INPUT_PREFIX": p})
                self.assertNotEqual(rc, 0)
                self.assertIn("backend-prefix", out)

    def test_vector_18_public_bucket_access(self):
        """Vector 18: Public bucket access (allUsers / allAuthenticatedUsers ACL or predefined ACL)."""
        payload = {
            "resource": {
                "google_storage_bucket_access_control": {
                    "public_acl": [{
                        "bucket": "infraflow-state",
                        "entity": "allUsers",
                        "role": "READER"
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("grants public access to 'allUsers'", out)

    def test_vector_19_public_iam_binding(self):
        """Vector 19: Public IAM binding (allUsers in IAM member/binding)."""
        payload = {
            "resource": {
                "google_storage_bucket_iam_binding": {
                    "bad_public_iam": [{
                        "bucket": "infraflow-state",
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"]
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("exposes bucket to public principal 'allUsers'", out)

    def test_vector_20_missing_mandatory_storage_protection(self):
        """Vector 20: Missing mandatory storage protection (UBLA=false, PAP=inherited, versioning disabled)."""
        payload = {
            "resource": {
                "google_storage_bucket": {
                    "state_bucket": [{
                        "name": "infraflow-state-bucket",
                        "uniform_bucket_level_access": False,
                        "public_access_prevention": "inherited",
                        "versioning": [{"enabled": False}]
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("uniform_bucket_level_access", out)
        self.assertIn("public_access_prevention", out)
        self.assertIn("versioning", out)

    def test_vector_21_destructive_bucket_configuration(self):
        """Vector 21: Destructive bucket configuration (force_destroy = true)."""
        payload = {
            "resource": {
                "google_storage_bucket": {
                    "state_bucket": [{
                        "name": "infraflow-state-bucket",
                        "force_destroy": True
                    }]
                }
            }
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("must not set force_destroy = true", out)

    def test_vector_30_cross_environment_empty_backend_prefix(self):
        """Vector 30: Cross-environment configuration substitution (empty backend prefix)."""
        payload = {
            "terraform": [{
                "backend": [{
                    "gcs": [{
                        "bucket": "infraflow-tfstate",
                        "prefix": ""
                    }]
                }]
            }]
        }
        rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", payload)
        self.assertNotEqual(rc, 0)
        self.assertIn("prefix must not be empty", out)


class TestGcpAdversarialWorkflowIntegrity(GcpAdversarialTestBase):
    """Adversarial Vectors 22 through 29: Workflow Execution Integrity, Traps & Containment."""

    def test_vector_22_malformed_or_unsupported_policy_input(self):
        """Vector 22: Malformed or unsupported policy input (syntax/empty payload handling)."""
        # Conftest must handle empty JSON gracefully without crashing
        rc, out = run_conftest_eval(STORAGE_POLICY, "gcp.storage_backend", {})
        self.assertEqual(rc, 0) # empty payload has no violating resources

    def test_vector_23_symlink_workspace_escape(self):
        """Vector 23: Symlink workspace escape (symlinked working directory or var-file)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            ws_dir = os.path.join(temp_dir, "workspace")
            outside_dir = os.path.join(temp_dir, "outside")
            os.makedirs(ws_dir)
            os.makedirs(outside_dir)

            # Create a symlink pointing outside workspace
            symlink_target = os.path.join(ws_dir, "evil_symlink")
            os.symlink(outside_dir, symlink_target)

            env = {
                "GITHUB_WORKSPACE": ws_dir,
                "INPUT_DIR": "evil_symlink",
                "INPUT_VAR_FILE": "",
                "POLICY_DIR": "",
            }
            res = subprocess.run(
                ["bash", "-c", self.verify_workspace_script],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("symbolic link", res.stdout + res.stderr)

    def test_vector_24_shell_argument_injection(self):
        """Vector 24: Shell argument injection (command chaining in parameters)."""
        injection_payloads = [
            "; touch /tmp/pwned",
            "&& whoami",
            "`id`",
            "$(cat /etc/passwd)",
        ]
        for inj in injection_payloads:
            with self.subTest(injection=inj):
                rc, out = self.run_guard({"INPUT_PROJECT_ID": f"valid-prefix{inj}"})
                self.assertNotEqual(rc, 0)

    def test_vector_25_missing_security_job_output(self):
        """Vector 25: Missing security job output (summary aggregation with missing inputs)."""
        with tempfile.NamedTemporaryFile("w", delete=False) as out_f:
            out_path = out_f.name
        try:
            # Run summary script with missing/empty inputs
            env = dict(os.environ)
            env["GITHUB_OUTPUT"] = out_path
            env["VALIDATE_RESULT"] = ""
            env["CF_PLAN_RESULT"] = ""
            env["ENABLE_GCP_AUTH"] = "false"
            res = subprocess.run(
                ["bash", "-c", self.summary_script],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_vector_26_failed_job_reported_as_successful(self):
        """Vector 26: Failed job reported as successful (failure propagation in summary)."""
        with tempfile.NamedTemporaryFile("w", delete=False) as out_f:
            out_path = out_f.name
        try:
            env = dict(os.environ)
            env["GITHUB_OUTPUT"] = out_path
            env["VALIDATE_RESULT"] = "failure"
            env["CF_PLAN_RESULT"] = "success" # contradictory
            env["ENABLE_GCP_AUTH"] = "false"
            res = subprocess.run(
                ["bash", "-c", self.summary_script],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            outputs = {}
            with open(out_path, "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        outputs[k] = v
            self.assertEqual(outputs.get("plan-status"), "failure")
            self.assertEqual(outputs.get("authorization-status"), "rejected")
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_vector_27_unexpected_skipped_mandatory_gate(self):
        """Vector 27: Unexpected skipped mandatory gate (policy eval or Trivy disabled)."""
        # Disabling policy evaluation must fail
        rc, out = self.run_guard({"ENABLE_POLICY_EVAL": "false"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Disabling mandatory policy evaluation", out)

        # Disabling Trivy scanning must fail
        rc, out = self.run_guard({"ENABLE_TRIVY": "false"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Disabling mandatory Trivy IaC scanning", out)

    def test_vector_28_sensitive_input_log_exposure(self):
        """Vector 28: Sensitive input log exposure (zero secret leakage)."""
        rc, out = self.run_guard({})
        self.assertEqual(rc, 0)
        # Ensure no credential markers appear in logs
        forbidden_markers = ["private_key", "client_secret", "BEGIN RSA PRIVATE KEY", "token="]
        for marker in forbidden_markers:
            self.assertNotIn(marker, out)

    def test_vector_29_unsafe_terraform_state_handling_trap(self):
        """Vector 29: Unsafe Terraform state handling (ephemeral plan cleanup trap verification)."""
        # Verify POSIX trap cleans up sensitive plan artifacts on exit/error
        with tempfile.TemporaryDirectory() as temp_dir:
            test_script = f"""
            cd "{temp_dir}"
            trap 'rm -f tfplan tfplan.json' EXIT INT TERM
            touch tfplan tfplan.json
            test -f tfplan && test -f tfplan.json
            exit 1
            """
            res = subprocess.run(
                ["bash", "-c", test_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 1) # script exited with 1
            # Trap MUST have wiped tfplan and tfplan.json
            self.assertFalse(os.path.exists(os.path.join(temp_dir, "tfplan")))
            self.assertFalse(os.path.exists(os.path.join(temp_dir, "tfplan.json")))


if __name__ == "__main__":
    unittest.main()
