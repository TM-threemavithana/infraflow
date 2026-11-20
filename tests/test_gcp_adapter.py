#!/usr/bin/env python3
"""
InfraFlow — GCP Adapter & Workload Identity Test Suite
Milestone: G07.2 — Google Cloud Adapter & Workload Identity Foundation

Validates security controls, input guards, workflow invariants, and regex patterns:
1. GCP Project ID format validation (positive and negative cases)
2. GCP Region format validation (positive and negative cases)
3. Workload Identity Provider resource format validation
4. Service Account email format validation
5. GCS bucket naming rules and reserved prefix rejection
6. GCS state prefix rules (leading slash and traversal rejection)
7. Workflow input guard extraction and execution
8. Live GCP authentication rejection (fail-closed simulation invariant)
9. Trusted workflow caller and immutable SHA pinning enforcement
10. Event and ref security guard assertions
11. Summary output aggregation and failure propagation
12. Reference module structure and mock provider contract
"""

import os
import re
import subprocess
import tempfile
import unittest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REUSABLE_GCP_WF = os.path.join(REPO_ROOT, ".github", "workflows", "reusable-tf-gcp.yml")
GCP_REF_MODULE = os.path.join(REPO_ROOT, "examples", "gcp-reference-module")

# Regex specifications matching reusable-tf-gcp.yml and enterprise policies
PROJECT_ID_REGEX = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
REGION_REGEX = re.compile(r"^[a-z]+-[a-z]+[0-9]+$")
WIF_PROVIDER_REGEX = re.compile(r"^projects/[0-9]+/locations/global/workloadIdentityPools/[a-zA-Z0-9_-]+/providers/[a-zA-Z0-9_-]+$")
SERVICE_ACCOUNT_REGEX = re.compile(r"^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$")
BUCKET_REGEX = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]$")
COMMIT_SHA_REGEX = re.compile(r"^[0-9a-f]{40}$")


class TestGcpRegexValidation(unittest.TestCase):
    """Validates regex pattern rules used in GCP adapter and security policies."""

    def test_project_id_valid(self):
        valid_projects = [
            "infraflow-dev",
            "infraflow-prod-123",
            "my-sample-proj",
            "abcde1",
        ]
        for proj in valid_projects:
            with self.subTest(project=proj):
                self.assertIsNotNone(PROJECT_ID_REGEX.match(proj))

    def test_project_id_invalid(self):
        invalid_projects = [
            "short",              # < 6 chars
            "a" * 31,             # > 30 chars
            "1starts-with-digit", # must start with letter
            "has_underscore",     # underscores not permitted
            "UPPERCASE-PROJ",     # uppercase not permitted
            "ends-with-dash-",    # must end with alphanumeric
            "proj;rm -rf /",      # command injection
        ]
        for proj in invalid_projects:
            with self.subTest(project=proj):
                self.assertIsNone(PROJECT_ID_REGEX.match(proj))

    def test_region_valid(self):
        valid_regions = [
            "us-central1",
            "europe-west3",
            "asia-northeast1",
            "southamerica-east1",
        ]
        for region in valid_regions:
            with self.subTest(region=region):
                self.assertIsNotNone(REGION_REGEX.match(region))

    def test_region_invalid(self):
        invalid_regions = [
            "US",                 # multi-region shortcut not allowed for regional spec
            "us_central1",        # underscore invalid
            "us-central-1",       # trailing hyphen before number invalid
            "invalid/region",     # path separators invalid
            "us-central1; evil",  # injection attempt
        ]
        for region in invalid_regions:
            with self.subTest(region=region):
                self.assertIsNone(REGION_REGEX.match(region))

    def test_wif_provider_valid(self):
        valid_wif = "projects/123456789012/locations/global/workloadIdentityPools/my-pool/providers/my-provider"
        self.assertIsNotNone(WIF_PROVIDER_REGEX.match(valid_wif))

    def test_wif_provider_invalid(self):
        invalid_wifs = [
            "projects/my-proj/locations/global/workloadIdentityPools/my-pool/providers/my-provider", # project must be number
            "projects/123456789012/locations/us-central1/workloadIdentityPools/my-pool/providers/my-provider", # must be global
            "arn:aws:iam::123456789012:role/my-role", # AWS ARN
            "projects/123456789012/locations/global/workloadIdentityPools/my-pool/providers/prov;rm -rf /",
        ]
        for wif in invalid_wifs:
            with self.subTest(wif=wif):
                self.assertIsNone(WIF_PROVIDER_REGEX.match(wif))

    def test_service_account_valid(self):
        valid_sas = [
            "infraflow-deployer@my-project.iam.gserviceaccount.com",
            "sa-123@prod-456.iam.gserviceaccount.com",
        ]
        for sa in valid_sas:
            with self.subTest(sa=sa):
                self.assertIsNotNone(SERVICE_ACCOUNT_REGEX.match(sa))

    def test_service_account_invalid(self):
        invalid_sas = [
            "user@example.com",
            "infraflow-deployer@my-project.gserviceaccount.com", # missing .iam.
            "root@gmail.com",
            "sa@invalid..iam.gserviceaccount.com",
            "sa@proj.iam.gserviceaccount.com; evil",
        ]
        for sa in invalid_sas:
            with self.subTest(sa=sa):
                self.assertIsNone(SERVICE_ACCOUNT_REGEX.match(sa))

    def test_bucket_name_valid(self):
        valid_buckets = [
            "my-org-tfstate",
            "infraflow-bucket-123",
            "my.domain.tfstate",
        ]
        for b in valid_buckets:
            with self.subTest(bucket=b):
                self.assertIsNotNone(BUCKET_REGEX.match(b))
                self.assertFalse(b.startswith("goog") or b.startswith("google"))

    def test_bucket_name_invalid(self):
        invalid_buckets = [
            "ab",                 # too short (<3)
            "a" * 64,             # too long (>63)
            "-starts-with-dash",
            "ends-with-dash-",
            "UPPERCASE-BUCKET",
            "bucket;rm -rf /",
        ]
        for b in invalid_buckets:
            with self.subTest(bucket=b):
                self.assertIsNone(BUCKET_REGEX.match(b))

    def test_bucket_reserved_prefixes(self):
        reserved_buckets = [
            "google-cloud-storage",
            "goog-state-bucket",
        ]
        for b in reserved_buckets:
            with self.subTest(bucket=b):
                self.assertTrue(b.startswith("goog") or b.startswith("google"))


class TestGcpWorkflowGuardExecution(unittest.TestCase):
    """Executes the extracted bash guard from reusable-tf-gcp.yml across negative test vectors."""

    @classmethod
    def setUpClass(cls):
        self_wf = REUSABLE_GCP_WF
        with open(self_wf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        steps = {s["id"]: s["run"] for s in data["jobs"]["validate-inputs"]["steps"] if "id" in s and "run" in s}
        cls.guard_script = steps["guard"]

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

    def test_legitimate_inputs_accepted(self):
        rc, out = self.run_guard({})
        self.assertEqual(rc, 0, f"Legitimate inputs unexpectedly rejected: {out}")

    def test_live_gcp_auth_strictly_rejected(self):
        """Simulation invariant: enable-gcp-auth: true MUST fail-closed in G07.2."""
        rc, out = self.run_guard({"ENABLE_GCP_AUTH": "true"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Live GCP authentication is strictly disabled in Milestone G07.2", out)

    def test_malformed_project_id_rejected(self):
        rc, out = self.run_guard({"INPUT_PROJECT_ID": "bad_project_with_underscore"})
        self.assertNotEqual(rc, 0)
        self.assertIn("project-id", out)

    def test_malformed_region_rejected(self):
        rc, out = self.run_guard({"INPUT_GCP_REGION": "us_central1"})
        self.assertNotEqual(rc, 0)
        self.assertIn("region", out)

    def test_malformed_wif_provider_rejected(self):
        rc, out = self.run_guard({"INPUT_WIF_PROVIDER": "invalid-provider-resource"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Workload Identity Provider", out)

    def test_malformed_service_account_rejected(self):
        rc, out = self.run_guard({"INPUT_SERVICE_ACCOUNT": "admin@gmail.com"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Service Account", out)

    def test_reserved_bucket_prefix_rejected(self):
        rc, out = self.run_guard({"INPUT_BUCKET": "google-state-storage"})
        self.assertNotEqual(rc, 0)
        self.assertIn("GCS bucket name cannot begin with 'goog' or 'google'", out)

    def test_leading_slash_backend_prefix_rejected(self):
        rc, out = self.run_guard({"INPUT_PREFIX": "/leading/slash"})
        self.assertNotEqual(rc, 0)
        self.assertIn("Leading slashes", out)

    def test_traversal_backend_prefix_rejected(self):
        rc, out = self.run_guard({"INPUT_PREFIX": "path/../../escape"})
        self.assertNotEqual(rc, 0)
        self.assertIn("path traversal", out)

    def test_untrusted_caller_repo_rejected(self):
        rc, out = self.run_guard({
            "WORKFLOW_REPO": "untrusted-attacker/infraflow",
            "GITHUB_REPOSITORY": "untrusted-attacker/infraflow",
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("trusted repository", out)

    def test_mutable_ref_rejected(self):
        rc, out = self.run_guard({
            "WORKFLOW_REF": "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@main",
            "WORKFLOW_SHA": "main",
        })
        self.assertNotEqual(rc, 0)
        self.assertIn("SHA", out)

    def test_untrusted_pull_request_with_gcp_auth_rejected(self):
        rc, out = self.run_guard({
            "EVENT_NAME": "pull_request",
            "ENABLE_GCP_AUTH": "true",
        })
        self.assertNotEqual(rc, 0)


class TestGcpWorkflowSummaryAggregation(unittest.TestCase):
    """Verifies output aggregation and failure propagation from reusable-tf-gcp.yml."""

    @classmethod
    def setUpClass(cls):
        with open(REUSABLE_GCP_WF, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        steps = {s["id"]: s["run"] for s in data["jobs"]["summary"]["steps"] if "id" in s and "run" in s}
        cls.summary_script = steps["aggregate"]

    def run_summary(self, env_vars):
        with tempfile.NamedTemporaryFile("w", delete=False) as out_f:
            out_path = out_f.name
        try:
            env = dict(os.environ)
            env["GITHUB_OUTPUT"] = out_path
            env.update(env_vars)
            res = subprocess.run(
                ["bash", "-c", self.summary_script],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            outputs = {}
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            outputs[k] = v
            return res.returncode, outputs
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_cloud_free_success_aggregation(self):
        rc, out = self.run_summary({
            "VALIDATE_RESULT": "success",
            "GCP_PLAN_RESULT": "skipped",
            "GCP_PLAN_STATUS": "skipped",
            "GCP_AUTH_STATUS": "disabled",
            "GCP_SEC_STATUS": "skipped",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "false",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "0",
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(out.get("plan-status"), "success")
        self.assertEqual(out.get("authorization-status"), "not-applicable")
        self.assertNotEqual(out.get("authorization-status"), "authorized")

    def test_validation_failure_propagation(self):
        rc, out = self.run_summary({
            "VALIDATE_RESULT": "failure",
            "GCP_PLAN_RESULT": "skipped",
            "GCP_PLAN_STATUS": "skipped",
            "GCP_AUTH_STATUS": "disabled",
            "GCP_SEC_STATUS": "skipped",
            "CF_PLAN_RESULT": "skipped",
            "CF_PLAN_STATUS": "skipped",
            "CF_SEC_STATUS": "skipped",
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertNotEqual(rc, 0)
        self.assertEqual(out.get("plan-status"), "failure")
        self.assertEqual(out.get("authorization-status"), "rejected")

    def test_cloud_free_failure_propagation(self):
        rc, out = self.run_summary({
            "VALIDATE_RESULT": "success",
            "GCP_PLAN_RESULT": "skipped",
            "GCP_PLAN_STATUS": "skipped",
            "GCP_AUTH_STATUS": "disabled",
            "GCP_SEC_STATUS": "skipped",
            "CF_PLAN_RESULT": "failure",
            "CF_PLAN_STATUS": "failure",
            "CF_SEC_STATUS": "failure",
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertNotEqual(rc, 0)
        self.assertEqual(out.get("plan-status"), "failure")
        self.assertEqual(out.get("authorization-status"), "rejected")


class TestGcpReferenceModuleStructure(unittest.TestCase):
    """Verifies that the GCP reference module meets all architectural requirements."""

    def test_required_files_exist(self):
        expected_files = [
            "versions.tf",
            "variables.tf",
            "main.tf",
            "outputs.tf",
            "tests/gcs_test.tftest.hcl",
            "README.md",
        ]
        for rel_path in expected_files:
            full_path = os.path.join(GCP_REF_MODULE, rel_path)
            self.assertTrue(os.path.isfile(full_path), f"Missing required file: {rel_path}")

    def test_terraform_version_requirement(self):
        versions_path = os.path.join(GCP_REF_MODULE, "versions.tf")
        with open(versions_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('required_version = ">= 1.7.0"', content)
        self.assertIn('backend "gcs" {}', content)

    def test_mock_provider_in_tests(self):
        test_path = os.path.join(GCP_REF_MODULE, "tests", "gcs_test.tftest.hcl")
        with open(test_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('mock_provider "google" {}', content)


if __name__ == "__main__":
    unittest.main()
