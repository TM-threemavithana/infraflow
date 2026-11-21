#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Consumer Onboarding & Adoption Contracts (Milestone G08.1)

Validates consumer onboarding configuration schema, validation rules, security
permission guards, path containment, and platform dependency pinning.
"""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Add repo root to sys.path and load validate-consumer.py via importlib
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import importlib.util
validator_path = REPO_ROOT / "scripts" / "validate-consumer.py"
spec = importlib.util.spec_from_file_location("validate_consumer", str(validator_path))
validate_consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_consumer)


class TestConsumerOnboardingContract(unittest.TestCase):
    """Unit tests for configuration validation logic in validate-consumer.py."""

    def setUp(self):
        self.valid_config = {
            "version": "1.0",
            "consumer_id": "test-service",
            "team": "platform-engineering",
            "workload_type": "general",
            "terraform_dir": "terraform",
            "environment": "dev",
            "adapter": "provider-neutral",
            "platform_ref": "TM-threemavithana/infraflow",
            "platform_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
            "terraform_version": "1.10.4",
            "security_controls": {
                "enforce_mandatory_scanners": True,
                "fail_on_destructive": False,
                "max_allowed_deletions": 25,
            },
        }

    def test_valid_config_passes(self):
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(self.valid_config, result)
        self.assertTrue(result.is_valid, f"Expected valid config to pass, got errors: {result.errors}")
        self.assertGreater(len(result.passes), 10)
        self.assertEqual(len(result.errors), 0)

    def test_missing_version_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        del cfg["version"]
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Contract Version" in e for e in result.errors))

    def test_unsupported_version_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["version"] = "2.0"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Unsupported schema version" in e for e in result.errors))

    def test_invalid_consumer_id_characters_rejected(self):
        invalid_ids = [
            "MyService",          # uppercase
            "test_service",       # underscore
            "-test-service",      # leading hyphen
            "test-service-",      # trailing hyphen
            "t",                  # too short (< 3 chars)
            "a" * 65,             # too long (> 64 chars)
            "test service",       # space
            "test$service",       # special char
        ]
        for bad_id in invalid_ids:
            with self.subTest(consumer_id=bad_id):
                cfg = copy.deepcopy(self.valid_config)
                cfg["consumer_id"] = bad_id
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("Consumer Identity" in e for e in result.errors))

    def test_missing_team_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["team"] = ""
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Consumer Team" in e for e in result.errors))

    def test_unsupported_workload_type_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["workload_type"] = "invalid-workload"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Workload Type" in e for e in result.errors))

    def test_valid_workload_types_accepted(self):
        for w_type in ["networking", "application", "data-platform", "general"]:
            with self.subTest(workload_type=w_type):
                cfg = copy.deepcopy(self.valid_config)
                cfg["workload_type"] = w_type
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertTrue(result.is_valid)

    def test_unsupported_environment_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["environment"] = "qa"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Environment" in e for e in result.errors))

    def test_unsupported_adapter_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["adapter"] = "oracle-cloud"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Adapter" in e for e in result.errors))

    def test_valid_adapters_accepted(self):
        for adp in ["provider-neutral", "aws", "gcp", "azure", "apply-simulation"]:
            with self.subTest(adapter=adp):
                cfg = copy.deepcopy(self.valid_config)
                cfg["adapter"] = adp
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertTrue(result.is_valid)

    def test_invalid_platform_ref_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["platform_ref"] = "rogue-org/infraflow"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Platform Reference" in e for e in result.errors))

    def test_mutable_platform_sha_rejected(self):
        mutable_refs = ["main", "master", "latest", "dev", "HEAD", "v0.5.0", "v1.0.0"]
        for bad_ref in mutable_refs:
            with self.subTest(platform_sha=bad_ref):
                cfg = copy.deepcopy(self.valid_config)
                cfg["platform_sha"] = bad_ref
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("Mutable reference" in e or "Invalid commit SHA" in e for e in result.errors))

    def test_malformed_platform_sha_length_or_charset_rejected(self):
        bad_shas = [
            "2ce0ddd",                                      # short (7 chars)
            "2CE0DDD5DE01530B6BF7ABA749F0081620FB9B27",      # uppercase
            "2ce0ddd5de01530b6bf7aba749f0081620fb9b2z",      # 'z' not hex
            "2ce0ddd5de01530b6bf7aba749f0081620fb9b27a",     # 41 chars
        ]
        for bad_sha in bad_shas:
            with self.subTest(sha=bad_sha):
                cfg = copy.deepcopy(self.valid_config)
                cfg["platform_sha"] = bad_sha
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("Invalid commit SHA" in e for e in result.errors))

    def test_terraform_version_below_1_6_0_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_version"] = "1.5.7"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("requires Terraform >= 1.6.0" in e for e in result.errors))

    def test_terraform_dir_path_traversal_rejected(self):
        traversals = ["../terraform", "../../etc", "terraform/../../secret", ".."]
        for bad_path in traversals:
            with self.subTest(path=bad_path):
                cfg = copy.deepcopy(self.valid_config)
                cfg["terraform_dir"] = bad_path
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("Path traversal" in e for e in result.errors))

    def test_terraform_dir_absolute_and_tilde_paths_rejected(self):
        bad_paths = ["/etc/terraform", "\\windows\\system32", "~/my-terraform"]
        for bad_path in bad_paths:
            with self.subTest(path=bad_path):
                cfg = copy.deepcopy(self.valid_config)
                cfg["terraform_dir"] = bad_path
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("Absolute path" in e or "Tilde path" in e for e in result.errors))

    def test_disabling_mandatory_scanners_strictly_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["security_controls"]["enforce_mandatory_scanners"] = False
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Mandatory Scanners" in e for e in result.errors))

    def test_deletion_ceiling_exceeded_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["security_controls"]["max_allowed_deletions"] = 50
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Deletion Ceiling" in e for e in result.errors))

    def test_cloud_auth_settings_fail_closed(self):
        bad_settings = ["enable-aws-auth", "enable-gcp-auth", "enable-azure-auth"]
        for s in bad_settings:
            with self.subTest(setting=s):
                cfg = copy.deepcopy(self.valid_config)
                cfg[s] = True
                result = validate_consumer.ValidationResult()
                validate_consumer.validate_consumer_config(cfg, result)
                self.assertFalse(result.is_valid)
                self.assertTrue(any("Disallowed cloud auth setting" in e for e in result.errors))

    def test_unknown_top_level_keys_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["arbitrary_unknown_key"] = "malicious_payload"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Unknown configuration keys" in e for e in result.errors))


class TestConsumerFilesystemAndWorkflowValidation(unittest.TestCase):
    """Tests for repository directory containment, symlink security, and workflow checks."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-test-consumer-")
        self.repo_dir = Path(self.tmp_dir)

        # Create basic directory structure
        self.tf_dir = self.repo_dir / "terraform"
        self.tf_dir.mkdir(parents=True, exist_ok=True)
        (self.tf_dir / "main.tf").write_text('resource "terraform_data" "x" {}', encoding="utf-8")

        self.wf_dir = self.repo_dir / ".github" / "workflows"
        self.wf_dir.mkdir(parents=True, exist_ok=True)

        self.valid_config = {
            "version": "1.0",
            "consumer_id": "test-fs-consumer",
            "team": "platform-engineering",
            "workload_type": "general",
            "terraform_dir": "terraform",
            "environment": "dev",
            "adapter": "provider-neutral",
            "platform_ref": "TM-threemavithana/infraflow",
            "platform_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
            "terraform_version": "1.10.4",
            "security_controls": {
                "enforce_mandatory_scanners": True,
                "fail_on_destructive": False,
                "max_allowed_deletions": 25,
            },
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_valid_filesystem_and_workflow_passes(self):
        wf_content = """name: "CI"
on: [pull_request]
permissions:
  contents: read
jobs:
  val:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
"""
        (self.wf_dir / "ci.yml").write_text(wf_content, encoding="utf-8")
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_filesystem(self.valid_config, self.repo_dir, result)
        self.assertTrue(result.is_valid, f"Expected valid filesystem to pass, got errors: {result.errors}")

    def test_missing_terraform_dir_fails(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_dir"] = "non-existent-dir"
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_filesystem(cfg, self.repo_dir, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("does not exist inside repository" in e for e in result.errors))

    def test_symlinked_terraform_dir_rejected(self):
        outside_dir = tempfile.mkdtemp(prefix="outside-tf-")
        symlink_target = self.repo_dir / "symlinked-tf"
        try:
            os.symlink(outside_dir, symlink_target)
            cfg = copy.deepcopy(self.valid_config)
            cfg["terraform_dir"] = "symlinked-tf"
            result = validate_consumer.ValidationResult()
            validate_consumer.validate_consumer_filesystem(cfg, self.repo_dir, result)
            self.assertFalse(result.is_valid)
            self.assertTrue(any("cannot be a symlink" in e for e in result.errors))
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    def test_excessive_write_all_permissions_rejected(self):
        wf_content = """name: "CI"
on: [pull_request]
permissions: write-all
jobs:
  val:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
"""
        (self.wf_dir / "ci.yml").write_text(wf_content, encoding="utf-8")
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_filesystem(self.valid_config, self.repo_dir, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("write-all" in e for e in result.errors))

    def test_pull_request_target_trigger_rejected(self):
        wf_content = """name: "CI"
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
jobs:
  val:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
"""
        (self.wf_dir / "ci.yml").write_text(wf_content, encoding="utf-8")
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_filesystem(self.valid_config, self.repo_dir, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("pull_request_target" in e for e in result.errors))

    def test_mutable_platform_ref_in_workflow_rejected(self):
        wf_content = """name: "CI"
on: [pull_request]
permissions:
  contents: read
jobs:
  val:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@main
"""
        (self.wf_dir / "ci.yml").write_text(wf_content, encoding="utf-8")
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_filesystem(self.valid_config, self.repo_dir, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("mutable ref '@main'" in e for e in result.errors))

    def test_mismatched_sha_between_workflow_and_config_rejected(self):
        wf_content = """name: "CI"
on: [pull_request]
permissions:
  contents: read
jobs:
  val:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@59500fddecd40cf50d4b53e1852b5aca8ed8f192
"""
        (self.wf_dir / "ci.yml").write_text(wf_content, encoding="utf-8")
        result = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_filesystem(self.valid_config, self.repo_dir, result)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Hashes must match" in e for e in result.errors))


class TestConsumerOnboardingCLIIntegration(unittest.TestCase):
    """End-to-end integration tests executing scripts/validate-consumer.py via CLI."""

    def test_cli_onboarding_template_passes(self):
        template_cfg = REPO_ROOT / "templates" / "consumer-repository" / "infraflow.config.yaml"
        template_dir = REPO_ROOT / "templates" / "consumer-repository"
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "validate-consumer.py"), "--config", str(template_cfg), "--repo-dir", str(template_dir)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"Validator failed on template: {proc.stdout}\n{proc.stderr}")
        self.assertIn("ALL CONSUMER ONBOARDING CHECKS PASSED", proc.stdout)

    def test_cli_reference_fixtures_pass(self):
        fixtures = ["networking", "application", "data-platform"]
        for fix in fixtures:
            with self.subTest(fixture=fix):
                cfg_path = REPO_ROOT / "fixtures" / "consumers" / fix / "infraflow.config.yaml"
                repo_path = REPO_ROOT / "fixtures" / "consumers" / fix
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "scripts" / "validate-consumer.py"), "--config", str(cfg_path), "--repo-dir", str(repo_path)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, f"Validator failed on fixture '{fix}': {proc.stdout}\n{proc.stderr}")
                self.assertIn("ALL CONSUMER ONBOARDING CHECKS PASSED", proc.stdout)

    def test_cli_json_mode_output(self):
        template_cfg = REPO_ROOT / "templates" / "consumer-repository" / "infraflow.config.yaml"
        template_dir = REPO_ROOT / "templates" / "consumer-repository"
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "validate-consumer.py"), "--config", str(template_cfg), "--repo-dir", str(template_dir), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data["valid"])
        self.assertEqual(data["summary"]["failed"], 0)
        self.assertGreater(data["summary"]["passed"], 10)

    def test_cli_missing_config_returns_exit_code_1(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "validate-consumer.py"), "--config", "/non/existent/path/infraflow.config.yaml"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Configuration file not found", proc.stdout)


if __name__ == "__main__":
    unittest.main()
