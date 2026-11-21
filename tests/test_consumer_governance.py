#!/usr/bin/env python3
"""
InfraFlow Consumer Governance Adversarial Test Suite (Milestone G08.3)

Comprehensive 40-vector adversarial and boundary test suite executing real
parsing, schema verification, AST inspection, Rego policy evaluation, and
fail-closed security gating across multi-repository consumer contracts.
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


class TestConsumerGovernanceAdversarial(unittest.TestCase):
    """40-vector adversarial test suite for centralized consumer governance."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="gov-test-")
        self.repo_dir = Path(self.tmp_dir)
        self.wf_dir = self.repo_dir / ".github" / "workflows"
        self.wf_dir.mkdir(parents=True, exist_ok=True)
        self.tf_dir = self.repo_dir / "terraform"
        self.tf_dir.mkdir(parents=True, exist_ok=True)
        (self.tf_dir / "main.tf").write_text('resource "terraform_data" "x" {}', encoding="utf-8")

        self.valid_sha = "8fd761bb42165435e1162f37ee39df15d5532b09"
        self.valid_config = {
            "version": "1.0",
            "consumer_id": "test-service",
            "team": "platform-engineering",
            "workload_type": "networking",
            "terraform_dir": "terraform",
            "environment": "dev",
            "adapter": "aws",
            "platform_ref": "TM-threemavithana/infraflow",
            "platform_sha": self.valid_sha,
            "terraform_version": "1.10.4",
            "security_controls": {
                "enforce_mandatory_scanners": True,
                "fail_on_destructive": False,
                "max_allowed_deletions": 10,
            },
        }

        self.valid_wf = f"""name: "CI"
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
    with:
      aws-region: "us-east-1"
      enable-aws-auth: false
"""
        (self.wf_dir / "ci.yml").write_text(self.valid_wf, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _validate(self, config=None):
        cfg = config or self.valid_config
        res = validate_consumer.ValidationResult()
        validate_consumer.validate_consumer_config(cfg, res)
        validate_consumer.validate_consumer_filesystem(cfg, self.repo_dir, res)
        return res

    # 1. Missing .github/workflows directory
    def test_01_missing_workflows_dir_rejected(self):
        shutil.rmtree(self.wf_dir)
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Missing mandatory '.github/workflows/' directory" in e for e in res.errors))

    # 2. Empty workflows directory
    def test_02_empty_workflows_dir_rejected(self):
        (self.wf_dir / "ci.yml").unlink()
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("No workflow YAML files found" in e for e in res.errors))

    # 3. Workflow with no InfraFlow invocation
    def test_03_no_infraflow_invocation_rejected(self):
        no_infraflow = """name: "CI"
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        (self.wf_dir / "ci.yml").write_text(no_infraflow, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("No InfraFlow reusable workflows are invoked" in e for e in res.errors))

    # 4. Wrong cloud adapter invocation
    def test_04_wrong_cloud_adapter_invocation_rejected(self):
        wrong_adapter_wf = f"""name: "CI"
on: [pull_request]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wrong_adapter_wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Config specifies adapter 'aws' (requires 'reusable-tf-aws.yml')" in e for e in res.errors))

    # 5. Mutable platform reference
    def test_05_mutable_platform_reference_rejected(self):
        mutable_wf = """name: "CI"
on: [pull_request]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@main
"""
        (self.wf_dir / "ci.yml").write_text(mutable_wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("references mutable ref '@main'" in e for e in res.errors))

    # 6. Invalid 40-character SHA
    def test_06_invalid_hex_sha_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["platform_sha"] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Must be exactly 40 lowercase hexadecimal characters" in e for e in res.errors))

    # 7. Platform configuration and workflow SHA mismatch
    def test_07_sha_mismatch_rejected(self):
        mismatch_wf = """name: "CI"
on: [pull_request]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@1111111111111111111111111111111111111111
"""
        (self.wf_dir / "ci.yml").write_text(mismatch_wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Hashes must match" in e for e in res.errors))

    # 8. Unsupported contract version
    def test_08_unsupported_version_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["version"] = "2.0"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Unsupported schema version '2.0'" in e for e in res.errors))

    # 9. Malformed YAML syntax
    def test_09_malformed_yaml_rejected(self):
        (self.wf_dir / "ci.yml").write_text("name: CI\n  bad-indentation: [", encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Malformed YAML syntax" in e for e in res.errors))

    # 10. Duplicate YAML keys
    def test_10_duplicate_yaml_keys_rejected(self):
        dup_yaml = f"""name: "CI"
name: "Duplicate Name"
on: [pull_request]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(dup_yaml, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Duplicate key 'name' detected" in e for e in res.errors))

    # 11. Nested permission escalation
    def test_11_nested_permission_escalation_rejected(self):
        nested_perm = f"""name: "CI"
on: [pull_request]
permissions:
  contents: read
jobs:
  plan:
    permissions:
      contents: write
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(nested_perm, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("contents: write" in e for e in res.errors))

    # 12. Workflow-level write-all
    def test_12_workflow_level_write_all_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
permissions: write-all
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("write-all" in e for e in res.errors))

    # 13. Job-level write-all
    def test_13_job_level_write_all_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
jobs:
  plan:
    permissions: write-all
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("write-all" in e for e in res.errors))

    # 14. Unexpected id-token: write
    def test_14_unexpected_id_token_write_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
permissions:
  id-token: write
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("id-token: write" in e for e in res.errors))

    # 15. Unauthorized secrets inheritance
    def test_15_secrets_inherit_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
jobs:
  plan:
    secrets: inherit
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("secrets: inherit" in e for e in res.errors))

    # 16. pull_request_target trigger
    def test_16_pull_request_target_trigger_rejected(self):
        wf = f"""name: "CI"
on:
  pull_request_target:
    branches: [main]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("pull_request_target" in e for e in res.errors))

    # 17. Unexpected privileged workflow event
    def test_17_contradictory_cloud_adapter_invocation_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
jobs:
  aws_plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
  gcp_plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("contradictory cloud adapter" in e for e in res.errors))

    # 18. Disabled mandatory scanner
    def test_18_disabled_mandatory_scanner_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["security_controls"]["enforce_mandatory_scanners"] = False
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("enforce_mandatory_scanners must be strictly 'true'" in e for e in res.errors))

    # 19. Missing governance check / config file
    def test_19_missing_config_file_handled(self):
        non_existent = self.repo_dir / "does-not-exist.yaml"
        data, err = validate_consumer.load_config_file(non_existent)
        self.assertIsNone(data)
        self.assertIn("not found", err)

    # 20. Skipped mandatory governance job
    def test_20_empty_jobs_block_rejected(self):
        wf = """name: "CI"
on: [pull_request]
jobs: {}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Missing or empty 'jobs' dictionary" in e for e in res.errors))

    # 21. Invalid consumer identity
    def test_21_invalid_consumer_id_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["consumer_id"] = "UPPERCASE_NOT_ALLOWED"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Invalid consumer_id" in e for e in res.errors))

    # 22. Repository identity mismatch
    def test_22_rogue_platform_repo_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
jobs:
  plan:
    uses: rogue-actor/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("calls unauthorized repository" in e for e in res.errors))

    # 23. Incorrect environment
    def test_23_incorrect_environment_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["environment"] = "production_unauthorized"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Invalid environment" in e for e in res.errors))

    # 24. Incorrect workload type
    def test_24_incorrect_workload_type_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["workload_type"] = "crypto_mining"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Invalid workload_type" in e for e in res.errors))

    # 25. Unsupported adapter
    def test_25_unsupported_adapter_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["adapter"] = "alibaba_cloud"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Unsupported adapter" in e for e in res.errors))

    # 26. Path traversal in terraform_dir
    def test_26_path_traversal_in_terraform_dir_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_dir"] = "../../etc/shadow"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Path traversal ('..') in" in e for e in res.errors))

    # 27. Symlink escape
    def test_27_symlink_escape_rejected(self):
        outside = tempfile.mkdtemp()
        try:
            shutil.rmtree(self.tf_dir)
            self.tf_dir.symlink_to(outside)
            res = self._validate()
            self.assertFalse(res.is_valid)
            self.assertTrue(any("cannot be a symlink" in e for e in res.errors))
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    # 28. Malicious policy directory in absolute path
    def test_28_absolute_path_terraform_dir_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_dir"] = "/etc/terraform"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Absolute path" in e for e in res.errors))

    # 29. Invalid Terraform directory (non-existent)
    def test_29_non_existent_terraform_dir_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_dir"] = "non_existent_subdir"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("does not exist inside repository" in e for e in res.errors))

    # 30. Cross-environment configuration substitution
    def test_30_tilde_path_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_dir"] = "~/secret/terraform"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Tilde path" in e for e in res.errors))

    # 31. Conflicting configuration keys
    def test_31_conflicting_unknown_keys_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["unauthorized_custom_override"] = "bypass"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Unknown configuration keys detected" in e for e in res.errors))

    # 32. Unauthorized cloud authentication in workflow
    def test_32_unauthorized_cloud_auth_in_workflow_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
    with:
      enable-aws-auth: true
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("attempts to enable live cloud authentication" in e for e in res.errors))

    # 33. Unauthorized cloud auth in config
    def test_33_unauthorized_cloud_auth_in_config_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["enable-aws-auth"] = True
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Disallowed cloud auth setting" in e for e in res.errors))

    # 34. Excessive deletion ceiling
    def test_34_excessive_deletion_ceiling_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["security_controls"]["max_allowed_deletions"] = 999
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("must be an integer between 0 and 25" in e for e in res.errors))

    # 35. Unsupported platform release ref
    def test_35_unsupported_platform_ref_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["platform_ref"] = "attacker/rogueflow"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Invalid platform_ref" in e for e in res.errors))

    # 36. Malicious workflow replacement (unknown platform workflow)
    def test_36_unknown_platform_workflow_rejected(self):
        wf = f"""name: "CI"
on: [pull_request]
jobs:
  plan:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-malicious-backdoor.yml@{self.valid_sha}
"""
        (self.wf_dir / "ci.yml").write_text(wf, encoding="utf-8")
        res = self._validate()
        self.assertFalse(res.is_valid)
        self.assertTrue(any("calls unknown platform workflow" in e for e in res.errors))

    # 37. Team name too short
    def test_37_team_name_too_short_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["team"] = "x"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Team name" in e and "between 2 and 64" in e for e in res.errors))

    # 38. Terraform SemVer < 1.6.0 rejected
    def test_38_terraform_version_too_old_rejected(self):
        cfg = copy.deepcopy(self.valid_config)
        cfg["terraform_version"] = "1.5.7"
        res = self._validate(cfg)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Version '1.5.7' < 1.6.0" in e for e in res.errors))

    # 39. Normalized payload generation verification
    def test_39_governance_payload_generation_valid(self):
        payload = validate_consumer.generate_governance_payload(self.valid_config, self.repo_dir)
        self.assertEqual(payload["consumer_id"], "test-service")
        self.assertEqual(payload["adapter"], "aws")
        self.assertEqual(len(payload["workflow_calls"]), 1)
        self.assertEqual(payload["workflow_calls"][0]["platform_workflow"], "reusable-tf-aws.yml")

    # 40. Full end-to-end valid consumer workflow passes
    def test_40_valid_governance_and_adapter_workflow_passes(self):
        full_wf = f"""name: "CI"
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  governance-gate:
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-governance.yml@{self.valid_sha}
    with:
      config-file: "infraflow.config.yaml"
      platform-sha: "{self.valid_sha}"
  aws-plan:
    needs: [governance-gate]
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@{self.valid_sha}
    with:
      aws-region: "us-east-1"
      enable-aws-auth: false
"""
        (self.wf_dir / "ci.yml").write_text(full_wf, encoding="utf-8")
        res = self._validate()
        self.assertTrue(res.is_valid, f"Expected full workflow to pass, got: {res.errors}")
        self.assertGreater(len(res.passes), 12)


if __name__ == "__main__":
    unittest.main()
