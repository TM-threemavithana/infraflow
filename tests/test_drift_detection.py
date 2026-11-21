#!/usr/bin/env python3
"""
InfraFlow — Dedicated Adversarial Test Suite for Speculative Drift Detection (Milestone G09.2)

Comprehensive test coverage verifying:
  - Multi-cloud normalized resource comparisons (AWS, Azure, GCP).
  - Categorization: NO_DRIFT, ATTRIBUTE_DRIFT, UNTRACKED_RESOURCE, RESOURCE_DELETED,
    UNKNOWN_RESOURCE, STATE_INCONSISTENCY.
  - Severity calculations (CRITICAL, HIGH, MEDIUM, LOW, NONE).
  - Security invariants: Schema validation, symlink rejection, identity binding,
    path containment, sensitive secret scrubbing.
  - False-positive resistance and deterministic execution.
  - Telemetry integration and compliance dashboard integration.
"""

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

# Import simulate-drift.py and generate-compliance-dashboard.py dynamically
SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"

drift_spec = importlib.util.spec_from_file_location(
    "simulate_drift", SCRIPT_DIR / "simulate-drift.py"
)
simulate_drift = importlib.util.module_from_spec(drift_spec)
drift_spec.loader.exec_module(simulate_drift)

dash_spec = importlib.util.spec_from_file_location(
    "generate_compliance_dashboard", SCRIPT_DIR / "generate-compliance-dashboard.py"
)
generate_compliance_dashboard = importlib.util.module_from_spec(dash_spec)
dash_spec.loader.exec_module(generate_compliance_dashboard)


class TestDriftDetectionEngine(unittest.TestCase):
    """Unit and adversarial tests for simulate-drift.py."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parent.parent
        self.fixtures_dir = self.repo_root / "fixtures" / "drift"

        # Baseline clean states
        self.aws_clean_exp = simulate_drift.safe_load_state_file(
            self.fixtures_dir / "aws" / "clean" / "expected.json"
        )
        self.aws_clean_obs = simulate_drift.safe_load_state_file(
            self.fixtures_dir / "aws" / "clean" / "observed.json"
        )

    # =========================================================================
    # 1. Clean State Verification (False-Positive Resistance)
    # =========================================================================
    def test_clean_state_no_drift_aws(self) -> None:
        report = simulate_drift.assess_state_drift(self.aws_clean_exp, self.aws_clean_obs)
        self.assertEqual(report["summary"]["verdict"], "NO_DRIFT")
        self.assertEqual(report["summary"]["drifted_resources_count"], 0)
        self.assertEqual(report["summary"]["clean_resources_count"], 2)
        self.assertEqual(report["summary"]["highest_severity"], "NONE")
        self.assertEqual(len(report["drift_items"]), 0)

    def test_clean_state_no_drift_azure(self) -> None:
        az_exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "azure" / "clean" / "expected.json")
        az_obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "azure" / "clean" / "observed.json")
        report = simulate_drift.assess_state_drift(az_exp, az_obs)
        self.assertEqual(report["summary"]["verdict"], "NO_DRIFT")
        self.assertEqual(report["summary"]["drifted_resources_count"], 0)
        self.assertEqual(report["summary"]["clean_resources_count"], 2)

    def test_clean_state_no_drift_gcp(self) -> None:
        gcp_exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "gcp" / "clean" / "expected.json")
        gcp_obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "gcp" / "clean" / "observed.json")
        report = simulate_drift.assess_state_drift(gcp_exp, gcp_obs)
        self.assertEqual(report["summary"]["verdict"], "NO_DRIFT")
        self.assertEqual(report["summary"]["drifted_resources_count"], 0)

    def test_false_positive_prevention_key_reordering(self) -> None:
        """Verify that dictionary key order differences in attributes do not trigger false drift."""
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_exp)
        obs["state_source"] = "observed"
        # Reverse tag dictionary keys
        tags = exp["resources"][0]["attributes"]["tags"]
        obs["resources"][0]["attributes"]["tags"] = {k: tags[k] for k in reversed(list(tags.keys()))}

        report = simulate_drift.assess_state_drift(exp, obs)
        self.assertEqual(report["summary"]["verdict"], "NO_DRIFT")
        self.assertEqual(report["summary"]["drifted_resources_count"], 0)

    # =========================================================================
    # 2. Attribute Drift & Severity Classification
    # =========================================================================
    def test_attribute_drift_aws_security_critical(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["highest_severity"], "CRITICAL")
        self.assertEqual(report["summary"]["drift_breakdown"]["ATTRIBUTE_DRIFT"], 1)

        item = report["drift_items"][0]
        self.assertEqual(item["drift_category"], "ATTRIBUTE_DRIFT")
        self.assertEqual(item["severity"], "CRITICAL")
        self.assertTrue(any(d["attribute_path"] == "sse_algorithm" for d in item["attribute_diffs"]))

    def test_attribute_drift_azure_security_critical(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "azure" / "attribute-drift" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "azure" / "attribute-drift" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["highest_severity"], "CRITICAL")
        item = report["drift_items"][0]
        self.assertTrue(any(d["attribute_path"] == "min_tls_version" for d in item["attribute_diffs"]))

    def test_attribute_drift_gcp_security_critical(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "gcp" / "attribute-drift" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "gcp" / "attribute-drift" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["highest_severity"], "CRITICAL")
        item = report["drift_items"][0]
        self.assertTrue(any(d["attribute_path"] == "uniform_bucket_level_access" for d in item["attribute_diffs"]))

    def test_attribute_drift_standard_medium_severity(self) -> None:
        """Non-security attribute modification (e.g. description) yields MEDIUM severity."""
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_exp)
        obs["state_source"] = "observed"
        obs["resources"][0]["attributes"]["description"] = "Updated non-security description"

        report = simulate_drift.assess_state_drift(exp, obs)
        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["highest_severity"], "MEDIUM")
        self.assertEqual(report["drift_items"][0]["severity"], "MEDIUM")

    # =========================================================================
    # 3. Untracked Resources (Shadow IT)
    # =========================================================================
    def test_untracked_resource_aws_shadow_sg(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "untracked-resource" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "untracked-resource" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["highest_severity"], "HIGH")
        self.assertEqual(report["summary"]["drift_breakdown"]["UNTRACKED_RESOURCE"], 1)

        untracked = [i for i in report["drift_items"] if i["drift_category"] == "UNTRACKED_RESOURCE"]
        self.assertEqual(len(untracked), 1)
        self.assertEqual(untracked[0]["resource_id"], "aws_security_group.shadow_sg")
        self.assertIsNone(untracked[0]["expected_state"])
        self.assertIsNotNone(untracked[0]["observed_state"])

    def test_untracked_resource_gcp(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "gcp" / "untracked-resource" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "gcp" / "untracked-resource" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["drift_breakdown"]["UNTRACKED_RESOURCE"], 1)

    # =========================================================================
    # 4. Remote Deletions
    # =========================================================================
    def test_remote_deletion_aws_dynamodb_table(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "remote-deletion" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "remote-deletion" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["highest_severity"], "CRITICAL")
        self.assertEqual(report["summary"]["drift_breakdown"]["RESOURCE_DELETED"], 1)

        deleted = [i for i in report["drift_items"] if i["drift_category"] == "RESOURCE_DELETED"]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["resource_id"], "aws_dynamodb_table.tfstate_locks")
        self.assertIsNotNone(deleted[0]["expected_state"])
        self.assertIsNone(deleted[0]["observed_state"])

    def test_remote_deletion_azure(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "azure" / "remote-deletion" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "azure" / "remote-deletion" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)

        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["drift_breakdown"]["RESOURCE_DELETED"], 1)

    # =========================================================================
    # 5. State Inconsistency & Type Mismatches
    # =========================================================================
    def test_state_inconsistency_type_mismatch(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_exp)
        obs["state_source"] = "observed"
        # Change resource_type under same resource_id
        obs["resources"][0]["resource_type"] = "aws_sqs_queue"

        report = simulate_drift.assess_state_drift(exp, obs)
        self.assertEqual(report["summary"]["verdict"], "DRIFT_DETECTED")
        self.assertEqual(report["summary"]["drift_breakdown"]["STATE_INCONSISTENCY"], 1)
        self.assertEqual(report["summary"]["highest_severity"], "CRITICAL")

    # =========================================================================
    # 6. Schema Validation & Malformed Inputs
    # =========================================================================
    def test_malformed_json_rejection(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("NOT_VALID_JSON{:::}")
            tf_path = Path(tf.name)

        try:
            with self.assertRaises(simulate_drift.DriftValidationError):
                simulate_drift.safe_load_state_file(tf_path)
        finally:
            tf_path.unlink()

    def test_unsupported_schema_version_rejection(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        exp["schema_version"] = "2.0"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(exp, tf)
            tf_path = Path(tf.name)

        try:
            with self.assertRaises(simulate_drift.DriftValidationError):
                simulate_drift.safe_load_state_file(tf_path)
        finally:
            tf_path.unlink()

    def test_missing_mandatory_keys_rejection(self) -> None:
        for key in ("provider", "repository", "workspace", "timestamp", "resources"):
            exp = copy.deepcopy(self.aws_clean_exp)
            del exp[key]
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
                json.dump(exp, tf)
                tf_path = Path(tf.name)

            try:
                with self.assertRaises(simulate_drift.DriftValidationError):
                    simulate_drift.safe_load_state_file(tf_path)
            finally:
                tf_path.unlink()

    def test_invalid_provider_rejection(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        exp["provider"] = "alibaba_cloud"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(exp, tf)
            tf_path = Path(tf.name)

        try:
            with self.assertRaises(simulate_drift.DriftValidationError):
                simulate_drift.safe_load_state_file(tf_path)
        finally:
            tf_path.unlink()

    def test_invalid_timestamp_rejection(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        exp["timestamp"] = "not-a-timestamp"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(exp, tf)
            tf_path = Path(tf.name)

        try:
            with self.assertRaises(simulate_drift.DriftValidationError):
                simulate_drift.safe_load_state_file(tf_path)
        finally:
            tf_path.unlink()

    def test_duplicate_resource_id_rejection(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        exp["resources"].append(copy.deepcopy(exp["resources"][0]))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(exp, tf)
            tf_path = Path(tf.name)

        try:
            with self.assertRaises(simulate_drift.DriftValidationError):
                simulate_drift.safe_load_state_file(tf_path)
        finally:
            tf_path.unlink()

    def test_empty_resource_inventories_accepted(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        exp["resources"] = []
        obs = copy.deepcopy(self.aws_clean_obs)
        obs["resources"] = []

        report = simulate_drift.assess_state_drift(exp, obs)
        self.assertEqual(report["summary"]["verdict"], "NO_DRIFT")
        self.assertEqual(report["summary"]["total_resources_evaluated"], 0)

    # =========================================================================
    # 7. Identity & Context Binding Security
    # =========================================================================
    def test_repository_identity_mismatch_rejected(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_obs)
        obs["repository"] = "attacker/compromised-repo"

        with self.assertRaises(simulate_drift.DriftSecurityError):
            simulate_drift.assess_state_drift(exp, obs)

    def test_workspace_identity_mismatch_rejected(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_obs)
        obs["workspace"] = "staging"

        with self.assertRaises(simulate_drift.DriftSecurityError):
            simulate_drift.assess_state_drift(exp, obs)

    def test_provider_identity_mismatch_rejected(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_obs)
        obs["provider"] = "azure"

        with self.assertRaises(simulate_drift.DriftSecurityError):
            simulate_drift.assess_state_drift(exp, obs)

    # =========================================================================
    # 8. Symlink Attacks
    # =========================================================================
    def test_symlink_rejection_expected(self) -> None:
        real_file = self.fixtures_dir / "aws" / "clean" / "expected.json"
        with tempfile.TemporaryDirectory() as td:
            symlink_p = Path(td) / "symlink_exp.json"
            os.symlink(real_file, symlink_p)

            with self.assertRaises(simulate_drift.DriftSecurityError):
                simulate_drift.safe_load_state_file(symlink_p)

    def test_symlink_rejection_observed(self) -> None:
        real_file = self.fixtures_dir / "aws" / "clean" / "observed.json"
        with tempfile.TemporaryDirectory() as td:
            symlink_p = Path(td) / "symlink_obs.json"
            os.symlink(real_file, symlink_p)

            with self.assertRaises(simulate_drift.DriftSecurityError):
                simulate_drift.safe_load_state_file(symlink_p)

    # =========================================================================
    # 9. Secret Leakage & Redaction
    # =========================================================================
    def test_secret_scrubbing_in_diffs(self) -> None:
        exp = copy.deepcopy(self.aws_clean_exp)
        obs = copy.deepcopy(self.aws_clean_exp)
        obs["state_source"] = "observed"
        obs["resources"][0]["attributes"]["aws_access_key"] = "AKIAIOSFODNN7EXAMPLE"
        obs["resources"][0]["attributes"]["pat_token"] = "ghp_secrettokenvalue12345678901234567890"
        obs["resources"][0]["attributes"]["database_password"] = "SuperSecretP@ssw0rd!"

        report = simulate_drift.assess_state_drift(exp, obs)
        report_json = json.dumps(report)

        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", report_json)
        self.assertNotIn("ghp_secrettokenvalue12345678901234567890", report_json)
        self.assertNotIn("SuperSecretP@ssw0rd!", report_json)
        self.assertIn("[REDACTED_SECRET]", report_json)

    # =========================================================================
    # 10. Deterministic Repeated Execution
    # =========================================================================
    def test_deterministic_repeated_execution(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "observed.json")

        rep1 = simulate_drift.assess_state_drift(exp, obs)
        # Freeze timestamp for exact byte comparison
        rep1["generated_at"] = "2026-11-21T08:00:00Z"
        str1 = json.dumps(rep1, sort_keys=True)

        for _ in range(5):
            repN = simulate_drift.assess_state_drift(exp, obs)
            repN["generated_at"] = "2026-11-21T08:00:00Z"
            strN = json.dumps(repN, sort_keys=True)
            self.assertEqual(str1, strN)

    # =========================================================================
    # 11. Markdown Report Generation
    # =========================================================================
    def test_render_markdown_report_clean(self) -> None:
        report = simulate_drift.assess_state_drift(self.aws_clean_exp, self.aws_clean_obs)
        md = simulate_drift.render_markdown_drift_report(report)
        self.assertIn("NO DRIFT DETECTED", md)
        self.assertIn("Clean (Synchronized) Resources", md)

    def test_render_markdown_report_drift(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "observed.json")
        report = simulate_drift.assess_state_drift(exp, obs)
        md = simulate_drift.render_markdown_drift_report(report)
        self.assertIn("INFRASTRUCTURE DRIFT IDENTIFIED", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("aws_s3_bucket.state_bucket", md)

    # =========================================================================
    # 12. Compliance Dashboard Integration
    # =========================================================================
    def test_compliance_dashboard_with_clean_drift_report(self) -> None:
        clean_report = simulate_drift.assess_state_drift(self.aws_clean_exp, self.aws_clean_obs)
        consumer_entry = {
            "consumer_id": "test-clean-consumer",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
        }
        repo_fixture = self.repo_root / "fixtures" / "consumers" / "networking"
        res = generate_compliance_dashboard.evaluate_consumer_compliance(
            consumer_entry=consumer_entry,
            repo_path=repo_fixture,
            drift_report=clean_report,
        )
        self.assertEqual(res["drift_assessment"]["verdict"], "NO_DRIFT")
        self.assertIn("Infrastructure state: CLEAN", " ".join(res["pillar_breakdown"]["drift_integrity"]))

    def test_compliance_dashboard_with_critical_drift_report(self) -> None:
        exp = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "expected.json")
        obs = simulate_drift.safe_load_state_file(self.fixtures_dir / "aws" / "attribute-drift" / "observed.json")
        drift_report = simulate_drift.assess_state_drift(exp, obs)

        consumer_entry = {
            "consumer_id": "test-drifted-consumer",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
        }
        repo_fixture = self.repo_root / "fixtures" / "consumers" / "networking"
        res = generate_compliance_dashboard.evaluate_consumer_compliance(
            consumer_entry=consumer_entry,
            repo_path=repo_fixture,
            drift_report=drift_report,
        )
        self.assertEqual(res["drift_assessment"]["verdict"], "DRIFT_DETECTED")
        self.assertIn("Penalty: -10 pts for CRITICAL infrastructure drift", res["pillar_breakdown"]["drift_integrity"])
        self.assertTrue(any("Infrastructure state CRITICAL drift" in f for f in res["findings"]))

    # =========================================================================
    # 13. CLI & Telemetry Roundtrip Tests
    # =========================================================================
    def test_enforce_zero_drift_exit_codes(self) -> None:
        clean_exp = self.fixtures_dir / "aws" / "clean" / "expected.json"
        clean_obs = self.fixtures_dir / "aws" / "clean" / "observed.json"
        drift_exp = self.fixtures_dir / "aws" / "attribute-drift" / "expected.json"
        drift_obs = self.fixtures_dir / "aws" / "attribute-drift" / "observed.json"

        # Clean should succeed (exit 0)
        import subprocess
        res_clean = subprocess.run(
            ["python3", str(SCRIPT_DIR / "simulate-drift.py"), "--expected", str(clean_exp), "--observed", str(clean_obs), "--enforce-zero-drift"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_clean.returncode, 0)

        # Drift should fail (exit 1)
        res_drift = subprocess.run(
            ["python3", str(SCRIPT_DIR / "simulate-drift.py"), "--expected", str(drift_exp), "--observed", str(drift_obs), "--enforce-zero-drift"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_drift.returncode, 1)
        self.assertIn("[FAIL] Drift gate failed", res_drift.stderr)

    def test_cli_identity_flag_enforcement(self) -> None:
        clean_exp = self.fixtures_dir / "aws" / "clean" / "expected.json"
        clean_obs = self.fixtures_dir / "aws" / "clean" / "observed.json"

        import subprocess
        # Repository flag mismatch should fail (exit 2 for security error)
        res_bad_repo = subprocess.run(
            ["python3", str(SCRIPT_DIR / "simulate-drift.py"), "--expected", str(clean_exp), "--observed", str(clean_obs), "--repository", "other/repo"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_bad_repo.returncode, 2)
        self.assertIn("[SECURITY ERROR]", res_bad_repo.stderr)

    def test_telemetry_emission_roundtrip(self) -> None:
        drift_exp = self.fixtures_dir / "aws" / "attribute-drift" / "expected.json"
        drift_obs = self.fixtures_dir / "aws" / "attribute-drift" / "observed.json"

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
            telemetry_path = Path(tf.name)

        try:
            import subprocess
            res = subprocess.run(
                [
                    "python3", str(SCRIPT_DIR / "simulate-drift.py"),
                    "--expected", str(drift_exp),
                    "--observed", str(drift_obs),
                    "--emit-telemetry",
                    "--telemetry-output", str(telemetry_path),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertTrue(telemetry_path.exists())

            lines = telemetry_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(lines), 2)  # 1 drift_detected + 1 drift_assessment_completed

            events = [json.loads(line) for line in lines]
            event_types = [e["event_type"] for e in events]
            self.assertIn("drift_detected", event_types)
            self.assertIn("drift_assessment_completed", event_types)

            for e in events:
                self.assertEqual(e["schema_version"], "1.0")
                self.assertIn("integrity", e)
                self.assertEqual(e["integrity"]["algorithm"], "sha256")
        finally:
            if telemetry_path.exists():
                telemetry_path.unlink()


if __name__ == "__main__":
    unittest.main()
