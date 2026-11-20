#!/usr/bin/env python3
"""
InfraFlow — GCP Plan Metrics & Output Contract Regression Test Suite
Milestone: G07.4 Finalization — Output Contract Verification

Tests comprehensive validation of plan change metrics, JSON path extraction,
strict typing, consistency rules, and failure propagation:
1. No-change plan analysis
2. Single resource creation
3. Multiple resource modifications
4. Destructive replacement & deletion classification
5. Missing total-changes field fail-closed rejection
6. Invalid metric type fail-closed rejection
7. Inconsistent boolean and numeric outputs rejection
8. Correct propagation through the workflow summary
"""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ANALYZER_SCRIPT = os.path.join(REPO_ROOT, "scripts", "analyze-plan.py")
REUSABLE_GCP_WF = os.path.join(REPO_ROOT, ".github", "workflows", "reusable-tf-gcp.yml")

# Dynamically import analyze-plan.py
spec = importlib.util.spec_from_file_location("analyze_plan_module", ANALYZER_SCRIPT)
analyzer_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer_mod)
analyze_plan = analyzer_mod.analyze_plan


def make_synthetic_plan(resource_changes=None, output_changes=None):
    """Generates a valid synthetic Terraform 1.x plan dictionary."""
    return {
        "format_version": "1.2",
        "terraform_version": "1.10.4",
        "resource_changes": resource_changes or [],
        "output_changes": output_changes or {},
    }


class TestGcpPlanMetricsAnalysis(unittest.TestCase):
    """Executes actual analyze-plan code against synthetic plans."""

    def test_01_no_change_plan(self):
        plan = make_synthetic_plan([])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(plan, f)
            p_path = f.name
        try:
            summary = analyze_plan(p_path)
            metrics = summary.get("metrics", {})
            self.assertEqual(metrics.get("total_changes"), 0)
            self.assertEqual(metrics.get("create"), 0)
            self.assertEqual(metrics.get("update"), 0)
            self.assertEqual(metrics.get("delete"), 0)
            self.assertEqual(metrics.get("replace"), 0)
            self.assertFalse(summary.get("has_changes"))
            self.assertFalse(summary.get("has_destructive_changes"))
        finally:
            os.unlink(p_path)

    def test_02_single_resource_creation(self):
        plan = make_synthetic_plan([
            {
                "address": "google_storage_bucket.state",
                "type": "google_storage_bucket",
                "name": "state",
                "change": {"actions": ["create"], "after": {"name": "test-bucket"}},
            }
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(plan, f)
            p_path = f.name
        try:
            summary = analyze_plan(p_path)
            metrics = summary.get("metrics", {})
            self.assertEqual(metrics.get("create"), 1)
            self.assertEqual(metrics.get("total_changes"), 1)
            self.assertTrue(summary.get("has_changes"))
            self.assertFalse(summary.get("has_destructive_changes"))
        finally:
            os.unlink(p_path)

    def test_03_multiple_resource_modifications(self):
        plan = make_synthetic_plan([
            {
                "address": "google_storage_bucket.bucket1",
                "type": "google_storage_bucket",
                "name": "bucket1",
                "change": {"actions": ["create"]},
            },
            {
                "address": "google_storage_bucket.bucket2",
                "type": "google_storage_bucket",
                "name": "bucket2",
                "change": {"actions": ["create"]},
            },
            {
                "address": "google_service_account.sa",
                "type": "google_service_account",
                "name": "sa",
                "change": {"actions": ["update"]},
            },
            {
                "address": "google_project.proj",
                "type": "google_project",
                "name": "proj",
                "change": {"actions": ["no-op"]},
            },
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(plan, f)
            p_path = f.name
        try:
            summary = analyze_plan(p_path)
            metrics = summary.get("metrics", {})
            self.assertEqual(metrics.get("create"), 2)
            self.assertEqual(metrics.get("update"), 1)
            self.assertEqual(metrics.get("no-op"), 1)
            self.assertEqual(metrics.get("total_changes"), 3)
            self.assertTrue(summary.get("has_changes"))
            self.assertFalse(summary.get("has_destructive_changes"))
        finally:
            os.unlink(p_path)

    def test_04_destructive_replacement(self):
        plan = make_synthetic_plan([
            {
                "address": "google_compute_instance.vm",
                "type": "google_compute_instance",
                "name": "vm",
                "change": {"actions": ["delete", "create"]},
            }
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(plan, f)
            p_path = f.name
        try:
            summary = analyze_plan(p_path)
            metrics = summary.get("metrics", {})
            self.assertEqual(metrics.get("replace"), 1)
            self.assertEqual(metrics.get("total_changes"), 1)
            self.assertTrue(summary.get("has_changes"))
            self.assertTrue(summary.get("has_destructive_changes"))
        finally:
            os.unlink(p_path)

    def test_05_destructive_deletion(self):
        plan = make_synthetic_plan([
            {
                "address": "google_storage_bucket.deprecated",
                "type": "google_storage_bucket",
                "name": "deprecated",
                "change": {"actions": ["delete"]},
            }
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(plan, f)
            p_path = f.name
        try:
            summary = analyze_plan(p_path)
            metrics = summary.get("metrics", {})
            self.assertEqual(metrics.get("delete"), 1)
            self.assertEqual(metrics.get("total_changes"), 1)
            self.assertTrue(summary.get("has_changes"))
            self.assertTrue(summary.get("has_destructive_changes"))
        finally:
            os.unlink(p_path)


class TestGcpPlanMetricsWorkflowExtraction(unittest.TestCase):
    """Tests the exact bash extraction logic used in reusable-tf-gcp.yml."""

    EXTRACTION_BASH = """
set -euo pipefail

if [[ ! -s "${METRICS_FILE}" ]]; then
  echo "::error::Plan metrics file missing or empty"
  exit 1
fi

TOTAL_CHANGES=$(jq -r '.metrics.total_changes' "${METRICS_FILE}" 2>/dev/null || echo "invalid")
HAS_CHANGES=$(jq -r '.has_changes' "${METRICS_FILE}" 2>/dev/null || echo "invalid")
HAS_DESTRUCTIVE=$(jq -r '.has_destructive_changes' "${METRICS_FILE}" 2>/dev/null || echo "invalid")

if [[ -z "${TOTAL_CHANGES}" || "${TOTAL_CHANGES}" == "null" || ! "${TOTAL_CHANGES}" =~ ^[0-9]+$ ]]; then
  echo "::error::Security Violation: 'metrics.total_changes' is missing or not a non-negative integer: '${TOTAL_CHANGES}'"
  exit 1
fi

if [[ "${HAS_CHANGES}" != "true" && "${HAS_CHANGES}" != "false" ]]; then
  echo "::error::Security Violation: 'has_changes' is missing or not a boolean: '${HAS_CHANGES}'"
  exit 1
fi

if [[ "${HAS_DESTRUCTIVE}" != "true" && "${HAS_DESTRUCTIVE}" != "false" ]]; then
  echo "::error::Security Violation: 'has_destructive_changes' is missing or not a boolean: '${HAS_DESTRUCTIVE}'"
  exit 1
fi

if [[ "${HAS_CHANGES}" == "true" && "${TOTAL_CHANGES}" -le 0 ]]; then
  echo "::error::Security Violation: Inconsistent plan metrics: has-changes is true but total-changes is ${TOTAL_CHANGES} (must be > 0)"
  exit 1
fi

if [[ "${HAS_CHANGES}" == "false" && "${TOTAL_CHANGES}" -ne 0 ]]; then
  echo "::error::Security Violation: Inconsistent plan metrics: has-changes is false but total-changes is ${TOTAL_CHANGES} (must be == 0)"
  exit 1
fi

echo "TOTAL_CHANGES=${TOTAL_CHANGES}"
echo "HAS_CHANGES=${HAS_CHANGES}"
echo "HAS_DESTRUCTIVE=${HAS_DESTRUCTIVE}"
"""

    def run_extractor(self, metrics_data):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            if isinstance(metrics_data, (dict, list)):
                json.dump(metrics_data, f)
            elif isinstance(metrics_data, str):
                f.write(metrics_data)
            f.flush()
            f_path = f.name

        try:
            env = dict(os.environ)
            env["METRICS_FILE"] = f_path
            p = subprocess.run(
                ["bash", "-c", self.EXTRACTION_BASH],
                env=env,
                capture_output=True,
                text=True,
            )
            combined_output = p.stdout + p.stderr
            return p.returncode, p.stdout, combined_output
        finally:
            if os.path.exists(f_path):
                os.unlink(f_path)

    def test_06_valid_metrics_extracted_successfully(self):
        data = {
            "metrics": {"total_changes": 2, "create": 2},
            "has_changes": True,
            "has_destructive_changes": False,
        }
        rc, out, _ = self.run_extractor(data)
        self.assertEqual(rc, 0)
        self.assertIn("TOTAL_CHANGES=2", out)
        self.assertIn("HAS_CHANGES=true", out)
        self.assertIn("HAS_DESTRUCTIVE=false", out)

    def test_07_valid_zero_changes_extracted_successfully(self):
        data = {
            "metrics": {"total_changes": 0, "create": 0},
            "has_changes": False,
            "has_destructive_changes": False,
        }
        rc, out, _ = self.run_extractor(data)
        self.assertEqual(rc, 0)
        self.assertIn("TOTAL_CHANGES=0", out)
        self.assertIn("HAS_CHANGES=false", out)
        self.assertIn("HAS_DESTRUCTIVE=false", out)

    def test_08_missing_total_changes_fails_closed(self):
        data = {
            "metrics": {"create": 1},  # missing total_changes
            "has_changes": True,
            "has_destructive_changes": False,
        }
        rc, _, err = self.run_extractor(data)
        self.assertNotEqual(rc, 0)
        self.assertIn("Security Violation", err)

    def test_09_missing_metrics_root_fails_closed(self):
        data = {
            "total_changes": 1,  # at root instead of .metrics
            "has_changes": True,
            "has_destructive_changes": False,
        }
        rc, _, err = self.run_extractor(data)
        self.assertNotEqual(rc, 0)
        self.assertIn("Security Violation", err)

    def test_10_negative_total_changes_fails_closed(self):
        data = {
            "metrics": {"total_changes": -1},
            "has_changes": True,
            "has_destructive_changes": False,
        }
        rc, _, err = self.run_extractor(data)
        self.assertNotEqual(rc, 0)
        self.assertIn("Security Violation", err)

    def test_11_string_total_changes_fails_closed(self):
        data = {
            "metrics": {"total_changes": "one"},
            "has_changes": True,
            "has_destructive_changes": False,
        }
        rc, _, err = self.run_extractor(data)
        self.assertNotEqual(rc, 0)
        self.assertIn("Security Violation", err)

    def test_12_inconsistent_has_changes_true_with_zero_count_fails_closed(self):
        data = {
            "metrics": {"total_changes": 0},
            "has_changes": True,  # Inconsistent: changes true but count is 0
            "has_destructive_changes": False,
        }
        rc, _, err = self.run_extractor(data)
        self.assertNotEqual(rc, 0)
        self.assertIn("Inconsistent plan metrics", err)

    def test_13_inconsistent_has_changes_false_with_positive_count_fails_closed(self):
        data = {
            "metrics": {"total_changes": 3},
            "has_changes": False,  # Inconsistent: changes false but count is 3
            "has_destructive_changes": False,
        }
        rc, _, err = self.run_extractor(data)
        self.assertNotEqual(rc, 0)
        self.assertIn("Inconsistent plan metrics", err)


class TestGcpPlanMetricsSummaryPropagation(unittest.TestCase):
    """Verifies that plan metrics propagate through the actual workflow summary aggregator."""

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
            combined_err = res.stdout + res.stderr
            return res.returncode, outputs, combined_err
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_14_positive_metrics_propagation_through_summary(self):
        rc, out, _ = self.run_summary({
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "true",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "1",
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(out.get("plan-status"), "success")
        self.assertEqual(out.get("authorization-status"), "not-applicable")
        self.assertEqual(out.get("has-changes"), "true")
        self.assertEqual(out.get("has-destructive-changes"), "false")
        self.assertEqual(out.get("total-changes"), "1")

    def test_15_no_change_metrics_propagation_through_summary(self):
        rc, out, _ = self.run_summary({
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "false",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "0",
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(out.get("total-changes"), "0")
        self.assertEqual(out.get("has-changes"), "false")
        self.assertEqual(out.get("authorization-status"), "not-applicable")

    def test_16_inconsistent_summary_has_changes_with_zero_count_rejected(self):
        rc, out, err = self.run_summary({
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "true",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "0",  # Inconsistent!
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertNotEqual(rc, 0)
        self.assertEqual(out.get("authorization-status"), "rejected")
        self.assertIn("Aggregated metrics inconsistent", err)

    def test_17_inconsistent_summary_no_changes_with_positive_count_rejected(self):
        rc, out, err = self.run_summary({
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "false",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "5",  # Inconsistent!
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertNotEqual(rc, 0)
        self.assertEqual(out.get("authorization-status"), "rejected")
        self.assertIn("Aggregated metrics inconsistent", err)

    def test_18_malformed_total_changes_in_summary_rejected(self):
        rc, out, err = self.run_summary({
            "VALIDATE_RESULT": "success",
            "CF_PLAN_RESULT": "success",
            "CF_PLAN_STATUS": "success",
            "CF_SEC_STATUS": "success",
            "CF_HAS_CHANGES": "true",
            "CF_HAS_DESTRUCTIVE": "false",
            "CF_TOTAL_CHANGES": "not_an_int",
            "ENABLE_GCP_AUTH": "false",
        })
        self.assertNotEqual(rc, 0)
        self.assertEqual(out.get("authorization-status"), "rejected")
        self.assertIn("not a non-negative integer", err)


if __name__ == "__main__":
    unittest.main()
