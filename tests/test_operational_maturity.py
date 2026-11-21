#!/usr/bin/env python3
"""
Unit and Adversarial Test Suite for InfraFlow Operational Maturity Verification (Milestone G09.4)

Covers:
  1. CLI arguments, flag parsing, and exit codes.
  2. Cryptographic report attestation signature calculation & tamper resistance.
  3. Pillar 1: Fleet Observability & Structured Telemetry validation, digest checking, and credential leakage detection.
  4. Pillar 2: Central Fleet Compliance 5-pillar evaluation and enforcement thresholds.
  5. Pillar 3: Multi-Cloud State Drift ingestion, 6-category classification, and critical drift gating.
  6. Pillar 4: Upgrade Campaign lifecycle tracking, Canary gate invariants, and rollback preparedness.
  7. Security guards: Path traversal rejection, symlink spoofing prevention, and secret scrubbing.
  8. End-to-end integration, JSON and Markdown generation, and telemetry event emission.
"""

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Load scripts under test dynamically to avoid import name collision
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def load_script(name: str, filename: str):
    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vom = load_script("verify_operational_maturity", "verify-operational-maturity.py")
et = load_script("emit_telemetry", "emit-telemetry.py")
oc = load_script("orchestrate_campaign", "orchestrate-campaign.py")
gcd = load_script("generate_compliance_dashboard", "generate-compliance-dashboard.py")


class TestOperationalMaturityVerification(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow_g09_4_test_")
        self.test_path = Path(self.test_dir)
        self.fixtures_consumers = REPO_ROOT / "fixtures" / "consumers"
        self.valid_manifest = REPO_ROOT / "config" / "fleet-manifest.yaml"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Attestation Signature & Determinism Tests
    # -------------------------------------------------------------------------

    def test_signature_deterministic(self):
        """Attestation signature must be strictly deterministic for identical report payloads."""
        payload = {
            "schema_version": "1.0",
            "verification_id": "op-verif-test-01",
            "overall_status": "COMPLIANT_AND_VERIFIED",
            "compliance_score": 90.0,
            "pillars": {"p1": {"status": "PASS"}},
        }
        sig1 = vom.compute_report_signature(payload)
        sig2 = vom.compute_report_signature(copy.deepcopy(payload))
        self.assertEqual(sig1, sig2)
        self.assertEqual(len(sig1), 64)

    def test_signature_tamper_detection(self):
        """Modifying any field in the report payload must change the computed signature."""
        payload1 = {
            "schema_version": "1.0",
            "overall_status": "COMPLIANT_AND_VERIFIED",
            "compliance_score": 90.0,
        }
        payload2 = copy.deepcopy(payload1)
        payload2["compliance_score"] = 90.1

        sig1 = vom.compute_report_signature(payload1)
        sig2 = vom.compute_report_signature(payload2)
        self.assertNotEqual(sig1, sig2)

    def test_signature_excludes_report_signature_field(self):
        """compute_report_signature must exclude 'report_signature' from digest computation."""
        payload = {
            "schema_version": "1.0",
            "overall_status": "COMPLIANT_AND_VERIFIED",
        }
        sig_before = vom.compute_report_signature(payload)
        payload["report_signature"] = "arbitrary_existing_signature"
        sig_after = vom.compute_report_signature(payload)
        self.assertEqual(sig_before, sig_after)

    # -------------------------------------------------------------------------
    # 2. Pillar 1: Telemetry & Observability Verification
    # -------------------------------------------------------------------------

    def test_telemetry_dry_run_success(self):
        """Dry-run verification without telemetry file passes with validated sample event."""
        res = vom.verify_telemetry_pillar(telemetry_path=None)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["events_evaluated"], 1)
        self.assertEqual(res["valid_events"], 1)

    def test_telemetry_valid_events_file(self):
        """Pillar 1 passes when reading valid telemetry event log."""
        tel_file = self.test_path / "valid_telemetry.jsonl"
        ev1 = et.create_telemetry_event(
            event_type="governance_gate_evaluated",
            consumer_id="platform",
            repository="TM-threemavithana/infraflow",
            status="PASS",
            adapter="core",
        )
        ev2 = et.create_telemetry_event(
            event_type="drift_detected",
            consumer_id="consumer-networking",
            repository="TM-threemavithana/infraflow-consumer-networking",
            status="WARN",
            adapter="aws",
        )
        et.emit_event(ev1, tel_file, append=True)
        et.emit_event(ev2, tel_file, append=True)

        res = vom.verify_telemetry_pillar(telemetry_path=tel_file)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["events_evaluated"], 2)
        self.assertEqual(res["valid_events"], 2)
        self.assertEqual(res["invalid_events"], 0)
        self.assertEqual(res["tampered_digests"], 0)

    def test_telemetry_invalid_schema_detected(self):
        """Pillar 1 fails when telemetry file contains events violating Schema v1.0."""
        tel_file = self.test_path / "invalid_telemetry.jsonl"
        bad_event = {"schema_version": "0.9", "event_id": "bad-01"}
        tel_file.write_text(json.dumps(bad_event) + "\n", encoding="utf-8")

        res = vom.verify_telemetry_pillar(telemetry_path=tel_file)
        self.assertEqual(res["status"], "FAIL")
        self.assertGreater(res["invalid_events"], 0)

    def test_telemetry_digest_tampering_detected(self):
        """Pillar 1 detects tampered event digests and fails."""
        tel_file = self.test_path / "tampered_telemetry.jsonl"
        ev = et.create_telemetry_event(
            event_type="governance_gate_evaluated",
            consumer_id="platform",
            repository="TM-threemavithana/infraflow",
            status="PASS",
            adapter="core",
        )
        # Tamper with payload while keeping original digest
        ev["verdict"]["status"] = "FAIL"
        tel_file.write_text(json.dumps(ev) + "\n", encoding="utf-8")

        res = vom.verify_telemetry_pillar(telemetry_path=tel_file)
        self.assertEqual(res["status"], "FAIL")
        self.assertGreaterEqual(res["tampered_digests"], 1)

    def test_telemetry_credential_leakage_detected(self):
        """Pillar 1 detects unredacted credential patterns in telemetry event stream."""
        tel_file = self.test_path / "leaked_telemetry.jsonl"
        ev = et.create_telemetry_event(
            event_type="security_scan_completed",
            consumer_id="platform",
            repository="TM-threemavithana/infraflow",
            status="PASS",
            adapter="aws",
        )
        # Inject unredacted secret into verdict reasons and update digest so schema passes
        raw_key = "AKIA" + ("1234567890123456"[:16])
        ev["verdict"]["reasons"] = [f"Found exposed key {raw_key}"]
        ev["integrity"]["event_digest"] = et.compute_event_digest(ev)

        tel_file.write_text(json.dumps(ev) + "\n", encoding="utf-8")
        res = vom.verify_telemetry_pillar(telemetry_path=tel_file)
        self.assertEqual(res["status"], "FAIL")
        self.assertGreater(res["unredacted_secrets_detected"], 0)

    # -------------------------------------------------------------------------
    # 3. Pillar 2: Central Fleet Compliance & Governance Scoring
    # -------------------------------------------------------------------------

    def test_compliance_evaluation_pass(self):
        """Pillar 2 returns PASS for compliant consumer fixtures meeting 90.0% threshold."""
        res = vom.verify_compliance_pillar(
            manifest_path=self.valid_manifest,
            fleet_root=self.fixtures_consumers,
            enforce_threshold=90.0,
        )
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["fleet_score"], 90.0)
        self.assertEqual(res["consumer_count"], 3)

    def test_compliance_threshold_enforcement_fail(self):
        """Pillar 2 returns FAIL if overall compliance score falls below enforcement threshold."""
        res = vom.verify_compliance_pillar(
            manifest_path=self.valid_manifest,
            fleet_root=self.fixtures_consumers,
            enforce_threshold=95.0,  # Fleet score is 90.0%
        )
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("below enforcement threshold", res["details"][0])

    def test_compliance_manifest_not_found(self):
        """Pillar 2 fails closed if manifest file is missing."""
        nonexistent = self.test_path / "no_manifest.yaml"
        with self.assertRaises(FileNotFoundError):
            vom.verify_compliance_pillar(manifest_path=nonexistent, fleet_root=self.fixtures_consumers)

    # -------------------------------------------------------------------------
    # 4. Pillar 3: Multi-Cloud State & Speculative Drift Detection
    # -------------------------------------------------------------------------

    def test_drift_offline_no_dir_pass(self):
        """Pillar 3 passes when drift directory is omitted (offline simulation mode)."""
        res = vom.verify_drift_pillar(manifest_path=self.valid_manifest, drift_dir=None)
        self.assertEqual(res["status"], "PASS")

    def test_drift_all_clean_workloads(self):
        """Pillar 3 returns PASS when all ingested drift reports are CLEAN."""
        drift_dir = self.test_path / "drift_clean"
        drift_dir.mkdir()
        for wid in ("consumer-networking", "consumer-application", "consumer-data-platform"):
            report = {
                "schema_version": "1.0",
                "summary": {
                    "verdict": "CLEAN",
                    "total_drifts": 0,
                    "severity_counts": {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                    "category_counts": {"NO_DRIFT": 3},
                },
            }
            (drift_dir / f"{wid}.json").write_text(json.dumps(report), encoding="utf-8")

        res = vom.verify_drift_pillar(manifest_path=self.valid_manifest, drift_dir=drift_dir)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["workloads_audited"], 3)
        self.assertEqual(res["clean_workloads"], 3)
        self.assertEqual(res["drifted_workloads"], 0)
        self.assertFalse(res["critical_drift_detected"])

    def test_drift_non_critical_warn(self):
        """Pillar 3 returns WARN when non-critical drift is detected without --fail-on-drift."""
        drift_dir = self.test_path / "drift_warn"
        drift_dir.mkdir()
        report = {
            "schema_version": "1.0",
            "summary": {
                "verdict": "DRIFT_DETECTED",
                "total_drifts": 1,
                "severity_counts": {"INFO": 0, "LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "category_counts": {"ATTRIBUTE_DRIFT": 1},
            },
        }
        (drift_dir / "consumer-networking.json").write_text(json.dumps(report), encoding="utf-8")

        res = vom.verify_drift_pillar(manifest_path=self.valid_manifest, drift_dir=drift_dir, fail_on_drift=False)
        self.assertEqual(res["status"], "WARN")
        self.assertEqual(res["drifted_workloads"], 1)

    def test_drift_critical_fail(self):
        """Pillar 3 returns FAIL when CRITICAL severity drift is detected (governance breaker)."""
        drift_dir = self.test_path / "drift_crit"
        drift_dir.mkdir()
        report = {
            "schema_version": "1.0",
            "summary": {
                "verdict": "DRIFT_DETECTED",
                "total_drifts": 1,
                "severity_counts": {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1},
                "category_counts": {"ATTRIBUTE_DRIFT": 1},
            },
        }
        (drift_dir / "consumer-networking.json").write_text(json.dumps(report), encoding="utf-8")

        res = vom.verify_drift_pillar(manifest_path=self.valid_manifest, drift_dir=drift_dir)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(res["critical_drift_detected"])

    def test_drift_fail_on_drift_flag(self):
        """Pillar 3 returns FAIL for non-critical drift when fail_on_drift=True."""
        drift_dir = self.test_path / "drift_flag"
        drift_dir.mkdir()
        report = {
            "schema_version": "1.0",
            "summary": {
                "verdict": "DRIFT_DETECTED",
                "total_drifts": 1,
                "severity_counts": {"INFO": 0, "LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "category_counts": {"ATTRIBUTE_DRIFT": 1},
            },
        }
        (drift_dir / "consumer-networking.json").write_text(json.dumps(report), encoding="utf-8")

        res = vom.verify_drift_pillar(manifest_path=self.valid_manifest, drift_dir=drift_dir, fail_on_drift=True)
        self.assertEqual(res["status"], "FAIL")

    # -------------------------------------------------------------------------
    # 5. Pillar 4: Upgrade Campaigns & Lifecycle Tracking
    # -------------------------------------------------------------------------

    def test_campaign_no_file_pass(self):
        """Pillar 4 passes when campaign file is omitted."""
        res = vom.verify_campaign_pillar(campaign_file=None)
        self.assertEqual(res["status"], "PASS")

    def test_campaign_valid_state_pass(self):
        """Pillar 4 passes for valid, signed Schema v1.0 upgrade campaign."""
        camp_file = self.test_path / "valid_campaign.json"
        valid_sha = "be51718f06a2662099500a710e93e6e8201b4f1c"
        campaign = oc.create_campaign(
            manifest_path=self.valid_manifest,
            target_sha=valid_sha,
            campaign_id="test-camp-01",
        )
        oc.save_campaign(campaign, camp_file)

        res = vom.verify_campaign_pillar(campaign_file=camp_file)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["campaign_id"], "test-camp-01")
        self.assertTrue(res["canary_gate_verified"])
        self.assertTrue(res["signature_valid"])

    def test_campaign_tampered_signature_fail(self):
        """Pillar 4 fails closed when campaign state has been tampered with."""
        camp_file = self.test_path / "tampered_campaign.json"
        valid_sha = "be51718f06a2662099500a710e93e6e8201b4f1c"
        campaign = oc.create_campaign(
            manifest_path=self.valid_manifest,
            target_sha=valid_sha,
            campaign_id="test-camp-02",
        )
        oc.save_campaign(campaign, camp_file)

        # Direct disk tampering
        content = camp_file.read_text(encoding="utf-8")
        tampered = content.replace('"status": "PLANNED"', '"status": "COMPLETED"')
        camp_file.write_text(tampered, encoding="utf-8")

        res = vom.verify_campaign_pillar(campaign_file=camp_file)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["signature_valid"])

    def test_campaign_canary_gate_breach(self):
        """Pillar 4 detects Canary Gate breach if progressive stage runs without canary verified."""
        camp_file = self.test_path / "breached_canary.json"
        valid_sha = "be51718f06a2662099500a710e93e6e8201b4f1c"
        campaign = oc.create_campaign(
            manifest_path=self.valid_manifest,
            target_sha=valid_sha,
            campaign_id="test-camp-03",
        )
        # Violate canary gate
        for s in campaign.get("stages", []):
            if s.get("stage_name") == "progressive":
                s["status"] = "RUNNING"
            elif s.get("stage_name") == "canary":
                s["status"] = "PENDING"
        campaign["signature"] = oc.compute_campaign_signature(campaign)
        camp_file.write_text(json.dumps(campaign, indent=2), encoding="utf-8")

        res = vom.verify_campaign_pillar(campaign_file=camp_file)
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["canary_gate_verified"])

    # -------------------------------------------------------------------------
    # 6. Security Guards & Defensive Controls
    # -------------------------------------------------------------------------

    def test_security_symlink_rejection(self):
        """validate_safe_path must reject symlinks unconditionally."""
        target_file = self.test_path / "real_file.txt"
        target_file.write_text("secure", encoding="utf-8")
        link_file = self.test_path / "symlink_file.txt"
        os.symlink(target_file, link_file)

        with self.assertRaises(PermissionError):
            vom.validate_safe_path(link_file)

    def test_security_path_traversal_rejection(self):
        """validate_safe_path must reject path traversal sequences (..)."""
        traversal_path = Path("some/nested/../../etc/passwd")
        with self.assertRaises(ValueError):
            vom.validate_safe_path(traversal_path, must_exist=False)

    def test_security_secret_scrubbing(self):
        """sanitize_secrets must scrub known credential patterns from nested structures."""
        test_key = "AKIA" + ("1234567890123456"[:16])
        test_token = "ghp_" + ("abcdefghijklmnopqrstuvwxyz1234567890"[:36])
        data = {
            "title": "audit",
            "nested": {
                "raw_aws_key": test_key,
                "github_token": test_token,
                "normal": "safe_string",
            },
            "list_val": [test_key, "regular"],
        }
        cleaned = vom.sanitize_secrets(data)
        self.assertEqual(cleaned["nested"]["raw_aws_key"], "[REDACTED_AWS_KEY]")
        self.assertEqual(cleaned["nested"]["github_token"], "[REDACTED_GITHUB_TOKEN]")
        self.assertEqual(cleaned["nested"]["normal"], "safe_string")
        self.assertEqual(cleaned["list_val"][0], "[REDACTED_AWS_KEY]")

    # -------------------------------------------------------------------------
    # 7. End-to-End Orchestration & Reporting
    # -------------------------------------------------------------------------

    def test_e2e_operational_maturity_compliant(self):
        """End-to-end execution across valid fixtures produces COMPLIANT_AND_VERIFIED report."""
        report = vom.execute_operational_maturity_verification(
            manifest_path=self.valid_manifest,
            fleet_root=self.fixtures_consumers,
            enforce_threshold=90.0,
        )
        self.assertEqual(report["overall_status"], "COMPLIANT_AND_VERIFIED")
        self.assertEqual(report["compliance_score"], 90.0)
        self.assertTrue(report["report_signature"])
        self.assertEqual(len(report["report_signature"]), 64)

        # Markdown report generation
        md = vom.generate_markdown_report(report)
        self.assertIn("COMPLIANT & VERIFIED", md)
        self.assertIn("Pillar 1: Fleet Observability", md)
        self.assertIn("Pillar 2: Central Compliance", md)
        self.assertIn("Pillar 3: Multi-Cloud Drift", md)
        self.assertIn("Pillar 4: Upgrade Campaigns", md)

    def test_e2e_cli_invocation_json_and_markdown(self):
        """CLI execution generates valid output JSON and Markdown files and exits with code 0."""
        out_json = self.test_path / "e2e_report.json"
        out_md = self.test_path / "e2e_report.md"

        cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "verify-operational-maturity.py"),
            "--manifest",
            str(self.valid_manifest),
            "--fleet-root",
            str(self.fixtures_consumers),
            "--output-json",
            str(out_json),
            "--output-markdown",
            str(out_md),
            "--quiet",
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI failed with error: {proc.stderr}")
        self.assertTrue(out_json.exists())
        self.assertTrue(out_md.exists())

        # Validate JSON content
        data = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(data["overall_status"], "COMPLIANT_AND_VERIFIED")
        self.assertTrue(data["report_signature"])

    def test_e2e_cli_threshold_failure_exit_code(self):
        """CLI returns exit code 1 when compliance threshold is violated."""
        cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "verify-operational-maturity.py"),
            "--manifest",
            str(self.valid_manifest),
            "--fleet-root",
            str(self.fixtures_consumers),
            "--enforce-threshold",
            "98.0",
            "--quiet",
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)

    def test_e2e_cli_emit_telemetry(self):
        """CLI with --emit-telemetry appends a valid schema v1.0 governance event."""
        tel_file = self.test_path / "cli_telemetry.jsonl"
        cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "verify-operational-maturity.py"),
            "--manifest",
            str(self.valid_manifest),
            "--fleet-root",
            str(self.fixtures_consumers),
            "--telemetry-file",
            str(tel_file),
            "--emit-telemetry",
            "--quiet",
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
        self.assertTrue(tel_file.exists())
        lines = tel_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertGreaterEqual(len(lines), 1)
        last_event = json.loads(lines[-1])
        self.assertEqual(last_event["event_type"], "governance_gate_evaluated")
        self.assertEqual(last_event["verdict"]["status"], "PASS")

    def test_cli_missing_campaign_file_handled(self):
        """CLI fails closed with exit code 2 when campaign file does not exist."""
        cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "verify-operational-maturity.py"),
            "--manifest",
            str(self.valid_manifest),
            "--fleet-root",
            str(self.fixtures_consumers),
            "--campaign-file",
            "/tmp/nonexistent_campaign_12345.json",
            "--quiet",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_cli_missing_drift_dir_handled(self):
        """CLI fails closed with exit code 2 when drift directory does not exist."""
        cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "verify-operational-maturity.py"),
            "--manifest",
            str(self.valid_manifest),
            "--fleet-root",
            str(self.fixtures_consumers),
            "--drift-dir",
            "/tmp/nonexistent_drift_dir_12345",
            "--quiet",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_telemetry_json_array_format(self):
        """Pillar 1 successfully parses telemetry provided as a JSON array of event objects."""
        tel_file = self.test_path / "array_telemetry.json"
        ev = et.create_telemetry_event(
            event_type="governance_gate_evaluated",
            consumer_id="platform",
            repository="TM-threemavithana/infraflow",
            status="PASS",
            adapter="core",
        )
        tel_file.write_text(json.dumps([ev]), encoding="utf-8")
        res = vom.verify_telemetry_pillar(telemetry_path=tel_file)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["events_evaluated"], 1)
        self.assertEqual(res["valid_events"], 1)

    def test_markdown_report_structure_and_tables(self):
        """generate_markdown_report generates expected markdown headings and tables."""
        report = vom.execute_operational_maturity_verification(
            manifest_path=self.valid_manifest,
            fleet_root=self.fixtures_consumers,
            enforce_threshold=90.0,
        )
        md = vom.generate_markdown_report(report)
        self.assertIn("# 🛡️ InfraFlow Enterprise Operational Maturity Verification Report", md)
        self.assertIn("## 1. Operational Maturity Pillars Summary", md)
        self.assertIn("## 2. Multi-Tenant Fleet Compliance Breakdown", md)
        self.assertIn("## 3. Multi-Cloud Infrastructure Drift Summary", md)
        self.assertIn("## 4. Platform Security & Governance Invariants", md)
        self.assertIn("Zero Cloud Spend ($0.00)", md)
        self.assertIn("Zero Destructive Remediation", md)

    def test_governance_invariants_flagged(self):
        """Verification report includes strict enterprise governance invariant guarantees."""
        report = vom.execute_operational_maturity_verification(
            manifest_path=self.valid_manifest,
            fleet_root=self.fixtures_consumers,
            enforce_threshold=90.0,
        )
        invariants = report.get("governance_invariants", {})
        self.assertTrue(invariants.get("zero_cloud_spend_enforced"))
        self.assertTrue(invariants.get("read_only_remediation_enforced"))
        self.assertTrue(invariants.get("symlink_traversal_guarded"))
        self.assertTrue(invariants.get("cryptographic_attestation_present"))


if __name__ == "__main__":
    unittest.main()
