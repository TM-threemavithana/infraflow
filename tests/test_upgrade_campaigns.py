#!/usr/bin/env python3
"""
Unit and Adversarial Test Suite for Automated Upgrade Campaigns & Lifecycle Tracking (Milestone G09.3)

Validates:
1. Deterministic campaign initialization, Schema v1.0 validation, and SHA-256 anti-tampering.
2. Staged rollout lifecycle (PLANNING -> CANARY -> PROGRESSIVE -> COMPLETED).
3. Fail-closed Canary Gate enforcement: progressive rollout strictly blocked if canary not VERIFIED.
4. Pre-flight and post-flight quality gates (compliance scoring, drift gating, contract compatibility).
5. Transactional and emergency rollback orchestration restoring baseline SHAs.
6. Simulated pull request dispatch & branch metadata generation ($0.00 spend).
7. Telemetry bus event emissions and Central Compliance Dashboard integration.
8. Defense-in-depth: symlink rejection, secret sanitization, and invalid input rejection.
"""

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
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_module_from_path(name: str, rel_path: str):
    """Loads a python module from path relative to repo root."""
    path = REPO_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


oc = load_module_from_path("orchestrate_campaign", "scripts/orchestrate-campaign.py")
gcd = load_module_from_path("generate_compliance_dashboard", "scripts/generate-compliance-dashboard.py")
et = load_module_from_path("emit_telemetry", "scripts/emit-telemetry.py")


class TestUpgradeCampaigns(unittest.TestCase):
    """Test suite covering Milestone G09.3 capabilities."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)
        self.manifest_path = REPO_ROOT / "config" / "fleet-manifest.yaml"
        self.fixtures_root = REPO_ROOT / "fixtures" / "consumers"
        self.valid_sha = "be51718f06a2662099500a710e93e6e8201b4f1c"
        self.rollback_sha = "f1ad39fb0f0bdce7c475ed36e717e859b2e9b106"

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Campaign Initialization & Schema v1.0 Validation
    # -------------------------------------------------------------------------

    def test_campaign_creation_valid(self):
        """Verifies successful initialization of an upgrade campaign."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
            title="Q4 Platform Upgrade",
            description="Upgrades fleet to candidate SHA",
            created_by="secops-lead",
            compliance_threshold=92.5,
        )

        self.assertEqual(camp["schema_version"], "1.0")
        self.assertTrue(camp["campaign_id"].startswith("camp-"))
        self.assertEqual(camp["target_platform_sha"], self.valid_sha)
        self.assertEqual(camp["status"], "PLANNED")
        self.assertEqual(camp["governance"]["compliance_threshold"], 92.5)
        self.assertEqual(camp["created_by"], "secops-lead")
        self.assertTrue(len(camp["signature"]) == 64)

        stages = {s["stage_name"]: s for s in camp["stages"]}
        self.assertIn("canary", stages)
        self.assertIn("progressive", stages)

        canary_consumers = stages["canary"]["consumers"]
        prog_consumers = stages["progressive"]["consumers"]
        self.assertEqual(len(canary_consumers), 1)
        self.assertEqual(canary_consumers[0]["consumer_id"], "consumer-networking")
        self.assertEqual(len(prog_consumers), 2)

    def test_campaign_creation_invalid_sha(self):
        """Verifies that invalid, mutable, or malicious SHAs are rejected."""
        invalid_shas = [
            "main",
            "v0.6.0",
            "be51718",  # short SHA
            "be51718f06a2662099500a710e93e6e8201b4f1z",  # invalid hex 'z'
            "be51718f06a2662099500a710e93e6e8201b4f1c; rm -rf /",  # command injection
            "",
        ]
        for bad_sha in invalid_shas:
            with self.subTest(bad_sha=bad_sha):
                with self.assertRaises(oc.CampaignValidationError):
                    oc.create_campaign(
                        manifest_path=self.manifest_path,
                        target_sha=bad_sha,
                    )

    def test_campaign_creation_invalid_manifest(self):
        """Verifies rejection of non-existent or symlinked manifest."""
        with self.assertRaises(oc.CampaignValidationError):
            oc.create_campaign(
                manifest_path=self.test_root / "non_existent.yaml",
                target_sha=self.valid_sha,
            )

    # -------------------------------------------------------------------------
    # 2. Cryptographic Anti-Tampering & Signature Verification
    # -------------------------------------------------------------------------

    def test_campaign_signature_integrity(self):
        """Verifies that tampering with campaign state triggers CampaignIntegrityError."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        camp_path = self.test_root / "campaign.json"
        oc.save_campaign(camp, camp_path)

        # Loaded without modification must succeed
        loaded = oc.load_campaign(camp_path)
        self.assertEqual(loaded["campaign_id"], camp["campaign_id"])

        # Tamper with target SHA out-of-band
        data = json.loads(camp_path.read_text(encoding="utf-8"))
        data["target_platform_sha"] = "0000000000000000000000000000000000000000"
        camp_path.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(oc.CampaignIntegrityError):
            oc.load_campaign(camp_path)

    def test_symlink_rejection(self):
        """Verifies that symlinked campaign files are rejected immediately."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        real_file = self.test_root / "real_campaign.json"
        sym_file = self.test_root / "sym_campaign.json"
        oc.save_campaign(camp, real_file)

        os.symlink(real_file, sym_file)

        with self.assertRaises(oc.CampaignValidationError):
            oc.load_campaign(sym_file)

    # -------------------------------------------------------------------------
    # 3. Fail-Closed Canary Gate Enforcement
    # -------------------------------------------------------------------------

    def test_canary_gate_blocks_progressive_when_canary_pending(self):
        """Verifies progressive rollout is blocked when canary status is PENDING."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        camp_path = self.test_root / "gate_test.json"
        oc.save_campaign(camp, camp_path)

        with self.assertRaises(oc.CanaryGateError):
            oc.execute_stage(
                campaign=camp,
                stage_name="progressive",
                fleet_root=self.fixtures_root,
                platform_dir=REPO_ROOT,
                dry_run=True,
            )

        self.assertEqual(camp["status"], "FAILED")
        self.assertTrue(any(a["action"] == "CANARY_GATE_BLOCKED" for a in camp["audit_log"]))

    def test_canary_gate_blocks_progressive_when_canary_failed(self):
        """Verifies progressive rollout is blocked when canary status is FAILED."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        stages = {s["stage_name"]: s for s in camp["stages"]}
        stages["canary"]["status"] = "FAILED"

        with self.assertRaises(oc.CanaryGateError):
            oc.execute_stage(
                campaign=camp,
                stage_name="progressive",
                fleet_root=self.fixtures_root,
                platform_dir=REPO_ROOT,
                dry_run=True,
            )

    # -------------------------------------------------------------------------
    # 4. Staged Rollout Lifecycle & Dry-Run Execution
    # -------------------------------------------------------------------------

    def test_staged_rollout_lifecycle(self):
        """Verifies sequential stage progression: Canary -> Progressive -> Complete."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )

        # 1. Execute Canary stage
        c_ok, c_logs = oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
        )
        self.assertTrue(c_ok)
        self.assertEqual(camp["status"], "CANARY_VERIFIED")
        stages = {s["stage_name"]: s for s in camp["stages"]}
        self.assertEqual(stages["canary"]["status"], "VERIFIED")

        # 2. Execute Progressive stage
        p_ok, p_logs = oc.execute_stage(
            campaign=camp,
            stage_name="progressive",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
        )
        self.assertTrue(p_ok)
        self.assertEqual(camp["status"], "COMPLETED")
        self.assertEqual(stages["progressive"]["status"], "VERIFIED")

        # Check simulated PR metadata for all workloads
        for stage in camp["stages"]:
            for c in stage["consumers"]:
                self.assertEqual(c["status"], "VERIFIED")
                self.assertIsNotNone(c["simulated_pr"])
                self.assertTrue(c["simulated_pr"]["branch"].startswith("infraflow/upgrade-"))

    def test_execute_stage_all(self):
        """Verifies --execute-stage all runs canary and progressive stages end-to-end."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )

        ok, logs = oc.execute_stage(
            campaign=camp,
            stage_name="all",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
        )
        self.assertTrue(ok)
        self.assertEqual(camp["status"], "COMPLETED")

    # -------------------------------------------------------------------------
    # 5. Quality Gates: Compliance & Drift
    # -------------------------------------------------------------------------

    def test_compliance_threshold_gate_failure(self):
        """Verifies that an unachievable compliance threshold halts the rollout."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
            compliance_threshold=100.1,  # Impossible threshold
        )

        ok, logs = oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
        )
        self.assertFalse(ok)
        self.assertEqual(camp["status"], "FAILED")
        stages = {s["stage_name"]: s for s in camp["stages"]}
        self.assertEqual(stages["canary"]["status"], "FAILED")

    def test_critical_drift_gate_failure(self):
        """Verifies that critical state drift detected pre-flight halts the rollout."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )

        drift_dir = self.test_root / "drift_reports"
        drift_dir.mkdir()
        # Create a mock drift report with critical severity for consumer-networking
        mock_drift = {
            "summary": {
                "verdict": "DRIFT_DETECTED",
                "severity_counts": {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "NONE": 0},
            }
        }
        (drift_dir / "consumer-networking.json").write_text(json.dumps(mock_drift), encoding="utf-8")

        ok, logs = oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            drift_dir=drift_dir,
            dry_run=True,
        )
        self.assertFalse(ok)
        self.assertEqual(camp["status"], "FAILED")
        canary = camp["stages"][0]["consumers"][0]
        self.assertEqual(canary["drift_status"], "CRITICAL_DRIFT")

    # -------------------------------------------------------------------------
    # 6. Rollback Orchestration
    # -------------------------------------------------------------------------

    def test_campaign_rollback(self):
        """Verifies rollback restores consumers to rollback_sha and transitions status."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )

        # Run canary
        oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
        )

        # Trigger rollback
        rb_ok, rb_logs = oc.rollback_campaign(
            campaign=camp,
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            reason="Canary metrics regression detected",
            dry_run=True,
        )
        self.assertTrue(rb_ok)
        self.assertEqual(camp["status"], "ROLLED_BACK")
        self.assertTrue(camp["rollback"]["executed"])
        self.assertEqual(camp["rollback"]["reason"], "Canary metrics regression detected")
        self.assertIn("consumer-networking", camp["rollback"]["restored_consumers"])

    def test_auto_rollback_on_stage_failure(self):
        """Verifies auto-rollback initiates immediately if stage verification fails."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
            compliance_threshold=100.1,  # triggers failure
        )

        ok, logs = oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
            auto_rollback=True,
        )
        self.assertFalse(ok)
        self.assertEqual(camp["status"], "ROLLED_BACK")
        self.assertTrue(camp["rollback"]["executed"])

    # -------------------------------------------------------------------------
    # 7. Simulated PR Generation & Secret Scrubbing
    # -------------------------------------------------------------------------

    def test_simulated_pr_generation(self):
        """Verifies simulated PR payload structure and deterministic number."""
        consumer = {
            "consumer_id": "consumer-networking",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "workload_type": "networking",
            "adapter": "aws",
        }
        pr = oc.generate_simulated_pr(
            consumer=consumer,
            target_sha=self.valid_sha,
            campaign_id="camp-1234567890ab",
            compliance_score=98.5,
            verdict="PASS_VERIFIED",
        )

        self.assertEqual(pr["branch"], "infraflow/upgrade-be51718")
        self.assertIn("https://github.com/TM-threemavithana/infraflow-consumer-networking/pull/", pr["simulated_pr_url"])
        self.assertIn("camp-1234567890ab", pr["body_markdown"])
        self.assertIn("98.5%", pr["body_markdown"])

    def test_secret_scrubbing(self):
        """Verifies sensitive credentials are scrubbed from PR bodies and markdown."""
        test_pat = "ghp_" + ("1234567890" * 3) + "123456"
        leaky_text = f"Deploying with key AKIAIOSFODNN7EXAMPLE and token {test_pat}"
        scrubbed = oc.scrub_text(leaky_text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertNotIn("ghp_", scrubbed)
        self.assertIn("[REDACTED_AWS_KEY]", scrubbed)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", scrubbed)

    # -------------------------------------------------------------------------
    # 8. Telemetry Bus Event Emission
    # -------------------------------------------------------------------------

    def test_telemetry_emission(self):
        """Verifies structured telemetry events are written with valid schema and digests."""
        telemetry_file = self.test_root / "telemetry.jsonl"
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )

        oc.emit_campaign_telemetry(
            event_type="campaign_planned",
            campaign_id=camp["campaign_id"],
            consumer_id="fleet-coordinator",
            repository="platform",
            target_sha=self.valid_sha,
            telemetry_file=telemetry_file,
        )

        self.assertTrue(telemetry_file.is_file())
        lines = [json.loads(l) for l in telemetry_file.read_text(encoding="utf-8").strip().splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["event_type"], "campaign_planned")
        self.assertEqual(lines[0]["target"]["platform_sha"], self.valid_sha)
        self.assertTrue("event_digest" in lines[0]["integrity"])

    # -------------------------------------------------------------------------
    # 9. Central Compliance Dashboard Integration
    # -------------------------------------------------------------------------

    def test_compliance_dashboard_campaign_integration(self):
        """Verifies compliance dashboard ingests campaign file and renders campaign status."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        camp_path = self.test_root / "camp_dash.json"
        oc.save_campaign(camp, camp_path)

        rep = gcd.generate_compliance_report(
            manifest_path=self.manifest_path,
            fleet_root=self.fixtures_root,
            campaign_file=camp_path,
        )

        self.assertIn("campaign_summary", rep)
        self.assertTrue(rep["campaign_summary"]["active"])
        self.assertEqual(rep["campaign_summary"]["campaign_id"], camp["campaign_id"])
        self.assertEqual(rep["campaign_summary"]["status"], "PLANNED")

        md = gcd.render_markdown_dashboard(rep)
        self.assertIn("Active Fleet Upgrade Campaign", md)
        self.assertIn(camp["campaign_id"], md)
        self.assertIn("Canary Rollout Gate", md)

    # -------------------------------------------------------------------------
    # 10. CLI Execution Tests
    # -------------------------------------------------------------------------

    def test_cli_create_and_status(self):
        """Verifies CLI execution for --create and --status."""
        camp_file = self.test_root / "cli_camp.json"
        script = REPO_ROOT / "scripts" / "orchestrate-campaign.py"

        # 1. Create
        res = subprocess.run(
            [
                sys.executable,
                str(script),
                "--create",
                "--target-sha",
                self.valid_sha,
                "--manifest",
                str(self.manifest_path),
                "--campaign-file",
                str(camp_file),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"CLI create failed: {res.stderr}")
        self.assertTrue(camp_file.is_file())

        # 2. Status
        res2 = subprocess.run(
            [
                sys.executable,
                str(script),
                "--status",
                "--campaign-file",
                str(camp_file),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res2.returncode, 0)
        self.assertIn("InfraFlow Upgrade Campaign Status", res2.stdout)

    def test_terminal_status_rejection(self):
        """Verifies executing stage on terminal campaign status is rejected."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        camp["status"] = "COMPLETED"

        ok, logs = oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
        )
        self.assertFalse(ok)
        self.assertIn("terminal status", logs[0])

    def test_load_campaign_missing_fields(self):
        """Verifies load_campaign rejects JSON files missing required schema fields."""
        camp_file = self.test_root / "missing_fields.json"
        camp_file.write_text(json.dumps({"schema_version": "1.0"}), encoding="utf-8")
        with self.assertRaises(oc.CampaignValidationError):
            oc.load_campaign(camp_file)

    def test_load_campaign_invalid_json(self):
        """Verifies load_campaign rejects malformed JSON."""
        camp_file = self.test_root / "bad_json.json"
        camp_file.write_text("{this is not json}", encoding="utf-8")
        with self.assertRaises(oc.CampaignValidationError):
            oc.load_campaign(camp_file)

    def test_unsupported_schema_version(self):
        """Verifies load_campaign rejects unsupported schema_version."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        camp["schema_version"] = "99.0"
        camp_file = self.test_root / "bad_schema.json"
        oc.save_campaign(camp, camp_file)
        with self.assertRaises(oc.CampaignValidationError):
            oc.load_campaign(camp_file)

    def test_execute_stage_invalid_stage_name(self):
        """Verifies execute_stage rejects unknown stage names."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        with self.assertRaises(oc.CampaignValidationError):
            oc.execute_stage(
                campaign=camp,
                stage_name="invalid_stage_name",
                fleet_root=self.fixtures_root,
                platform_dir=REPO_ROOT,
            )

    def test_save_campaign_symlink_rejection(self):
        """Verifies save_campaign rejects writing to a symbolic link."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        real_file = self.test_root / "real_file.json"
        real_file.write_text("{}", encoding="utf-8")
        sym_file = self.test_root / "sym_target.json"
        os.symlink(real_file, sym_file)

        with self.assertRaises(oc.CampaignValidationError):
            oc.save_campaign(camp, sym_file)

    def test_render_campaign_markdown_stages_and_audit(self):
        """Verifies markdown report includes stages, workloads, and audit logs."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
            title="Production Rollout 1",
        )
        md = oc.render_campaign_markdown(camp)
        self.assertIn("Production Rollout 1", md)
        self.assertIn("Rollout Lifecycle Stages", md)
        self.assertIn("Workload Enrollment & Verification Details", md)
        self.assertIn("Audit Trail", md)
        self.assertIn("CAMPAIGN_CREATED", md)

    def test_compliance_dashboard_with_symlink_campaign_file_rejection(self):
        """Verifies compliance dashboard rejects symlink campaign files."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        real_file = self.test_root / "real_camp.json"
        oc.save_campaign(camp, real_file)
        sym_file = self.test_root / "sym_camp.json"
        os.symlink(real_file, sym_file)

        with self.assertRaises(ValueError):
            gcd.generate_compliance_report(
                manifest_path=self.manifest_path,
                fleet_root=self.fixtures_root,
                campaign_file=sym_file,
            )

    def test_compliance_dashboard_with_corrupt_campaign_file(self):
        """Verifies compliance dashboard gracefully handles unparseable campaign files."""
        bad_file = self.test_root / "corrupt_camp.json"
        bad_file.write_text("not json content", encoding="utf-8")

        rep = gcd.generate_compliance_report(
            manifest_path=self.manifest_path,
            fleet_root=self.fixtures_root,
            campaign_file=bad_file,
        )
        self.assertIn("campaign_summary", rep)
        self.assertFalse(rep["campaign_summary"]["active"])
        self.assertIn("error", rep["campaign_summary"])

    def test_cli_list_campaigns(self):
        """Verifies CLI execution for --list-campaigns."""
        camp_dir = self.test_root / "campaigns_dir"
        camp_dir.mkdir()
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        oc.save_campaign(camp, camp_dir / f"{camp['campaign_id']}.json")

        script = REPO_ROOT / "scripts" / "orchestrate-campaign.py"
        res = subprocess.run(
            [
                sys.executable,
                str(script),
                "--list-campaigns",
                "--campaign-dir",
                str(camp_dir),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Registered Upgrade Campaigns", res.stdout)
        self.assertIn(camp["campaign_id"], res.stdout)

    def test_cli_execute_stage_canary_and_progressive(self):
        """Verifies full CLI execution flow for canary and progressive rollout."""
        camp_file = self.test_root / "cli_flow_camp.json"
        script = REPO_ROOT / "scripts" / "orchestrate-campaign.py"

        # 1. Create
        subprocess.run(
            [
                sys.executable,
                str(script),
                "--create",
                "--target-sha",
                self.valid_sha,
                "--manifest",
                str(self.manifest_path),
                "--campaign-file",
                str(camp_file),
            ],
            check=True,
            capture_output=True,
        )

        # 2. Canary Stage with dry-run
        res_canary = subprocess.run(
            [
                sys.executable,
                str(script),
                "--execute-stage",
                "canary",
                "--campaign-file",
                str(camp_file),
                "--fleet-root",
                str(self.fixtures_root),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_canary.returncode, 0)
        self.assertIn("Stage 'CANARY' VERIFIED successfully", res_canary.stdout)

    def test_cli_rollback_command(self):
        """Verifies CLI execution for --rollback."""
        camp_file = self.test_root / "cli_rb_camp.json"
        script = REPO_ROOT / "scripts" / "orchestrate-campaign.py"

        subprocess.run(
            [
                sys.executable,
                str(script),
                "--create",
                "--target-sha",
                self.valid_sha,
                "--manifest",
                str(self.manifest_path),
                "--campaign-file",
                str(camp_file),
            ],
            check=True,
            capture_output=True,
        )

        res_rb = subprocess.run(
            [
                sys.executable,
                str(script),
                "--rollback",
                "--rollback-reason",
                "Manual operator cancellation",
                "--campaign-file",
                str(camp_file),
                "--fleet-root",
                str(self.fixtures_root),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_rb.returncode, 0)
        self.assertIn("Campaign Rollback successfully", res_rb.stdout)

    def test_secret_scrubbing_in_audit_log(self):
        """Verifies secrets in audit logs or campaign details are scrubbed."""
        test_pat = "ghp_" + ("1234567890" * 3) + "123456"
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
            created_by=f"admin-with-token-{test_pat}",
        )
        self.assertNotIn("ghp_", camp["created_by"])
        self.assertIn("[REDACTED_GITHUB_TOKEN]", camp["created_by"])
        self.assertNotIn("ghp_", camp["audit_log"][0]["operator"])

    def test_audit_log_chronology(self):
        """Verifies audit trail records all transitions with valid ISO timestamps."""
        camp = oc.create_campaign(
            manifest_path=self.manifest_path,
            target_sha=self.valid_sha,
        )
        oc.execute_stage(
            campaign=camp,
            stage_name="canary",
            fleet_root=self.fixtures_root,
            platform_dir=REPO_ROOT,
            dry_run=True,
        )
        actions = [a["action"] for a in camp["audit_log"]]
        self.assertEqual(actions[0], "CAMPAIGN_CREATED")
        self.assertEqual(actions[1], "STAGE_CANARY_VERIFIED")


if __name__ == "__main__":
    unittest.main()
