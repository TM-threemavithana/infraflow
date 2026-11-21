#!/usr/bin/env python3
"""
Unit and Adversarial Test Suite for Fleet Observability & Compliance Dashboard (Milestone G09.1)
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Load emit-telemetry.py
emit_path = REPO_ROOT / "scripts" / "emit-telemetry.py"
spec_emit = importlib.util.spec_from_file_location("telemetry", str(emit_path))
telemetry = importlib.util.module_from_spec(spec_emit)
spec_emit.loader.exec_module(telemetry)

# Load generate-compliance-dashboard.py
dash_path = REPO_ROOT / "scripts" / "generate-compliance-dashboard.py"
spec_dash = importlib.util.spec_from_file_location("dashboard", str(dash_path))
dashboard = importlib.util.module_from_spec(spec_dash)
spec_dash.loader.exec_module(dashboard)


class TestTelemetryEngine(unittest.TestCase):
    """Tests for emit_telemetry.py event creation, validation, and sanitization."""

    def test_01_valid_event_creation(self):
        event = telemetry.create_telemetry_event(
            event_type="governance_gate_evaluated",
            consumer_id="consumer-networking",
            repository="TM-threemavithana/infraflow-consumer-networking",
            status="PASS",
            adapter="aws",
            platform_sha="be51718f06a2662099500a710e93e6e8201b4f1c",
        )
        self.assertEqual(event["schema_version"], "1.0")
        self.assertTrue(event["event_id"].startswith("evt_"))
        self.assertEqual(event["event_type"], "governance_gate_evaluated")
        self.assertEqual(event["verdict"]["status"], "PASS")
        self.assertEqual(event["verdict"]["compliance_status"], "COMPLIANT")
        self.assertIn("event_digest", event["integrity"])

        is_valid, errors = telemetry.validate_telemetry_event(event)
        self.assertTrue(is_valid, f"Validation failed with: {errors}")

    def test_02_all_valid_event_types(self):
        for et in telemetry.VALID_EVENT_TYPES:
            event = telemetry.create_telemetry_event(
                event_type=et,
                consumer_id="cid-test",
                repository="org/repo",
                status="PASS",
            )
            is_valid, errors = telemetry.validate_telemetry_event(event)
            self.assertTrue(is_valid, f"Event type '{et}' failed validation: {errors}")

    def test_03_invalid_event_type_raises(self):
        with self.assertRaises(telemetry.TelemetryValidationError):
            telemetry.create_telemetry_event(
                event_type="unauthorized_event_type",
                consumer_id="cid-test",
                repository="org/repo",
                status="PASS",
            )

    def test_04_invalid_status_raises(self):
        with self.assertRaises(telemetry.TelemetryValidationError):
            telemetry.create_telemetry_event(
                event_type="governance_gate_evaluated",
                consumer_id="cid-test",
                repository="org/repo",
                status="INVALID_STATUS",
            )

    def test_05_empty_identifiers_raise(self):
        with self.assertRaises(telemetry.TelemetryValidationError):
            telemetry.create_telemetry_event(
                event_type="governance_gate_evaluated",
                consumer_id="",
                repository="org/repo",
                status="PASS",
            )
        with self.assertRaises(telemetry.TelemetryValidationError):
            telemetry.create_telemetry_event(
                event_type="governance_gate_evaluated",
                consumer_id="cid-test",
                repository="",
                status="PASS",
            )

    def test_06_custom_metrics_and_reasons(self):
        event = telemetry.create_telemetry_event(
            event_type="security_scan_completed",
            consumer_id="cid-app",
            repository="org/app",
            status="WARN",
            metrics={"scanners_run": 3, "findings_count": 2},
            verdict_reasons=["Minor warning in optional tag", "Recommended encryption review"],
        )
        self.assertEqual(event["verdict"]["status"], "WARN")
        self.assertEqual(event["verdict"]["compliance_status"], "WARNING")
        self.assertEqual(event["metrics"]["scanners_run"], 3)
        self.assertEqual(len(event["verdict"]["reasons"]), 2)

    def test_07_scrub_aws_access_key(self):
        leak_text = "Encountered key AKIAIOSFODNN7EXAMPLE during test execution"
        scrubbed = telemetry.scrub_sensitive_string(leak_text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertIn("[REDACTED_AWS_KEY]", scrubbed)

    def test_08_scrub_github_tokens(self):
        leak_pat = "github_pat_11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01"
        leak_ghp = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        scrubbed = telemetry.scrub_sensitive_string(f"pat: {leak_pat} and ghp: {leak_ghp}")
        self.assertNotIn(leak_pat, scrubbed)
        self.assertNotIn(leak_ghp, scrubbed)
        self.assertIn("[REDACTED_GITHUB_PAT]", scrubbed)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", scrubbed)

    def test_09_scrub_jwt_token(self):
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        scrubbed = telemetry.scrub_sensitive_string(f"Bearer {fake_jwt}")
        self.assertNotIn(fake_jwt, scrubbed)
        self.assertIn("[REDACTED_JWT]", scrubbed)

    def test_10_scrub_private_key_block(self):
        fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA04...sample...key\n-----END RSA PRIVATE KEY-----"
        scrubbed = telemetry.scrub_sensitive_string(f"Key data:\n{fake_pem}")
        self.assertNotIn("sample...key", scrubbed)
        self.assertIn("[REDACTED_PRIVATE_KEY]", scrubbed)

    def test_11_scrub_dictionary_sensitive_keys(self):
        data = {
            "safe_metric": 42,
            "admin_password": "supersecretpassword123",
            "nested": {
                "api_key": "secret-api-token-value",
                "normal": "value",
            },
        }
        scrubbed = telemetry.scrub_sensitive_data(data)
        self.assertEqual(scrubbed["safe_metric"], 42)
        self.assertEqual(scrubbed["admin_password"], "[REDACTED_SENSITIVE_FIELD]")
        self.assertEqual(scrubbed["nested"]["api_key"], "[REDACTED_SENSITIVE_FIELD]")
        self.assertEqual(scrubbed["nested"]["normal"], "value")

    def test_12_tampered_event_digest_fails_validation(self):
        event = telemetry.create_telemetry_event(
            event_type="contract_verified",
            consumer_id="cid-app",
            repository="org/app",
            status="PASS",
        )
        # Tamper with event status after creation
        event["verdict"]["status"] = "FAIL"
        is_valid, errors = telemetry.validate_telemetry_event(event)
        self.assertFalse(is_valid)
        self.assertTrue(any("tampering detected" in err.lower() for err in errors))

    def test_13_emit_event_file_and_append(self):
        temp_dir = tempfile.mkdtemp()
        try:
            out_file = Path(temp_dir) / "telemetry.json"
            event1 = telemetry.create_telemetry_event(
                event_type="contract_verified",
                consumer_id="cid-1",
                repository="org/repo",
                status="PASS",
            )
            telemetry.emit_event(event1, output_path=out_file)
            self.assertTrue(out_file.is_file())

            # Read and verify
            loaded = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(loaded["consumer_id"] if "consumer_id" in loaded else loaded["target"]["consumer_id"], "cid-1")

            # Append mode (JSONL)
            jsonl_file = Path(temp_dir) / "telemetry.jsonl"
            telemetry.emit_event(event1, output_path=jsonl_file, append=True)
            event2 = telemetry.create_telemetry_event(
                event_type="security_scan_completed",
                consumer_id="cid-2",
                repository="org/repo",
                status="PASS",
            )
            telemetry.emit_event(event2, output_path=jsonl_file, append=True)

            lines = jsonl_file.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["target"]["consumer_id"], "cid-1")
            self.assertEqual(json.loads(lines[1])["target"]["consumer_id"], "cid-2")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestComplianceDashboard(unittest.TestCase):
    """Tests for generate_compliance_dashboard.py scoring and rendering."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manifest_path = REPO_ROOT / "config" / "fleet-manifest.yaml"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_14_load_valid_manifest(self):
        data = dashboard.load_fleet_manifest(self.manifest_path)
        self.assertIn("consumers", data)
        self.assertGreaterEqual(len(data["consumers"]), 3)

    def test_15_load_missing_manifest_raises(self):
        with self.assertRaises(dashboard.ComplianceEvaluationError):
            dashboard.load_fleet_manifest(Path(self.temp_dir) / "non-existent.yaml")

    def test_16_evaluate_missing_repo_yields_zero(self):
        c_entry = {
            "consumer_id": "test-none",
            "repository": "org/test-none",
            "adapter": "aws",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, Path(self.temp_dir) / "ghost-dir")
        self.assertEqual(res["total_score"], 0.0)
        self.assertEqual(res["status"], "NON_COMPLIANT")
        self.assertFalse(res["exists_locally"])

    def test_17_evaluate_compliant_fixture(self):
        networking_fixture = REPO_ROOT / "fixtures" / "consumers" / "networking"
        c_entry = {
            "consumer_id": "fixture-networking",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
            "target_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, networking_fixture)
        self.assertEqual(res["total_score"], 100.0)
        self.assertEqual(res["status"], "COMPLIANT")
        self.assertEqual(len(res["findings"]), 0)

    def test_18_evaluate_missing_config_penalized(self):
        # Create a repo with workflows but missing infraflow.config.yaml
        repo = Path(self.temp_dir) / "no-config"
        repo.mkdir()
        (repo / ".github" / "workflows").mkdir(parents=True)
        (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")

        c_entry = {"consumer_id": "c-test", "repository": "org/test", "adapter": "aws"}
        res = dashboard.evaluate_consumer_compliance(c_entry, repo)
        self.assertEqual(res["pillar_scores"]["contract_validity"], 0)
        self.assertLess(res["total_score"], 50.0)
        self.assertTrue(any("Missing infraflow.config.yaml" in f for f in res["findings"]))

    def test_19_evaluate_mutable_ref_penalized(self):
        # Create a valid repo but with @main mutable reference in workflow
        repo = Path(self.temp_dir) / "mutable-ref"
        repo.mkdir()
        shutil.copytree(REPO_ROOT / "fixtures" / "consumers" / "networking" / ".github", repo / ".github")
        shutil.copy(REPO_ROOT / "fixtures" / "consumers" / "networking" / "infraflow.config.yaml", repo / "infraflow.config.yaml")

        # Mutate workflow to @main
        wf = repo / ".github" / "workflows" / "infraflow-ci.yml"
        content = wf.read_text(encoding="utf-8")
        mutated = content.replace("2ce0ddd5de01530b6bf7aba749f0081620fb9b27", "main")
        wf.write_text(mutated, encoding="utf-8")

        c_entry = {
            "consumer_id": "fixture-networking",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
            "target_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, repo)
        self.assertEqual(res["pillar_scores"]["supply_chain_immutability"], 10)  # config has 40-char SHA (+10), but workflow is @main (+0)
        self.assertTrue(any("Mutable platform references detected" in f for f in res["findings"]))

    def test_20_evaluate_disabled_scanners_penalized(self):
        repo = Path(self.temp_dir) / "no-scanners"
        repo.mkdir()
        shutil.copytree(REPO_ROOT / "fixtures" / "consumers" / "application" / ".github", repo / ".github")
        cfg_content = (REPO_ROOT / "fixtures" / "consumers" / "application" / "infraflow.config.yaml").read_text(encoding="utf-8")
        mutated_cfg = cfg_content.replace("enforce_mandatory_scanners: true", "enforce_mandatory_scanners: false")
        (repo / "infraflow.config.yaml").write_text(mutated_cfg, encoding="utf-8")

        c_entry = {
            "consumer_id": "fixture-application",
            "repository": "TM-threemavithana/infraflow-consumer-application",
            "adapter": "azure",
            "target_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, repo)
        self.assertEqual(res["pillar_scores"]["security_controls"], 10)  # Governance invoked (+10), but scanners disabled (+0)
        self.assertTrue(any("enforce_mandatory_scanners is not true" in f for f in res["findings"]))

    def test_21_evaluate_forbidden_permissions_penalized(self):
        repo = Path(self.temp_dir) / "bad-permissions"
        repo.mkdir()
        shutil.copytree(REPO_ROOT / "fixtures" / "consumers" / "networking" / ".github", repo / ".github")
        shutil.copy(REPO_ROOT / "fixtures" / "consumers" / "networking" / "infraflow.config.yaml", repo / "infraflow.config.yaml")

        wf = repo / ".github" / "workflows" / "infraflow-ci.yml"
        content = wf.read_text(encoding="utf-8")
        mutated = content.replace("contents: read", "write-all\n    id-token: write")
        wf.write_text(mutated, encoding="utf-8")

        c_entry = {
            "consumer_id": "fixture-networking",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
            "target_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, repo)
        self.assertEqual(res["pillar_scores"]["permission_boundary"], 5)  # zero pull_request_target (+5), but write-all and id-token write fail (+0)
        self.assertTrue(any("Forbidden 'write-all'" in f for f in res["findings"]))
        self.assertTrue(any("Forbidden 'id-token: write'" in f for f in res["findings"]))

    def test_22_evaluate_pull_request_target_penalized(self):
        repo = Path(self.temp_dir) / "pr-target"
        repo.mkdir()
        shutil.copytree(REPO_ROOT / "fixtures" / "consumers" / "networking" / ".github", repo / ".github")
        shutil.copy(REPO_ROOT / "fixtures" / "consumers" / "networking" / "infraflow.config.yaml", repo / "infraflow.config.yaml")

        wf = repo / ".github" / "workflows" / "infraflow-ci.yml"
        content = wf.read_text(encoding="utf-8")
        mutated = content.replace("pull_request:", "pull_request_target:")
        wf.write_text(mutated, encoding="utf-8")

        c_entry = {
            "consumer_id": "fixture-networking",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
            "target_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, repo)
        self.assertEqual(res["pillar_scores"]["permission_boundary"], 15)  # least-privilege (+10), no id-token write (+5), pr_target fails (+0)
        self.assertTrue(any("pull_request_target" in f for f in res["findings"]))

    def test_23_evaluate_sha_drift_penalized(self):
        repo = Path(self.temp_dir) / "sha-drift"
        repo.mkdir()
        shutil.copytree(REPO_ROOT / "fixtures" / "consumers" / "networking" / ".github", repo / ".github")
        cfg_content = (REPO_ROOT / "fixtures" / "consumers" / "networking" / "infraflow.config.yaml").read_text(encoding="utf-8")
        # Change config SHA to a different valid 40-char SHA
        mutated_cfg = cfg_content.replace(
            "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        (repo / "infraflow.config.yaml").write_text(mutated_cfg, encoding="utf-8")

        c_entry = {
            "consumer_id": "fixture-networking",
            "repository": "TM-threemavithana/infraflow-consumer-networking",
            "adapter": "aws",
            "target_sha": "2ce0ddd5de01530b6bf7aba749f0081620fb9b27",
        }
        res = dashboard.evaluate_consumer_compliance(c_entry, repo)
        self.assertEqual(res["pillar_scores"]["drift_integrity"], 5)  # adapter matches (+5), but config != workflow (+0) and config != target (+0)
        self.assertTrue(any("Drift between config SHA" in f for f in res["findings"]))

    def test_24_render_markdown_structure(self):
        report = dashboard.generate_compliance_report(self.manifest_path, REPO_ROOT)
        md = dashboard.render_markdown_dashboard(report)
        self.assertIn("# InfraFlow Central Fleet Compliance & Observability Dashboard", md)
        self.assertIn("## 1. Fleet Executive Summary", md)
        self.assertIn("## 2. Multi-Tenant Workload Posture", md)
        self.assertIn("## 3. Governance Findings & Recommendations", md)
        self.assertIn("consumer-networking", md)
        self.assertIn("consumer-application", md)
        self.assertIn("consumer-data-platform", md)

    def test_25_render_html_dashboard_offline_ready(self):
        report = dashboard.generate_compliance_report(self.manifest_path, REPO_ROOT)
        html_out = dashboard.render_html_dashboard(report)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("InfraFlow Fleet Compliance Dashboard", html_out)
        self.assertIn("Multi-Tenant Consumer Fleet Posture", html_out)
        # Verify offline self-contained requirement: zero external http/https stylesheets or scripts
        self.assertNotIn("https://cdn.", html_out)
        self.assertNotIn("http://", html_out)
        self.assertNotIn("<link rel=\"stylesheet\" href=\"http", html_out)
        self.assertNotIn("<script src=\"http", html_out)

    def test_26_cli_emit_telemetry_success(self):
        out_f = Path(self.temp_dir) / "cli_event.json"
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "emit-telemetry.py"),
            "--event-type", "governance_gate_evaluated",
            "--consumer-id", "test-cid",
            "--repository", "TM-threemavithana/infraflow",
            "--status", "PASS",
            "--adapter", "aws",
            "--output", str(out_f),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(out_f.is_file())

    def test_27_cli_emit_telemetry_missing_required_args_fails(self):
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "emit-telemetry.py"),
            "--event-type", "governance_gate_evaluated",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)

    def test_28_cli_generate_dashboard_success(self):
        out_json = Path(self.temp_dir) / "dash.json"
        out_md = Path(self.temp_dir) / "dash.md"
        out_html = Path(self.temp_dir) / "dash.html"
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-compliance-dashboard.py"),
            "--manifest", str(self.manifest_path),
            "--fleet-root", str(REPO_ROOT),
            "--output-json", str(out_json),
            "--output-markdown", str(out_md),
            "--output-html", str(out_html),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(out_json.is_file())
        self.assertTrue(out_md.is_file())
        self.assertTrue(out_html.is_file())

    def test_29_cli_generate_dashboard_threshold_enforcement_pass(self):
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-compliance-dashboard.py"),
            "--manifest", str(self.manifest_path),
            "--fleet-root", str(REPO_ROOT),
            "--enforce-threshold", "50.0",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

    def test_30_cli_generate_dashboard_threshold_enforcement_fail(self):
        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-compliance-dashboard.py"),
            "--manifest", str(self.manifest_path),
            "--fleet-root", str(Path(self.temp_dir) / "empty"),
            "--enforce-threshold", "90.0",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)

    def test_31_telemetry_scrubs_generic_password_and_secret_assignments(self):
        leak_str = 'db_password="SuperSecretPassword123!" api_key="secret-api-key-value-here"'
        scrubbed = telemetry.scrub_sensitive_string(leak_str)
        self.assertNotIn("SuperSecretPassword123!", scrubbed)
        self.assertNotIn("secret-api-key-value-here", scrubbed)
        self.assertIn("[REDACTED_SECRET]", scrubbed)


if __name__ == "__main__":
    unittest.main()
