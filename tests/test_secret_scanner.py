#!/usr/bin/env python3
"""
InfraFlow — Consumer Secret Defense Adversarial Test Suite
Milestone: G10.3

Validates secret scanning engine across:
- AWS access keys and secret keys.
- GitHub classic and fine-grained personal access tokens.
- Cryptographic PEM private keys.
- Hardcoded passwords and bearer tokens.
- Obfuscated / placeholder false-positive handling.
- Binary Terraform execution plan exclusion.
- Complete secret redaction (zero secret leakage in findings/reports).
- CLI execution and exit codes.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infraflow.scanner import SecretScanner, SecretScanError, redact_secret, is_placeholder


class TestSecretScannerAdversarial(unittest.TestCase):
    """Comprehensive test suite for consumer secret scanning defense."""

    def setUp(self):
        self.scanner = SecretScanner()
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-secret-test-")
        self.tmp_path = Path(self.tmp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. AWS Credential Detection Tests
    # --------------------------------------------------------------------------

    def test_aws_access_key_detected(self):
        """Detects AWS access key ID in source files."""
        raw_key = "AKIAIOSFODNN7EXAMPLE"
        text = f'aws_access_key = "{raw_key}"'
        findings = self.scanner.scan_text(text, "main.tf")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-AWS-001")
        self.assertNotIn(raw_key, findings[0].redacted_match)
        self.assertIn("AKIA", findings[0].redacted_match)

    def test_aws_secret_access_key_detected(self):
        """Detects AWS secret access key assignments."""
        raw_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f'aws_secret_access_key = "{raw_secret}"'
        findings = self.scanner.scan_text(text, "creds.env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-AWS-002")
        self.assertNotIn(raw_secret, findings[0].redacted_match)

    # --------------------------------------------------------------------------
    # 2. GitHub Token Detection Tests
    # --------------------------------------------------------------------------

    def test_github_classic_pat_detected(self):
        """Detects classic GitHub personal access token (ghp_)."""
        raw_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        text = f'export GITHUB_TOKEN="{raw_token}"'
        findings = self.scanner.scan_text(text, "deploy.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-GH-001")
        self.assertNotIn(raw_token, findings[0].redacted_match)
        self.assertTrue(findings[0].redacted_match.startswith("ghp_"))

    def test_github_fine_grained_pat_detected(self):
        """Detects GitHub fine-grained PAT (github_pat_)."""
        raw_token = "github_pat_11ABCD1234567890abcdef_1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr"
        text = f'token: {raw_token}'
        findings = self.scanner.scan_text(text, "config.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-GH-002")
        self.assertNotIn(raw_token, findings[0].redacted_match)

    def test_github_oauth_and_app_tokens_detected(self):
        """Detects GitHub OAuth (gho_) and app tokens (ghu_, ghs_, ghr_)."""
        t_oauth = "gho_1234567890abcdefghijklmnopqrstuvwxyz"
        t_app = "ghs_1234567890abcdefghijklmnopqrstuvwxyz"
        text = f'oauth = "{t_oauth}"\nserver = "{t_app}"'
        findings = self.scanner.scan_text(text, "tokens.tf")
        self.assertEqual(len(findings), 2)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SEC-GH-003", rule_ids)
        self.assertIn("SEC-GH-004", rule_ids)

    # --------------------------------------------------------------------------
    # 3. Cryptographic Private Key Detection Tests
    # --------------------------------------------------------------------------

    def test_pem_private_key_detected(self):
        """Detects RSA, OpenSSH, and EC private key headers."""
        pem_rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        findings = self.scanner.scan_text(pem_rsa, "id_rsa")
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].rule_id, "SEC-KEY-001")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_generic_private_key_detected(self):
        """Detects generic PKCS#8 private key header."""
        pem_pkcs8 = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."
        findings = self.scanner.scan_text(pem_pkcs8, "key.pem")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-KEY-002")

    # --------------------------------------------------------------------------
    # 4. Passwords, Google API Keys, and Bearer Tokens
    # --------------------------------------------------------------------------

    def test_hardcoded_password_detected(self):
        """Detects hardcoded database and service passwords."""
        raw_pw = "SuperSecretDbPassword99#"
        text = f'password = "{raw_pw}"'
        findings = self.scanner.scan_text(text, "terraform.tfvars")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-CRED-001")
        self.assertNotIn(raw_pw, findings[0].redacted_match)

    def test_google_api_key_detected(self):
        """Detects GCP API keys (AIza...)."""
        raw_gcp = "AIzaSyD-1234567890abcdefghijklmnopqrst"
        text = f'gcp_key = "{raw_gcp}"'
        findings = self.scanner.scan_text(text, "vars.tf")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-GCP-001")

    def test_bearer_token_detected(self):
        """Detects Authorization: Bearer tokens."""
        raw_bearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        text = f'Authorization: Bearer {raw_bearer}'
        findings = self.scanner.scan_text(text, "curl.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-AUTH-001")

    # --------------------------------------------------------------------------
    # 5. False-Positive and Placeholder Filtering
    # --------------------------------------------------------------------------

    def test_placeholder_passwords_ignored(self):
        """Placeholders like 'changeme' or '${var.password}' are ignored."""
        text = """
        db_password = "${var.db_password}"
        admin_pass = "CHANGEME_NOW"
        dummy_secret = "placeholder_secret_value"
        sample_key = "dummy_token_12345"
        """
        findings = self.scanner.scan_text(text, "variables.tf")
        self.assertEqual(len(findings), 0)

    # --------------------------------------------------------------------------
    # 6. Binary Plan File Exclusion
    # --------------------------------------------------------------------------

    def test_binary_tfplan_file_skipped(self):
        """Binary .tfplan files are never scanned as plaintext source files."""
        tfplan_file = self.tmp_path / "tfplan.binary"
        # Write binary data with null bytes and random byte strings
        tfplan_file.write_bytes(b"\x00\x01\x02\x03TFPLAN_BINARY_PAYLOAD_AKIAIOSFODNN7EXAMPLE\x00\x00")

        findings = self.scanner.scan_file(tfplan_file)
        self.assertEqual(len(findings), 0)

    def test_extension_exclusion_skips_plan_extension(self):
        """Files with .tfplan or .plan extensions are immediately skipped by extension check."""
        plan_f = self.tmp_path / "production.tfplan"
        plan_f.write_text('aws_access_key = "AKIAIOSFODNN7EXAMPLE"', encoding="utf-8")

        findings = self.scanner.scan_file(plan_f)
        self.assertEqual(len(findings), 0)

    # --------------------------------------------------------------------------
    # 7. Redaction & Zero Leakage Invariant
    # --------------------------------------------------------------------------

    def test_zero_raw_secret_leakage_in_report(self):
        """Verifies report dictionary never contains unmasked secret values."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        test_file = self.tmp_path / "main.tf"
        test_file.write_text(f'variable "key" {{ default = "{raw_secret}" }}', encoding="utf-8")

        report = self.scanner.scan_directory(self.tmp_path)
        self.assertFalse(report["is_clean"])
        self.assertEqual(report["total_secrets_found"], 1)

        # Convert entire report to JSON string and verify raw secret does not exist
        report_json = json.dumps(report)
        self.assertNotIn(raw_secret, report_json)
        self.assertIn("AKIA", report_json)
        self.assertIn("***", report_json)

    # --------------------------------------------------------------------------
    # 8. Directory Recursion and Clean Directory
    # --------------------------------------------------------------------------

    def test_clean_directory_passes(self):
        """Directory without secrets produces status PASS."""
        (self.tmp_path / "main.tf").write_text('resource "terraform_data" "x" {}', encoding="utf-8")
        (self.tmp_path / "README.md").write_text('# Documentation\nNo secrets here.', encoding="utf-8")

        report = self.scanner.scan_directory(self.tmp_path)
        self.assertTrue(report["is_clean"])
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["total_secrets_found"], 0)

    # --------------------------------------------------------------------------
    # 9. CLI Execution Tests
    # --------------------------------------------------------------------------

    def test_cli_clean_directory_exit_code_zero(self):
        """scan-secrets.py returns 0 on clean repository."""
        clean_dir = self.tmp_path / "clean"
        clean_dir.mkdir()
        (clean_dir / "main.tf").write_text('resource "terraform_data" "x" {}', encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "scan-secrets.py"), "--target-dir", str(clean_dir), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data["is_clean"])

    def test_cli_detected_secret_exit_code_one(self):
        """scan-secrets.py returns 1 when credentials are found."""
        dirty_dir = self.tmp_path / "dirty"
        dirty_dir.mkdir()
        (dirty_dir / "creds.tf").write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"', encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "scan-secrets.py"), "--target-dir", str(dirty_dir), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertFalse(data["is_clean"])
        self.assertEqual(data["total_secrets_found"], 1)

    def test_cli_invalid_target_dir_exit_code_two(self):
        """scan-secrets.py returns 2 on invalid path."""
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "scan-secrets.py"), "--target-dir", "/non/existent/path/xyz"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
