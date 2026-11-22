#!/usr/bin/env python3
"""
InfraFlow Unified CLI Test Suite (Milestone G10.1)

Comprehensive functional and unit tests covering:
1. Platform version and help command propagation.
2. Platform doctor 12-check diagnostics, strict mode, and JSON emission.
3. Consumer configuration, manifest, and OPA policy validation.
4. Policy error enhancement, source line mapping, and remediation hints.
5. Continuous state and speculative drift detection simulation and gates.
6. Fleet upgrade planning and JSON telemetry outputs.
7. Secret redaction engine (AWS keys, GitHub tokens, private keys).
8. Fail-closed security controls (symlink rejection, path traversal protection).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_PATH = REPO_ROOT / "scripts" / "infraflow-cli.py"

# Add scripts directory to sys.path for direct component testing
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# Import CLI module
import importlib.util
spec = importlib.util.spec_from_file_location("infraflow_cli", str(CLI_PATH))
infraflow_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(infraflow_cli)


class TestCLIHelpAndVersion(unittest.TestCase):
    """Verifies help output, version flags, and global argument handling."""

    def test_version_flag(self):
        res = subprocess.run([sys.executable, str(CLI_PATH), "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("infraflow version 0.7.0", res.stdout)
        self.assertIn("TM-threemavithana/infraflow", res.stdout)

    def test_help_flag(self):
        res = subprocess.run([sys.executable, str(CLI_PATH), "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("doctor", res.stdout)
        self.assertIn("validate", res.stdout)
        self.assertIn("drift", res.stdout)
        self.assertIn("upgrade", res.stdout)
        self.assertIn("init", res.stdout)
        self.assertIn("register", res.stdout)

    def test_subcommand_helps(self):
        for subcmd in ["doctor", "validate", "drift", "upgrade", "init", "register"]:
            res = subprocess.run([sys.executable, str(CLI_PATH), subcmd, "--help"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn(f"usage: infraflow {subcmd}", res.stdout)


class TestCLIDoctor(unittest.TestCase):
    """Verifies the 12-dimension Platform Doctor diagnostics."""

    def test_doctor_execution_text(self):
        res = subprocess.run([sys.executable, str(CLI_PATH), "doctor"], capture_output=True, text=True)
        # Should exit 0 since core tools, python, dirs, policies, and deps are intact
        self.assertEqual(res.returncode, 0)
        self.assertIn("InfraFlow Platform Diagnostic Engine", res.stdout)
        self.assertIn("Python Runtime (>= 3.10)", res.stdout)
        self.assertIn("Terraform CLI (>= 1.6.0)", res.stdout)
        self.assertIn("Conftest Open Policy Agent (OPA)", res.stdout)
        self.assertIn("Platform Directory Hierarchy", res.stdout)
        self.assertIn("Core Security & Governance Policies", res.stdout)

    def test_doctor_execution_json(self):
        res = subprocess.run([sys.executable, str(CLI_PATH), "doctor", "--json"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        payload = json.loads(res.stdout)
        self.assertEqual(payload["platform_version"], "0.7.0")
        self.assertEqual(payload["summary"]["total"], 12)
        self.assertGreaterEqual(payload["summary"]["passed"], 10)
        self.assertEqual(payload["summary"]["failed"], 0)

        check_ids = [c["id"] for c in payload["checks"]]
        self.assertIn("DOC-01-PYTHON", check_ids)
        self.assertIn("DOC-02-TERRAFORM", check_ids)
        self.assertIn("DOC-03-GIT", check_ids)
        self.assertIn("DOC-06-CONFTEST", check_ids)
        self.assertIn("DOC-09-DIRS", check_ids)
        self.assertIn("DOC-10-POLICIES", check_ids)
        self.assertIn("DOC-11-PYDEPS", check_ids)
        self.assertIn("DOC-12-GITSTATE", check_ids)


class TestCLIValidate(unittest.TestCase):
    """Verifies consumer config, manifest, and policy validation."""

    def test_validate_consumer_config_success(self):
        config_path = REPO_ROOT / "fixtures" / "consumers" / "networking" / "infraflow.config.yaml"
        res = subprocess.run([sys.executable, str(CLI_PATH), "validate", "--config", str(config_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("ALL CONSUMER ONBOARDING CHECKS PASSED", res.stdout)

    def test_validate_consumer_config_json(self):
        config_path = REPO_ROOT / "fixtures" / "consumers" / "networking" / "infraflow.config.yaml"
        res = subprocess.run([sys.executable, str(CLI_PATH), "validate", "--config", str(config_path), "--json"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertTrue(data["valid"])
        self.assertEqual(data["summary"]["failed"], 0)

    def test_validate_fleet_manifest_success(self):
        manifest_path = REPO_ROOT / "config" / "fleet-manifest.yaml"
        res = subprocess.run([sys.executable, str(CLI_PATH), "validate", "-m", str(manifest_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Fleet Manifest Valid", res.stdout)
        self.assertIn("Candidate SHA: be51718f06a2662099500a710e93e6e8201b4f1c", res.stdout)

    def test_validate_policy_with_error_enhancement(self):
        policy_file = REPO_ROOT / "policies" / "aws" / "s3.rego"
        bad_input = REPO_ROOT / "fixtures" / "security" / "policies" / "invalid-aws" / "main.tf"
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "validate", "-p", str(policy_file), "-i", str(bad_input), "-n", "aws.s3"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Policy Evaluation Failed: 1 violation(s) detected", res.stdout)
        self.assertIn("AWS-SEC-S3-ACL-001 (CRITICAL)", res.stdout)
        self.assertIn("aws_s3_bucket.bad_acl_bucket", res.stdout)
        self.assertIn("Remediation:", res.stdout)

    def test_validate_policy_json_format(self):
        policy_file = REPO_ROOT / "policies" / "aws" / "s3.rego"
        bad_input = REPO_ROOT / "fixtures" / "security" / "policies" / "invalid-aws" / "main.tf"
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "validate", "-p", str(policy_file), "-i", str(bad_input), "-n", "aws.s3", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertFalse(data["valid"])
        self.assertEqual(data["violations_count"], 1)
        violation = data["violations"][0]
        self.assertEqual(violation["policy_id"], "AWS-SEC-S3-ACL-001")
        self.assertEqual(violation["severity"], "CRITICAL")
        self.assertEqual(violation["resource"], "aws_s3_bucket.bad_acl_bucket")
        self.assertEqual(violation["line"], 5)
        self.assertTrue(len(violation["remediation"]) > 10)


class TestCLIDrift(unittest.TestCase):
    """Verifies continuous state and speculative drift detection simulation."""

    def test_drift_clean_no_drift(self):
        exp = REPO_ROOT / "fixtures" / "drift" / "aws" / "clean" / "expected.json"
        obs = REPO_ROOT / "fixtures" / "drift" / "aws" / "clean" / "observed.json"
        res = subprocess.run([sys.executable, str(CLI_PATH), "drift", "-e", str(exp), "-o", str(obs)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Verdict: NO_DRIFT", res.stdout)

    def test_drift_detected_without_gate(self):
        exp = REPO_ROOT / "fixtures" / "drift" / "aws" / "attribute-drift" / "expected.json"
        obs = REPO_ROOT / "fixtures" / "drift" / "aws" / "attribute-drift" / "observed.json"
        res = subprocess.run([sys.executable, str(CLI_PATH), "drift", "-e", str(exp), "-o", str(obs)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)  # Exits 0 unless --enforce-zero-drift
        self.assertIn("Verdict: DRIFT_DETECTED", res.stdout)
        self.assertIn("ATTRIBUTE_DRIFT", res.stdout)

    def test_drift_enforce_zero_drift_gate_fails(self):
        exp = REPO_ROOT / "fixtures" / "drift" / "aws" / "attribute-drift" / "expected.json"
        obs = REPO_ROOT / "fixtures" / "drift" / "aws" / "attribute-drift" / "observed.json"
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "drift", "-e", str(exp), "-o", str(obs), "--enforce-zero-drift"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Drift gate failed", res.stderr)

    def test_drift_json_export(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.close()
        try:
            exp = REPO_ROOT / "fixtures" / "drift" / "aws" / "clean" / "expected.json"
            obs = REPO_ROOT / "fixtures" / "drift" / "aws" / "clean" / "observed.json"
            res = subprocess.run(
                [sys.executable, str(CLI_PATH), "drift", "-e", str(exp), "-o", str(obs), "--output-json", tmp.name],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            data = json.loads(Path(tmp.name).read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["verdict"], "NO_DRIFT")
        finally:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)


class TestCLIUpgrade(unittest.TestCase):
    """Verifies fleet upgrade dry-run planning and campaign operations."""

    def test_upgrade_plan_dry_run(self):
        manifest_path = REPO_ROOT / "config" / "fleet-manifest.yaml"
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "upgrade", "-m", str(manifest_path), "--plan"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("InfraFlow Fleet Upgrade Plan (Dry-Run)", res.stdout)
        self.assertIn("Stage 1 — Canary Rollout:", res.stdout)
        self.assertIn("Stage 2 — Progressive Rollout", res.stdout)

    def test_upgrade_plan_json(self):
        manifest_path = REPO_ROOT / "config" / "fleet-manifest.yaml"
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "upgrade", "-m", str(manifest_path), "--plan", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("candidate_sha", data)
        self.assertIn("staged_rollout", data)
        self.assertIn("canary", data["staged_rollout"])


class TestCLISecurityAndSanitization(unittest.TestCase):
    """Verifies secret redaction, path traversal defense, and symlink prohibition."""

    def test_secret_redaction_unit(self):
        sanitizer = infraflow_cli.SecretSanitizer
        mock_pat = "ghp_" + ("A" * 36)
        sample_text = (
            f"Connecting with AKIAIOSFODNN7EXAMPLE and secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY. "
            f"Token is {mock_pat} and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy."
        )
        scrubbed = sanitizer.sanitize_text(sample_text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertNotIn(mock_pat, scrubbed)
        self.assertIn("[REDACTED_SECRET]", scrubbed)

    def test_symlink_rejection_security(self):
        tmp_dir = tempfile.mkdtemp(prefix="cli-symlink-test-")
        try:
            real_file = Path(tmp_dir) / "real.json"
            real_file.write_text('{"schema_version": "1.0"}', encoding="utf-8")
            symlink_file = Path(tmp_dir) / "link.json"
            os.symlink(real_file, symlink_file)

            # Pass symlink to drift command
            res = subprocess.run(
                [sys.executable, str(CLI_PATH), "drift", "-e", str(symlink_file), "-o", str(real_file)],
                capture_output=True,
                text=True,
            )
            # Must fail with EXIT_SECURITY (2)
            self.assertEqual(res.returncode, 2)
            self.assertIn("Symbolic link prohibited by security policy", res.stderr)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_path_traversal_non_existent(self):
        fake_path = REPO_ROOT / "fixtures" / ".." / ".." / ".." / "etc" / "passwd"
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "validate", "--config", str(fake_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("File not found", res.stderr)


class TestCLIPackageInstallation(unittest.TestCase):
    """Verifies packaging metadata, module parity, entry points, and exit code contracts (G10.1.1)."""

    def test_package_import_and_metadata(self):
        import infraflow
        self.assertEqual(infraflow.__version__, "0.7.0")
        self.assertEqual(infraflow.__canonical_ref__, "TM-threemavithana/infraflow")
        self.assertTrue(len(infraflow.__author__) > 0)

    def test_cli_module_parity(self):
        from infraflow import cli as pkg_cli
        self.assertTrue(hasattr(pkg_cli, "main"))
        self.assertTrue(hasattr(pkg_cli, "build_parser"))
        self.assertTrue(hasattr(pkg_cli, "PlatformDoctor"))
        self.assertTrue(hasattr(pkg_cli, "SecretSanitizer"))
        self.assertTrue(hasattr(pkg_cli, "PathValidator"))
        self.assertTrue(hasattr(pkg_cli, "CLIHandlers"))

        # scripts/infraflow-cli.py should expose the same public symbols
        self.assertTrue(hasattr(infraflow_cli, "main"))
        self.assertTrue(hasattr(infraflow_cli, "build_parser"))
        self.assertTrue(hasattr(infraflow_cli, "PlatformDoctor"))

    def test_pyproject_toml_configuration(self):
        pyproject_file = REPO_ROOT / "pyproject.toml"
        self.assertTrue(pyproject_file.is_file(), "pyproject.toml must exist at repository root")
        content = pyproject_file.read_text(encoding="utf-8")
        self.assertIn('[build-system]', content)
        self.assertIn('requires = ["setuptools>=61.0", "wheel"]', content)
        self.assertIn('name = "infraflow"', content)
        self.assertIn('version = "0.7.0"', content)
        self.assertIn('[project.scripts]', content)
        self.assertIn('infraflow = "infraflow.cli:main"', content)

    def test_setup_py_shim_exists(self):
        setup_file = REPO_ROOT / "setup.py"
        self.assertTrue(setup_file.is_file(), "setup.py shim must exist for legacy compatibility")
        content = setup_file.read_text(encoding="utf-8")
        self.assertIn("setup()", content)

    def test_python_module_execution_m_flag(self):
        res = subprocess.run(
            [sys.executable, "-m", "infraflow.cli", "--version"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("infraflow version 0.7.0", res.stdout)

    def test_programmatic_invocation_main(self):
        from infraflow.cli import main
        # No arguments prints help and returns EXIT_OK (0)
        rc = main([])
        self.assertEqual(rc, 0)

        # --version raises SystemExit(0)
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

        # Unknown argument raises SystemExit(2)
        with self.assertRaises(SystemExit) as cm:
            main(["--invalid-argument-xyz"])
        self.assertEqual(cm.exception.code, 2)

    def test_exit_code_contract_constants(self):
        from infraflow.cli import EXIT_OK, EXIT_ERROR, EXIT_SECURITY
        self.assertEqual(EXIT_OK, 0)
        self.assertEqual(EXIT_ERROR, 1)
        self.assertEqual(EXIT_SECURITY, 2)


if __name__ == "__main__":
    unittest.main()
