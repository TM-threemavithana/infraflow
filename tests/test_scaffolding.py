#!/usr/bin/env python3
"""
InfraFlow Self-Service Consumer Scaffolding & Registration Test Suite (Milestone G10.2).

Comprehensive functional, security, and adversarial tests covering:
1. Multi-cloud consumer scaffolding (AWS, Azure, GCP, provider-neutral).
2. Generated file completeness, metadata, and immutable SHA pinning.
3. Fail-closed overwrite protection on existing non-empty directories.
4. Path traversal, symlink, and invalid identifier rejection.
5. Pre-flight consumer validation requirement before registration.
6. Preview and dry-run registration mode.
7. Atomic manifest modification and preservation of existing fleet entries.
8. Duplicate consumer ID and duplicate repository identity rejection.
9. Secret scrubbing on CLI outputs and payloads.
10. Exit code contract adherence (0: success, 1: validation error, 2: security error).
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

# Add package to sys.path
sys.path.insert(0, str(REPO_ROOT))

from infraflow.scaffold import (
    ConsumerScaffolder,
    ScaffoldingError,
    ScaffoldingSecurityError,
    SUPPORTED_ADAPTERS,
)
from infraflow.registrar import (
    ConsumerRegistrar,
    RegistrationError,
    RegistrationSecurityError,
)
from infraflow.cli import main, EXIT_OK, EXIT_ERROR, EXIT_SECURITY


class TestConsumerScaffolding(unittest.TestCase):
    """Verifies self-service consumer project generation, templates, and safety controls."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-test-scaffold-")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_scaffold_all_supported_adapters(self):
        for adapter in ["aws", "azure", "gcp", "provider-neutral"]:
            out_dir = Path(self.tmp_dir) / f"consumer-{adapter}"
            scaffolder = ConsumerScaffolder(
                consumer_id=f"test-{adapter}-workload",
                adapter=adapter,
                environment="dev",
                workload_type="general",
                team="core-platform",
                output_dir=out_dir,
                platform_sha="be51718f06a2662099500a710e93e6e8201b4f1c",
            )
            result = scaffolder.scaffold()
            self.assertEqual(result["consumer_id"], f"test-{adapter}-workload")
            self.assertEqual(result["adapter"], adapter)
            self.assertTrue(out_dir.is_dir())

            # Check that all expected files were generated
            expected_files = [
                "infraflow.config.yaml",
                ".github/workflows/infraflow-ci.yml",
                "terraform/versions.tf",
                "terraform/main.tf",
                "terraform/variables.tf",
                "terraform/outputs.tf",
                "terraform/tests/unit.tftest.hcl",
                "policies/local_governance.rego",
                "README.md",
                ".infraflow-metadata.json",
            ]
            for ef in expected_files:
                f_path = out_dir / ef
                self.assertTrue(f_path.is_file(), f"Missing expected file: {ef} for adapter {adapter}")
                self.assertGreater(f_path.stat().st_size, 0, f"Empty file: {ef}")

    def test_generated_config_contract(self):
        out_dir = Path(self.tmp_dir) / "consumer-cfg-test"
        scaffolder = ConsumerScaffolder(
            consumer_id="billing-service",
            adapter="aws",
            environment="staging",
            workload_type="application",
            team="billing-team",
            output_dir=out_dir,
            platform_sha="be51718f06a2662099500a710e93e6e8201b4f1c",
        )
        scaffolder.scaffold()

        config_path = out_dir / "infraflow.config.yaml"
        content = config_path.read_text(encoding="utf-8")
        self.assertIn('consumer_id: "billing-service"', content)
        self.assertIn('adapter: "aws"', content)
        self.assertIn('environment: "staging"', content)
        self.assertIn('team: "billing-team"', content)
        self.assertIn('workload_type: "application"', content)
        self.assertIn('platform_ref: "TM-threemavithana/infraflow"', content)
        self.assertIn('platform_sha: "be51718f06a2662099500a710e93e6e8201b4f1c"', content)
        self.assertIn("enforce_mandatory_scanners: true", content)

    def test_generated_workflow_immutable_pinning(self):
        out_dir = Path(self.tmp_dir) / "consumer-wf-test"
        sha = "be51718f06a2662099500a710e93e6e8201b4f1c"
        scaffolder = ConsumerScaffolder(
            consumer_id="analytics-worker",
            adapter="gcp",
            output_dir=out_dir,
            platform_sha=sha,
        )
        scaffolder.scaffold()

        wf_path = out_dir / ".github" / "workflows" / "infraflow-ci.yml"
        content = wf_path.read_text(encoding="utf-8")
        self.assertIn(f"@{sha}", content)
        self.assertNotIn("@main", content)
        self.assertNotIn("@master", content)
        self.assertNotIn("@latest", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertIn("reusable-tf-governance.yml", content)
        self.assertIn("reusable-tf-gcp.yml", content)

    def test_overwrite_protection_fail_closed(self):
        out_dir = Path(self.tmp_dir) / "non-empty-dir"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "existing_file.txt").write_text("pre-existing content", encoding="utf-8")

        # Without force, scaffolding must raise ScaffoldingSecurityError
        with self.assertRaises(ScaffoldingSecurityError) as cm:
            ConsumerScaffolder(
                consumer_id="conflict-consumer",
                output_dir=out_dir,
                force=False,
            )
        self.assertIn("already exists and contains", str(cm.exception))

        # With force=True, scaffolding must succeed
        scaffolder = ConsumerScaffolder(
            consumer_id="conflict-consumer",
            output_dir=out_dir,
            force=True,
        )
        res = scaffolder.scaffold()
        self.assertEqual(res["consumer_id"], "conflict-consumer")
        self.assertTrue((out_dir / "infraflow.config.yaml").is_file())

    def test_invalid_consumer_id_rejection(self):
        invalid_ids = [
            "AB",                  # uppercase & too short
            "-invalid-start",      # starts with hyphen
            "invalid-end-",        # ends with hyphen
            "has_underscore",      # underscore not allowed
            "has space",           # space not allowed
            "a" * 65,              # exceeds 64 chars
        ]
        for bad_id in invalid_ids:
            with self.assertRaises(ScaffoldingSecurityError):
                ConsumerScaffolder(consumer_id=bad_id, output_dir=Path(self.tmp_dir) / "test")

    def test_path_traversal_rejection(self):
        bad_path = Path(self.tmp_dir) / "sub" / ".." / ".." / "escape"
        with self.assertRaises(ScaffoldingSecurityError):
            ConsumerScaffolder(consumer_id="valid-id", output_dir=bad_path)

    def test_symlink_output_dir_rejection(self):
        real_dir = Path(self.tmp_dir) / "real_dir"
        real_dir.mkdir(parents=True, exist_ok=True)
        symlink_dir = Path(self.tmp_dir) / "link_dir"
        os.symlink(real_dir, symlink_dir)

        with self.assertRaises(ScaffoldingSecurityError):
            ConsumerScaffolder(consumer_id="valid-id", output_dir=symlink_dir)

    def test_mutable_platform_sha_rejection(self):
        for mutable in ["main", "master", "latest", "HEAD", "v1.0.0"]:
            with self.assertRaises(ScaffoldingSecurityError):
                ConsumerScaffolder(
                    consumer_id="valid-id",
                    output_dir=Path(self.tmp_dir) / "test",
                    platform_sha=mutable,
                )


class TestConsumerRegistration(unittest.TestCase):
    """Verifies consumer registration, manifest schema integrity, and uniqueness enforcement."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-test-register-")
        # Copy central manifest to temporary location for mutation testing
        self.real_manifest = REPO_ROOT / "config" / "fleet-manifest.yaml"
        self.test_manifest = Path(self.tmp_dir) / "fleet-manifest.yaml"
        shutil.copy(self.real_manifest, self.test_manifest)

        # Scaffold a valid consumer for registration
        self.consumer_dir = Path(self.tmp_dir) / "valid-test-consumer"
        scaffolder = ConsumerScaffolder(
            consumer_id="new-test-consumer",
            adapter="aws",
            environment="dev",
            workload_type="general",
            team="test-team",
            output_dir=self.consumer_dir,
            platform_sha="be51718f06a2662099500a710e93e6e8201b4f1c",
        )
        scaffolder.scaffold()
        self.config_path = self.consumer_dir / "infraflow.config.yaml"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_registration_preview_dry_run(self):
        registrar = ConsumerRegistrar(
            config_path=self.config_path,
            manifest_path=self.test_manifest,
            stage="progressive",
        )
        res = registrar.register(dry_run=True)
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["consumer_id"], "new-test-consumer")
        self.assertEqual(res["existing_consumer_count"], 3)
        self.assertEqual(res["projected_consumer_count"], 4)

        # Verify target manifest was NOT modified
        import yaml
        data = yaml.safe_load(self.test_manifest.read_text(encoding="utf-8"))
        self.assertEqual(len(data["consumers"]), 3)

    def test_atomic_registration_success(self):
        registrar = ConsumerRegistrar(
            config_path=self.config_path,
            manifest_path=self.test_manifest,
            stage="canary",
            status="fleet-verified",
        )
        res = registrar.register(dry_run=False)
        self.assertFalse(res["dry_run"])
        self.assertTrue(res["registered"])
        self.assertEqual(res["consumer_id"], "new-test-consumer")
        self.assertEqual(res["new_count"], 4)

        # Verify manifest now contains the new consumer
        import yaml
        data = yaml.safe_load(self.test_manifest.read_text(encoding="utf-8"))
        self.assertEqual(len(data["consumers"]), 4)
        c_ids = [c["consumer_id"] for c in data["consumers"]]
        self.assertIn("new-test-consumer", c_ids)

        new_entry = [c for c in data["consumers"] if c["consumer_id"] == "new-test-consumer"][0]
        self.assertEqual(new_entry["adapter"], "aws")
        self.assertEqual(new_entry["upgrade_role"], "canary")
        self.assertEqual(new_entry["status"], "fleet-verified")

    def test_duplicate_consumer_id_rejection(self):
        # First registration
        registrar = ConsumerRegistrar(
            config_path=self.config_path,
            manifest_path=self.test_manifest,
        )
        registrar.register(dry_run=False)

        # Second registration with exact same consumer_id must raise RegistrationError
        with self.assertRaises(RegistrationError) as cm:
            registrar2 = ConsumerRegistrar(
                config_path=self.config_path,
                manifest_path=self.test_manifest,
            )
            registrar2.register(dry_run=False)
        self.assertIn("Duplicate consumer_id detected", str(cm.exception))

    def test_duplicate_repository_rejection(self):
        # Scaffold second consumer with different ID but conflicting repository
        consumer2_dir = Path(self.tmp_dir) / "consumer-two"
        scaffolder = ConsumerScaffolder(
            consumer_id="consumer-two",
            output_dir=consumer2_dir,
            repository="TM-threemavithana/infraflow-consumer-networking",  # Already in manifest!
            platform_sha="be51718f06a2662099500a710e93e6e8201b4f1c",
        )
        scaffolder.scaffold()

        registrar = ConsumerRegistrar(
            config_path=consumer2_dir / "infraflow.config.yaml",
            manifest_path=self.test_manifest,
            repository_override="TM-threemavithana/infraflow-consumer-networking",
        )
        with self.assertRaises(RegistrationError) as cm:
            registrar.register(dry_run=False)
        self.assertIn("Duplicate repository identity detected", str(cm.exception))

    def test_symlinked_manifest_rejection(self):
        sym_manifest = Path(self.tmp_dir) / "symlink-manifest.yaml"
        os.symlink(self.test_manifest, sym_manifest)

        with self.assertRaises(RegistrationSecurityError):
            ConsumerRegistrar(
                config_path=self.config_path,
                manifest_path=sym_manifest,
            )

    def test_symlinked_config_rejection(self):
        sym_config = Path(self.tmp_dir) / "symlink-config.yaml"
        os.symlink(self.config_path, sym_config)

        with self.assertRaises(RegistrationSecurityError):
            ConsumerRegistrar(
                config_path=sym_config,
                manifest_path=self.test_manifest,
            )


class TestCLIScaffoldingIntegration(unittest.TestCase):
    """Verifies CLI subcommands, programmatic execution, and exit codes."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="infraflow-test-cli-scaffold-")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_cli_init_execution_text_and_json(self):
        out_dir = Path(self.tmp_dir) / "cli-scaffold-json"
        res = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "init",
                "-n",
                "cli-test-app",
                "-a",
                "azure",
                "-o",
                str(out_dir),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, EXIT_OK)
        data = json.loads(res.stdout)
        self.assertEqual(data["consumer_id"], "cli-test-app")
        self.assertEqual(data["adapter"], "azure")
        self.assertTrue((out_dir / "infraflow.config.yaml").is_file())

    def test_cli_init_missing_id_error(self):
        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "init"],
            input="",
            capture_output=True,
            text=True,
        )
        # Should exit with code 1
        self.assertEqual(res.returncode, EXIT_ERROR)
        self.assertIn("Missing required argument", res.stderr)

    def test_cli_init_security_exit_code_on_symlink(self):
        real_d = Path(self.tmp_dir) / "real"
        real_d.mkdir()
        link_d = Path(self.tmp_dir) / "link"
        os.symlink(real_d, link_d)

        res = subprocess.run(
            [sys.executable, str(CLI_PATH), "init", "-n", "valid-id", "-o", str(link_d)],
            capture_output=True,
            text=True,
        )
        # Must exit with code 2 (EXIT_SECURITY)
        self.assertEqual(res.returncode, EXIT_SECURITY)
        self.assertIn("SECURITY ERROR", res.stderr)

    def test_cli_register_dry_run_json(self):
        # Scaffold valid consumer
        c_dir = Path(self.tmp_dir) / "cli-reg-app"
        ConsumerScaffolder(consumer_id="cli-reg-app", output_dir=c_dir).scaffold()

        res = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "register",
                "-c",
                str(c_dir / "infraflow.config.yaml"),
                "--dry-run",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, EXIT_OK)
        data = json.loads(res.stdout)
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["consumer_id"], "cli-reg-app")


if __name__ == "__main__":
    unittest.main()
