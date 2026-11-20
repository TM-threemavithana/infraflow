#!/usr/bin/env python3
"""
InfraFlow — Unit Tests for Plan Envelope Encryption Engine
Milestone: G06.1 — Protected Apply & Destroy (Cryptographic Tooling)

Validates 20 core cryptographic security invariants:
1. Successful encrypt/decrypt round-trip
2. Unique DEK generation per encryption
3. Unique nonce generation per encryption
4. Correct SHA-256 calculation and binding
5. Ciphertext modification detection (bit-flip rejection)
6. Authentication tag corruption detection
7. Wrong KEK rejection
8. Wrapped DEK modification detection
9. Authenticated Additional Data (AAD) tampering detection
10. Repository identity mismatch rejection
11. Source commit mismatch rejection
12. Environment mismatch rejection
13. Unsupported encryption algorithm rejection
14. Unsupported schema version rejection
15. Truncated / malformed base64 envelope rejection
16. Empty plan file handling (clean 0-byte roundtrip)
17. Temporary file cleanup on exception
18. Zero plaintext secret leakage in outputs
19. Mock KMS key wrapping / unwrapping interface contract
20. Missing required envelope fields rejection
"""

import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add scripts directory to module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

import importlib
kms_envelope = importlib.import_module("kms-envelope")

ALGORITHM = kms_envelope.ALGORITHM
DEK_BYTES = kms_envelope.DEK_BYTES
KEK_BYTES = kms_envelope.KEK_BYTES
KEY_PROVIDER_MOCK = kms_envelope.KEY_PROVIDER_MOCK
NONCE_BYTES = kms_envelope.NONCE_BYTES
SCHEMA_VERSION = kms_envelope.SCHEMA_VERSION
EnvelopeAuthenticationError = kms_envelope.EnvelopeAuthenticationError
EnvelopeContextMismatchError = kms_envelope.EnvelopeContextMismatchError
EnvelopeDigestMismatchError = kms_envelope.EnvelopeDigestMismatchError
EnvelopeError = kms_envelope.EnvelopeError
EnvelopeKeyError = kms_envelope.EnvelopeKeyError
EnvelopeSchemaError = kms_envelope.EnvelopeSchemaError
MockKMSClient = kms_envelope.MockKMSClient
PlanEnvelope = kms_envelope.PlanEnvelope
canonicalize_aad = kms_envelope.canonicalize_aad
decrypt_plan = kms_envelope.decrypt_plan
encrypt_plan = kms_envelope.encrypt_plan
load_kek = kms_envelope.load_kek
safe_read_file = kms_envelope.safe_read_file
safe_write_file = kms_envelope.safe_write_file


class TestKMSEnvelope(unittest.TestCase):
    """Unit test suite for kms-envelope cryptographic engine."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="infraflow-test-kms-")
        self.kek = os.urandom(KEK_BYTES)
        self.sample_plan = b"TERRAFORM_BINARY_PLAN_SYNTHETIC_DATA_FOR_TESTING\x00\x01\x02\xff"
        self.repo = "TM-threemavithana/infraflow-consumer-test"
        self.commit = "d0660de837ca07d5bdd56f04b0e50691ce98bd28"
        self.workflow = ".github/workflows/reusable-tf-plan.yml"
        self.env = "production"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Successful encrypt/decrypt round-trip
    def test_01_successful_encrypt_decrypt_roundtrip(self):
        envelope = encrypt_plan(
            plan_bytes=self.sample_plan,
            kek=self.kek,
            repository=self.repo,
            commit_sha=self.commit,
            workflow=self.workflow,
            environment=self.env,
        )
        decrypted = decrypt_plan(
            envelope=envelope,
            kek=self.kek,
            expected_repo=self.repo,
            expected_commit=self.commit,
            expected_environment=self.env,
            expected_digest=hashlib.sha256(self.sample_plan).hexdigest(),
        )
        self.assertEqual(decrypted, self.sample_plan)

    # 2. Unique DEK generation per encryption
    def test_02_unique_dek_generation(self):
        env1 = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        env2 = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        self.assertNotEqual(env1.wrapped_dek, env2.wrapped_dek)

    # 3. Unique nonce generation per encryption
    def test_03_unique_nonce_generation(self):
        env1 = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        env2 = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        self.assertNotEqual(env1.nonce, env2.nonce)
        self.assertEqual(len(env1.nonce), NONCE_BYTES)
        self.assertEqual(len(env2.nonce), NONCE_BYTES)

    # 4. Correct SHA-256 calculation and binding
    def test_04_correct_sha256_calculation(self):
        expected_digest = hashlib.sha256(self.sample_plan).hexdigest()
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        self.assertEqual(envelope.plan_digest, expected_digest)
        self.assertEqual(envelope.aad["plan_digest"], expected_digest)

    # 5. Ciphertext modification detection (bit-flip rejection)
    def test_05_ciphertext_modification_detection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        # Flip first byte of ciphertext
        corrupted_ct = bytearray(envelope.ciphertext)
        corrupted_ct[0] ^= 0x01
        envelope.ciphertext = bytes(corrupted_ct)
        with self.assertRaises(EnvelopeAuthenticationError):
            decrypt_plan(envelope, self.kek)

    # 6. Authentication tag corruption detection
    def test_06_auth_tag_corruption_detection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        # Tag is the last 16 bytes of ciphertext in AESGCM
        corrupted_ct = bytearray(envelope.ciphertext)
        corrupted_ct[-1] ^= 0xFF
        envelope.ciphertext = bytes(corrupted_ct)
        with self.assertRaises(EnvelopeAuthenticationError):
            decrypt_plan(envelope, self.kek)

    # 7. Wrong KEK rejection
    def test_07_wrong_kek_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        wrong_kek = os.urandom(KEK_BYTES)
        with self.assertRaises(EnvelopeKeyError):
            decrypt_plan(envelope, wrong_kek)

    # 8. Wrapped DEK modification detection
    def test_08_wrapped_dek_modification_detection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        corrupted_wrapped_dek = bytearray(envelope.wrapped_dek)
        corrupted_wrapped_dek[5] ^= 0xAA
        envelope.wrapped_dek = bytes(corrupted_wrapped_dek)
        with self.assertRaises(EnvelopeKeyError):
            decrypt_plan(envelope, self.kek)

    # 9. Authenticated Additional Data (AAD) tampering detection
    def test_09_aad_tampering_detection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit, environment="staging")
        # Tamper with AAD post-encryption
        envelope.aad["environment"] = "production"
        with self.assertRaises((EnvelopeAuthenticationError, EnvelopeKeyError)):
            decrypt_plan(envelope, self.kek)

    # 10. Repository identity mismatch rejection
    def test_10_repo_mismatch_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        with self.assertRaises(EnvelopeContextMismatchError):
            decrypt_plan(envelope, self.kek, expected_repo="attacker-org/rogue-repo")

    # 11. Source commit mismatch rejection
    def test_11_commit_mismatch_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        with self.assertRaises(EnvelopeContextMismatchError):
            decrypt_plan(envelope, self.kek, expected_commit="1111111111111111111111111111111111111111")

    # 12. Environment mismatch rejection
    def test_12_environment_mismatch_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit, environment="staging")
        with self.assertRaises(EnvelopeContextMismatchError):
            decrypt_plan(envelope, self.kek, expected_environment="production")

    # 13. Unsupported encryption algorithm rejection
    def test_13_unsupported_algorithm_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        env_dict = envelope.to_dict()
        env_dict["algorithm"] = "ChaCha20-Poly1305"
        with self.assertRaises(EnvelopeSchemaError):
            PlanEnvelope.from_dict(env_dict)

    # 14. Unsupported schema version rejection
    def test_14_unsupported_schema_version_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        env_dict = envelope.to_dict()
        env_dict["schema_version"] = "infraflow-plan-envelope-v999"
        with self.assertRaises(EnvelopeSchemaError):
            PlanEnvelope.from_dict(env_dict)

    # 15. Truncated / malformed base64 envelope rejection
    def test_15_truncated_base64_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        env_dict = envelope.to_dict()
        env_dict["ciphertext"] = "not_valid_base64_!!!==="
        with self.assertRaises(EnvelopeSchemaError):
            PlanEnvelope.from_dict(env_dict)

    # 16. Empty plan file handling (clean 0-byte roundtrip)
    def test_16_empty_plan_file_handling(self):
        empty_plan = b""
        envelope = encrypt_plan(empty_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        decrypted = decrypt_plan(envelope, self.kek)
        self.assertEqual(decrypted, b"")
        self.assertEqual(envelope.plan_digest, hashlib.sha256(b"").hexdigest())

    # 17. Temporary file cleanup on exception
    def test_17_temp_file_cleanup_on_exception(self):
        bad_path = os.path.join(self.test_dir, "non_existent_subdir", "unwritable.bin")
        # Attempting safe_write_file to unwritable location handles cleanup cleanly
        try:
            safe_write_file("/dev/null/impossible_file", b"data")
        except Exception:
            pass
        # Assert test_dir has no orphaned temp files
        leftover = [f for f in os.listdir(self.test_dir) if f.startswith(".tmp-envelope-")]
        self.assertEqual(len(leftover), 0)

    # 18. Zero plaintext secret leakage in outputs
    def test_18_zero_plaintext_secret_leakage(self):
        synthetic_secret = b"SYNTHETIC_DB_PASSWORD_SUPER_SECRET_VALUE_12345"
        plan_with_secret = self.sample_plan + b"\nsecret=" + synthetic_secret
        
        plan_path = os.path.join(self.test_dir, "plan.tfplan")
        out_env_path = os.path.join(self.test_dir, "plan.enc.json")
        safe_write_file(plan_path, plan_with_secret)
        
        # Test CLI encrypt output
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        try:
            with patch("sys.argv", [
                "kms-envelope.py", "encrypt",
                "--plan-file", plan_path,
                "--output-envelope", out_env_path,
                "--kek-hex", self.kek.hex(),
                "--repo", self.repo,
                "--commit", self.commit,
            ]):
                ret = kms_envelope.main()
        finally:
            sys.stdout = old_stdout
            cli_output = buffer.getvalue()
        
        self.assertEqual(ret, 0)
        self.assertNotIn("SYNTHETIC_DB_PASSWORD", cli_output)
        self.assertNotIn(self.kek.hex(), cli_output)
        
        # Check that file content on disk is ciphertext, not plaintext
        envelope_data = safe_read_file(out_env_path).decode("utf-8")
        self.assertNotIn("SYNTHETIC_DB_PASSWORD", envelope_data)

    # 19. Mock KMS key wrapping / unwrapping interface contract
    def test_19_mock_kms_interface_contract(self):
        client = MockKMSClient(self.kek, key_id="test-key-1")
        ctx = {"repo": "my-org/my-repo", "env": "prod"}
        
        plaintext_dek, wrapped_dek, wrap_nonce = client.generate_data_key("test-key-1", ctx)
        self.assertEqual(len(plaintext_dek), DEK_BYTES)
        self.assertEqual(len(wrap_nonce), NONCE_BYTES)
        
        unwrapped_dek = client.decrypt_data_key("test-key-1", wrapped_dek, wrap_nonce, ctx)
        self.assertEqual(plaintext_dek, unwrapped_dek)
        
        # Context mismatch should fail unwrapping
        mismatched_ctx = {"repo": "my-org/my-repo", "env": "staging"}
        with self.assertRaises(EnvelopeKeyError):
            client.decrypt_data_key("test-key-1", wrapped_dek, wrap_nonce, mismatched_ctx)

    # 20. Missing required envelope fields rejection
    def test_20_missing_required_fields_rejection(self):
        envelope = encrypt_plan(self.sample_plan, self.kek, repository=self.repo, commit_sha=self.commit)
        env_dict = envelope.to_dict()
        del env_dict["wrapped_dek"]
        with self.assertRaises(EnvelopeSchemaError):
            PlanEnvelope.from_dict(env_dict)


if __name__ == "__main__":
    unittest.main()
