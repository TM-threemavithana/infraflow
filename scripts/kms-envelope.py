#!/usr/bin/env python3
"""
InfraFlow — Plan Envelope Encryption & Local Cryptographic Tooling
Milestone: G06.1 — Protected Apply & Destroy (Cryptographic Foundation)

Implements client-side AES-256-GCM envelope encryption for Terraform binary plans:
- Fresh, cryptographically random 256-bit Data Encryption Key (DEK) per plan
- AES-256-GCM authenticated encryption with a unique 96-bit nonce
- Cryptographic binding to original binary plan SHA-256 digest
- Authenticated Additional Data (AAD) binding repository, commit, workflow, environment, and plan ID
- Key wrapping abstraction with local Mock KMS Simulator (GenerateDataKey / Decrypt)
- Canonical JSON AAD serialization (RFC 8785 inspired deterministic key-sorting)
- Restrictive file permissions (POSIX 0600) and atomic temporary file operations
- Strict fail-closed verification: detects ciphertext tampering, tag corruption, metadata tampering,
  wrong keys, context mismatches, and unsupported envelope schemas.

[MOCK KMS NOTICE]:
The key-wrapping engine in this module operates as an offline simulation using local AES-256-GCM.
It does NOT connect to AWS KMS, and locally wrapped keys are NOT valid AWS KMS ciphertexts.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA_VERSION = "infraflow-plan-envelope-v1"
ALGORITHM = "AES-256-GCM"
DEK_BYTES = 32  # 256 bits
NONCE_BYTES = 12  # 96 bits
TAG_BYTES = 16  # 128 bits
KEK_BYTES = 32  # 256 bits
KEY_PROVIDER_MOCK = "mock-kms"


class EnvelopeError(Exception):
    """Base exception for envelope encryption operations."""
    pass


class EnvelopeSchemaError(EnvelopeError):
    """Raised when envelope schema or formatting is invalid."""
    pass


class EnvelopeKeyError(EnvelopeError):
    """Raised when key wrapping/unwrapping fails or key is unauthorized."""
    pass


class EnvelopeAuthenticationError(EnvelopeError):
    """Raised when ciphertext or AAD authentication fails."""
    pass


class EnvelopeDigestMismatchError(EnvelopeError):
    """Raised when plan SHA-256 digest does not match expected value."""
    pass


class EnvelopeContextMismatchError(EnvelopeError):
    """Raised when expected context (repo, commit, env) does not match."""
    pass


def canonicalize_aad(aad: Dict[str, Any]) -> bytes:
    """
    Serializes AAD dictionary into canonical, deterministic bytes.
    Enforces sorted keys, no whitespace outside strings, and ASCII encoding.
    """
    if not isinstance(aad, dict):
        raise EnvelopeSchemaError("AAD must be a dictionary")
    return json.dumps(aad, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def safe_write_file(path: str, data: bytes, mode: int = 0o600) -> None:
    """
    Writes data to a file atomically with restrictive POSIX permissions.
    Creates parent directories if necessary and cleans up temporary files on error.
    """
    abs_path = os.path.abspath(path)
    dir_name = os.path.dirname(abs_path)
    os.makedirs(dir_name, exist_ok=True)
    
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp-envelope-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, abs_path)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise


def safe_read_file(path: str) -> bytes:
    """Reads complete binary content of a file, verifying existence."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "rb") as f:
        return f.read()


def load_kek(kek_file: Optional[str] = None, kek_hex: Optional[str] = None) -> bytes:
    """Loads a 256-bit Key Encryption Key (KEK) from a file or hex string."""
    if kek_file and kek_hex:
        raise EnvelopeKeyError("Specify either --kek-file or --kek-hex, not both")
    if kek_file:
        raw = safe_read_file(kek_file).strip()
        # Accept 64 hex characters or 32 raw bytes
        if len(raw) == 64:
            try:
                return bytes.fromhex(raw.decode("ascii"))
            except ValueError:
                pass
        if len(raw) == KEK_BYTES:
            return raw
        try:
            k = bytes.fromhex(raw.decode("ascii"))
            if len(k) == KEK_BYTES:
                return k
        except Exception:
            pass
        raise EnvelopeKeyError(f"KEK file must contain 32 raw bytes or 64 hex characters, got {len(raw)} bytes")
    elif kek_hex:
        try:
            k = bytes.fromhex(kek_hex.strip())
            if len(k) != KEK_BYTES:
                raise ValueError()
            return k
        except Exception:
            raise EnvelopeKeyError("KEK hex must be exactly 64 hexadecimal characters (256 bits)")
    else:
        raise EnvelopeKeyError("Must provide --kek-file or --kek-hex for KMS key operations")


class MockKMSClient:
    """
    Local-only Key Encryption Key (KEK) simulator.
    Simulates the conceptual interface of AWS KMS:
      - GenerateDataKey(KeyId, EncryptionContext) -> (PlaintextDEK, CiphertextDEK)
      - Decrypt(CiphertextBlob, EncryptionContext) -> PlaintextDEK

    [MOCK KMS ONLY]: This uses local AES-256-GCM for offline test environments.
    It does NOT connect to AWS KMS, and locally wrapped keys are NOT valid AWS KMS ciphertexts.
    """

    def __init__(self, kek: bytes, key_id: str = "mock-kms-kek-1"):
        if len(kek) != KEK_BYTES:
            raise EnvelopeKeyError(f"KEK must be exactly {KEK_BYTES} bytes (256 bits), got {len(kek)}")
        if not key_id or not isinstance(key_id, str):
            raise EnvelopeKeyError("Key ID must be a non-empty string")
        self.kek = kek
        self.key_id = key_id

    def generate_data_key(self, key_id: str, encryption_context: Dict[str, Any]) -> Tuple[bytes, bytes, bytes]:
        """
        Generates a fresh 256-bit plaintext DEK and wraps it using KEK under AES-256-GCM.
        Returns: (plaintext_dek, wrapped_dek, wrap_nonce)
        """
        if key_id != self.key_id:
            raise EnvelopeKeyError(f"Unauthorized or unknown Key ID: '{key_id}'")

        plaintext_dek = AESGCM.generate_key(bit_length=256)
        wrap_nonce = os.urandom(NONCE_BYTES)
        kek_cipher = AESGCM(self.kek)
        aad_bytes = canonicalize_aad(encryption_context)
        wrapped_dek = kek_cipher.encrypt(wrap_nonce, plaintext_dek, aad_bytes)
        return plaintext_dek, wrapped_dek, wrap_nonce

    def decrypt_data_key(
        self, key_id: str, wrapped_dek: bytes, wrap_nonce: bytes, encryption_context: Dict[str, Any]
    ) -> bytes:
        """
        Unwraps a wrapped DEK using KEK and validates the encryption context.
        Returns: plaintext_dek
        """
        if key_id != self.key_id:
            raise EnvelopeKeyError(f"Unauthorized or unknown Key ID: '{key_id}'")
        if len(wrap_nonce) != NONCE_BYTES:
            raise EnvelopeKeyError(f"Invalid wrap nonce length: {len(wrap_nonce)}, expected {NONCE_BYTES}")

        kek_cipher = AESGCM(self.kek)
        aad_bytes = canonicalize_aad(encryption_context)
        try:
            plaintext_dek = kek_cipher.decrypt(wrap_nonce, wrapped_dek, aad_bytes)
            return plaintext_dek
        except InvalidTag:
            raise EnvelopeKeyError(
                "Failed to unwrap DEK: wrong KEK, corrupted wrapped DEK, or encryption context mismatch"
            )


class PlanEnvelope:
    """Data container and parser for InfraFlow encrypted plan envelopes."""

    def __init__(
        self,
        schema_version: str,
        algorithm: str,
        key_provider: str,
        key_id: str,
        wrapped_dek: bytes,
        wrapped_dek_nonce: bytes,
        nonce: bytes,
        plan_digest: str,
        plan_size_bytes: int,
        created_at: str,
        aad: Dict[str, Any],
        ciphertext: bytes,
    ):
        self.schema_version = schema_version
        self.algorithm = algorithm
        self.key_provider = key_provider
        self.key_id = key_id
        self.wrapped_dek = wrapped_dek
        self.wrapped_dek_nonce = wrapped_dek_nonce
        self.nonce = nonce
        self.plan_digest = plan_digest
        self.plan_size_bytes = plan_size_bytes
        self.created_at = created_at
        self.aad = aad
        self.ciphertext = ciphertext
        self.validate()

    def validate(self) -> None:
        """Strictly validates envelope structure, sizes, and formats."""
        if self.schema_version != SCHEMA_VERSION:
            raise EnvelopeSchemaError(
                f"Unsupported schema version: '{self.schema_version}', expected '{SCHEMA_VERSION}'"
            )
        if self.algorithm != ALGORITHM:
            raise EnvelopeSchemaError(
                f"Unsupported algorithm: '{self.algorithm}', expected '{ALGORITHM}'"
            )
        if self.key_provider != KEY_PROVIDER_MOCK:
            raise EnvelopeSchemaError(
                f"Unsupported key provider: '{self.key_provider}' (Milestone G06.1 strictly requires '{KEY_PROVIDER_MOCK}')"
            )
        if not self.key_id or not isinstance(self.key_id, str):
            raise EnvelopeSchemaError("key_id must be a non-empty string")
        if len(self.nonce) != NONCE_BYTES:
            raise EnvelopeSchemaError(f"Invalid nonce length: {len(self.nonce)}, expected {NONCE_BYTES}")
        if len(self.wrapped_dek_nonce) != NONCE_BYTES:
            raise EnvelopeSchemaError(
                f"Invalid wrapped_dek_nonce length: {len(self.wrapped_dek_nonce)}, expected {NONCE_BYTES}"
            )
        if len(self.wrapped_dek) < (DEK_BYTES + TAG_BYTES):
            raise EnvelopeSchemaError(
                f"wrapped_dek payload too short: {len(self.wrapped_dek)} bytes (minimum {DEK_BYTES + TAG_BYTES})"
            )
        if len(self.ciphertext) < TAG_BYTES:
            raise EnvelopeSchemaError(
                f"ciphertext payload too short: {len(self.ciphertext)} bytes (must include {TAG_BYTES}-byte auth tag)"
            )
        if not isinstance(self.plan_digest, str) or not re.match(r"^[0-9a-f]{64}$", self.plan_digest):
            raise EnvelopeSchemaError(
                f"Invalid plan_digest: '{self.plan_digest}' must be a 64-character lowercase SHA-256 hex string"
            )
        if not isinstance(self.plan_size_bytes, int) or self.plan_size_bytes < 0:
            raise EnvelopeSchemaError(f"Invalid plan_size_bytes: {self.plan_size_bytes}")
        if not isinstance(self.aad, dict):
            raise EnvelopeSchemaError("aad must be a dictionary")

        required_aad_keys = ["commit_sha", "environment", "plan_digest", "plan_identifier", "repository", "schema_version", "workflow"]
        for k in required_aad_keys:
            if k not in self.aad:
                raise EnvelopeSchemaError(f"Missing required key in AAD: '{k}'")
        if self.aad.get("plan_digest") != self.plan_digest:
            raise EnvelopeSchemaError("plan_digest in envelope header does not match AAD plan_digest")
        if self.aad.get("schema_version") != self.schema_version:
            raise EnvelopeSchemaError("schema_version in envelope header does not match AAD schema_version")

    def to_dict(self) -> Dict[str, Any]:
        """Serializes envelope to JSON-compatible dictionary with base64 strings."""
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "key_provider": self.key_provider,
            "key_id": self.key_id,
            "wrapped_dek": base64.b64encode(self.wrapped_dek).decode("ascii"),
            "wrapped_dek_nonce": base64.b64encode(self.wrapped_dek_nonce).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "plan_digest": self.plan_digest,
            "plan_size_bytes": self.plan_size_bytes,
            "created_at": self.created_at,
            "aad": self.aad,
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes envelope to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlanEnvelope":
        """Instantiates and validates a PlanEnvelope from a dictionary."""
        if not isinstance(data, dict):
            raise EnvelopeSchemaError("Envelope data must be a JSON dictionary")

        required_fields = [
            "schema_version",
            "algorithm",
            "key_provider",
            "key_id",
            "wrapped_dek",
            "wrapped_dek_nonce",
            "nonce",
            "plan_digest",
            "plan_size_bytes",
            "created_at",
            "aad",
            "ciphertext",
        ]
        for field in required_fields:
            if field not in data:
                raise EnvelopeSchemaError(f"Missing required field in envelope: '{field}'")

        try:
            wrapped_dek = base64.b64decode(data["wrapped_dek"], validate=True)
            wrapped_dek_nonce = base64.b64decode(data["wrapped_dek_nonce"], validate=True)
            nonce = base64.b64decode(data["nonce"], validate=True)
            ciphertext = base64.b64decode(data["ciphertext"], validate=True)
        except Exception as e:
            raise EnvelopeSchemaError(f"Failed to decode base64 field in envelope: {e}")

        return cls(
            schema_version=data["schema_version"],
            algorithm=data["algorithm"],
            key_provider=data["key_provider"],
            key_id=data["key_id"],
            wrapped_dek=wrapped_dek,
            wrapped_dek_nonce=wrapped_dek_nonce,
            nonce=nonce,
            plan_digest=data["plan_digest"],
            plan_size_bytes=data["plan_size_bytes"],
            created_at=data["created_at"],
            aad=data["aad"],
            ciphertext=ciphertext,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "PlanEnvelope":
        """Parses and validates a PlanEnvelope from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise EnvelopeSchemaError(f"Malformed envelope JSON: {e}")
        return cls.from_dict(data)


def encrypt_plan(
    plan_bytes: bytes,
    kek: bytes,
    key_id: str = "mock-kms-kek-1",
    repository: str = "unknown/repo",
    commit_sha: str = "0000000000000000000000000000000000000000",
    workflow: str = ".github/workflows/reusable-tf-plan.yml",
    environment: str = "production",
    plan_identifier: Optional[str] = None,
    kms_client: Optional[MockKMSClient] = None,
) -> PlanEnvelope:
    """
    Encrypts Terraform binary plan bytes using AES-256-GCM envelope encryption.
    A fresh 256-bit DEK and 96-bit nonce are generated for each operation.
    """
    if not isinstance(plan_bytes, (bytes, bytearray)):
        raise TypeError("plan_bytes must be bytes or bytearray")

    plan_size_bytes = len(plan_bytes)
    plan_digest = hashlib.sha256(plan_bytes).hexdigest()
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    plan_id = plan_identifier or f"plan-{plan_digest[:16]}-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}"

    aad_dict = {
        "commit_sha": commit_sha,
        "environment": environment,
        "plan_digest": plan_digest,
        "plan_identifier": plan_id,
        "repository": repository,
        "schema_version": SCHEMA_VERSION,
        "workflow": workflow,
    }
    aad_bytes = canonicalize_aad(aad_dict)

    client = kms_client or MockKMSClient(kek=kek, key_id=key_id)
    plaintext_dek, wrapped_dek, wrapped_dek_nonce = client.generate_data_key(key_id, aad_dict)

    plan_nonce = os.urandom(NONCE_BYTES)
    aesgcm = AESGCM(plaintext_dek)

    try:
        ciphertext = aesgcm.encrypt(plan_nonce, plan_bytes, aad_bytes)
    finally:
        # Best effort memory cleanup
        del plaintext_dek

    return PlanEnvelope(
        schema_version=SCHEMA_VERSION,
        algorithm=ALGORITHM,
        key_provider=KEY_PROVIDER_MOCK,
        key_id=key_id,
        wrapped_dek=wrapped_dek,
        wrapped_dek_nonce=wrapped_dek_nonce,
        nonce=plan_nonce,
        plan_digest=plan_digest,
        plan_size_bytes=plan_size_bytes,
        created_at=created_at,
        aad=aad_dict,
        ciphertext=ciphertext,
    )


def decrypt_plan(
    envelope: PlanEnvelope,
    kek: bytes,
    expected_repo: Optional[str] = None,
    expected_commit: Optional[str] = None,
    expected_environment: Optional[str] = None,
    expected_digest: Optional[str] = None,
    kms_client: Optional[MockKMSClient] = None,
) -> bytes:
    """
    Decrypts an encrypted plan envelope and verifies integrity, digests, and context.
    Fails closed if any authentication check, digest comparison, or context check fails.
    """
    if not isinstance(envelope, PlanEnvelope):
        raise TypeError("envelope must be a PlanEnvelope instance")

    # 1. Context validation against expected criteria
    if expected_repo is not None:
        actual_repo = envelope.aad.get("repository")
        if actual_repo != expected_repo:
            raise EnvelopeContextMismatchError(
                f"Repository mismatch in envelope: expected '{expected_repo}', got '{actual_repo}'"
            )
    if expected_commit is not None:
        actual_commit = envelope.aad.get("commit_sha")
        if actual_commit != expected_commit:
            raise EnvelopeContextMismatchError(
                f"Commit SHA mismatch in envelope: expected '{expected_commit}', got '{actual_commit}'"
            )
    if expected_environment is not None:
        actual_env = envelope.aad.get("environment")
        if actual_env != expected_environment:
            raise EnvelopeContextMismatchError(
                f"Environment mismatch in envelope: expected '{expected_environment}', got '{actual_env}'"
            )
    if expected_digest is not None:
        if envelope.plan_digest != expected_digest.lower():
            raise EnvelopeDigestMismatchError(
                f"Plan digest mismatch in envelope header: expected '{expected_digest.lower()}', got '{envelope.plan_digest}'"
            )

    # 2. Canonicalize AAD
    aad_bytes = canonicalize_aad(envelope.aad)

    # 3. Unwrap DEK via KMS
    client = kms_client or MockKMSClient(kek=kek, key_id=envelope.key_id)
    plaintext_dek = client.decrypt_data_key(
        envelope.key_id, envelope.wrapped_dek, envelope.wrapped_dek_nonce, envelope.aad
    )

    # 4. Decrypt plan payload with AES-256-GCM
    aesgcm = AESGCM(plaintext_dek)
    try:
        plan_bytes = aesgcm.decrypt(envelope.nonce, envelope.ciphertext, aad_bytes)
    except InvalidTag:
        raise EnvelopeAuthenticationError(
            "Authentication failed: ciphertext or authenticated metadata has been modified or corrupted"
        )
    finally:
        del plaintext_dek

    # 5. Verify plan digest against decrypted bytes
    computed_digest = hashlib.sha256(plan_bytes).hexdigest()
    if computed_digest != envelope.plan_digest:
        raise EnvelopeDigestMismatchError(
            f"Decrypted plan SHA-256 digest ({computed_digest}) does not match envelope header ({envelope.plan_digest})"
        )
    if expected_digest is not None and computed_digest != expected_digest.lower():
        raise EnvelopeDigestMismatchError(
            f"Decrypted plan SHA-256 digest ({computed_digest}) does not match expected digest ({expected_digest.lower()})"
        )

    # 6. Verify plan size
    if len(plan_bytes) != envelope.plan_size_bytes:
        raise EnvelopeDigestMismatchError(
            f"Decrypted plan size ({len(plan_bytes)} bytes) does not match envelope header ({envelope.plan_size_bytes} bytes)"
        )

    return plan_bytes


def main() -> int:
    """CLI entrypoint for plan envelope encryption tooling."""
    parser = argparse.ArgumentParser(
        description="InfraFlow — Plan Envelope Encryption & Local Cryptographic Tooling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # generate-kek
    p_kek = subparsers.add_parser("generate-kek", help="Generate a local mock 256-bit Key Encryption Key (KEK)")
    p_kek.add_argument("--output-kek", required=True, help="Destination path for generated KEK file (mode 0600)")
    p_kek.add_argument("--print-hex", action="store_true", help="Print hex-encoded KEK to stdout")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt binary Terraform plan file into an envelope bundle")
    p_enc.add_argument("--plan-file", required=True, help="Path to plaintext binary Terraform plan file")
    p_enc.add_argument("--output-envelope", required=True, help="Path to destination envelope JSON file")
    p_enc.add_argument("--kek-file", help="Path to 256-bit KEK file")
    p_enc.add_argument("--kek-hex", help="Hex-encoded 256-bit KEK string")
    p_enc.add_argument("--key-id", default="mock-kms-kek-1", help="Key identifier (default: mock-kms-kek-1)")
    p_enc.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", "unknown/repo"), help="Source repository")
    p_enc.add_argument("--commit", default=os.getenv("GITHUB_SHA", "0" * 40), help="Source commit SHA")
    p_enc.add_argument(
        "--workflow",
        default=os.getenv("GITHUB_WORKFLOW_REF", ".github/workflows/reusable-tf-plan.yml"),
        help="Workflow identity",
    )
    p_enc.add_argument("--environment", default="production", help="Deployment environment name")
    p_enc.add_argument("--plan-id", help="Unique plan identifier")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt and verify an encrypted plan envelope bundle")
    p_dec.add_argument("--envelope-file", required=True, help="Path to encrypted plan envelope JSON file")
    p_dec.add_argument("--output-plan", required=True, help="Path to destination decrypted binary plan file")
    p_dec.add_argument("--kek-file", help="Path to 256-bit KEK file")
    p_dec.add_argument("--kek-hex", help="Hex-encoded 256-bit KEK string")
    p_dec.add_argument("--expected-repo", help="Assert envelope matches expected source repository")
    p_dec.add_argument("--expected-commit", help="Assert envelope matches expected source commit SHA")
    p_dec.add_argument("--expected-environment", help="Assert envelope matches expected environment")
    p_dec.add_argument("--expected-digest", help="Assert decrypted plan SHA-256 matches expected digest")

    # verify-envelope
    p_ver = subparsers.add_parser("verify-envelope", help="Statically verify envelope JSON schema and context headers")
    p_ver.add_argument("--envelope-file", required=True, help="Path to envelope JSON file")
    p_ver.add_argument("--expected-repo", help="Assert envelope matches expected repository")
    p_ver.add_argument("--expected-commit", help="Assert envelope matches expected commit SHA")
    p_ver.add_argument("--expected-environment", help="Assert envelope matches expected environment")
    p_ver.add_argument("--expected-digest", help="Assert envelope header matches expected SHA-256 digest")

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        return 2

    try:
        if args.subcommand == "generate-kek":
            kek = os.urandom(KEK_BYTES)
            safe_write_file(args.output_kek, kek, mode=0o600)
            print(f"Generated 256-bit KEK successfully: {args.output_kek} (mode 0600)")
            if args.print_hex:
                print(f"KEK Hex: {kek.hex()}")
            return 0

        elif args.subcommand == "encrypt":
            kek = load_kek(kek_file=args.kek_file, kek_hex=args.kek_hex)
            plan_bytes = safe_read_file(args.plan_file)
            envelope = encrypt_plan(
                plan_bytes=plan_bytes,
                kek=kek,
                key_id=args.key_id,
                repository=args.repo,
                commit_sha=args.commit,
                workflow=args.workflow,
                environment=args.environment,
                plan_identifier=args.plan_id,
            )
            safe_write_file(args.output_envelope, envelope.to_json().encode("utf-8"), mode=0o600)
            summary = {
                "status": "success",
                "envelope_file": args.output_envelope,
                "plan_digest": envelope.plan_digest,
                "plan_size_bytes": envelope.plan_size_bytes,
                "key_id": envelope.key_id,
                "key_provider": envelope.key_provider,
                "schema_version": envelope.schema_version,
                "created_at": envelope.created_at,
            }
            print(json.dumps(summary, indent=2))
            return 0

        elif args.subcommand == "decrypt":
            kek = load_kek(kek_file=args.kek_file, kek_hex=args.kek_hex)
            envelope_raw = safe_read_file(args.envelope_file).decode("utf-8")
            envelope = PlanEnvelope.from_json(envelope_raw)
            plan_bytes = decrypt_plan(
                envelope=envelope,
                kek=kek,
                expected_repo=args.expected_repo,
                expected_commit=args.expected_commit,
                expected_environment=args.expected_environment,
                expected_digest=args.expected_digest,
            )
            safe_write_file(args.output_plan, plan_bytes, mode=0o600)
            print(f"Decrypted plan successfully to: {args.output_plan}")
            print(f"Verified SHA-256 Digest: {envelope.plan_digest}")
            print(f"Verified Plan Size: {len(plan_bytes)} bytes")
            return 0

        elif args.subcommand == "verify-envelope":
            envelope_raw = safe_read_file(args.envelope_file).decode("utf-8")
            envelope = PlanEnvelope.from_json(envelope_raw)
            if args.expected_repo and envelope.aad.get("repository") != args.expected_repo:
                raise EnvelopeContextMismatchError(
                    f"Repository mismatch: expected '{args.expected_repo}', got '{envelope.aad.get('repository')}'"
                )
            if args.expected_commit and envelope.aad.get("commit_sha") != args.expected_commit:
                raise EnvelopeContextMismatchError(
                    f"Commit SHA mismatch: expected '{args.expected_commit}', got '{envelope.aad.get('commit_sha')}'"
                )
            if args.expected_environment and envelope.aad.get("environment") != args.expected_environment:
                raise EnvelopeContextMismatchError(
                    f"Environment mismatch: expected '{args.expected_environment}', got '{envelope.aad.get('environment')}'"
                )
            if args.expected_digest and envelope.plan_digest != args.expected_digest.lower():
                raise EnvelopeDigestMismatchError(
                    f"Digest mismatch: expected '{args.expected_digest.lower()}', got '{envelope.plan_digest}'"
                )
            print(f"Envelope header and schema validation PASSED for: {args.envelope_file}")
            print(f"Schema Version: {envelope.schema_version}")
            print(f"Algorithm: {envelope.algorithm}")
            print(f"Plan Digest: {envelope.plan_digest}")
            print(f"Plan Size: {envelope.plan_size_bytes} bytes")
            print(f"Repository: {envelope.aad.get('repository')}")
            print(f"Commit SHA: {envelope.aad.get('commit_sha')}")
            print(f"Environment: {envelope.aad.get('environment')}")
            return 0

    except EnvelopeError as e:
        print(f"Error [{type(e).__name__}]: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
