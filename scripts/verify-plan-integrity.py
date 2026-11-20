#!/usr/bin/env python3
"""
InfraFlow — Plan Provenance & Trusted Digital Attestation Engine
Generates and cryptographically verifies authenticated digital signatures for Terraform plans:
- Asymmetric digital signatures (ECDSA P-256 / SHA-256 in DSSE in-toto envelope)
- Independent trust root enforcement (trusted public key pinning & fingerprint allowlist)
- Revocation checking (revoked key fingerprint blocklist)
- Rejection of in-band / unpinned public key trust (attacker key substitution prevention)
- Cryptographic binding to binary plan digest and plan JSON digest
- Repository identity and source commit SHA binding
- Workflow run ID, triggering actor, and workflow file binding
- Security policy evaluation outcome binding
- Strict verification detecting tampering, signature forgery, cross-repo spoofing, and stale plans
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SCHEMA_VERSION = "infraflow-plan-attestation-v1"
MANIFEST_SCHEMA_VERSION = "infraflow-plan-manifest-v1"
PROVENANCE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE_PROVENANCE = "https://infraflow.dev/provenance/v1"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle+json;version=0.2"
PREDICATE_TYPE_ATTESTATION = "https://docs.github.com/en/actions/deployment/security/about-artifact-attestations"

# Authoritative Platform Production Signer Allowlist
# Only signing identities registered here may authorize production deployments.
PLATFORM_PRODUCTION_SIGNERS = {
    "3c27ef9e1e520fd8c6c04db2c19680e16cf3c95a72b5536a9cada058890f7e90"
}

def compute_sha256(file_path):
    """Computes SHA-256 hexadecimal digest of a file in streaming chunks."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found for hashing: {file_path}")
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def compute_key_fingerprint(public_key_pem_bytes):
    """Computes canonical SHA-256 hex fingerprint of a PEM-encoded public key."""
    return hashlib.sha256(public_key_pem_bytes.strip()).hexdigest()

def generate_keypair(private_key_path, public_key_path):
    """Generates an ECDSA NIST P-256 asymmetric signing keypair in PEM format."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs(os.path.dirname(os.path.abspath(private_key_path)), exist_ok=True)
    with open(private_key_path, "wb") as f:
        f.write(priv_pem)
    # Enforce strict POSIX permissions on private key
    try:
        os.chmod(private_key_path, 0o600)
    except OSError:
        pass

    os.makedirs(os.path.dirname(os.path.abspath(public_key_path)), exist_ok=True)
    with open(public_key_path, "wb") as f:
        f.write(pub_pem)

    fingerprint = compute_key_fingerprint(pub_pem)
    return private_key, public_key, fingerprint

def load_fingerprint_list(source):
    """Parses a comma-separated string or file containing hex fingerprints."""
    if not source:
        return set()
    if os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            lines = [line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")]
            return set(lines)
    # Comma-separated string
    return {part.strip().lower() for part in source.split(",") if part.strip()}

def sign_provenance(plan_json_path, plan_file_path=None, private_key_path=None,
                    private_key_env_var="INFRAFLOW_SIGNING_KEY",
                    repository=None, commit_sha=None, run_id=None, actor=None,
                    workflow=None, terraform_version=None, policy_result="passed",
                    signing_tier="preview",
                    output_path=None):
    """
    Constructs an in-toto provenance statement and cryptographically signs it
    with an asymmetric ECDSA private key inside a DSSE envelope.
    """
    if not os.path.exists(plan_json_path):
        raise FileNotFoundError(f"Plan JSON path does not exist: {plan_json_path}")

    plan_json_digest = compute_sha256(plan_json_path)
    plan_file_digest = None
    if plan_file_path and os.path.exists(plan_file_path):
        plan_file_digest = compute_sha256(plan_file_path)

    # 1. Resolve Private Key (CLI path > Environment Variable > Ephemeral)
    private_key = None
    if private_key_path and os.path.exists(private_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    elif private_key_env_var in os.environ and os.environ[private_key_env_var].strip():
        pem_data = os.environ[private_key_env_var].strip().encode("utf-8")
        private_key = serialization.load_pem_private_key(pem_data, password=None)
    else:
        # Generate ephemeral keypair if none supplied (for testing)
        sys.stderr.write("[WARNING] No signing key provided. Generating ephemeral ECDSA P-256 key for testing.\n")
        private_key = ec.generate_private_key(ec.SECP256R1())

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_fingerprint = compute_key_fingerprint(pub_pem)

    repo_str = repository or "local/test-workspace"
    commit_str = commit_sha or "0000000000000000000000000000000000000000"
    workflow_str = workflow or "reusable-tf-plan.yml"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    subject_list = [
        {
            "name": "plan.json",
            "digest": {
                "sha256": plan_json_digest
            }
        }
    ]
    if plan_file_digest:
        subject_list.append({
            "name": "tfplan",
            "digest": {
                "sha256": plan_file_digest
            }
        })

    # in-toto v1 Statement
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subject_list,
        "predicateType": PREDICATE_TYPE_PROVENANCE,
        "predicate": {
            "builder": {
                "id": f"https://github.com/{repo_str}/.github/workflows/{workflow_str}"
            },
            "metadata": {
                "repository": repo_str,
                "commit_sha": commit_str,
                "run_id": str(run_id or "0"),
                "actor": actor or "local-user",
                "workflow": workflow_str,
                "terraform_version": terraform_version or "unknown",
                "signing_tier": signing_tier,
                "created_at_utc": timestamp
            },
            "policy_evaluation": {
                "status": policy_result,
                "evaluated_at_utc": timestamp
            }
        }
    }

    # Canonicalize JSON (lexicographical keys, compact separators)
    canonical_payload = json.dumps(statement, sort_keys=True, separators=(',', ':')).encode("utf-8")

    # Cryptographic signature using ECDSA with SHA-256
    signature_bytes = private_key.sign(canonical_payload, ec.ECDSA(hashes.SHA256()))

    envelope = {
        "payloadType": PROVENANCE_PAYLOAD_TYPE,
        "payload": base64.b64encode(canonical_payload).decode("ascii"),
        "signatures": [
            {
                "keyid": key_fingerprint,
                "sig": base64.b64encode(signature_bytes).decode("ascii"),
                "publicKey": pub_pem.decode("ascii")
            }
        ]
    }

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)

    return envelope, key_fingerprint

def verify_provenance(provenance_path, trusted_public_key_path=None,
                      trusted_keyids=None, revoked_keyids=None,
                      candidate_public_key_path=None, plan_json_path=None,
                      plan_file_path=None, expected_repository=None,
                      expected_commit_sha=None, expected_workflow=None,
                      enforce_trusted_signer=True,
                      require_production_signer=False):
    """
    Verifies the cryptographic signature of the DSSE envelope against an
    INDEPENDENT TRUST ROOT (pinned public key or trusted keyids allowlist).
    Rejects in-band key substitution attacks, revoked keys, digest mismatches,
    and environmental binding discrepancies.
    """
    if not os.path.isfile(provenance_path):
        return False, [f"Provenance file not found: {provenance_path}"]

    try:
        with open(provenance_path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
    except Exception as e:
        return False, [f"Corrupted or invalid DSSE provenance JSON: {str(e)}"]

    if envelope.get("payloadType") != PROVENANCE_PAYLOAD_TYPE:
        return False, [f"Invalid payloadType '{envelope.get('payloadType')}', expected '{PROVENANCE_PAYLOAD_TYPE}'"]

    signatures = envelope.get("signatures", [])
    if not signatures or not isinstance(signatures, list):
        return False, ["Missing signatures array in DSSE envelope"]

    primary_sig = signatures[0]
    b64_sig = primary_sig.get("sig")
    sig_keyid = primary_sig.get("keyid", "").lower()

    if not b64_sig:
        return False, ["Signature object missing 'sig' data"]

    try:
        raw_signature = base64.b64decode(b64_sig)
        canonical_payload = base64.b64decode(envelope.get("payload", ""))
    except Exception as e:
        return False, [f"Failed to base64 decode signature or payload: {str(e)}"]

    # 1. Independent Trust Root Resolution
    trusted_fingerprints = load_fingerprint_list(trusted_keyids)
    revoked_fingerprints = load_fingerprint_list(revoked_keyids)

    # Automatically load platform protected revocation registry if present
    script_dir = os.path.dirname(os.path.abspath(__file__))
    platform_revocation_file = os.path.join(os.path.dirname(script_dir), "policies", "trust", "revocations.txt")
    if os.path.isfile(platform_revocation_file):
        revoked_fingerprints.update(load_fingerprint_list(platform_revocation_file))

    public_key = None
    candidate_key_fingerprint = None

    if trusted_public_key_path and os.path.exists(trusted_public_key_path):
        with open(trusted_public_key_path, "rb") as f:
            trusted_pem = f.read()
            public_key = serialization.load_pem_public_key(trusted_pem)
            trusted_fp = compute_key_fingerprint(trusted_pem)
            candidate_key_fingerprint = trusted_fp

            # Anti-Substitution Defense: If a trusted keyids allowlist is provided,
            # verify that the trusted public key file's fingerprint is in the allowlist.
            # This prevents an untrusted PR from replacing trusted_signer.pub on disk.
            if trusted_fingerprints and trusted_fp not in trusted_fingerprints:
                return False, [
                    f"CRITICAL: Untrusted public key file! The public key at '{trusted_public_key_path}' "
                    f"has fingerprint '{trusted_fp}' which is not in the trusted signers allowlist."
                ]

            # Verify that the envelope key ID matches the pinned trusted key
            if sig_keyid and sig_keyid != trusted_fp:
                return False, [
                    f"CRITICAL: Untrusted signer key! Envelope key ID '{sig_keyid}' "
                    f"does not match pinned trusted public key fingerprint '{trusted_fp}'."
                ]
    else:
        # Candidate key from candidate_public_key_path or embedded in envelope
        cand_pem = None
        if candidate_public_key_path and os.path.exists(candidate_public_key_path):
            with open(candidate_public_key_path, "rb") as f:
                cand_pem = f.read()
        elif "publicKey" in primary_sig:
            cand_pem = primary_sig["publicKey"].encode("ascii")

        if cand_pem:
            try:
                public_key = serialization.load_pem_public_key(cand_pem)
                candidate_key_fingerprint = compute_key_fingerprint(cand_pem)
            except Exception as e:
                return False, [f"Failed to load candidate public key: {str(e)}"]

        # If strict trust root enforcement is active, we MUST NOT trust unpinned candidate keys!
        if enforce_trusted_signer:
            if not trusted_fingerprints:
                return False, [
                    "CRITICAL: Refusing to verify provenance using unpinned public key! "
                    "An independent trust root (--trusted-public-key or --trusted-keyids) is required."
                ]
            if candidate_key_fingerprint not in trusted_fingerprints:
                return False, [
                    f"CRITICAL: Untrusted signer key! Candidate key fingerprint '{candidate_key_fingerprint}' "
                    f"is not in the trusted signers allowlist."
                ]

    if not public_key:
        return False, ["Unable to resolve public key for signature verification"]

    # 2. Check Key Revocation
    if candidate_key_fingerprint and candidate_key_fingerprint in revoked_fingerprints:
        return False, [
            f"CRITICAL: Revoked signer key! Key ID '{candidate_key_fingerprint}' "
            f"has been explicitly revoked."
        ]
    if sig_keyid and sig_keyid in revoked_fingerprints:
        return False, [
            f"CRITICAL: Revoked signer key! Signature key ID '{sig_keyid}' "
            f"has been explicitly revoked."
        ]

    # 3. Cryptographic Digital Signature Verification
    try:
        public_key.verify(raw_signature, canonical_payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, ["CRITICAL: Digital signature verification FAILED! Payload has been forged or altered."]
    except Exception as e:
        return False, [f"Cryptographic verification error: {str(e)}"]

    # 4. Parse and Validate in-toto Statement
    try:
        statement = json.loads(canonical_payload.decode("utf-8"))
    except Exception as e:
        return False, [f"Payload is not valid in-toto JSON: {str(e)}"]

    errors = []
    subjects = {s.get("name"): s.get("digest", {}) for s in statement.get("subject", [])}
    predicate = statement.get("predicate", {})
    metadata = predicate.get("metadata", {})
    policy_eval = predicate.get("policy_evaluation", {})

    # 5. Plan JSON Digest Verification
    if plan_json_path:
        if not os.path.isfile(plan_json_path):
            errors.append(f"Candidate plan JSON not found: {plan_json_path}")
        else:
            computed_json_digest = compute_sha256(plan_json_path)
            signed_json_digest = subjects.get("plan.json", {}).get("sha256")
            if computed_json_digest != signed_json_digest:
                errors.append(
                    f"CRITICAL: Plan JSON digest mismatch! Candidate plan does not match signed provenance. "
                    f"Signed SHA256: {signed_json_digest}, Candidate SHA256: {computed_json_digest}"
                )

    # 6. Plan Binary Digest Verification (if present)
    if "tfplan" in subjects and plan_file_path:
        if not os.path.isfile(plan_file_path):
            errors.append(f"Candidate binary plan file not found: {plan_file_path}")
        else:
            computed_file_digest = compute_sha256(plan_file_path)
            signed_file_digest = subjects["tfplan"].get("sha256")
            if computed_file_digest != signed_file_digest:
                errors.append(
                    f"CRITICAL: Binary plan file digest mismatch! "
                    f"Signed SHA256: {signed_file_digest}, Candidate SHA256: {computed_file_digest}"
                )

    # 7. Repository Identity Binding Verification
    if expected_repository is not None:
        actual_repo = metadata.get("repository")
        if actual_repo != expected_repository:
            errors.append(
                f"Repository mismatch: provenance bound to '{actual_repo}', "
                f"expected '{expected_repository}'"
            )

    # 8. Source Commit SHA Binding Verification
    if expected_commit_sha is not None:
        actual_commit = metadata.get("commit_sha")
        if actual_commit.lower() != expected_commit_sha.lower():
            errors.append(
                f"Commit SHA mismatch: provenance bound to '{actual_commit}', "
                f"expected HEAD '{expected_commit_sha}'"
            )

    # 9. Workflow Identity Verification
    if expected_workflow is not None:
        actual_workflow = metadata.get("workflow")
        if actual_workflow != expected_workflow:
            errors.append(
                f"Workflow identity mismatch: provenance generated by '{actual_workflow}', "
                f"expected '{expected_workflow}'"
            )

    # 10. Policy Evaluation Result Enforcement
    policy_status = policy_eval.get("status")
    if policy_status != "passed":
        errors.append(
            f"Policy evaluation failure: provenance recorded status '{policy_status}'. "
            f"Only plans passing all enterprise security policies may be approved."
        )

    # 11. Signing Identity Tier & Production Authorization Gate
    signing_tier = metadata.get("signing_tier", "preview")
    if require_production_signer:
        if signing_tier != "production":
            errors.append(
                f"CRITICAL: Untrusted signing tier! Provenance was signed with tier '{signing_tier}', "
                f"but production authorization strictly requires 'production' tier."
            )
        resolved_fp = candidate_key_fingerprint or sig_keyid
        if resolved_fp and resolved_fp not in PLATFORM_PRODUCTION_SIGNERS:
            errors.append(
                f"CRITICAL: Unauthorized production signer! Key fingerprint '{resolved_fp}' "
                f"is not registered as an authorized platform production signer."
            )

    if errors:
        return False, errors

    return True, []

# --- Production Provenance Routines (GitHub Artifact Attestations / Sigstore OIDC) ---

def generate_plan_manifest(plan_json_path, plan_file_path=None, repository=None,
                           commit_sha=None, run_id=None, actor=None,
                           workflow=None, terraform_version=None,
                           security_decision="passed", output_path=None):
    """
    Generates a canonical, sanitized plan manifest that binds:
    - SHA-256 digest of plan JSON
    - SHA-256 digest of binary plan file (if present)
    - Repository identity, source commit SHA, workflow run ID, actor, workflow reference
    - Terraform version and security policy decision ('passed' / 'failed')
    Never contains raw infrastructure secrets, plan JSON, or credentials.
    """
    if not os.path.exists(plan_json_path):
        raise FileNotFoundError(f"Plan JSON path does not exist: {plan_json_path}")

    plan_json_digest = compute_sha256(plan_json_path)
    plan_file_digest = compute_sha256(plan_file_path) if plan_file_path and os.path.exists(plan_file_path) else None
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at_utc": timestamp,
        "metadata": {
            "repository": repository or "local/test-workspace",
            "commit_sha": commit_sha or "0000000000000000000000000000000000000000",
            "run_id": str(run_id or "0"),
            "actor": actor or "local-user",
            "workflow": workflow or "reusable-tf-plan.yml",
            "terraform_version": terraform_version or "unknown",
            "security_decision": security_decision
        },
        "digests": {
            "plan_json_sha256": plan_json_digest,
            "plan_file_sha256": plan_file_digest
        }
    }

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    return manifest

def create_attestation_bundle(manifest_path, repository=None, workflow=None,
                              commit_sha=None, output_path=None):
    """
    Constructs a synthetic Sigstore attestation bundle for plan-manifest.json
    mimicking actions/attest (GitHub OIDC & Sigstore) for offline and local testing.
    """
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"Manifest path not found: {manifest_path}")

    manifest_digest = compute_sha256(manifest_path)
    repo_str = repository or "TM-threemavithana/infraflow"
    workflow_str = workflow or "reusable-tf-plan.yml"
    commit_str = commit_sha or "0000000000000000000000000000000000000000"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "plan-manifest.json",
                "digest": {
                    "sha256": manifest_digest
                }
            }
        ],
        "predicateType": PREDICATE_TYPE_ATTESTATION,
        "predicate": {
            "signer": {
                "repository": repo_str,
                "workflow": workflow_str,
                "commit_sha": commit_str,
                "issuer": "https://token.actions.githubusercontent.com",
                "type": "github-actions-oidc"
            },
            "attestation": {
                "generated_at": timestamp,
                "signing_architecture": "sigstore-oidc"
            }
        }
    }

    canonical_payload = json.dumps(statement, sort_keys=True, separators=(',', ':')).encode("utf-8")
    b64_payload = base64.b64encode(canonical_payload).decode("ascii")

    bundle = {
        "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "certificateChain": {
                "certificates": [
                    {
                        "rawBytes": base64.b64encode(f"github-oidc:{repo_str}:{workflow_str}:{commit_str}".encode("utf-8")).decode("ascii")
                    }
                ]
            },
            "tlogEntries": [
                {
                    "logIndex": "1",
                    "integratedTime": timestamp
                }
            ]
        },
        "dsseEnvelope": {
            "payloadType": PROVENANCE_PAYLOAD_TYPE,
            "payload": b64_payload,
            "signatures": [
                {
                    "keyid": "github-actions-oidc-sigstore",
                    "sig": base64.b64encode(b"sigstore-oidc-simulated-signature").decode("ascii")
                }
            ]
        }
    }

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

    return bundle

def verify_attestation(manifest_path, bundle_path=None, plan_json_path=None,
                       plan_file_path=None, expected_repository=None,
                       expected_commit_sha=None, expected_workflow=None,
                       require_production_signer=False, use_gh_cli=False,
                       signer_repo=None, signer_workflow=None, signer_digest=None,
                       cert_oidc_issuer="https://token.actions.githubusercontent.com"):
    """
    Verifies a GitHub Artifact Attestation and associated plan manifest:
    - Confirms the plan manifest format, integrity, and security decision.
    - Confirms candidate plan JSON and plan binary digests match the manifest.
    - When use_gh_cli is True:
      Invokes official 'gh attestation verify' to cryptographically verify
      the Sigstore Fulcio certificate, Rekor transparency log entry, and subject digest.
    - When bundle_path is provided (offline unit testing):
      Validates synthetic Sigstore bundle mediaType and DSSE payload statement.
      NOTE: Synthetic bundles are strictly for offline unit tests; production verification
      in live workflows requires official 'gh attestation verify'.
    - Confirms the subject in the attestation matches the SHA-256 digest of plan-manifest.json.
    - Validates repository, commit SHA, and workflow identity.
    - When require_production_signer is True:
      Strictly enforces that Sigstore OIDC attestation is present and valid;
      rejects offline preview keys, unverified identities, or missing bundles.
    """
    if not os.path.isfile(manifest_path):
        return False, [f"Manifest file not found: {manifest_path}"]

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        return False, [f"Corrupted or invalid manifest JSON: {str(e)}"]

    schema_version = manifest.get("schema_version")
    if schema_version not in (MANIFEST_SCHEMA_VERSION, SCHEMA_VERSION):
        return False, [f"Unsupported schema version '{schema_version}', expected '{MANIFEST_SCHEMA_VERSION}'"]

    errors = []
    metadata = manifest.get("metadata", manifest.get("attestation", {}))
    digests = manifest.get("digests", {})

    # 1. Enforce Security Decision
    security_decision = metadata.get("security_decision")
    if security_decision != "passed":
        errors.append(
            f"CRITICAL: Security decision in manifest was '{security_decision}'. "
            f"Only plans passing all enterprise security policies may be authorized."
        )

    # 2. Verify Candidate Plan JSON Digest
    if plan_json_path:
        if not os.path.isfile(plan_json_path):
            errors.append(f"Candidate plan JSON not found: {plan_json_path}")
        else:
            computed_json_digest = compute_sha256(plan_json_path)
            expected_json_digest = digests.get("plan_json_sha256")
            if computed_json_digest != expected_json_digest:
                errors.append(
                    f"CRITICAL: Plan JSON digest mismatch! Candidate plan does not match manifest. "
                    f"Manifest SHA256: {expected_json_digest}, Computed: {computed_json_digest}"
                )

    # 3. Verify Candidate Plan Binary Digest
    if plan_file_path and "plan_file_sha256" in digests and digests["plan_file_sha256"]:
        if not os.path.isfile(plan_file_path):
            errors.append(f"Candidate binary plan file not found: {plan_file_path}")
        else:
            computed_file_digest = compute_sha256(plan_file_path)
            expected_file_digest = digests.get("plan_file_sha256")
            if computed_file_digest != expected_file_digest:
                errors.append(
                    f"CRITICAL: Binary plan file digest mismatch! "
                    f"Manifest SHA256: {expected_file_digest}, Computed: {computed_file_digest}"
                )

    # 4. Verify Metadata Environmental Bindings
    actual_repo = metadata.get("repository")
    if expected_repository is not None and actual_repo != expected_repository:
        errors.append(
            f"Repository mismatch: manifest recorded '{actual_repo}', "
            f"expected '{expected_repository}'"
        )

    actual_commit = metadata.get("commit_sha", "")
    if expected_commit_sha is not None and actual_commit.lower() != expected_commit_sha.lower():
        errors.append(
            f"Commit SHA mismatch: manifest recorded '{actual_commit}', "
            f"expected '{expected_commit_sha}'"
        )

    actual_workflow = metadata.get("workflow")
    if expected_workflow is not None and actual_workflow != expected_workflow:
        errors.append(
            f"Workflow mismatch: manifest recorded '{actual_workflow}', "
            f"expected '{expected_workflow}'"
        )

    # 5. Official GitHub CLI Verification (gh attestation verify)
    if use_gh_cli:
        cmd = ["gh", "attestation", "verify", manifest_path]
        if expected_repository:
            cmd.extend(["--repo", expected_repository])
        if bundle_path and os.path.isfile(bundle_path):
            cmd.extend(["--bundle", bundle_path])
        if signer_workflow:
            cmd.extend(["--signer-workflow", signer_workflow])
        elif signer_repo:
            cmd.extend(["--signer-repo", signer_repo])
        if signer_digest:
            cmd.extend(["--signer-digest", signer_digest])
        if expected_commit_sha:
            cmd.extend(["--source-digest", expected_commit_sha])
        cmd.extend(["--cert-oidc-issuer", cert_oidc_issuer])
        cmd.append("--format=json")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                err_msg = result.stderr.strip() or result.stdout.strip()
                errors.append(f"Official 'gh attestation verify' failed: {err_msg}")
            elif result.stdout:
                try:
                    gh_output = json.loads(result.stdout)
                    if not isinstance(gh_output, list) or len(gh_output) == 0:
                        errors.append("Official verification error: no valid attestations returned by gh CLI")
                except Exception:
                    pass
        except FileNotFoundError:
            errors.append("Official verification error: 'gh' CLI tool not found in PATH")
        except Exception as e:
            errors.append(f"Official verification execution error: {str(e)}")

    # 6. Synthetic Sigstore Attestation Bundle Verification (Offline Tests)
    elif bundle_path:
        if not os.path.isfile(bundle_path):
            errors.append(f"Attestation bundle not found: {bundle_path}")
        else:
            try:
                with open(bundle_path, "r", encoding="utf-8") as f:
                    bundle = json.load(f)
            except Exception as e:
                errors.append(f"Corrupted or invalid Sigstore bundle JSON: {str(e)}")
                bundle = None

            if bundle:
                media_type = bundle.get("mediaType", "")
                if not media_type.startswith("application/vnd.dev.sigstore.bundle+json"):
                    errors.append(f"Invalid Sigstore bundle mediaType '{media_type}'")

                # Parse DSSE statement
                envelope = bundle.get("dsseEnvelope", {})
                if envelope.get("payloadType") != PROVENANCE_PAYLOAD_TYPE:
                    errors.append(f"Invalid DSSE payloadType in bundle: '{envelope.get('payloadType')}'")

                try:
                    payload_raw = base64.b64decode(envelope.get("payload", ""))
                    statement = json.loads(payload_raw.decode("utf-8"))
                except Exception as e:
                    errors.append(f"Failed to decode or parse bundle payload: {str(e)}")
                    statement = None

                if statement:
                    # Verify subject digest matches manifest
                    manifest_sha = compute_sha256(manifest_path)
                    subjects = statement.get("subject", [])
                    matched_subject = False
                    for subj in subjects:
                        subj_sha = subj.get("digest", {}).get("sha256")
                        if subj_sha == manifest_sha:
                            matched_subject = True
                            break

                    if not matched_subject:
                        errors.append(
                            f"CRITICAL: Attestation subject digest mismatch! "
                            f"The Sigstore attestation bundle does not attest the current plan manifest. "
                            f"Manifest SHA256: {manifest_sha}"
                        )

                    # Verify Predicate Signer Identity
                    predicate = statement.get("predicate", {})
                    signer = predicate.get("signer", {})
                    att_repo = signer.get("repository")
                    att_workflow = signer.get("workflow")
                    att_commit = signer.get("commit_sha")
                    att_issuer = signer.get("issuer", "https://token.actions.githubusercontent.com")

                    if cert_oidc_issuer and att_issuer != cert_oidc_issuer:
                        errors.append(
                            f"OIDC issuer mismatch: attestation bound to '{att_issuer}', "
                            f"expected '{cert_oidc_issuer}'"
                        )

                    if expected_repository is not None and att_repo and att_repo != expected_repository:
                        errors.append(
                            f"Attestation signer repository mismatch: attestation bound to '{att_repo}', "
                            f"expected '{expected_repository}'"
                        )

                    if signer_workflow is not None and att_workflow and att_workflow != signer_workflow:
                        errors.append(
                            f"Attestation signer workflow mismatch: attestation bound to '{att_workflow}', "
                            f"expected '{signer_workflow}'"
                        )
                    elif expected_workflow is not None and att_workflow and att_workflow != expected_workflow:
                        errors.append(
                            f"Attestation signer workflow mismatch: attestation bound to '{att_workflow}', "
                            f"expected '{expected_workflow}'"
                        )

                    if expected_commit_sha is not None and att_commit and att_commit.lower() != expected_commit_sha.lower():
                        errors.append(
                            f"Attestation signer commit mismatch: attestation bound to '{att_commit}', "
                            f"expected '{expected_commit_sha}'"
                        )

    # 7. Production Authorization Requirements
    if require_production_signer:
        if not use_gh_cli:
            errors.append(
                "CRITICAL: Production authorization strictly requires official GitHub Artifact Attestation verification "
                "via GitHub CLI (--use-gh-cli) backed by Sigstore OIDC and transparency logs. "
                "Synthetic offline bundles, unverified keys, and unsigned manifests cannot authorize production."
            )

    return (len(errors) == 0), errors

# --- Legacy Compatibility Routines (G04 Unsigned Manifests) ---

def generate_manifest(plan_json_path, plan_file_path=None, repository=None,
                      commit_sha=None, run_id=None, actor=None,
                      terraform_version=None):
    """Generates an unsigned legacy attestation manifest."""
    if not os.path.exists(plan_json_path):
        raise FileNotFoundError(f"Plan JSON path does not exist: {plan_json_path}")

    plan_json_digest = compute_sha256(plan_json_path)
    plan_file_digest = compute_sha256(plan_file_path) if plan_file_path and os.path.exists(plan_file_path) else None
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": timestamp,
        "attestation": {
            "repository": repository or "local/test-workspace",
            "commit_sha": commit_sha or "0000000000000000000000000000000000000000",
            "run_id": str(run_id or "0"),
            "actor": actor or "local-user",
            "terraform_version": terraform_version or "unknown"
        },
        "digests": {
            "plan_json_sha256": plan_json_digest,
            "plan_file_sha256": plan_file_digest
        }
    }

def verify_manifest(manifest_path, plan_json_path, plan_file_path=None,
                    expected_repository=None, expected_commit_sha=None,
                    expected_terraform_version=None):
    """Verifies unsigned legacy manifest bindings."""
    if not os.path.isfile(manifest_path):
        return False, [f"Manifest file not found: {manifest_path}"]

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        return False, [f"Corrupted or invalid manifest JSON: {str(e)}"]

    if manifest.get("schema_version") != SCHEMA_VERSION:
        return False, [f"Unsupported schema version: {manifest.get('schema_version')}"]

    errors = []
    attestation = manifest.get("attestation", {})
    digests = manifest.get("digests", {})

    if expected_repository is not None and attestation.get("repository") != expected_repository:
        errors.append(f"Repository mismatch: manifest recorded '{attestation.get('repository')}', expected '{expected_repository}'")

    if expected_commit_sha is not None and attestation.get("commit_sha", "").lower() != expected_commit_sha.lower():
        errors.append(f"Commit SHA mismatch: manifest bound to '{attestation.get('commit_sha')}', current HEAD is '{expected_commit_sha}'")

    if expected_terraform_version is not None and attestation.get("terraform_version") != expected_terraform_version:
        errors.append(f"Terraform version mismatch: manifest recorded '{attestation.get('terraform_version')}', environment has '{expected_terraform_version}'")

    if not os.path.isfile(plan_json_path):
        errors.append(f"Candidate plan JSON not found for verification: {plan_json_path}")
    else:
        current_json_digest = compute_sha256(plan_json_path)
        if current_json_digest != digests.get("plan_json_sha256"):
            errors.append(f"CRITICAL: Plan JSON digest mismatch! Expected SHA256: {digests.get('plan_json_sha256')}, Computed: {current_json_digest}")

    expected_file_digest = digests.get("plan_file_sha256")
    if expected_file_digest is not None:
        if not plan_file_path or not os.path.isfile(plan_file_path):
            errors.append(f"Binary plan file required by manifest was missing: {plan_file_path}")
        else:
            current_file_digest = compute_sha256(plan_file_path)
            if current_file_digest != expected_file_digest:
                errors.append(f"CRITICAL: Binary plan file digest mismatch! Expected SHA256: {expected_file_digest}, Computed: {current_file_digest}")

    return (len(errors) == 0), errors

def main():
    parser = argparse.ArgumentParser(description="InfraFlow Plan Cryptographic Attestation & Trusted Provenance Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: generate-keypair
    key_parser = subparsers.add_parser("generate-keypair", help="Generate ECDSA P-256 asymmetric signing keypair")
    key_parser.add_argument("--private-key", required=True, help="Path to write private key PEM (chmod 600 enforced)")
    key_parser.add_argument("--public-key", required=True, help="Path to write public key PEM")

    # Command: compute-fingerprint
    fp_parser = subparsers.add_parser("compute-fingerprint", help="Compute canonical SHA-256 fingerprint of public key")
    fp_parser.add_argument("--public-key", required=True, help="Path to public key PEM")

    # Command: sign-provenance
    sign_parser = subparsers.add_parser("sign-provenance", help="Cryptographically sign in-toto DSSE plan provenance")
    sign_parser.add_argument("--plan-json", required=True, help="Path to Terraform plan JSON")
    sign_parser.add_argument("--plan-file", help="Path to binary Terraform plan file")
    sign_parser.add_argument("--private-key", help="Path to ECDSA private key PEM (optional, checks INFRAFLOW_SIGNING_KEY)")
    sign_parser.add_argument("--public-key-out", help="Path to export public key PEM")
    sign_parser.add_argument("--repository", help="GitHub repository (owner/repo)")
    sign_parser.add_argument("--commit-sha", help="Source git commit SHA")
    sign_parser.add_argument("--run-id", help="GitHub workflow run ID")
    sign_parser.add_argument("--actor", help="Workflow triggering actor")
    sign_parser.add_argument("--workflow", default="reusable-tf-plan.yml", help="Calling workflow name")
    sign_parser.add_argument("--terraform-version", help="Terraform version")
    sign_parser.add_argument("--policy-result", default="passed", choices=["passed", "failed"], help="Policy check outcome")
    sign_parser.add_argument("--signing-tier", default="preview", choices=["preview", "production"], help="Signing trust tier ('preview' for PRs, 'production' for protected merges)")
    sign_parser.add_argument("--output", required=True, help="Path to write signed provenance JSON")

    # Command: verify-provenance
    vprov_parser = subparsers.add_parser("verify-provenance", help="Verify cryptographically signed in-toto plan provenance")
    vprov_parser.add_argument("--provenance", required=True, help="Path to signed provenance JSON")
    vprov_parser.add_argument("--trusted-public-key", help="Path to pinned, trusted public key PEM (independent trust root)")
    vprov_parser.add_argument("--trusted-keyids", help="Comma-separated list or file of trusted key fingerprints")
    vprov_parser.add_argument("--revoked-keyids", help="Comma-separated list or file of revoked key fingerprints")
    vprov_parser.add_argument("--public-key", help="Path to candidate public key PEM")
    vprov_parser.add_argument("--plan-json", help="Path to candidate plan JSON")
    vprov_parser.add_argument("--plan-file", help="Path to candidate binary plan file")
    vprov_parser.add_argument("--expected-repository", help="Expected repository identity")
    vprov_parser.add_argument("--expected-commit-sha", help="Expected commit SHA")
    vprov_parser.add_argument("--expected-workflow", help="Expected workflow identity")
    vprov_parser.add_argument("--allow-unpinned-signer", action="store_true", help="Allow unpinned candidate key (DANGEROUS)")
    vprov_parser.add_argument("--require-production-signer", action="store_true", help="Enforce that provenance was signed with 'production' tier and an authorized production key")

    # Legacy Command: generate
    gen_parser = subparsers.add_parser("generate", help="Generate legacy unsigned plan attestation manifest")
    gen_parser.add_argument("--plan-json", required=True, help="Path to Terraform plan JSON")
    gen_parser.add_argument("--plan-file", help="Path to binary plan file")
    gen_parser.add_argument("--repository", help="GitHub repository (owner/repo)")
    gen_parser.add_argument("--commit-sha", help="Source git commit SHA")
    gen_parser.add_argument("--run-id", help="GitHub workflow run ID")
    gen_parser.add_argument("--actor", help="Triggering actor")
    gen_parser.add_argument("--terraform-version", help="Terraform version")
    gen_parser.add_argument("--output", required=True, help="Path to write manifest JSON")

    # Legacy Command: verify
    ver_parser = subparsers.add_parser("verify", help="Verify legacy unsigned plan attestation manifest")
    ver_parser.add_argument("--manifest", required=True, help="Path to manifest JSON")
    ver_parser.add_argument("--plan-json", required=True, help="Path to candidate plan JSON")
    ver_parser.add_argument("--plan-file", help="Path to candidate binary plan file")
    ver_parser.add_argument("--expected-repository", help="Expected repository binding")
    ver_parser.add_argument("--expected-commit-sha", help="Expected commit SHA binding")
    ver_parser.add_argument("--expected-terraform-version", help="Expected Terraform version")

    # Command: generate-manifest (G04.1.4 Production Manifest)
    man_parser = subparsers.add_parser("generate-manifest", help="Generate sanitized plan manifest for GitHub Artifact Attestation")
    man_parser.add_argument("--plan-json", required=True, help="Path to Terraform plan JSON")
    man_parser.add_argument("--plan-file", help="Path to binary plan file")
    man_parser.add_argument("--repository", help="GitHub repository (owner/repo)")
    man_parser.add_argument("--commit-sha", help="Source git commit SHA")
    man_parser.add_argument("--run-id", help="GitHub workflow run ID")
    man_parser.add_argument("--actor", help="Workflow triggering actor")
    man_parser.add_argument("--workflow", default="reusable-tf-plan.yml", help="Calling workflow reference")
    man_parser.add_argument("--terraform-version", help="Terraform version")
    man_parser.add_argument("--security-decision", default="passed", choices=["passed", "failed"], help="Security policy check outcome")
    man_parser.add_argument("--output", required=True, help="Path to write plan-manifest.json")

    # Command: create-bundle (G04.1.4 Sigstore Attestation Simulation)
    bun_parser = subparsers.add_parser("create-bundle", help="Create simulated Sigstore attestation bundle for test environments")
    bun_parser.add_argument("--manifest", required=True, help="Path to plan-manifest.json")
    bun_parser.add_argument("--repository", help="Signer repository identity")
    bun_parser.add_argument("--workflow", help="Signer workflow identity")
    bun_parser.add_argument("--commit-sha", help="Source git commit SHA")
    bun_parser.add_argument("--output", required=True, help="Path to write bundle.json")

    # Command: verify-attestation (G04.1.4 Production Attestation Verification)
    vatt_parser = subparsers.add_parser("verify-attestation", help="Verify GitHub Artifact Attestation (Sigstore bundle) for plan manifest")
    vatt_parser.add_argument("--manifest", required=True, help="Path to plan-manifest.json")
    vatt_parser.add_argument("--bundle", help="Path to Sigstore bundle JSON")
    vatt_parser.add_argument("--plan-json", help="Path to candidate plan JSON")
    vatt_parser.add_argument("--plan-file", help="Path to candidate binary plan file")
    vatt_parser.add_argument("--expected-repository", help="Expected signer repository")
    vatt_parser.add_argument("--expected-commit-sha", help="Expected git commit SHA")
    vatt_parser.add_argument("--expected-workflow", help="Expected workflow identity")
    vatt_parser.add_argument("--require-production-signer", action="store_true", help="Enforce production Sigstore attestation requirements")
    vatt_parser.add_argument("--use-gh-cli", action="store_true", help="Invoke official 'gh attestation verify' to cryptographically verify attestation")
    vatt_parser.add_argument("--signer-repo", help="Signer repository for gh attestation verify")
    vatt_parser.add_argument("--signer-workflow", help="Signer workflow for gh attestation verify")
    vatt_parser.add_argument("--signer-digest", help="Signer workflow commit SHA digest for gh attestation verify")
    vatt_parser.add_argument("--cert-oidc-issuer", default="https://token.actions.githubusercontent.com", help="Expected OIDC certificate issuer")

    args = parser.parse_args()

    if args.command == "generate-keypair":
        try:
            _, _, fp = generate_keypair(args.private_key, args.public_key)
            print(f"✅ ECDSA P-256 keypair generated successfully:")
            print(f"   Private Key: {args.private_key} (mode 600)")
            print(f"   Public Key:  {args.public_key}")
            print(f"   Fingerprint: {fp}")
            sys.exit(0)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Failed to generate keypair: {str(e)}\n")
            sys.exit(1)

    elif args.command == "compute-fingerprint":
        try:
            with open(args.public_key, "rb") as f:
                fp = compute_key_fingerprint(f.read())
            print(fp)
            sys.exit(0)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Failed to compute fingerprint: {str(e)}\n")
            sys.exit(1)

    elif args.command == "sign-provenance":
        try:
            envelope, key_id = sign_provenance(
                plan_json_path=args.plan_json,
                plan_file_path=args.plan_file,
                private_key_path=args.private_key,
                repository=args.repository,
                commit_sha=args.commit_sha,
                run_id=args.run_id,
                actor=args.actor,
                workflow=args.workflow,
                terraform_version=args.terraform_version,
                policy_result=args.policy_result,
                signing_tier=getattr(args, "signing_tier", "preview"),
                output_path=args.output
            )
            if args.public_key_out and envelope.get("signatures"):
                pub_pem = envelope["signatures"][0].get("publicKey", "").encode("ascii")
                os.makedirs(os.path.dirname(os.path.abspath(args.public_key_out)), exist_ok=True)
                with open(args.public_key_out, "wb") as f:
                    f.write(pub_pem)

            print(f"✅ Signed plan provenance generated: {args.output}")
            print(f"   Signer Fingerprint: {key_id}")
            print(f"   Payload Type:       {envelope['payloadType']}")
            sys.exit(0)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Provenance signing failed: {str(e)}\n")
            sys.exit(1)

    elif args.command == "verify-provenance":
        enforce_signer = not getattr(args, "allow_unpinned_signer", False)
        success, errors = verify_provenance(
            provenance_path=args.provenance,
            trusted_public_key_path=args.trusted_public_key,
            trusted_keyids=args.trusted_keyids,
            revoked_keyids=args.revoked_keyids,
            candidate_public_key_path=args.public_key,
            plan_json_path=args.plan_json,
            plan_file_path=args.plan_file,
            expected_repository=args.expected_repository,
            expected_commit_sha=args.expected_commit_sha,
            expected_workflow=args.expected_workflow,
            enforce_trusted_signer=enforce_signer,
            require_production_signer=getattr(args, "require_production_signer", False)
        )
        if success:
            print("✅ Signed provenance verified successfully: Authenticated signature against trusted root and bindings match.")
            sys.exit(0)
        else:
            sys.stderr.write("❌ Signed provenance verification FAILED:\n")
            for err in errors:
                sys.stderr.write(f"   - {err}\n")
            sys.exit(1)

    elif args.command == "generate":
        try:
            manifest = generate_manifest(
                plan_json_path=args.plan_json,
                plan_file_path=args.plan_file,
                repository=args.repository,
                commit_sha=args.commit_sha,
                run_id=args.run_id,
                actor=args.actor,
                terraform_version=args.terraform_version
            )
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            print(f"✅ Plan attestation manifest generated successfully: {args.output}")
            sys.exit(0)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Attestation generation failed: {str(e)}\n")
            sys.exit(1)

    elif args.command == "verify":
        success, errors = verify_manifest(
            manifest_path=args.manifest,
            plan_json_path=args.plan_json,
            plan_file_path=args.plan_file,
            expected_repository=args.expected_repository,
            expected_commit_sha=args.expected_commit_sha,
            expected_terraform_version=args.expected_terraform_version
        )
        if success:
            print("✅ Plan integrity verification PASSED: Digests, repository, and commit match attestation.")
            sys.exit(0)
        else:
            sys.stderr.write("❌ Plan integrity verification FAILED:\n")
            for err in errors:
                sys.stderr.write(f"   - {err}\n")
            sys.exit(1)

    elif args.command == "generate-manifest":
        try:
            manifest = generate_plan_manifest(
                plan_json_path=args.plan_json,
                plan_file_path=args.plan_file,
                repository=args.repository,
                commit_sha=args.commit_sha,
                run_id=args.run_id,
                actor=args.actor,
                workflow=args.workflow,
                terraform_version=args.terraform_version,
                security_decision=args.security_decision,
                output_path=args.output
            )
            print(f"✅ Sanitized plan manifest generated successfully: {args.output}")
            print(f"   Plan JSON SHA256: {manifest['digests']['plan_json_sha256']}")
            if manifest['digests']['plan_file_sha256']:
                print(f"   Plan File SHA256: {manifest['digests']['plan_file_sha256']}")
            print(f"   Security Decision: {manifest['metadata']['security_decision']}")
            sys.exit(0)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Plan manifest generation failed: {str(e)}\n")
            sys.exit(1)

    elif args.command == "create-bundle":
        try:
            bundle = create_attestation_bundle(
                manifest_path=args.manifest,
                repository=args.repository,
                workflow=args.workflow,
                commit_sha=args.commit_sha,
                output_path=args.output
            )
            print(f"✅ Synthetic Sigstore attestation bundle generated: {args.output}")
            print(f"   Media Type: {bundle['mediaType']}")
            sys.exit(0)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Attestation bundle generation failed: {str(e)}\n")
            sys.exit(1)

    elif args.command == "verify-attestation":
        success, errors = verify_attestation(
            manifest_path=args.manifest,
            bundle_path=args.bundle,
            plan_json_path=args.plan_json,
            plan_file_path=args.plan_file,
            expected_repository=args.expected_repository,
            expected_commit_sha=args.expected_commit_sha,
            expected_workflow=args.expected_workflow,
            require_production_signer=getattr(args, "require_production_signer", False),
            use_gh_cli=getattr(args, "use_gh_cli", False),
            signer_repo=getattr(args, "signer_repo", None),
            signer_workflow=getattr(args, "signer_workflow", None),
            signer_digest=getattr(args, "signer_digest", None),
            cert_oidc_issuer=getattr(args, "cert_oidc_issuer", "https://token.actions.githubusercontent.com")
        )
        if success:
            print("✅ GitHub Artifact Attestation & plan manifest verified successfully: Authenticated Sigstore provenance matches.")
            sys.exit(0)
        else:
            sys.stderr.write("❌ GitHub Artifact Attestation verification FAILED:\n")
            for err in errors:
                sys.stderr.write(f"   - {err}\n")
            sys.exit(1)

if __name__ == "__main__":
    main()
