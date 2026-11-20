# InfraFlow Plan Envelope Encryption & Cryptographic Architecture

**Document ID:** `INFRAFLOW-SEC-G06-001`  
**Milestone:** G06.1 — Protected Apply & Destroy (Cryptographic Foundation)  
**Classification:** Security Architecture & Cryptographic Specification  
**Author:** Senior DevSecOps Engineer & Cloud Security Architect  
**Status:** IMPLEMENTED (Offline Baseline)  
**Budget Consumed:** $0.00 (Zero Cloud Spending Invariant Strictly Preserved)

---

## 1. Executive Summary

In public GitHub repositories, standard workflow artifacts uploaded via `actions/upload-artifact` are accessible to anyone with repository read access. Raw Terraform binary execution plans (`tfplan`) frequently contain plaintext secrets—including database master passwords, initial API credentials, private certificates, and full network resource mappings.

To resolve this critical information disclosure risk (`SEC-07`) while enabling exact-plan execution (`terraform apply <tfplan>`) in **Milestone G06**, InfraFlow introduces a client-side **Plan Envelope Encryption Engine** (`scripts/kms-envelope.py`).

The engine utilizes industry-standard **AES-256-GCM** authenticated envelope encryption, wrapping ephemeral Data Encryption Keys (DEKs) with Key Encryption Keys (KEKs) and cryptographically binding execution context into Authenticated Additional Data (AAD).

---

## 2. Cryptographic Architecture

```
                    PLAN ENVELOPE ENCRYPTION ARCHITECTURE
                    
  [Plaintext Binary Plan] ────► SHA-256 ────► plan_digest (e.g. 5a1b...)
            │                                       │
            ▼                                       ▼
  ┌───────────────────┐                   ┌─────────────────────────────┐
  │ AES-256-GCM       │◄──── fresh DEK ───│ KEK (Master Key)            │
  │ Encryption        │     (256 bits)    │ - Mock KMS (G06.1 Offline)  │
  │                   │                   │ - AWS KMS (Future Stage)    │
  │ Nonce (96 bits)   │                   └──────────────┬──────────────┘
  │                   │                                  │
  │ AAD Context       │                           kms:GenerateDataKey
  │ - repo            │                                  │
  │ - commit_sha      │                                  ▼
  │ - workflow        │                           ┌──────────────┐
  │ - environment     │                           │ wrapped_dek  │
  │ - plan_id         │                           │ (Ciphertext) │
  │ - plan_digest     │                           └──────────────┘
  └─────────┬─────────┘                                  │
            │                                            │
            ▼                                            │
  ┌──────────────────────────────────────────────────────┴─────────────┐
  │                 PLAN ENVELOPE (JSON BUNDLE)                         │
  │ - schema_version: "infraflow-plan-envelope-v1"                     │
  │ - algorithm: "AES-256-GCM"                                         │
  │ - key_provider: "mock-kms"                                         │
  │ - key_id: "mock-kms-kek-1"                                         │
  │ - wrapped_dek: "<base64>"                                          │
  │ - wrapped_dek_nonce: "<base64>"                                    │
  │ - nonce: "<base64>"                                                │
  │ - plan_digest: "5a1b..."                                           │
  │ - plan_size_bytes: 142050                                          │
  │ - aad: { ... context ... }                                         │
  │ - ciphertext: "<base64 payload + 16-byte auth tag>"                │
  └────────────────────────────────────────────────────────────────────┘
```

### 2.1 Cryptographic Primitives
InfraFlow strictly uses established, NIST-approved cryptographic primitives provided by the Python `cryptography` library (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`). No custom encryption algorithms are designed or implemented.

- **Payload Cipher:** AES-GCM (Galois/Counter Mode) with 256-bit key length.
- **Data Encryption Key (DEK):** Fresh 256-bit cryptographically secure pseudorandom key (`os.urandom(32)`) generated per individual plan file. Never reused across multiple plans.
- **Nonce / IV:** 96-bit (12-byte) cryptographically secure pseudorandom initialization vector (`os.urandom(12)`) generated per AES-GCM encryption operation.
- **Authentication Tag:** 128-bit (16-byte) GHASH authentication tag appended to the ciphertext, verifying payload integrity and authenticity.
- **Plan Digest:** SHA-256 cryptographic hash of the original unencrypted binary plan bytes.

### 2.2 Canonical Authenticated Additional Data (AAD)
AES-GCM supports Authenticated Additional Data (AAD) that is authenticated by the GMAC tag without being encrypted. InfraFlow embeds operational context directly into the AAD:
- `schema_version`: Identifies envelope specification (`"infraflow-plan-envelope-v1"`).
- `repository`: Caller repository identity (`$GITHUB_REPOSITORY`).
- `commit_sha`: Git commit SHA for which the plan was evaluated (`$GITHUB_SHA`).
- `workflow`: Workflow identity reference (`$GITHUB_WORKFLOW_REF`).
- `environment`: Target deployment environment name (e.g. `production`).
- `plan_identifier`: Unique execution plan identifier.
- `plan_digest`: Original binary plan SHA-256 digest.

**Deterministic Canonicalization:**  
To prevent cross-platform serialization mismatches, the AAD dictionary is serialized using RFC 8785-inspired canonical JSON: keys sorted lexicographically, no whitespace between tokens (`separators=(',', ':')`), and UTF-8 encoding. Any tampering with AAD fields in the envelope causes AES-GCM decryption to fail immediately with `InvalidTag`.

---

## 3. Envelope Schema Specification (`infraflow-plan-envelope-v1`)

The encrypted plan envelope is serialized as a single, self-describing JSON file:

```json
{
  "schema_version": "infraflow-plan-envelope-v1",
  "algorithm": "AES-256-GCM",
  "key_provider": "mock-kms",
  "key_id": "mock-kms-kek-1",
  "wrapped_dek": "base64-encoded-wrapped-dek",
  "wrapped_dek_nonce": "base64-encoded-96-bit-wrap-nonce",
  "nonce": "base64-encoded-96-bit-plan-nonce",
  "plan_digest": "484b067aa500d5523d1bccc06ce111cfe736a8af000000000000000000000000",
  "plan_size_bytes": 1048576,
  "created_at": "2026-11-20T10:45:00.000000+00:00",
  "aad": {
    "commit_sha": "d0660de837ca07d5bdd56f04b0e50691ce98bd28",
    "environment": "production",
    "plan_digest": "484b067aa500d5523d1bccc06ce111cfe736a8af000000000000000000000000",
    "plan_identifier": "plan-484b067a-1795171500",
    "repository": "TM-threemavithana/infraflow-consumer-test",
    "schema_version": "infraflow-plan-envelope-v1",
    "workflow": ".github/workflows/reusable-tf-plan.yml"
  },
  "ciphertext": "base64-encoded-ciphertext-plus-16-byte-auth-tag"
}
```

---

## 4. Offline Mock KMS Simulator & AWS KMS Future Contract

### 4.1 Mock KMS Simulator Purpose & Scope
Milestone G06.1 is developed under a strict **$0.00 cloud spending invariant** without AWS credentials. To enable comprehensive automated testing without live AWS accounts:
- `MockKMSClient` simulates the conceptual behavior of AWS KMS Key Management Service.
- It models the two core AWS KMS cryptographic APIs:
  1. `GenerateDataKey(KeyId, EncryptionContext)`: Generates a 256-bit plaintext DEK and wraps it using local AES-256-GCM with a simulated Key Encryption Key (KEK).
  2. `Decrypt(CiphertextBlob, EncryptionContext)`: Unwraps the DEK, cryptographically enforcing that the encryption context matches the context supplied during generation.
- **Security Boundaries:**
  - `MockKMSClient` is explicitly labeled `[MOCK KMS ONLY]`.
  - Locally wrapped keys are **not** interchangeable with real AWS KMS ciphertexts.
  - The simulator never transmits data over networks and stores temporary keys in memory or ephemeral test files (mode `0600`).

### 4.2 Future AWS KMS & Private S3 Integration Contract
When transitioning to live cloud execution (Milestone G06.3+), `kms-envelope.py` is architected to seamlessly interface with AWS KMS via a decoupled provider adapter:
1. `key_provider: "aws-kms"` replaces `"mock-kms"`.
2. `kms.generate_data_key()` invokes AWS STS-authenticated KMS endpoint via `boto3`.
3. Encrypted plan bundles (`tfplan.enc.json`) are uploaded directly to a private, non-public Amazon S3 bucket (`s3://<caller>-infraflow-plans/<plan_id>.enc.json`) with SSE-KMS bucket policies, completely bypassing public GitHub Artifact storage.
4. Downstream apply jobs fetch the encrypted bundle using IAM credentials, decrypt via KMS, and apply.

---

## 5. Artifact & Key Lifecycle

1. **Key Generation:**
   - DEKs are ephemeral, generated in memory via CSPRNG (`os.urandom(32)`), used once to encrypt the plan, and promptly deleted from Python scope (`del plaintext_dek`).
   - Mock KEKs are generated via `kms-envelope.py generate-kek --output-kek <path>` with POSIX permissions `0600`.
2. **Atomic File Operations:**
   - All file writes utilize `safe_write_file`, writing to temporary files (`tempfile.mkstemp`) with mode `0600` before atomic replacement (`os.replace`).
   - On unhandled exceptions or cryptographic failures, temporary files are immediately removed via exception handlers.
3. **Artifact Cleanup:**
   - Raw binary plans remain strictly ephemeral. Decrypted plan files must be purged immediately following `terraform apply` via exit traps.
4. **Memory Hygiene Reality:**
   - In Python (CPython), immutable strings and byte sequences cannot be guaranteed zeroized in memory due to garbage collection and memory pooling. While variables are explicitly deleted (`del`) and garbage collected, InfraFlow transparently discloses that operating-system level memory dumps could theoretically inspect ephemeral keys prior to process termination.

---

## 6. Threat Model & Security Posture (STRIDE)

| Threat Category | Potential Attack Vector | Engine Defense Mechanism |
| :--- | :--- | :--- |
| **Information Disclosure** | Plaintext plan leaked in GitHub Artifacts or logs. | Plans are encrypted with AES-256-GCM before exiting runner; raw plans purged; zero plaintext output on stdout/stderr. |
| **Tampering** | Attacker modifies ciphertext or wraps altered binary. | AES-GCM GHASH tag verification fails (`InvalidTag`); SHA-256 plan digest comparison fails closed. |
| **Context Substitution** | Attacker takes an approved plan from staging and applies it in production. | AAD binds `environment` and `repository`; decrypting with `--expected-environment production` fails closed. |
| **Key Compromise** | Unauthorized caller attempts to unwrap DEK. | Decryption requires access to the authoritative KEK (or KMS IAM permissions); wrong keys fail closed. |
| **Algorithm Degradation** | Attacker modifies envelope header to specify weak/no cipher. | Strict validation: `algorithm` must be exactly `"AES-256-GCM"`; all other algorithms rejected. |
| **Schema Hijacking** | Attacker supplies arbitrary JSON to confuse parser. | Strict schema version validation (`"infraflow-plan-envelope-v1"`) and type checking. |

---

## 7. Operational Truth & Known Limitations

> [!IMPORTANT]
> **Operational Truth Disclosures:**
> 1. **Mocks are Not Proof of Cloud Functionality:** Local execution against `MockKMSClient` proves cryptographic algorithms, digest binding, and input parsing. It does **not** prove that AWS KMS IAM policies, KMS Key policies, or S3 bucket ACLs are properly configured.
> 2. **Apply Execution Deferred:** Milestone G06.1 delivers the cryptographic tooling only. It does not execute `terraform apply` or modify infrastructure.
> 3. **Lifecycle & Replay Integration (G06.2 Implemented):** In Milestone G06.2, envelope verification is formally bound to plan expiration (12h TTL), state consistency (lineage/serial checks), and transactional replay prevention via `scripts/verify-plan-lifecycle.py`. For complete architectural specifications, see [G06-PLAN-LIFECYCLE.md](file:////wsl.localhost/Ubuntu/home/tharuka/projects/infraflow/docs/security/G06-PLAN-LIFECYCLE.md).
