"""
InfraFlow Platform — Distributed State Locking & Concurrency Engine
Milestone: G10.4.2 — Core Locking Engine & LocalFS Driver

Provides:
- DistributedLockDriver: Pure worker abstract base class (zero force-break capabilities).
- LockDescriptor, LeaseState, LockRecord, LockResult, LockHandle.
- derive_canonical_lock_identity(): Deterministic backend-bound canonical key derivation.
- validate_lock_metadata(): Schema integrity and secret-leakage defense.
- LocalFSDriver: Single-host filesystem lock driver with durable atomic fencing tokens (POSIX flock).
- MockDistributedDriver: In-memory simulation driver for adversarial network/concurrency testing.
- LockManager: High-level lifecycle coordinator with background heartbeat and fast-fail abort.
- Full exception taxonomy: LockError, LockAcquisitionError, LockHeldError, etc.

SECURITY INVARIANTS:
1. Stale owners CANNOT release newer locks (verified by lock_id, fencing_token, and generation).
2. Fencing tokens are durable and monotonically increasing (never reset on release or restart).
3. Concurrent acquisition races fail-closed for losing claimants.
4. Expired ownership is rejected upon renewal or release.
5. Zero secrets in metadata: raises SecurityViolationError if credentials detected.
6. Fail-closed on uncertain ownership or corrupted storage.
7. Preserves native Terraform state locking (orthogonal platform layer).
8. Force-unlock is strictly excluded from worker driver interfaces.
9. LocalFS explicitly disclaims multi-host distributed guarantees.
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union
import uuid

# Platform & schema constants
LOCK_SCHEMA_VERSION = "infraflow-lock-metadata-v1"
DEFAULT_LOCK_TTL_SECONDS = 900          # 15 minutes
MAX_LOCK_TTL_SECONDS = 3600              # 1 hour absolute max for a single acquisition
MIN_LOCK_TTL_SECONDS = 5                 # 5 seconds minimum
DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 60 # 60 seconds tolerance
DEFAULT_NETWORK_RTT_TOLERANCE_SECONDS = 30 # 30 seconds network buffer
DEFAULT_HEARTBEAT_RATIO = 1.0 / 3.0      # Renew at 1/3 of TTL
DEFAULT_FAST_FAIL_RATIO = 2.0 / 3.0      # Abort/kill at 2/3 of TTL if unrenewed
MAX_RENEWALS_DEFAULT = 16                # Up to 4 hours max total lifetime

# Platform execution boundary notice
LOCALFS_LIMITATION_NOTICE = (
    "LocalFSDriver is strictly confined to a single host. "
    "It does NOT provide distributed multi-host synchronization and must "
    "never be used on shared network filesystems (NFS/SMB) due to cache inconsistencies."
)

# Cross-platform file locking support
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False


# ==============================================================================
# 1. Exception Taxonomy (conforming to Section 9 of G10 Locking Architecture)
# ==============================================================================

class LockError(Exception):
    """Base platform exception for all InfraFlow distributed locking errors."""
    pass


class LockAcquisitionError(LockError):
    """Raised when lock acquisition fails."""
    pass


class LockHeldError(LockAcquisitionError):
    """Lock is actively owned by another unexpired worker."""
    def __init__(self, message: str, holder_identity: Optional[Dict[str, Any]] = None, expires_at: Optional[str] = None):
        super().__init__(message)
        self.holder_identity = holder_identity or {}
        self.expires_at = expires_at


class ContentionTimeoutError(LockAcquisitionError):
    """Timeout waiting for lock contention to clear."""
    pass


class ResourceIdentityError(LockAcquisitionError):
    """Malformed canonical identity or path traversal detected in resource specification."""
    pass


class LockLostError(LockError):
    """Lock was lost during active execution or lease became invalid."""
    pass


class LeaseExpiredError(LockLostError):
    """Lease expired before renewal or release was processed."""
    pass


class StaleOwnerError(LockLostError):
    """Caller identity does not match active owner or newer lock has been granted."""
    pass


class StaleFencingTokenError(LockLostError):
    """Presented fencing token is less than storage high-water mark or active token."""
    pass


class LeaseGenerationMismatchError(LockLostError):
    """CAS generation mismatch during lease renewal or release."""
    pass


class LeaseRenewalError(LockError):
    """Failure during lease renewal operation."""
    pass


class HeartbeatTimeoutError(LeaseRenewalError):
    """Heartbeat daemon failed to contact storage backend before safety threshold."""
    pass


class MaxRenewalsExceededError(LeaseRenewalError):
    """Lease exceeded maximum permissible cumulative lifetime renewals."""
    pass


class ClockSkewExceededError(LockError):
    """Clock drift between client and storage backend exceeds permissible tolerance."""
    pass


class UncertainOutcomeError(LockError):
    """Operation resulted in uncertain state due to network timeout or IO partition."""
    pass


class AdministrativeOverrideError(LockError):
    """Lock was terminated by privileged administrative recovery service."""
    pass


class SecurityViolationError(LockError):
    """Security violation detected: hardcoded credential in metadata, traversal, or symlink attack."""
    pass


# ==============================================================================
# 2. Secret Scanning & Sensitive Data Sanitization
# ==============================================================================

SENSITIVE_PATTERNS = [
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID"),
    # AWS Secret Key (approximate base64 / 40 chars)
    (re.compile(r"(?i)(secret[_-]?key|aws[_-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "AWS Secret Key"),
    # GitHub Personal Access Token / Fine-grained token
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub Personal Access Token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub Fine-Grained Token"),
    # Generic JWT
    (re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"), "JWT Bearer Token"),
    # Private Key blocks
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "Private Key Block"),
    # Generic Password / Secret assignments
    (re.compile(r"(?i)(password|passwd|secret|api_key|auth_token)['\"]?\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"), "Credential / Password Assignment"),
]


def check_metadata_secrets(data: Any, path: str = "root") -> None:
    """
    Recursively scans lock metadata structures for hardcoded credentials.
    Fails closed with SecurityViolationError if any credential pattern is matched.
    """
    if isinstance(data, str):
        for pattern, name in SENSITIVE_PATTERNS:
            if pattern.search(data):
                raise SecurityViolationError(
                    f"Credential detected in lock metadata at '{path}': potential exposed {name}. "
                    "Lock metadata must never store live secrets or tokens."
                )
    elif isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k).lower()
            if any(s in k_str for s in ("password", "passwd", "secret", "private_key", "api_key", "auth_token")):
                if isinstance(v, str) and len(v.strip()) > 0 and not v.startswith("[REDACTED"):
                    raise SecurityViolationError(
                        f"Credential detected in lock metadata key '{path}.{k}'. "
                        "Secret keys and passwords must never be stored in lock descriptors."
                    )
            check_metadata_secrets(v, f"{path}.{k}")
    elif isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            check_metadata_secrets(item, f"{path}[{idx}]")


# ==============================================================================
# 3. Canonical Identity & Helper Functions
# ==============================================================================

def parse_iso_utc(ts: str) -> datetime:
    """Parses ISO 8601 UTC timestamp string safely across Python 3.10-3.12."""
    if not ts or not isinstance(ts, str):
        raise ValueError("Timestamp must be a non-empty string.")
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_iso_utc(dt: datetime) -> str:
    """Formats datetime to canonical ISO 8601 UTC string ending in 'Z'."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def derive_canonical_lock_identity(
    backend_type: str,
    storage_location: str,
    account_or_project: str,
    state_key: str,
    workspace: str = "default",
    tenant_id: Optional[str] = None,
    repository: Optional[str] = None,
    environment: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Derives canonical hierarchical lock key and deterministic SHA-256 fingerprint
    bound to the actual Terraform state backend target (Section 4 of G10-DISTRIBUTED-LOCKING-ARCHITECTURE).

    Returns:
        (canonical_key, resource_fingerprint)
    """
    # Guard against empty, traversal, or control characters
    for name, part in (
        ("backend_type", backend_type),
        ("storage_location", storage_location),
        ("account_or_project", account_or_project),
        ("state_key", state_key),
        ("workspace", workspace),
    ):
        if not part or not isinstance(part, str) or not part.strip():
            raise ResourceIdentityError(f"Lock identity part '{name}' must be a non-empty string.")
        if ".." in part or part.startswith("/") or part.startswith("\\") or "\x00" in part or "\n" in part:
            raise ResourceIdentityError(f"Invalid characters or traversal in lock identity part '{name}': '{part}'")

    b_type = backend_type.strip().lower()
    loc = storage_location.strip()
    acct = account_or_project.strip().lower()
    s_key = state_key.strip().lstrip("/").replace("\\", "/")
    ws = workspace.strip().lower()

    canonical_key = f"infraflow/locks/v1/{b_type}/{acct}/{loc}/{s_key}/{ws}.lock"
    fingerprint = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()
    return canonical_key, fingerprint


def compute_payload_sha256(descriptor_dict: Dict[str, Any], lease_dict: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 integrity checksum over canonical JSON payload."""
    canonical = {
        "descriptor": descriptor_dict,
        "lease": lease_dict,
    }
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ==============================================================================
# 4. Data Models: Descriptor, LeaseState, LockRecord, LockResult
# ==============================================================================

@dataclass(frozen=True)
class LockDescriptor:
    """Immutable identity and execution context established at lock acquisition."""
    lock_id: str
    canonical_key: str
    resource_fingerprint: str
    backend_target: Dict[str, str]
    owner_identity: Dict[str, Any]
    purpose: str
    created_at: str
    plan_binding: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "lock_id": self.lock_id,
            "canonical_key": self.canonical_key,
            "resource_fingerprint": self.resource_fingerprint,
            "backend_target": dict(self.backend_target),
            "owner_identity": dict(self.owner_identity),
            "purpose": self.purpose,
            "created_at": self.created_at,
        }
        if self.plan_binding:
            d["plan_binding"] = dict(self.plan_binding)
        return d


@dataclass(frozen=True)
class LeaseState:
    """Mutable lease progression updated on each heartbeat via Compare-And-Swap."""
    fencing_token: int
    lease_generation: int
    lease_duration_seconds: int
    acquired_at: str
    expires_at: str
    renewed_at: Optional[str] = None
    renewal_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "fencing_token": self.fencing_token,
            "lease_generation": self.lease_generation,
            "lease_duration_seconds": self.lease_duration_seconds,
            "acquired_at": self.acquired_at,
            "expires_at": self.expires_at,
            "renewal_count": self.renewal_count,
        }
        if self.renewed_at:
            d["renewed_at"] = self.renewed_at
        return d


@dataclass(frozen=True)
class LockRecord:
    """Complete serialized lock record matching schema infraflow-lock-metadata-v1."""
    descriptor: LockDescriptor
    lease: LeaseState
    payload_sha256: str
    storage_generation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "$schema": "https://infraflow.dev/schemas/v1/lock-metadata.json",
            "schema_version": LOCK_SCHEMA_VERSION,
            "descriptor": self.descriptor.to_dict(),
            "lease": self.lease.to_dict(),
            "integrity": {
                "payload_sha256": self.payload_sha256,
                "storage_generation": self.storage_generation,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LockRecord":
        validate_lock_metadata(data)
        desc_raw = data["descriptor"]
        lease_raw = data["lease"]
        integrity_raw = data["integrity"]

        descriptor = LockDescriptor(
            lock_id=desc_raw["lock_id"],
            canonical_key=desc_raw["canonical_key"],
            resource_fingerprint=desc_raw["resource_fingerprint"],
            backend_target=desc_raw["backend_target"],
            owner_identity=desc_raw["owner_identity"],
            purpose=desc_raw["purpose"],
            created_at=desc_raw["created_at"],
            plan_binding=desc_raw.get("plan_binding"),
        )
        lease = LeaseState(
            fencing_token=int(lease_raw["fencing_token"]),
            lease_generation=int(lease_raw["lease_generation"]),
            lease_duration_seconds=int(lease_raw["lease_duration_seconds"]),
            acquired_at=lease_raw["acquired_at"],
            expires_at=lease_raw["expires_at"],
            renewed_at=lease_raw.get("renewed_at"),
            renewal_count=int(lease_raw.get("renewal_count", 0)),
        )
        return cls(
            descriptor=descriptor,
            lease=lease,
            payload_sha256=integrity_raw["payload_sha256"],
            storage_generation=integrity_raw.get("storage_generation", "gen-0"),
        )

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Determines if the active lease expiration timestamp has elapsed."""
        now = current_time or datetime.now(timezone.utc)
        expires_dt = parse_iso_utc(self.lease.expires_at)
        return now >= expires_dt


@dataclass(frozen=True)
class LockResult:
    """Result envelope returned by lock driver operations."""
    success: bool
    record: Optional[LockRecord] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


def validate_lock_metadata(data: Dict[str, Any]) -> None:
    """
    Validates dictionary against infraflow-lock-metadata-v1 schema.
    Verifies payload SHA-256 integrity checksum and scans for credentials.
    """
    if not isinstance(data, dict):
        raise LockError("Lock metadata must be a JSON dictionary.")

    schema_version = data.get("schema_version")
    if schema_version != LOCK_SCHEMA_VERSION:
        raise LockError(f"Unsupported schema_version: '{schema_version}' (expected '{LOCK_SCHEMA_VERSION}')")

    for section in ("descriptor", "lease", "integrity"):
        if section not in data or not isinstance(data[section], dict):
            raise LockError(f"Missing or malformed lock metadata section: '{section}'")

    desc = data["descriptor"]
    for field_name in ("lock_id", "canonical_key", "resource_fingerprint", "backend_target", "owner_identity", "purpose", "created_at"):
        if field_name not in desc:
            raise LockError(f"Missing required descriptor field: '{field_name}'")

    lease = data["lease"]
    for field_name in ("fencing_token", "lease_generation", "lease_duration_seconds", "acquired_at", "expires_at"):
        if field_name not in lease:
            raise LockError(f"Missing required lease field: '{field_name}'")

    if not isinstance(lease["fencing_token"], int) or lease["fencing_token"] < 1:
        raise LockError(f"fencing_token must be a positive integer, got: {lease.get('fencing_token')}")

    if not isinstance(lease["lease_generation"], int) or lease["lease_generation"] < 1:
        raise LockError(f"lease_generation must be a positive integer, got: {lease.get('lease_generation')}")

    # Check for hardcoded credentials / secrets
    check_metadata_secrets(data)

    # Validate integrity checksum
    expected_sha256 = compute_payload_sha256(desc, lease)
    recorded_sha256 = data["integrity"].get("payload_sha256")
    if recorded_sha256 != expected_sha256:
        raise LockError(
            f"Integrity checksum mismatch in lock metadata: expected {expected_sha256}, got {recorded_sha256}"
        )


# ==============================================================================
# 5. Pure Worker Driver Interface (DistributedLockDriver)
# ==============================================================================

class DistributedLockDriver(ABC):
    """
    Pure worker driver interface for distributed lock backends (Section 8.1).
    Guarantees atomic Compare-And-Swap (CAS) semantics.
    CRITICAL: force-break / force-unlock is strictly excluded from this interface.
    """

    @abstractmethod
    def acquire(
        self,
        key: str,
        owner_identity: Dict[str, Any],
        ttl_seconds: int,
        purpose: str,
        backend_target: Optional[Dict[str, str]] = None,
        plan_binding: Optional[Dict[str, str]] = None,
        idempotency_token: Optional[str] = None,
        lock_id: Optional[str] = None,
    ) -> LockResult:
        """
        Atomically attempts to acquire the lock.
        Succeeds if key is UNLOCKED or if current lease is EXPIRED.
        Increments durable high-water mark fencing token on new lease grant.
        Idempotent if called with matching (key, lock_id, owner_id).
        """
        pass

    @abstractmethod
    def renew(
        self,
        key: str,
        lock_id: str,
        owner_id: str,
        fencing_token: int,
        lease_generation: int,
        extension_seconds: int,
    ) -> LockResult:
        """
        Atomically extends the lease expiration if and only if:
        key == key AND lock_id == lock_id AND fencing_token == token AND generation == gen.
        Increments lease_generation on success.
        Fails if lock was lost, expired, or claimed by another owner.
        """
        pass

    @abstractmethod
    def release(
        self,
        key: str,
        lock_id: str,
        owner_id: str,
        fencing_token: int,
        lease_generation: int,
    ) -> LockResult:
        """
        Atomically releases the lock if and only if caller matches active ownership.
        Fails closed if caller is stale, fencing token is outdated, or lease expired.
        """
        pass

    @abstractmethod
    def inspect(self, key: str) -> Optional[LockRecord]:
        """
        Read-only inspection of active lock record.
        Returns LockRecord if currently held or expired, or None if unlocked.
        """
        pass

    @abstractmethod
    def get_high_water_mark(self, key: str) -> int:
        """
        Returns the durable high-water mark counter for the given canonical key.
        The counter survives lock releases and reboots.
        """
        pass


# ==============================================================================
# 6. LocalFS Driver (LocalFSDriver)
# ==============================================================================

class LocalFSDriver(DistributedLockDriver):
    """
    Local filesystem distributed lock driver for developer workstations and single-host CI.
    Uses atomic file replacement (os.replace) and OS-level file locking (fcntl.flock).
    Maintains a durable .hwm sequence file that survives lock releases.

    LIMITATION: Confined to a single host. Does NOT provide multi-host distributed guarantees.
    """
    LIMITATION_NOTICE = LOCALFS_LIMITATION_NOTICE

    def __init__(
        self,
        base_dir: Union[str, Path],
        clock_fn: Optional[Callable[[], datetime]] = None,
    ):
        self._base_dir = Path(base_dir).resolve()
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._clock_fn = clock_fn or (lambda: datetime.now(timezone.utc))
        self._thread_lock = threading.RLock()
        self._release_idempotency_cache: Dict[Tuple[str, int], float] = {}

    def _resolve_key_path(self, key_or_fingerprint: str, suffix: str) -> Path:
        """Resolves target file path within base_dir, guarding against symlinks and traversal."""
        if not key_or_fingerprint or not isinstance(key_or_fingerprint, str):
            raise ResourceIdentityError("Key/fingerprint must be a non-empty string.")
        if ".." in key_or_fingerprint or "\x00" in key_or_fingerprint:
            raise ResourceIdentityError(f"Invalid characters or traversal in key/fingerprint: '{key_or_fingerprint}'")

        if len(key_or_fingerprint) == 64 and all(c in "0123456789abcdefABCDEF" for c in key_or_fingerprint):
            fp = key_or_fingerprint.lower()
        else:
            fp = hashlib.sha256(key_or_fingerprint.encode("utf-8")).hexdigest()

        target_path = (self._base_dir / f"{fp}.{suffix}").resolve()
        try:
            target_path.relative_to(self._base_dir.resolve())
        except ValueError:
            raise SecurityViolationError(f"Path traversal detected: {target_path} is outside {self._base_dir}")

        if target_path.is_symlink():
            real_target = target_path.resolve()
            try:
                real_target.relative_to(self._base_dir.resolve())
            except ValueError:
                raise SecurityViolationError(f"Symlink attack detected: {target_path} points outside base directory")

        return target_path

    @contextmanager
    def _acquire_mutex(self, fingerprint: str) -> Generator[Any, None, None]:
        """Process-level and thread-level mutual exclusion context."""
        with self._thread_lock:
            mutex_path = self._resolve_key_path(fingerprint, "mutex")
            f = open(mutex_path, "a+b")
            try:
                if HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                elif HAS_MSVCRT:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                yield f
            finally:
                try:
                    if HAS_FCNTL:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    elif HAS_MSVCRT:
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
                finally:
                    f.close()

    def _read_hwm(self, fingerprint: str) -> int:
        """Reads the durable high-water mark token counter from storage."""
        hwm_path = self._resolve_key_path(fingerprint, "hwm")
        if not hwm_path.exists():
            return 0
        try:
            text = hwm_path.read_text(encoding="utf-8").strip()
            return int(text) if text else 0
        except Exception as e:
            raise LockError(f"Corrupted high-water mark file '{hwm_path}': {e}") from e

    def _write_hwm(self, fingerprint: str, token: int) -> None:
        """Persists the durable high-water mark token atomically."""
        hwm_path = self._resolve_key_path(fingerprint, "hwm")
        tmp_path = hwm_path.with_suffix(f".tmp.{uuid.uuid4().hex[:6]}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(str(token))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, hwm_path)

    def _validate_key(self, key: str) -> str:
        """Validates key against traversal and returns deterministic fingerprint."""
        if not key or not isinstance(key, str) or not key.strip():
            raise ResourceIdentityError("Key must be a non-empty string.")
        if ".." in key or "\x00" in key:
            raise ResourceIdentityError(f"Path traversal or invalid characters in key: '{key}'")
        if len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
            return key.lower()
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def get_high_water_mark(self, key: str) -> int:
        fp = self._validate_key(key)
        with self._acquire_mutex(fp):
            return self._read_hwm(fp)

    def acquire(
        self,
        key: str,
        owner_identity: Dict[str, Any],
        ttl_seconds: int,
        purpose: str,
        backend_target: Optional[Dict[str, str]] = None,
        plan_binding: Optional[Dict[str, str]] = None,
        idempotency_token: Optional[str] = None,
        lock_id: Optional[str] = None,
    ) -> LockResult:
        if ttl_seconds <= 0 or ttl_seconds > MAX_LOCK_TTL_SECONDS:
            raise LockAcquisitionError(f"Invalid ttl_seconds {ttl_seconds}. Must be between 1 and {MAX_LOCK_TTL_SECONDS}.")

        fp = self._validate_key(key)

        # Check for credential leakage in caller-provided structures
        check_metadata_secrets(owner_identity, "owner_identity")
        if backend_target:
            check_metadata_secrets(backend_target, "backend_target")
        if plan_binding:
            check_metadata_secrets(plan_binding, "plan_binding")

        with self._acquire_mutex(fp):
            now = self._clock_fn()
            lock_path = self._resolve_key_path(fp, "lock.json")

            if lock_path.exists():
                try:
                    with open(lock_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    existing = LockRecord.from_dict(data)
                except Exception as e:
                    raise LockError(f"Failed to read existing lock record: {e}") from e

                # Idempotency check: same lock_id or idempotency_token
                caller_runner = owner_identity.get("runner_id") if isinstance(owner_identity, dict) else None
                existing_runner = existing.descriptor.owner_identity.get("runner_id") if isinstance(existing.descriptor.owner_identity, dict) else None

                if lock_id and existing.descriptor.lock_id == lock_id and (not caller_runner or caller_runner == existing_runner):
                    return LockResult(success=True, record=existing)

                if idempotency_token and existing.descriptor.owner_identity.get("idempotency_token") == idempotency_token:
                    return LockResult(success=True, record=existing)

                # Lease expiration check
                if not existing.is_expired(now):
                    return LockResult(
                        success=False,
                        record=existing,
                        error_code="LOCK_HELD",
                        error_message=f"Lock actively held by '{existing_runner}' until {existing.lease.expires_at} (fencing token: {existing.lease.fencing_token})",
                    )
                # If expired, we fall through to reclaim stale lock

            # Allocate strictly monotonic fencing token from durable HWM
            current_hwm = self._read_hwm(fp)
            new_token = current_hwm + 1
            self._write_hwm(fp, new_token)

            effective_lock_id = lock_id or str(uuid.uuid4())
            created_iso = format_iso_utc(now)
            expires_iso = format_iso_utc(now + timedelta(seconds=ttl_seconds))
            storage_gen = f"gen-{uuid.uuid4().hex[:8]}"

            b_target = backend_target or {
                "provider": "local",
                "storage_location": str(self._base_dir),
                "account_or_project": "local-workstation",
                "state_key": "terraform.tfstate",
                "workspace": "default",
            }

            desc = LockDescriptor(
                lock_id=effective_lock_id,
                canonical_key=key,
                resource_fingerprint=fp,
                backend_target=b_target,
                owner_identity=dict(owner_identity),
                purpose=purpose,
                created_at=created_iso,
                plan_binding=plan_binding,
            )
            lease = LeaseState(
                fencing_token=new_token,
                lease_generation=1,
                lease_duration_seconds=ttl_seconds,
                acquired_at=created_iso,
                expires_at=expires_iso,
                renewed_at=None,
                renewal_count=0,
            )
            payload_sha256 = compute_payload_sha256(desc.to_dict(), lease.to_dict())
            record = LockRecord(
                descriptor=desc,
                lease=lease,
                payload_sha256=payload_sha256,
                storage_generation=storage_gen,
            )

            # Validate generated metadata
            validate_lock_metadata(record.to_dict())

            # Write atomically via temp file + os.replace
            tmp_path = lock_path.with_suffix(f".tmp.{uuid.uuid4().hex[:6]}")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(record.to_dict(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, lock_path)

            return LockResult(success=True, record=record)

    def renew(
        self,
        key: str,
        lock_id: str,
        owner_id: str,
        fencing_token: int,
        lease_generation: int,
        extension_seconds: int,
    ) -> LockResult:
        if extension_seconds <= 0 or extension_seconds > MAX_LOCK_TTL_SECONDS:
            raise LeaseRenewalError(f"Invalid extension_seconds {extension_seconds}.")

        fp = self._validate_key(key)

        with self._acquire_mutex(fp):
            now = self._clock_fn()
            lock_path = self._resolve_key_path(fp, "lock.json")

            if not lock_path.exists():
                return LockResult(success=False, error_code="LOCK_NOT_FOUND", error_message="Lock does not exist.")

            try:
                with open(lock_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                record = LockRecord.from_dict(data)
            except Exception as e:
                raise LockError(f"Failed to read lock record during renewal: {e}") from e

            # Stale owner check
            if record.descriptor.lock_id != lock_id:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Presented lock_id '{lock_id}' does not match active lock '{record.descriptor.lock_id}'.",
                )

            # Stale fencing token check
            if record.lease.fencing_token != fencing_token:
                return LockResult(
                    success=False,
                    error_code="STALE_FENCING_TOKEN",
                    error_message=f"Presented fencing token {fencing_token} does not match active token {record.lease.fencing_token}.",
                )

            # Owner identity check
            record_owner = record.descriptor.owner_identity.get("runner_id") or record.descriptor.owner_identity.get("actor")
            if owner_id and record_owner and owner_id != record_owner:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Caller owner_id '{owner_id}' does not match active owner '{record_owner}'.",
                )

            # Idempotency check: renewal already processed
            if record.lease.lease_generation == lease_generation + 1 and record.lease.renewed_at:
                return LockResult(success=True, record=record)

            # Lease generation check
            if record.lease.lease_generation != lease_generation:
                return LockResult(
                    success=False,
                    error_code="LEASE_GENERATION_MISMATCH",
                    error_message=f"Presented generation {lease_generation} does not match current generation {record.lease.lease_generation}.",
                )

            # Expiration check: reject expired ownership
            if record.is_expired(now):
                return LockResult(
                    success=False,
                    error_code="LEASE_EXPIRED",
                    error_message=f"Lease has expired at {record.lease.expires_at} (current time: {format_iso_utc(now)}).",
                )

            # Maximum renewals check
            if record.lease.renewal_count >= MAX_RENEWALS_DEFAULT:
                return LockResult(
                    success=False,
                    error_code="MAX_RENEWALS_EXCEEDED",
                    error_message=f"Lease renewal limit exceeded ({record.lease.renewal_count} >= {MAX_RENEWALS_DEFAULT}).",
                )

            # Perform CAS update
            new_expires_dt = now + timedelta(seconds=extension_seconds)
            updated_lease = LeaseState(
                fencing_token=fencing_token,
                lease_generation=lease_generation + 1,
                lease_duration_seconds=extension_seconds,
                acquired_at=record.lease.acquired_at,
                expires_at=format_iso_utc(new_expires_dt),
                renewed_at=format_iso_utc(now),
                renewal_count=record.lease.renewal_count + 1,
            )
            storage_gen = f"gen-{uuid.uuid4().hex[:8]}"
            payload_sha256 = compute_payload_sha256(record.descriptor.to_dict(), updated_lease.to_dict())
            updated_record = LockRecord(
                descriptor=record.descriptor,
                lease=updated_lease,
                payload_sha256=payload_sha256,
                storage_generation=storage_gen,
            )

            tmp_path = lock_path.with_suffix(f".tmp.{uuid.uuid4().hex[:6]}")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(updated_record.to_dict(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, lock_path)

            return LockResult(success=True, record=updated_record)

    def release(
        self,
        key: str,
        lock_id: str,
        owner_id: str,
        fencing_token: int,
        lease_generation: int,
    ) -> LockResult:
        fp = self._validate_key(key)

        with self._acquire_mutex(fp):
            now = self._clock_fn()
            lock_path = self._resolve_key_path(fp, "lock.json")

            if not lock_path.exists():
                cache_key = (lock_id, fencing_token)
                if cache_key in self._release_idempotency_cache:
                    return LockResult(success=True)
                return LockResult(success=False, error_code="LOCK_NOT_FOUND", error_message="Lock does not exist.")

            try:
                with open(lock_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                record = LockRecord.from_dict(data)
            except Exception as e:
                raise LockError(f"Failed to read lock record during release: {e}") from e

            # Stale owner check: lock_id must match active lock
            if record.descriptor.lock_id != lock_id:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Cannot release lock: presented lock_id '{lock_id}' does not match active lock '{record.descriptor.lock_id}'.",
                )

            # Stale fencing token check
            if record.lease.fencing_token != fencing_token:
                return LockResult(
                    success=False,
                    error_code="STALE_FENCING_TOKEN",
                    error_message=f"Cannot release lock: presented fencing token {fencing_token} does not match active token {record.lease.fencing_token}.",
                )

            # Owner identity check
            record_owner = record.descriptor.owner_identity.get("runner_id") or record.descriptor.owner_identity.get("actor")
            if owner_id and record_owner and owner_id != record_owner:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Cannot release lock: caller owner_id '{owner_id}' does not match active owner '{record_owner}'.",
                )

            # Lease generation check
            if record.lease.lease_generation != lease_generation:
                return LockResult(
                    success=False,
                    error_code="LEASE_GENERATION_MISMATCH",
                    error_message=f"Cannot release lock: presented generation {lease_generation} does not match current generation {record.lease.lease_generation}.",
                )

            # Expiration check: reject expired ownership release
            if record.is_expired(now):
                return LockResult(
                    success=False,
                    error_code="LEASE_EXPIRED",
                    error_message=f"Cannot release lock: lease has already expired at {record.lease.expires_at} (current time: {format_iso_utc(now)}).",
                )

            # Successful release: delete lock file
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass

            # Record in idempotency cache
            self._release_idempotency_cache[(lock_id, fencing_token)] = now.timestamp()
            # CRITICAL: Do NOT delete the .hwm file! Fencing counter remains persistent.
            return LockResult(success=True)

    def inspect(self, key: str) -> Optional[LockRecord]:
        fp = self._validate_key(key)
        with self._acquire_mutex(fp):
            lock_path = self._resolve_key_path(fp, "lock.json")
            if not lock_path.exists():
                return None
            try:
                with open(lock_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return LockRecord.from_dict(data)
            except Exception as e:
                raise LockError(f"Failed to inspect lock record: {e}") from e


# ==============================================================================
# 7. Mock Distributed Driver (MockDistributedDriver)
# ==============================================================================

class MockDistributedDriver(DistributedLockDriver):
    """
    In-memory simulation driver for adversarial unit and integration testing (Section 11.2).
    Supports network partition simulation, clock skew, metadata corruption, and fault injection.
    """

    def __init__(self, clock_fn: Optional[Callable[[], datetime]] = None):
        self._locks: Dict[str, LockRecord] = {}
        self._hwm: Dict[str, int] = {}
        self._release_cache: Dict[Tuple[str, int], float] = {}
        self._clock_fn = clock_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._partition_enabled = False
        self._clock_skew_seconds = 0.0
        self._corrupted_keys: Set[str] = set()

    def simulate_partition(self, enabled: bool = True) -> None:
        """Enables or disables simulated network partition."""
        with self._lock:
            self._partition_enabled = enabled

    def inject_clock_skew(self, seconds: float) -> None:
        """Injects simulated clock drift on the storage backend."""
        with self._lock:
            self._clock_skew_seconds = seconds

    def inject_corrupted_metadata(self, key: str) -> None:
        """Injects corrupted metadata payload into target lock record."""
        with self._lock:
            self._corrupted_keys.add(key)

    def _now(self) -> datetime:
        base_now = self._clock_fn()
        if self._clock_skew_seconds != 0.0:
            return base_now + timedelta(seconds=self._clock_skew_seconds)
        return base_now

    def _validate_key(self, key: str) -> None:
        if not key or not isinstance(key, str) or not key.strip():
            raise ResourceIdentityError("Key must be a non-empty string.")
        if ".." in key or "\x00" in key:
            raise ResourceIdentityError(f"Path traversal or invalid characters in key: '{key}'")

    def get_high_water_mark(self, key: str) -> int:
        with self._lock:
            self._validate_key(key)
            if self._partition_enabled:
                raise UncertainOutcomeError("Network partition simulated: storage driver unreachable")
            return self._hwm.get(key, 0)

    def acquire(
        self,
        key: str,
        owner_identity: Dict[str, Any],
        ttl_seconds: int,
        purpose: str,
        backend_target: Optional[Dict[str, str]] = None,
        plan_binding: Optional[Dict[str, str]] = None,
        idempotency_token: Optional[str] = None,
        lock_id: Optional[str] = None,
    ) -> LockResult:
        with self._lock:
            self._validate_key(key)
            if self._partition_enabled:
                raise UncertainOutcomeError("Network partition simulated: acquire timed out")

            check_metadata_secrets(owner_identity, "owner_identity")
            if backend_target:
                check_metadata_secrets(backend_target, "backend_target")
            if plan_binding:
                check_metadata_secrets(plan_binding, "plan_binding")

            if key in self._corrupted_keys:
                raise LockError("Integrity checksum mismatch in lock metadata: storage corrupted")

            now = self._now()
            existing = self._locks.get(key)

            if existing is not None:
                caller_runner = owner_identity.get("runner_id") if isinstance(owner_identity, dict) else None
                existing_runner = existing.descriptor.owner_identity.get("runner_id") if isinstance(existing.descriptor.owner_identity, dict) else None

                # Idempotency check
                if lock_id and existing.descriptor.lock_id == lock_id and (not caller_runner or caller_runner == existing_runner):
                    return LockResult(success=True, record=existing)

                if idempotency_token and existing.descriptor.owner_identity.get("idempotency_token") == idempotency_token:
                    return LockResult(success=True, record=existing)

                if not existing.is_expired(now):
                    return LockResult(
                        success=False,
                        record=existing,
                        error_code="LOCK_HELD",
                        error_message=f"Lock actively held by '{existing_runner}' until {existing.lease.expires_at}",
                    )

            # Monotonic HWM allocation
            current_hwm = self._hwm.get(key, 0)
            new_token = current_hwm + 1
            self._hwm[key] = new_token

            effective_lock_id = lock_id or str(uuid.uuid4())
            created_iso = format_iso_utc(now)
            expires_iso = format_iso_utc(now + timedelta(seconds=ttl_seconds))
            storage_gen = f"gen-{uuid.uuid4().hex[:8]}"

            b_target = backend_target or {
                "provider": "mock",
                "storage_location": "memory",
                "account_or_project": "test-env",
                "state_key": "terraform.tfstate",
                "workspace": "default",
            }

            desc = LockDescriptor(
                lock_id=effective_lock_id,
                canonical_key=key,
                resource_fingerprint=hashlib.sha256(key.encode("utf-8")).hexdigest(),
                backend_target=b_target,
                owner_identity=dict(owner_identity),
                purpose=purpose,
                created_at=created_iso,
                plan_binding=plan_binding,
            )
            lease = LeaseState(
                fencing_token=new_token,
                lease_generation=1,
                lease_duration_seconds=ttl_seconds,
                acquired_at=created_iso,
                expires_at=expires_iso,
                renewed_at=None,
                renewal_count=0,
            )
            payload_sha256 = compute_payload_sha256(desc.to_dict(), lease.to_dict())
            record = LockRecord(
                descriptor=desc,
                lease=lease,
                payload_sha256=payload_sha256,
                storage_generation=storage_gen,
            )

            validate_lock_metadata(record.to_dict())
            self._locks[key] = record
            return LockResult(success=True, record=record)

    def renew(
        self,
        key: str,
        lock_id: str,
        owner_id: str,
        fencing_token: int,
        lease_generation: int,
        extension_seconds: int,
    ) -> LockResult:
        with self._lock:
            self._validate_key(key)
            if self._partition_enabled:
                raise UncertainOutcomeError("Network partition simulated: renewal timed out")

            if key in self._corrupted_keys:
                raise LockError("Integrity checksum mismatch in lock metadata: storage corrupted")

            now = self._now()
            record = self._locks.get(key)
            if record is None:
                return LockResult(success=False, error_code="LOCK_NOT_FOUND", error_message="Lock does not exist.")

            if record.descriptor.lock_id != lock_id:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Presented lock_id '{lock_id}' does not match active lock '{record.descriptor.lock_id}'.",
                )

            if record.lease.fencing_token != fencing_token:
                return LockResult(
                    success=False,
                    error_code="STALE_FENCING_TOKEN",
                    error_message=f"Presented fencing token {fencing_token} does not match active token {record.lease.fencing_token}.",
                )

            record_owner = record.descriptor.owner_identity.get("runner_id") or record.descriptor.owner_identity.get("actor")
            if owner_id and record_owner and owner_id != record_owner:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Caller owner_id '{owner_id}' does not match active owner '{record_owner}'.",
                )

            if record.lease.lease_generation == lease_generation + 1 and record.lease.renewed_at:
                return LockResult(success=True, record=record)

            if record.lease.lease_generation != lease_generation:
                return LockResult(
                    success=False,
                    error_code="LEASE_GENERATION_MISMATCH",
                    error_message=f"Presented generation {lease_generation} does not match current generation {record.lease.lease_generation}.",
                )

            if record.is_expired(now):
                return LockResult(
                    success=False,
                    error_code="LEASE_EXPIRED",
                    error_message=f"Lease has expired at {record.lease.expires_at} (current time: {format_iso_utc(now)}).",
                )

            if record.lease.renewal_count >= MAX_RENEWALS_DEFAULT:
                return LockResult(
                    success=False,
                    error_code="MAX_RENEWALS_EXCEEDED",
                    error_message=f"Lease renewal limit exceeded ({record.lease.renewal_count} >= {MAX_RENEWALS_DEFAULT}).",
                )

            new_expires_dt = now + timedelta(seconds=extension_seconds)
            updated_lease = LeaseState(
                fencing_token=fencing_token,
                lease_generation=lease_generation + 1,
                lease_duration_seconds=extension_seconds,
                acquired_at=record.lease.acquired_at,
                expires_at=format_iso_utc(new_expires_dt),
                renewed_at=format_iso_utc(now),
                renewal_count=record.lease.renewal_count + 1,
            )
            storage_gen = f"gen-{uuid.uuid4().hex[:8]}"
            payload_sha256 = compute_payload_sha256(record.descriptor.to_dict(), updated_lease.to_dict())
            updated_record = LockRecord(
                descriptor=record.descriptor,
                lease=updated_lease,
                payload_sha256=payload_sha256,
                storage_generation=storage_gen,
            )
            self._locks[key] = updated_record
            return LockResult(success=True, record=updated_record)

    def release(
        self,
        key: str,
        lock_id: str,
        owner_id: str,
        fencing_token: int,
        lease_generation: int,
    ) -> LockResult:
        with self._lock:
            self._validate_key(key)
            if self._partition_enabled:
                raise UncertainOutcomeError("Network partition simulated: release timed out")

            now = self._now()
            record = self._locks.get(key)
            if record is None:
                cache_key = (lock_id, fencing_token)
                if cache_key in self._release_cache:
                    return LockResult(success=True)
                return LockResult(success=False, error_code="LOCK_NOT_FOUND", error_message="Lock does not exist.")

            if record.descriptor.lock_id != lock_id:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Cannot release lock: presented lock_id '{lock_id}' does not match active lock '{record.descriptor.lock_id}'.",
                )

            if record.lease.fencing_token != fencing_token:
                return LockResult(
                    success=False,
                    error_code="STALE_FENCING_TOKEN",
                    error_message=f"Cannot release lock: presented fencing token {fencing_token} does not match active token {record.lease.fencing_token}.",
                )

            record_owner = record.descriptor.owner_identity.get("runner_id") or record.descriptor.owner_identity.get("actor")
            if owner_id and record_owner and owner_id != record_owner:
                return LockResult(
                    success=False,
                    error_code="STALE_OWNER",
                    error_message=f"Cannot release lock: caller owner_id '{owner_id}' does not match active owner '{record_owner}'.",
                )

            if record.lease.lease_generation != lease_generation:
                return LockResult(
                    success=False,
                    error_code="LEASE_GENERATION_MISMATCH",
                    error_message=f"Cannot release lock: presented generation {lease_generation} does not match current generation {record.lease.lease_generation}.",
                )

            if record.is_expired(now):
                return LockResult(
                    success=False,
                    error_code="LEASE_EXPIRED",
                    error_message=f"Cannot release lock: lease has already expired at {record.lease.expires_at} (current time: {format_iso_utc(now)}).",
                )

            del self._locks[key]
            self._release_cache[(lock_id, fencing_token)] = now.timestamp()
            # Fencing token HWM in self._hwm is preserved
            return LockResult(success=True)

    def inspect(self, key: str) -> Optional[LockRecord]:
        with self._lock:
            self._validate_key(key)
            if self._partition_enabled:
                raise UncertainOutcomeError("Network partition simulated: inspect timed out")
            if key in self._corrupted_keys:
                raise LockError("Integrity checksum mismatch in lock metadata: storage corrupted")
            return self._locks.get(key)


# ==============================================================================
# 8. Lock Handle & Background Heartbeat Daemon
# ==============================================================================

class LockHandle:
    """Active lock handle held by an application or pipeline worker."""

    def __init__(self, record: LockRecord, driver: DistributedLockDriver, manager: "LockManager"):
        self.record = record
        self.driver = driver
        self.manager = manager
        self.status = "ACTIVE"
        self._child_process: Optional[Any] = None
        self._lost_callbacks: List[Callable[[str], None]] = []
        self._heartbeat_daemon: Optional["_HeartbeatDaemon"] = None
        self._lock = threading.Lock()

    @property
    def key(self) -> str:
        return self.record.descriptor.canonical_key

    @property
    def lock_id(self) -> str:
        return self.record.descriptor.lock_id

    @property
    def fencing_token(self) -> int:
        return self.record.lease.fencing_token

    @property
    def lease_generation(self) -> int:
        return self.record.lease.lease_generation

    @property
    def expires_at(self) -> str:
        return self.record.lease.expires_at

    @property
    def owner_identity(self) -> Dict[str, Any]:
        return self.record.descriptor.owner_identity

    def is_active(self) -> bool:
        with self._lock:
            return self.status == "ACTIVE"

    def register_child_process(self, proc: Any) -> None:
        """Binds a child subprocess (e.g. Terraform) for automatic fast-fail termination."""
        with self._lock:
            self._child_process = proc

    def register_lost_callback(self, cb: Callable[[str], None]) -> None:
        """Registers a callback to execute if the lock lease is lost."""
        with self._lock:
            self._lost_callbacks.append(cb)

    def terminate_child_process(self, grace_period_seconds: float = 2.0) -> None:
        """Terminates bound child process via SIGTERM followed by SIGKILL."""
        with self._lock:
            proc = self._child_process
        if proc is None:
            return
        try:
            if hasattr(proc, "terminate"):
                proc.terminate()
            if hasattr(proc, "wait"):
                try:
                    proc.wait(timeout=grace_period_seconds)
                    return
                except Exception:
                    pass
            if hasattr(proc, "kill"):
                proc.kill()
        except Exception:
            pass

    def mark_lost(self, reason: str) -> None:
        """Marks the lock as lost and triggers fast-fail child process abort."""
        with self._lock:
            if self.status != "ACTIVE":
                return
            self.status = "LOST"
            cbs = list(self._lost_callbacks)

        self.terminate_child_process()
        for cb in cbs:
            try:
                cb(reason)
            except Exception:
                pass


class _HeartbeatDaemon:
    """Background daemon thread maintaining periodic lease extensions."""

    def __init__(self, handle: LockHandle, manager: "LockManager", interval_seconds: float, cutoff_seconds: float):
        self._handle = handle
        self._manager = manager
        self._interval = max(0.1, interval_seconds)
        self._cutoff = max(self._interval, cutoff_seconds)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"infraflow-hb-{handle.lock_id[:8]}",
            daemon=True,
        )
        self._first_failure_time: Optional[float] = None

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive() and self._thread != threading.current_thread():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_event.wait(timeout=self._interval):
            if not self._handle.is_active():
                break
            try:
                self._manager.renew_lock(self._handle)
                self._first_failure_time = None
            except Exception as e:
                now_ts = time.time()
                if self._first_failure_time is None:
                    self._first_failure_time = now_ts
                elapsed = now_ts - self._first_failure_time
                if elapsed >= self._cutoff:
                    self._handle.mark_lost(
                        f"Heartbeat renewal unacknowledged for {elapsed:.1f}s (> {self._cutoff:.1f}s threshold): {e}"
                    )
                    break


# ==============================================================================
# 9. High-Level Lock Manager (LockManager)
# ==============================================================================

class LockManager:
    """
    High-level platform lock orchestration engine.
    Coordinates lease acquisition, renewal, release, heartbeat management,
    telemetry event dispatching, and safety margins.
    """

    def __init__(
        self,
        driver: DistributedLockDriver,
        default_ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
        clock_skew_tolerance: int = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
        network_rtt_tolerance: int = DEFAULT_NETWORK_RTT_TOLERANCE_SECONDS,
        telemetry_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.driver = driver
        self.default_ttl = max(MIN_LOCK_TTL_SECONDS, min(default_ttl_seconds, MAX_LOCK_TTL_SECONDS))
        self.clock_skew_tolerance = clock_skew_tolerance
        self.network_rtt_tolerance = network_rtt_tolerance
        self.telemetry_callback = telemetry_callback

    def _emit_telemetry(self, event_type: str, status: str = "PASS", details: Optional[Dict[str, Any]] = None) -> None:
        """Dispatches structured telemetry event to callback and platform telemetry engine."""
        payload = details or {}
        if self.telemetry_callback:
            try:
                self.telemetry_callback(event_type, payload)
            except Exception:
                pass

        try:
            repo_root = Path(__file__).resolve().parent.parent
            scripts_dir = repo_root / "scripts"
            if str(scripts_dir) not in sys.path:
                sys.path.insert(0, str(scripts_dir))
            import emit_telemetry  # type: ignore
            emit_telemetry.create_telemetry_event(
                event_type=event_type,
                consumer_id=payload.get("consumer_id", "platform-locking"),
                repository=payload.get("repository", "TM-threemavithana/infraflow"),
                status=status,
                metrics={"duration_ms": 0},
                verdict_reasons=[str(payload)],
            )
        except Exception:
            pass

    def acquire_lock(
        self,
        key: str,
        owner_identity: Dict[str, Any],
        purpose: str,
        ttl_seconds: Optional[int] = None,
        backend_target: Optional[Dict[str, str]] = None,
        plan_binding: Optional[Dict[str, str]] = None,
        idempotency_token: Optional[str] = None,
        lock_id: Optional[str] = None,
        auto_renew: bool = False,
    ) -> LockHandle:
        """
        Acquires an authoritative distributed lock.
        Validates metadata, computes client safety margins, calls driver, and starts heartbeat.
        """
        ttl = ttl_seconds or self.default_ttl
        check_metadata_secrets(owner_identity, "owner_identity")

        # Compute client effective TTL with clock skew and network latency buffers
        effective_ttl = max(MIN_LOCK_TTL_SECONDS, ttl - self.clock_skew_tolerance - self.network_rtt_tolerance)

        result = self.driver.acquire(
            key=key,
            owner_identity=owner_identity,
            ttl_seconds=ttl,
            purpose=purpose,
            backend_target=backend_target,
            plan_binding=plan_binding,
            idempotency_token=idempotency_token,
            lock_id=lock_id,
        )

        if not result.success:
            if result.error_code == "LOCK_HELD":
                self._emit_telemetry("lock_contention", status="WARN", details={
                    "key": key,
                    "error": result.error_message,
                    "held_by": result.record.descriptor.owner_identity if result.record else None,
                })
                raise LockHeldError(
                    result.error_message or "Lock actively held by another process.",
                    holder_identity=result.record.descriptor.owner_identity if result.record else None,
                    expires_at=result.record.lease.expires_at if result.record else None,
                )
            else:
                raise LockAcquisitionError(result.error_message or f"Acquisition failed: {result.error_code}")

        record = result.record
        if record is None:
            raise UncertainOutcomeError("Driver reported success but omitted LockRecord.")

        handle = LockHandle(record=record, driver=self.driver, manager=self)

        self._emit_telemetry("lock_acquired", status="PASS", details={
            "key": key,
            "lock_id": handle.lock_id,
            "fencing_token": handle.fencing_token,
            "owner": handle.owner_identity,
            "expires_at": handle.expires_at,
        })

        if auto_renew:
            hb_interval = effective_ttl * DEFAULT_HEARTBEAT_RATIO
            fast_fail_cutoff = effective_ttl * DEFAULT_FAST_FAIL_RATIO
            daemon = _HeartbeatDaemon(handle, self, hb_interval, fast_fail_cutoff)
            handle._heartbeat_daemon = daemon
            daemon.start()

        return handle

    def renew_lock(self, handle: LockHandle, extension_seconds: Optional[int] = None) -> LockHandle:
        """Renews an active lock lease, updating handle generation and expiry."""
        if not handle.is_active():
            raise LockLostError(f"Cannot renew inactive lock (status: {handle.status}).")

        ext = extension_seconds or self.default_ttl
        owner_id = handle.owner_identity.get("runner_id") or handle.owner_identity.get("actor") or ""

        result = self.driver.renew(
            key=handle.key,
            lock_id=handle.lock_id,
            owner_id=owner_id,
            fencing_token=handle.fencing_token,
            lease_generation=handle.lease_generation,
            extension_seconds=ext,
        )

        if not result.success:
            err = result.error_code or "UNKNOWN"
            msg = result.error_message or "Renewal rejected by driver."

            if "FENCING" in err:
                self._emit_telemetry("lock_fencing_violation", status="FAIL", details={"key": handle.key, "error": msg})
                raise StaleFencingTokenError(msg)
            elif err == "LEASE_EXPIRED":
                self._emit_telemetry("lock_lost", status="FAIL", details={"key": handle.key, "reason": "expired"})
                raise LeaseExpiredError(msg)
            elif err == "STALE_OWNER":
                self._emit_telemetry("lock_lost", status="FAIL", details={"key": handle.key, "reason": "stale_owner"})
                raise StaleOwnerError(msg)
            elif err == "LEASE_GENERATION_MISMATCH":
                raise LeaseGenerationMismatchError(msg)
            elif err == "MAX_RENEWALS_EXCEEDED":
                raise MaxRenewalsExceededError(msg)
            else:
                raise LeaseRenewalError(msg)

        handle.record = result.record  # type: ignore
        self._emit_telemetry("lock_renewed", status="PASS", details={
            "key": handle.key,
            "lock_id": handle.lock_id,
            "fencing_token": handle.fencing_token,
            "generation": handle.lease_generation,
            "expires_at": handle.expires_at,
        })
        return handle

    def release_lock(self, handle: LockHandle) -> bool:
        """Releases an active lock lease, terminating heartbeat thread and cache."""
        if handle._heartbeat_daemon:
            handle._heartbeat_daemon.stop()

        if handle.status == "RELEASED":
            return True
        if handle.status == "LOST":
            return False

        owner_id = handle.owner_identity.get("runner_id") or handle.owner_identity.get("actor") or ""
        result = self.driver.release(
            key=handle.key,
            lock_id=handle.lock_id,
            owner_id=owner_id,
            fencing_token=handle.fencing_token,
            lease_generation=handle.lease_generation,
        )

        if not result.success:
            err = result.error_code or "UNKNOWN"
            msg = result.error_message or "Release failed."
            if err == "STALE_OWNER":
                raise StaleOwnerError(msg)
            elif err == "STALE_FENCING_TOKEN":
                raise StaleFencingTokenError(msg)
            elif err == "LEASE_EXPIRED":
                raise LeaseExpiredError(msg)
            elif err == "LEASE_GENERATION_MISMATCH":
                raise LeaseGenerationMismatchError(msg)
            else:
                raise LockLostError(msg)

        with handle._lock:
            handle.status = "RELEASED"

        self._emit_telemetry("lock_released", status="PASS", details={
            "key": handle.key,
            "lock_id": handle.lock_id,
            "fencing_token": handle.fencing_token,
        })
        return True

    @contextmanager
    def lock(
        self,
        key: str,
        owner_identity: Dict[str, Any],
        purpose: str,
        ttl_seconds: Optional[int] = None,
        backend_target: Optional[Dict[str, str]] = None,
        plan_binding: Optional[Dict[str, str]] = None,
        auto_renew: bool = False,
    ) -> Generator[LockHandle, None, None]:
        """Context manager providing scoped lock acquisition and guaranteed release."""
        handle = self.acquire_lock(
            key=key,
            owner_identity=owner_identity,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            backend_target=backend_target,
            plan_binding=plan_binding,
            auto_renew=auto_renew,
        )
        try:
            yield handle
        finally:
            if handle.is_active():
                try:
                    self.release_lock(handle)
                except Exception:
                    pass
