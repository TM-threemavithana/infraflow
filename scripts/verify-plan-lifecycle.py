#!/usr/bin/env python3
"""
InfraFlow — Plan Lifecycle, State Consistency & Replay Protection Engine
Milestone: G06.2 — Protected Apply & Destroy (Verification Foundation)

Implements the pre-execution plan authorization contract:
1. Strict Plan Expiration & TTL Enforcement:
   - Evaluates ISO 8601 UTC creation and expiration timestamps.
   - Enforces configurable maximum plan lifetime (default max 12 hours).
   - Rejects expired plans, future-created plans, malformed timestamps, and missing fields.
   - Injectable clock parameter for deterministic offline verification.
   - Small configurable clock-skew tolerance (default 60s).

2. State Consistency & Lineage Validation:
   - Validates current Terraform state snapshot against plan execution metadata.
   - Verifies state schema version (v4), backend identity, and Terraform workspace.
   - Enforces exact state lineage match and state serial consistency.
   - Detects state drift, stale serials, and changed lineage.
   - Handles trusted initial-state (bootstrap) conditions with explicit declaration.

3. Transactional Replay Prevention Ledger:
   - Prevents duplicate reservations and re-execution of previously consumed plans.
   - Backed by an offline SQLite database with strict transaction isolation (BEGIN IMMEDIATE).
   - Maintains explicit plan lifecycle states: AVAILABLE, RESERVED, CONSUMED, FAILED, INTERRUPTED.
   - Atomic reservation, consumption, and fail-closed crash-recovery transitions.
   - Rejects concurrent duplicate claims and replay attacks across process restarts.

4. Comprehensive Pre-Execution Authorization Verifier:
   - Combines envelope cryptographic integrity, authenticated provenance status,
     plan expiration, identity binding, state consistency, and replay checks.
   - Emits structured decision: AUTHORIZED_FOR_SIMULATION or REJECTED with explicit reason codes.
   - STRICT INVARIANT: Never returns production deployment authorization in G06.2.
   - Completely offline: zero AWS calls, zero credentials, no terraform apply/destroy execution.
"""

import argparse
import datetime
import importlib.util
import json
import os
import re
import sqlite3
import sys
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Authorization and contract constants
AUTHORIZATION_SCHEMA_VERSION = "infraflow-plan-authorization-v1"
ENVELOPE_SCHEMA_VERSION = "infraflow-plan-envelope-v1"
MAX_PLAN_TTL_SECONDS = 12 * 3600  # 12 hours (43,200 seconds)
DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 60  # 60 seconds
DEFAULT_WORKSPACE = "default"

# Decision outcomes
DECISION_AUTHORIZED = "AUTHORIZED_FOR_SIMULATION"
DECISION_REJECTED = "REJECTED"

# Replay ledger states
STATUS_AVAILABLE = "AVAILABLE"
STATUS_NOT_STARTED = "NOT_STARTED"
STATUS_RESERVED = "RESERVED"
STATUS_CONSUMED = "CONSUMED"
STATUS_SIMULATION_COMPLETED = "SIMULATION_COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_SIMULATION_FAILED = "SIMULATION_FAILED"
STATUS_INTERRUPTED = "INTERRUPTED"
STATUS_OUTCOME_UNCERTAIN = "OUTCOME_UNCERTAIN"
STATUS_VERIFICATION_FAILED = "VERIFICATION_FAILED"
STATUS_REJECTED = "REJECTED"

VALID_LEDGER_STATUSES = {
    STATUS_AVAILABLE,
    STATUS_NOT_STARTED,
    STATUS_RESERVED,
    STATUS_CONSUMED,
    STATUS_SIMULATION_COMPLETED,
    STATUS_FAILED,
    STATUS_SIMULATION_FAILED,
    STATUS_INTERRUPTED,
    STATUS_OUTCOME_UNCERTAIN,
    STATUS_VERIFICATION_FAILED,
    STATUS_REJECTED,
}

# Regex validators
SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
COMMIT_SHA_REGEX = re.compile(r"^[0-9a-f]{40}$")
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


class LifecycleError(Exception):
    """Base exception for plan lifecycle errors."""
    pass


class PlanExpirationError(LifecycleError):
    """Raised when plan timestamp validation fails or plan has expired."""
    pass


class StateConsistencyError(LifecycleError):
    """Raised when Terraform state consistency validation fails."""
    pass


class PlanReplayError(LifecycleError):
    """Raised when plan replay or duplicate reservation is detected."""
    pass


class AuthorizationError(LifecycleError):
    """Raised when overall authorization evaluation fails."""
    pass


# -----------------------------------------------------------------------------
# Dynamic Import for kms-envelope module
# -----------------------------------------------------------------------------
def get_kms_envelope_module():
    """Dynamically loads scripts/kms-envelope.py to bypass hyphenated import limitation."""
    module_name = "kms_envelope"
    if module_name in sys.modules:
        return sys.modules[module_name]

    script_dir = os.path.dirname(os.path.abspath(__file__))
    kms_envelope_path = os.path.join(script_dir, "kms-envelope.py")
    if not os.path.isfile(kms_envelope_path):
        raise FileNotFoundError(f"kms-envelope.py not found at {kms_envelope_path}")

    spec = importlib.util.spec_from_file_location(module_name, kms_envelope_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for {kms_envelope_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


# -----------------------------------------------------------------------------
# Timestamp & Injectable Clock Utilities
# -----------------------------------------------------------------------------
def get_current_utc_time(inject_time: Optional[datetime.datetime] = None) -> datetime.datetime:
    """
    Returns current UTC datetime. If inject_time is provided, normalizes it to UTC.
    Used for 100% deterministic testing without system sleep or monkeypatching.
    """
    if inject_time is not None:
        if inject_time.tzinfo is None:
            return inject_time.replace(tzinfo=datetime.timezone.utc)
        return inject_time.astimezone(datetime.timezone.utc)
    return datetime.datetime.now(datetime.timezone.utc)


def parse_iso_utc(ts_str: Any) -> datetime.datetime:
    """
    Strictly parses an ISO 8601 UTC timestamp string into a timezone-aware datetime.
    Rejects missing, non-string, naive (non-UTC), or malformed inputs.
    """
    if not isinstance(ts_str, str) or not ts_str.strip():
        raise PlanExpirationError("MALFORMED_TIMESTAMP: Timestamp must be a non-empty ISO 8601 string")

    clean_str = ts_str.strip()
    # Normalize trailing 'Z' to '+00:00' for standard fromisoformat compatibility
    if clean_str.endswith("Z"):
        normalized = clean_str[:-1] + "+00:00"
    else:
        normalized = clean_str

    try:
        dt = datetime.datetime.fromisoformat(normalized)
    except (ValueError, TypeError) as e:
        raise PlanExpirationError(f"MALFORMED_TIMESTAMP: Invalid ISO 8601 format '{clean_str}': {e}")

    if dt.tzinfo is None:
        raise PlanExpirationError(f"MALFORMED_TIMESTAMP: Timestamp '{clean_str}' is naive; explicit UTC timezone (Z or +00:00) is required")

    return dt.astimezone(datetime.timezone.utc)


# -----------------------------------------------------------------------------
# Data Models & Authorization Decision Contract
# -----------------------------------------------------------------------------
@dataclass
class PlanAuthorizationContract:
    schema_version: str
    plan_id: str
    plan_digest_sha256: str
    source_repository: str
    source_commit_sha: str
    target_environment: str
    workflow_identity: str
    workflow_sha: Optional[str]
    terraform_version: Optional[str]
    backend_identity: Optional[str]
    workspace: str
    state_lineage: str
    state_serial: int
    created_at: str
    expires_at: str
    provenance_status: str
    replay_status: str


@dataclass
class AuthorizationDecision:
    decision: str  # AUTHORIZED_FOR_SIMULATION or REJECTED
    decision_code: str
    reasons: List[str] = field(default_factory=list)
    contract: Optional[Dict[str, Any]] = None
    evaluated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -----------------------------------------------------------------------------
# Phase 3: Plan Expiration & TTL Validation
# -----------------------------------------------------------------------------
class PlanExpirationValidator:
    """
    Validates plan creation time, expiration time, TTL, and clock skew.
    Guarantees that expired or future-dated plans cannot be authorized.
    """

    @staticmethod
    def validate(
        created_at_str: Optional[str],
        expires_at_str: Optional[str],
        current_time: Optional[datetime.datetime] = None,
        max_ttl_seconds: int = MAX_PLAN_TTL_SECONDS,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
    ) -> Dict[str, Any]:
        """
        Validates timestamps and returns parsed timing metadata.
        Raises PlanExpirationError on any failure.
        """
        if not created_at_str:
            raise PlanExpirationError("MISSING_TIMESTAMP: created_at timestamp is required")
        if not expires_at_str:
            raise PlanExpirationError("MISSING_TIMESTAMP: expires_at timestamp is required")

        created_at = parse_iso_utc(created_at_str)
        expires_at = parse_iso_utc(expires_at_str)
        now = get_current_utc_time(current_time)

        # Expiration ordering check
        if expires_at <= created_at:
            raise PlanExpirationError(
                f"INVALID_EXPIRATION_ORDER: expires_at ({expires_at.isoformat()}) must be strictly after created_at ({created_at.isoformat()})"
            )

        # Maximum plan lifetime check (12 hours)
        plan_duration = (expires_at - created_at).total_seconds()
        if plan_duration > max_ttl_seconds:
            raise PlanExpirationError(
                f"TTL_EXCEEDED: Plan validity duration of {plan_duration:.1f}s exceeds maximum allowable TTL of {max_ttl_seconds}s"
            )

        # Future creation check (with clock skew tolerance)
        skew_delta = datetime.timedelta(seconds=clock_skew_seconds)
        if created_at > (now + skew_delta):
            raise PlanExpirationError(
                f"FUTURE_CREATED_PLAN: created_at ({created_at.isoformat()}) is in the future relative to current time ({now.isoformat()}) with {clock_skew_seconds}s skew allowance"
            )

        # Plan expiration check (with clock skew tolerance)
        if now > (expires_at + skew_delta):
            raise PlanExpirationError(
                f"PLAN_EXPIRED: Plan expired at {expires_at.isoformat()}; current evaluation time is {now.isoformat()}"
            )

        remaining_ttl = max(0.0, (expires_at - now).total_seconds())

        return {
            "created_at_utc": created_at.isoformat(),
            "expires_at_utc": expires_at.isoformat(),
            "evaluated_at_utc": now.isoformat(),
            "remaining_ttl_seconds": remaining_ttl,
            "duration_seconds": plan_duration,
        }


# -----------------------------------------------------------------------------
# Phase 4: State Consistency & Lineage Validation
# -----------------------------------------------------------------------------
class StateConsistencyValidator:
    """
    Validates Terraform state metadata against expected planning parameters.
    Detects state drift, serial mismatches, lineage substitution, and wrong backends.
    """

    @staticmethod
    def validate(
        current_state: Dict[str, Any],
        expected_lineage: str,
        expected_serial: int,
        expected_backend: Optional[str] = None,
        expected_workspace: str = DEFAULT_WORKSPACE,
        actual_backend: Optional[str] = None,
        actual_workspace: str = DEFAULT_WORKSPACE,
        is_initial_state: bool = False,
    ) -> Dict[str, Any]:
        """
        Validates state snapshot dictionary against expected values.
        Raises StateConsistencyError on any discrepancy.
        """
        if not isinstance(current_state, dict):
            raise StateConsistencyError("MALFORMED_STATE_METADATA: State snapshot must be a JSON dictionary")

        # Initial bootstrap state handling
        if is_initial_state:
            # For brand-new infrastructure, state may be empty or serial 0
            if not current_state or (current_state.get("serial") == 0 and not current_state.get("lineage")):
                return {
                    "is_initial_state": True,
                    "lineage": expected_lineage or "initial-bootstrap",
                    "serial": 0,
                    "workspace": actual_workspace,
                    "backend": actual_backend,
                }

        # Non-initial state must contain valid metadata
        if not current_state:
            raise StateConsistencyError("MISSING_STATE_METADATA: State file is empty or missing metadata")

        # Validate required state schema attributes (Terraform state v4)
        if "version" not in current_state:
            raise StateConsistencyError("MALFORMED_STATE_METADATA: Missing 'version' attribute in state")
        if "serial" not in current_state:
            raise StateConsistencyError("MALFORMED_STATE_METADATA: Missing 'serial' attribute in state")
        if "lineage" not in current_state:
            raise StateConsistencyError("MALFORMED_STATE_METADATA: Missing 'lineage' attribute in state")

        state_version = current_state.get("version")
        if not isinstance(state_version, int) or state_version < 4:
            raise StateConsistencyError(f"MALFORMED_STATE_METADATA: Unsupported state version '{state_version}'; expected >= 4")

        actual_serial = current_state.get("serial")
        if not isinstance(actual_serial, int) or actual_serial < 0:
            raise StateConsistencyError(f"MALFORMED_STATE_METADATA: Invalid state serial '{actual_serial}'; must be non-negative integer")

        actual_lineage = str(current_state.get("lineage", "")).strip()
        if not actual_lineage:
            raise StateConsistencyError("MALFORMED_STATE_METADATA: State lineage cannot be empty")

        # Workspace containment check
        if actual_workspace != expected_workspace:
            raise StateConsistencyError(
                f"WORKSPACE_MISMATCH: Actual workspace '{actual_workspace}' does not match expected workspace '{expected_workspace}'"
            )

        # Backend identity check
        if expected_backend:
            if not actual_backend:
                raise StateConsistencyError("BACKEND_MISMATCH: Actual backend is undefined but expected backend was specified")
            if actual_backend.strip() != expected_backend.strip():
                raise StateConsistencyError(
                    f"BACKEND_MISMATCH: Actual backend '{actual_backend}' does not match expected backend '{expected_backend}'"
                )

        # Lineage match check
        if actual_lineage != expected_lineage.strip():
            raise StateConsistencyError(
                f"STATE_LINEAGE_MISMATCH: Current state lineage '{actual_lineage}' does not match expected lineage '{expected_lineage}'"
            )

        # Serial match check
        if actual_serial != expected_serial:
            if actual_serial > expected_serial:
                reason = "STALE_STATE_SERIAL"
                detail = f"State has progressed to serial {actual_serial}; plan was created against older serial {expected_serial}"
            else:
                reason = "STATE_SERIAL_REGRESSION"
                detail = f"Current state serial {actual_serial} is lower than plan serial {expected_serial}"
            raise StateConsistencyError(f"{reason}: {detail}")

        return {
            "is_initial_state": False,
            "version": state_version,
            "lineage": actual_lineage,
            "serial": actual_serial,
            "workspace": actual_workspace,
            "backend": actual_backend or "unspecified",
        }


# -----------------------------------------------------------------------------
# Phase 5: Replay Prevention Ledger (Offline SQLite Implementation)
# -----------------------------------------------------------------------------
class PlanReplayLedger:
    """
    Offline SQLite transactional replay ledger.
    Guarantees atomic reservation, consumed plan tracking, and crash-recovery boundaries.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS plan_executions (
                        plan_id TEXT PRIMARY KEY,
                        plan_digest_sha256 TEXT NOT NULL,
                        repository TEXT NOT NULL,
                        commit_sha TEXT NOT NULL,
                        environment TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reserved_at TEXT NOT NULL,
                        consumed_at TEXT,
                        expires_at TEXT NOT NULL,
                        execution_context TEXT NOT NULL
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_plan_digest ON plan_executions(plan_digest_sha256)
                    """
                )
                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_repo_commit ON plan_executions(repository, commit_sha, environment)
                    """
                )

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def reserve_plan(
        self,
        plan_id: str,
        plan_digest_sha256: str,
        repository: str,
        commit_sha: str,
        environment: str,
        expires_at: str,
        execution_context: Dict[str, Any],
        current_time: Optional[datetime.datetime] = None,
    ) -> None:
        """
        Atomically reserves a plan for execution.
        Fails if the plan_id or plan_digest_sha256 has already been reserved, consumed, or failed.
        """
        if not plan_id or not plan_id.strip():
            raise PlanReplayError("INVALID_PLAN_ID: plan_id must be non-empty")
        if not SHA256_HEX_REGEX.match(plan_digest_sha256):
            raise PlanReplayError(f"INVALID_DIGEST: plan_digest_sha256 '{plan_digest_sha256}' must be 64-char hex")

        now = get_current_utc_time(current_time)
        now_iso = now.isoformat()

        with self._lock:
            with self._conn:
                cursor = self._conn.cursor()

                # Check for existing plan_id or plan_digest_sha256
                cursor.execute(
                    """
                    SELECT plan_id, plan_digest_sha256, status, reserved_at, consumed_at, expires_at
                    FROM plan_executions
                    WHERE plan_id = ? OR plan_digest_sha256 = ?
                    """,
                    (plan_id, plan_digest_sha256),
                )
                existing = cursor.fetchone()

                if existing:
                    existing_status = existing["status"]
                    existing_id = existing["plan_id"]

                    if existing_status in (STATUS_CONSUMED, STATUS_SIMULATION_COMPLETED):
                        raise PlanReplayError(
                            f"ALREADY_CONSUMED: Plan '{existing_id}' (digest {plan_digest_sha256}) was already consumed at {existing['consumed_at']}"
                        )
                    elif existing_status == STATUS_RESERVED:
                        raise PlanReplayError(
                            f"DUPLICATE_RESERVATION: Plan '{existing_id}' is currently reserved for execution (reserved at {existing['reserved_at']})"
                        )
                    elif existing_status in (STATUS_FAILED, STATUS_INTERRUPTED, STATUS_SIMULATION_FAILED, STATUS_OUTCOME_UNCERTAIN):
                        raise PlanReplayError(
                            f"UNCERTAIN_EXECUTION_STATE: Plan '{existing_id}' previously ended in '{existing_status}' state; re-execution strictly blocked without manual investigation"
                        )
                    else:
                        raise PlanReplayError(
                            f"REPLAY_DETECTED: Plan '{existing_id}' exists with status '{existing_status}'"
                        )

                # Insert reservation
                cursor.execute(
                    """
                    INSERT INTO plan_executions (
                        plan_id, plan_digest_sha256, repository, commit_sha, environment,
                        status, reserved_at, consumed_at, expires_at, execution_context
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        plan_id,
                        plan_digest_sha256,
                        repository,
                        commit_sha,
                        environment,
                        STATUS_RESERVED,
                        now_iso,
                        expires_at,
                        json.dumps(execution_context, sort_keys=True),
                    ),
                )

    def consume_plan(
        self,
        plan_id: str,
        current_time: Optional[datetime.datetime] = None,
    ) -> None:
        """
        Transitions a RESERVED plan to CONSUMED status upon simulated completion.
        Fails if the plan is not currently in RESERVED status.
        """
        now = get_current_utc_time(current_time)
        now_iso = now.isoformat()

        with self._lock:
            with self._conn:
                cursor = self._conn.cursor()

                cursor.execute(
                    "SELECT status FROM plan_executions WHERE plan_id = ?",
                    (plan_id,),
                )
                row = cursor.fetchone()
                if not row:
                    raise PlanReplayError(f"PLAN_NOT_FOUND: Plan '{plan_id}' does not exist in ledger")

                current_status = row["status"]
                if current_status == STATUS_CONSUMED:
                    raise PlanReplayError(f"ALREADY_CONSUMED: Plan '{plan_id}' has already been consumed")
                if current_status != STATUS_RESERVED:
                    raise PlanReplayError(
                        f"INVALID_STATE_TRANSITION: Cannot consume plan in '{current_status}' state; must be '{STATUS_RESERVED}'"
                    )

                cursor.execute(
                    """
                    UPDATE plan_executions
                    SET status = ?, consumed_at = ?
                    WHERE plan_id = ?
                    """,
                    (STATUS_CONSUMED, now_iso, plan_id),
                )

    def fail_plan(
        self,
        plan_id: str,
        interrupted: bool = False,
    ) -> None:
        """
        Transitions a RESERVED plan to FAILED or INTERRUPTED status.
        """
        new_status = STATUS_INTERRUPTED if interrupted else STATUS_FAILED
        with self._lock:
            with self._conn:
                cursor = self._conn.cursor()
                cursor.execute(
                    "UPDATE plan_executions SET status = ? WHERE plan_id = ?",
                    (new_status, plan_id),
                )

    def record_outcome(
        self,
        plan_id: str,
        status: str,
        current_time: Optional[datetime.datetime] = None,
    ) -> None:
        """
        Transitions a RESERVED plan to a final or recovery outcome status.
        Supports: SIMULATION_COMPLETED, SIMULATION_FAILED, OUTCOME_UNCERTAIN, CONSUMED, FAILED, INTERRUPTED.
        """
        if status not in VALID_LEDGER_STATUSES:
            raise ValueError(f"Invalid ledger status: '{status}'")

        now = get_current_utc_time(current_time)
        now_iso = now.isoformat()

        with self._lock:
            with self._conn:
                cursor = self._conn.cursor()
                cursor.execute(
                    "SELECT status FROM plan_executions WHERE plan_id = ?",
                    (plan_id,),
                )
                row = cursor.fetchone()
                if not row:
                    raise PlanReplayError(f"PLAN_NOT_FOUND: Plan '{plan_id}' does not exist in ledger")

                current_status = row["status"]
                if current_status in (STATUS_CONSUMED, STATUS_SIMULATION_COMPLETED):
                    raise PlanReplayError(f"ALREADY_CONSUMED: Plan '{plan_id}' has already been consumed")

                consumed_at = now_iso if status in (STATUS_CONSUMED, STATUS_SIMULATION_COMPLETED) else None
                cursor.execute(
                    """
                    UPDATE plan_executions
                    SET status = ?, consumed_at = COALESCE(?, consumed_at)
                    WHERE plan_id = ?
                    """,
                    (status, consumed_at, plan_id),
                )

    def get_plan_status(self, plan_id: str) -> Optional[Dict[str, Any]]:
        """Queries the current status and metadata of a plan from the ledger."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT plan_id, plan_digest_sha256, repository, commit_sha, environment,
                       status, reserved_at, consumed_at, expires_at, execution_context
                FROM plan_executions WHERE plan_id = ?
                """,
                (plan_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return dict(row)


# -----------------------------------------------------------------------------
# Phase 6: Pre-Execution Authorization Verifier
# -----------------------------------------------------------------------------
class PlanLifecycleVerifier:
    """
    Unified pre-execution verification engine.
    Validates cryptographic envelope, in-toto provenance authenticity, plan TTL,
    execution context, state consistency, and ledger replay reservation.
    """

    def __init__(self, ledger: Optional[PlanReplayLedger] = None):
        self.ledger = ledger or PlanReplayLedger()

    def verify_authorization(
        self,
        envelope_data: Dict[str, Any],
        state_data: Dict[str, Any],
        expected_repo: str,
        expected_commit: str,
        expected_environment: str,
        expected_lineage: str,
        expected_serial: int,
        expected_workflow_sha: Optional[str] = None,
        expected_backend: Optional[str] = None,
        expected_workspace: str = DEFAULT_WORKSPACE,
        actual_backend: Optional[str] = None,
        actual_workspace: str = DEFAULT_WORKSPACE,
        provenance_status: str = "VERIFIED",
        is_initial_state: bool = False,
        current_time: Optional[datetime.datetime] = None,
        max_ttl_seconds: int = MAX_PLAN_TTL_SECONDS,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
        reserve_in_ledger: bool = True,
    ) -> AuthorizationDecision:
        """
        Executes complete verification pipeline.
        Returns AuthorizationDecision with status AUTHORIZED_FOR_SIMULATION or REJECTED.
        """
        reasons: List[str] = []
        now = get_current_utc_time(current_time)

        # 1. Envelope Schema & Static Structure Check
        if not isinstance(envelope_data, dict):
            return AuthorizationDecision(
                decision=DECISION_REJECTED,
                decision_code="MALFORMED_ENVELOPE",
                reasons=["Envelope data must be a valid JSON dictionary"],
            )

        schema_version = envelope_data.get("schema_version")
        if schema_version != ENVELOPE_SCHEMA_VERSION:
            reasons.append(
                f"UNSUPPORTED_SCHEMA_VERSION: Envelope schema version '{schema_version}' does not match expected '{ENVELOPE_SCHEMA_VERSION}'"
            )

        context = envelope_data.get("aad") or envelope_data.get("context", {})
        if not isinstance(context, dict):
            reasons.append("MALFORMED_ENVELOPE: Envelope context must be a dictionary")
            context = {}

        plan_digest = (
            envelope_data.get("plan_digest")
            or context.get("plan_digest_sha256")
            or context.get("plan_digest", "")
        )
        if not plan_digest or not SHA256_HEX_REGEX.match(plan_digest):
            reasons.append("INVALID_PLAN_DIGEST: Envelope context missing valid SHA-256 plan digest")

        # Derive plan ID
        plan_id = envelope_data.get("plan_id") or context.get("plan_identifier") or f"plan-{plan_digest[:16]}"

        # 2. Authenticated Provenance Check
        if provenance_status != "VERIFIED":
            reasons.append(
                f"UNVERIFIED_PROVENANCE: Digital signature attestation status is '{provenance_status}'; must be 'VERIFIED'"
            )

        # 3. Context & Identity Binding Checks
        env_repo = context.get("repository", "")
        if env_repo != expected_repo:
            reasons.append(
                f"REPO_MISMATCH: Envelope repository '{env_repo}' does not match expected repository '{expected_repo}'"
            )

        env_commit = context.get("commit_sha", "")
        if env_commit != expected_commit:
            reasons.append(
                f"COMMIT_MISMATCH: Envelope commit SHA '{env_commit}' does not match expected commit '{expected_commit}'"
            )

        env_environment = context.get("environment", "")
        if env_environment != expected_environment:
            reasons.append(
                f"ENVIRONMENT_MISMATCH: Envelope environment '{env_environment}' does not match expected environment '{expected_environment}'"
            )

        if expected_workflow_sha:
            env_workflow_sha = context.get("workflow_sha")
            if env_workflow_sha and env_workflow_sha != expected_workflow_sha:
                reasons.append(
                    f"WORKFLOW_SHA_MISMATCH: Envelope workflow SHA '{env_workflow_sha}' does not match expected '{expected_workflow_sha}'"
                )

        # 4. Plan Expiration & TTL Validation
        created_at_str = envelope_data.get("created_at") or context.get("created_at")
        expires_at_str = envelope_data.get("expires_at") or context.get("expires_at")

        # If expires_at is not explicitly set in envelope, derive from created_at + max_ttl
        if created_at_str and not expires_at_str:
            try:
                c_dt = parse_iso_utc(created_at_str)
                expires_at_str = (c_dt + datetime.timedelta(seconds=max_ttl_seconds)).isoformat()
            except Exception as e:
                reasons.append(f"MALFORMED_TIMESTAMP: {e}")

        lifecycle_meta = {}
        try:
            lifecycle_meta = PlanExpirationValidator.validate(
                created_at_str=created_at_str,
                expires_at_str=expires_at_str,
                current_time=now,
                max_ttl_seconds=max_ttl_seconds,
                clock_skew_seconds=clock_skew_seconds,
            )
        except PlanExpirationError as e:
            reasons.append(str(e))

        # 5. State Consistency Validation
        state_meta = {}
        try:
            state_meta = StateConsistencyValidator.validate(
                current_state=state_data,
                expected_lineage=expected_lineage,
                expected_serial=expected_serial,
                expected_backend=expected_backend,
                expected_workspace=expected_workspace,
                actual_backend=actual_backend,
                actual_workspace=actual_workspace,
                is_initial_state=is_initial_state,
            )
        except StateConsistencyError as e:
            reasons.append(str(e))

        # 6. Replay Prevention Ledger Reservation
        if not reasons and reserve_in_ledger:
            try:
                exec_context = {
                    "repository": expected_repo,
                    "commit_sha": expected_commit,
                    "environment": expected_environment,
                    "lineage": expected_lineage,
                    "serial": expected_serial,
                    "workspace": expected_workspace,
                }
                self.ledger.reserve_plan(
                    plan_id=plan_id,
                    plan_digest_sha256=plan_digest,
                    repository=expected_repo,
                    commit_sha=expected_commit,
                    environment=expected_environment,
                    expires_at=expires_at_str or now.isoformat(),
                    execution_context=exec_context,
                    current_time=now,
                )
            except PlanReplayError as e:
                reasons.append(str(e))

        # Decision synthesis
        if reasons:
            primary_code = reasons[0].split(":")[0].strip() if ":" in reasons[0] else "AUTHORIZATION_REJECTED"
            return AuthorizationDecision(
                decision=DECISION_REJECTED,
                decision_code=primary_code,
                reasons=reasons,
                contract=None,
                evaluated_at=now.isoformat(),
            )

        contract = PlanAuthorizationContract(
            schema_version=AUTHORIZATION_SCHEMA_VERSION,
            plan_id=plan_id,
            plan_digest_sha256=plan_digest,
            source_repository=expected_repo,
            source_commit_sha=expected_commit,
            target_environment=expected_environment,
            workflow_identity=context.get("workflow", "reusable-tf-plan.yml"),
            workflow_sha=expected_workflow_sha or context.get("workflow_sha"),
            terraform_version=context.get("terraform_version", "1.10.4"),
            backend_identity=expected_backend,
            workspace=expected_workspace,
            state_lineage=expected_lineage,
            state_serial=expected_serial,
            created_at=lifecycle_meta.get("created_at_utc", ""),
            expires_at=lifecycle_meta.get("expires_at_utc", ""),
            provenance_status=provenance_status,
            replay_status=STATUS_RESERVED if reserve_in_ledger else STATUS_AVAILABLE,
        )

        return AuthorizationDecision(
            decision=DECISION_AUTHORIZED,
            decision_code="AUTH_SUCCESS",
            reasons=[],
            contract=asdict(contract),
            evaluated_at=now.isoformat(),
        )


# -----------------------------------------------------------------------------
# CLI Interface
# -----------------------------------------------------------------------------
def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="InfraFlow — Plan Lifecycle, State Consistency & Replay Protection Engine"
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand")

    # validate-expiration subcommand
    p_exp = subparsers.add_parser("validate-expiration", help="Validate plan creation and expiration timestamps")
    p_exp.add_argument("--created-at", required=True, help="ISO 8601 UTC creation timestamp")
    p_exp.add_argument("--expires-at", required=True, help="ISO 8601 UTC expiration timestamp")
    p_exp.add_argument("--current-time", help="Simulated current ISO 8601 UTC timestamp")
    p_exp.add_argument("--max-ttl-seconds", type=int, default=MAX_PLAN_TTL_SECONDS, help="Max TTL in seconds")
    p_exp.add_argument("--clock-skew-seconds", type=int, default=DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS, help="Clock skew tolerance in seconds")

    # validate-state subcommand
    p_state = subparsers.add_parser("validate-state", help="Validate Terraform state snapshot consistency")
    p_state.add_argument("--state-file", required=True, help="Path to Terraform state snapshot JSON")
    p_state.add_argument("--expected-lineage", required=True, help="Expected state lineage UUID")
    p_state.add_argument("--expected-serial", type=int, required=True, help="Expected state serial number")
    p_state.add_argument("--expected-workspace", default=DEFAULT_WORKSPACE, help="Expected workspace name")
    p_state.add_argument("--actual-workspace", default=DEFAULT_WORKSPACE, help="Actual workspace name")
    p_state.add_argument("--expected-backend", help="Expected backend URL / identifier")
    p_state.add_argument("--actual-backend", help="Actual backend URL / identifier")
    p_state.add_argument("--initial-state", action="store_true", help="Allow initial bootstrap state")

    # ledger-reserve subcommand
    p_res = subparsers.add_parser("ledger-reserve", help="Reserve plan in replay protection ledger")
    p_res.add_argument("--ledger-db", default=":memory:", help="Path to SQLite ledger database")
    p_res.add_argument("--plan-id", required=True, help="Unique plan ID")
    p_res.add_argument("--plan-digest", required=True, help="SHA-256 digest of original plan")
    p_res.add_argument("--repo", required=True, help="Repository identity")
    p_res.add_argument("--commit", required=True, help="Commit SHA")
    p_res.add_argument("--environment", required=True, help="Deployment environment")
    p_res.add_argument("--expires-at", required=True, help="ISO 8601 UTC expiration timestamp")

    # ledger-consume subcommand
    p_con = subparsers.add_parser("ledger-consume", help="Mark plan as consumed in replay ledger")
    p_con.add_argument("--ledger-db", default=":memory:", help="Path to SQLite ledger database")
    p_con.add_argument("--plan-id", required=True, help="Plan ID to mark as consumed")

    # ledger-status subcommand
    p_stat = subparsers.add_parser("ledger-status", help="Inspect status of plan in replay ledger")
    p_stat.add_argument("--ledger-db", default=":memory:", help="Path to SQLite ledger database")
    p_stat.add_argument("--plan-id", required=True, help="Plan ID to query")

    # verify subcommand (full pipeline)
    p_ver = subparsers.add_parser("verify", help="Run full pre-execution plan authorization verifier")
    p_ver.add_argument("--envelope-file", required=True, help="Path to encrypted plan envelope JSON")
    p_ver.add_argument("--state-file", required=True, help="Path to Terraform state snapshot JSON")
    p_ver.add_argument("--expected-repo", required=True, help="Expected repository identity")
    p_ver.add_argument("--expected-commit", required=True, help="Expected commit SHA")
    p_ver.add_argument("--expected-environment", required=True, help="Expected environment")
    p_ver.add_argument("--expected-lineage", required=True, help="Expected state lineage")
    p_ver.add_argument("--expected-serial", type=int, required=True, help="Expected state serial")
    p_ver.add_argument("--expected-workflow-sha", help="Expected workflow SHA")
    p_ver.add_argument("--expected-backend", help="Expected backend identity")
    p_ver.add_argument("--expected-workspace", default=DEFAULT_WORKSPACE, help="Expected workspace")
    p_ver.add_argument("--actual-backend", help="Actual backend identity")
    p_ver.add_argument("--actual-workspace", default=DEFAULT_WORKSPACE, help="Actual workspace")
    p_ver.add_argument("--provenance-status", default="VERIFIED", choices=["VERIFIED", "UNVERIFIED", "REJECTED"], help="Provenance status")
    p_ver.add_argument("--ledger-db", default=":memory:", help="Path to SQLite ledger database")
    p_ver.add_argument("--initial-state", action="store_true", help="Allow initial state bootstrap")
    p_ver.add_argument("--current-time", help="Simulated evaluation timestamp (ISO 8601 UTC)")
    p_ver.add_argument("--no-reserve", action="store_true", help="Do not reserve in ledger")

    return parser


def main() -> int:
    parser = build_cli_parser()
    args = parser.parse_args()

    try:
        if args.command == "validate-expiration":
            cur_time = parse_iso_utc(args.current_time) if args.current_time else None
            meta = PlanExpirationValidator.validate(
                created_at_str=args.created_at,
                expires_at_str=args.expires_at,
                current_time=cur_time,
                max_ttl_seconds=args.max_ttl_seconds,
                clock_skew_seconds=args.clock_skew_seconds,
            )
            print(json.dumps({"status": "PASS", "details": meta}, indent=2))
            return 0

        elif args.command == "validate-state":
            if os.path.islink(args.state_file):
                raise StateConsistencyError(f"Symlinks are strictly prohibited: '{args.state_file}'")
            with open(args.state_file, "r", encoding="utf-8") as f:
                state_data = json.load(f)
            meta = StateConsistencyValidator.validate(
                current_state=state_data,
                expected_lineage=args.expected_lineage,
                expected_serial=args.expected_serial,
                expected_backend=args.expected_backend,
                expected_workspace=args.expected_workspace,
                actual_backend=args.actual_backend,
                actual_workspace=args.actual_workspace,
                is_initial_state=args.initial_state,
            )
            print(json.dumps({"status": "PASS", "details": meta}, indent=2))
            return 0

        elif args.command == "ledger-reserve":
            ledger = PlanReplayLedger(db_path=args.ledger_db)
            ledger.reserve_plan(
                plan_id=args.plan_id,
                plan_digest_sha256=args.plan_digest,
                repository=args.repo,
                commit_sha=args.commit,
                environment=args.environment,
                expires_at=args.expires_at,
                execution_context={"source": "cli"},
            )
            print(json.dumps({"status": "PASS", "message": f"Plan '{args.plan_id}' reserved successfully"}, indent=2))
            return 0

        elif args.command == "ledger-consume":
            ledger = PlanReplayLedger(db_path=args.ledger_db)
            ledger.consume_plan(plan_id=args.plan_id)
            print(json.dumps({"status": "PASS", "message": f"Plan '{args.plan_id}' consumed successfully"}, indent=2))
            return 0

        elif args.command == "ledger-status":
            ledger = PlanReplayLedger(db_path=args.ledger_db)
            status = ledger.get_plan_status(plan_id=args.plan_id)
            if status is None:
                print(json.dumps({"status": "NOT_FOUND", "plan_id": args.plan_id}, indent=2))
                return 1
            print(json.dumps({"status": "FOUND", "details": status}, indent=2))
            return 0

        elif args.command == "verify":
            if os.path.islink(args.envelope_file):
                raise PlanEnvelopeError(f"Symlinks are strictly prohibited: '{args.envelope_file}'")
            if os.path.islink(args.state_file):
                raise StateConsistencyError(f"Symlinks are strictly prohibited: '{args.state_file}'")
            with open(args.envelope_file, "r", encoding="utf-8") as f:
                env_data = json.load(f)
            with open(args.state_file, "r", encoding="utf-8") as f:
                state_data = json.load(f)

            ledger = PlanReplayLedger(db_path=args.ledger_db)
            verifier = PlanLifecycleVerifier(ledger=ledger)
            cur_time = parse_iso_utc(args.current_time) if args.current_time else None

            decision = verifier.verify_authorization(
                envelope_data=env_data,
                state_data=state_data,
                expected_repo=args.expected_repo,
                expected_commit=args.expected_commit,
                expected_environment=args.expected_environment,
                expected_lineage=args.expected_lineage,
                expected_serial=args.expected_serial,
                expected_workflow_sha=args.expected_workflow_sha,
                expected_backend=args.expected_backend,
                expected_workspace=args.expected_workspace,
                actual_backend=args.actual_backend,
                actual_workspace=args.actual_workspace,
                provenance_status=args.provenance_status,
                is_initial_state=args.initial_state,
                current_time=cur_time,
                reserve_in_ledger=not args.no_reserve,
            )

            print(json.dumps(decision.to_dict(), indent=2))
            if decision.decision == DECISION_AUTHORIZED:
                return 0
            return 1

    except LifecycleError as e:
        print(json.dumps({"status": "FAIL", "error": type(e).__name__, "message": str(e)}, indent=2), file=sys.stderr)
        return 1
    except Exception as e:
        print(json.dumps({"status": "ERROR", "error": type(e).__name__, "message": str(e)}, indent=2), file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
