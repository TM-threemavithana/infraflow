#!/usr/bin/env python3
"""
InfraFlow — Controlled Destruction, Blast-Radius Protection & Failure Recovery Engine
Milestone: G06.4

Analyzes Terraform execution plans for destructive changes:
- Classifies pure deletions, create-before-destroy, and destroy-before-create replacements.
- Detects state-wide destroy operations and unknown/malformed action sequences (fail-closed).
- Identifies security-critical control and asset destructions.
- Evaluates blast-radius limits (max deletions, max replacements, protected types).
- Verifies cryptographically bound, plan-specific destruction confirmation tokens.
- Enforces execution state machine with crash diagnostics and non-retryable uncertain states.
"""

import argparse
import datetime
import json
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Platform Hard Guardrail Ceilings
PLATFORM_MAX_DELETIONS_CEILING = 25
PLATFORM_MAX_REPLACEMENTS_CEILING = 50

# Schema Versions
DESTRUCTION_POLICY_SCHEMA_VERSION = "infraflow-destruction-policy-v1"
DESTRUCTION_CONFIRMATION_SCHEMA_VERSION = "infraflow-destruction-confirmation-v1"
ASSESSMENT_DECISION_SCHEMA_VERSION = "infraflow-destruction-assessment-v1"

# Decision Constants
DECISION_AUTHORIZED = "AUTHORIZED_FOR_SIMULATION"
DECISION_REJECTED = "REJECTED"

# Execution State Machine
STATE_NOT_STARTED = "NOT_STARTED"
STATE_VERIFICATION_FAILED = "VERIFICATION_FAILED"
STATE_RESERVED = "RESERVED"
STATE_SIMULATION_COMPLETED = "SIMULATION_COMPLETED"
STATE_SIMULATION_FAILED = "SIMULATION_FAILED"
STATE_OUTCOME_UNCERTAIN = "OUTCOME_UNCERTAIN"
STATE_REJECTED = "REJECTED"

VALID_EXECUTION_STATES = {
    STATE_NOT_STARTED,
    STATE_VERIFICATION_FAILED,
    STATE_RESERVED,
    STATE_SIMULATION_COMPLETED,
    STATE_SIMULATION_FAILED,
    STATE_OUTCOME_UNCERTAIN,
    STATE_REJECTED,
}

# Regex Validators
SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
RFC3339_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

# Generic confirmation tokens that MUST be rejected
GENERIC_CONFIRMATION_BLOCKLIST = {
    "yes", "y", "true", "1", "destroy", "apply", "confirm", "confirmed",
    "approved", "ok", "proceed", "force", "override", "default"
}

# Security-critical resource types that cannot be deleted without special authorization
SECURITY_CRITICAL_RESOURCE_TYPES: Set[str] = {
    # AWS Databases & Caches
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_dynamodb_table",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_redshift_cluster",
    # AWS IAM & Access Control
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user",
    "aws_iam_group",
    "aws_iam_openid_connect_provider",
    # AWS Key Management & Encryption
    "aws_kms_key",
    "aws_kms_alias",
    "aws_kms_replica_key",
    # AWS Storage & Network Perimeter
    "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc",
    "aws_route_table",
    "aws_network_acl",
    "aws_internet_gateway",
    # Azure Databases & Caches
    "azurerm_postgresql_server",
    "azurerm_postgresql_flexible_server",
    "azurerm_mssql_server",
    "azurerm_mssql_database",
    "azurerm_cosmosdb_account",
    "azurerm_mariadb_server",
    "azurerm_redis_cache",
    # Azure Key Vault & Security
    "azurerm_key_vault",
    "azurerm_key_vault_key",
    "azurerm_key_vault_secret",
    "azurerm_key_vault_managed_hardware_security_module",
    "azurerm_storage_account_network_rules",
    "azurerm_role_definition",
    "azurerm_role_assignment",
    "azurerm_user_assigned_identity",
    "azurerm_network_security_group",
    "azurerm_network_security_rule",
    "azurerm_virtual_network",
    "azurerm_firewall",
    # GCP Databases & Caches
    "google_sql_database_instance",
    "google_spanner_instance",
    "google_spanner_database",
    "google_bigtable_instance",
    "google_redis_instance",
    # GCP KMS, Storage Controls & IAM
    "google_kms_crypto_key",
    "google_kms_key_ring",
    "google_kms_crypto_key_version",
    "google_storage_bucket_iam_binding",
    "google_storage_bucket_iam_member",
    "google_service_account",
    "google_project_iam_binding",
    "google_project_iam_member",
    "google_organization_iam_binding",
    "google_compute_firewall",
    "google_compute_network",
    "google_compute_subnetwork",
    "google_compute_router",
}

# Supported Canonical Action Sets
VALID_ACTIONS_NOOP = {"no-op"}
VALID_ACTIONS_CREATE = {"create"}
VALID_ACTIONS_UPDATE = {"update"}
VALID_ACTIONS_DELETE = {"delete"}
VALID_ACTIONS_REPLACE = {"create", "delete"}
VALID_ACTIONS_READ = {"read"}

ALL_KNOWN_ACTION_TOKENS = {"no-op", "create", "update", "delete", "read"}


class DestructionAssessmentError(Exception):
    """Base exception for destructive plan assessment errors."""
    def __init__(self, message: str, decision_code: str = "ASSESSMENT_ERROR"):
        super().__init__(message)
        self.decision_code = decision_code


class MalformedPlanError(DestructionAssessmentError):
    def __init__(self, message: str):
        super().__init__(message, "MALFORMED_PLAN")


class UnknownActionError(DestructionAssessmentError):
    def __init__(self, message: str):
        super().__init__(message, "UNKNOWN_ACTION")


class BlastRadiusExceededError(DestructionAssessmentError):
    def __init__(self, message: str, code: str = "BLAST_RADIUS_EXCEEDED"):
        super().__init__(message, code)


class ConfirmationError(DestructionAssessmentError):
    def __init__(self, message: str, code: str = "INVALID_CONFIRMATION"):
        super().__init__(message, code)


def parse_rfc3339_utc(ts_str: str) -> datetime.datetime:
    """Parses strict RFC 3339 timestamp with UTC offset."""
    if not isinstance(ts_str, str) or not RFC3339_REGEX.match(ts_str):
        raise ValueError(f"Timestamp '{ts_str}' is not valid RFC 3339 format")
    normalized = ts_str.replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(normalized)
    return dt.astimezone(datetime.timezone.utc)


def get_current_utc(current_time: Optional[datetime.datetime] = None) -> datetime.datetime:
    """Returns current UTC time or injected clock."""
    if current_time is not None:
        if current_time.tzinfo is None:
            return current_time.replace(tzinfo=datetime.timezone.utc)
        return current_time.astimezone(datetime.timezone.utc)
    return datetime.datetime.now(datetime.timezone.utc)


# =============================================================================
# Phase 2: Destructive Plan Change Classifier
# =============================================================================
class DestructivePlanClassifier:
    """
    Parses and categorizes Terraform plan JSON for destructive operations:
    - Pure deletions
    - Create-before-destroy replacements
    - Destroy-before-create replacements
    - State-wide destroy detection
    - Security-critical resource changes
    - Malformed or unknown action fail-closed enforcement
    """

    @staticmethod
    def classify_resource_action(actions: List[str]) -> Tuple[str, str]:
        """
        Returns (action_category, replacement_direction) for a resource actions list.
        Fails closed on any unknown action tokens.
        """
        if not isinstance(actions, list) or len(actions) == 0:
            raise UnknownActionError("Missing or non-list change actions")

        # Check for unknown tokens
        for a in actions:
            if not isinstance(a, str) or a not in ALL_KNOWN_ACTION_TOKENS:
                raise UnknownActionError(f"Unknown or unsupported action token '{a}' in actions {actions}")

        if actions == ["no-op"]:
            return "no-op", "none"
        if actions == ["create"]:
            return "create", "none"
        if actions == ["update"]:
            return "update", "none"
        if actions == ["read"]:
            return "read", "none"
        if actions == ["delete"]:
            return "delete", "none"

        # Replacements
        if len(actions) == 2 and set(actions) == {"create", "delete"}:
            if actions == ["create", "delete"]:
                return "replace", "create_before_destroy"
            elif actions == ["delete", "create"]:
                return "replace", "destroy_before_create"

        raise UnknownActionError(f"Unsupported action combination: {actions}")

    @classmethod
    def analyze_plan_dict(cls, plan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes pre-parsed plan dictionary for destructive metrics.
        Fails closed on malformed schemas.
        """
        if not isinstance(plan_data, dict):
            raise MalformedPlanError("Plan JSON root must be an object")

        if plan_data.get("errored", False) is True:
            raise MalformedPlanError("Terraform plan is marked as errored")

        resource_changes = plan_data.get("resource_changes")
        if resource_changes is None:
            # Empty plan is valid with 0 changes
            resource_changes = []
        elif not isinstance(resource_changes, list):
            raise MalformedPlanError("'resource_changes' must be a list")

        pure_deletions = 0
        replacements = 0
        create_before_destroy_count = 0
        destroy_before_create_count = 0
        creates = 0
        updates = 0
        no_ops = 0
        reads = 0

        affected_resources: List[Dict[str, Any]] = []
        security_critical_changes: List[Dict[str, Any]] = []

        total_active_resources = 0

        for rc in resource_changes:
            if not isinstance(rc, dict):
                raise MalformedPlanError("Invalid resource_change entry; expected object")

            address = rc.get("address", "unknown")
            res_type = rc.get("type", "unknown")
            res_name = rc.get("name", "unknown")
            module_addr = rc.get("module_address", "")
            change = rc.get("change")

            if not isinstance(change, dict):
                raise MalformedPlanError(f"Resource '{address}' is missing change object")

            raw_actions = change.get("actions")
            if not isinstance(raw_actions, list):
                raise MalformedPlanError(f"Resource '{address}' change block is missing 'actions' list")

            category, replacement_dir = cls.classify_resource_action(raw_actions)

            is_destructive = category in ("delete", "replace")
            is_security_critical = res_type in SECURITY_CRITICAL_RESOURCE_TYPES

            res_info = {
                "address": address,
                "type": res_type,
                "name": res_name,
                "module_address": module_addr,
                "category": category,
                "replacement_direction": replacement_dir,
                "raw_actions": raw_actions,
                "is_security_critical": is_security_critical,
                "is_destructive": is_destructive,
            }

            if category == "delete":
                pure_deletions += 1
                affected_resources.append(res_info)
                total_active_resources += 1
            elif category == "replace":
                replacements += 1
                if replacement_dir == "create_before_destroy":
                    create_before_destroy_count += 1
                else:
                    destroy_before_create_count += 1
                affected_resources.append(res_info)
                total_active_resources += 1
            elif category == "create":
                creates += 1
                total_active_resources += 1
            elif category == "update":
                updates += 1
                total_active_resources += 1
            elif category == "no-op":
                no_ops += 1
            elif category == "read":
                reads += 1

            if is_security_critical and is_destructive:
                security_critical_changes.append(res_info)

        total_destructive = pure_deletions + replacements

        # State-wide destroy detection:
        # If active resources exist, and ALL active resources are being deleted (no creates, updates, or replaces)
        is_state_wide_destroy = False
        if total_active_resources > 0 and pure_deletions == total_active_resources and creates == 0 and updates == 0 and replacements == 0:
            is_state_wide_destroy = True

        return {
            "total_resources_evaluated": len(resource_changes),
            "total_active_changes": total_active_resources,
            "pure_deletions": pure_deletions,
            "replacements": replacements,
            "create_before_destroy": create_before_destroy_count,
            "destroy_before_create": destroy_before_create_count,
            "creates": creates,
            "updates": updates,
            "no_ops": no_ops,
            "reads": reads,
            "total_destructive": total_destructive,
            "is_state_wide_destroy": is_state_wide_destroy,
            "security_critical_count": len(security_critical_changes),
            "security_critical_changes": security_critical_changes,
            "affected_resources": affected_resources,
        }

    @classmethod
    def analyze_plan_file(cls, plan_path: str) -> Dict[str, Any]:
        """Loads and analyzes a plan JSON file, enforcing symlink rejection."""
        if os.path.islink(plan_path):
            raise MalformedPlanError(f"Symlinks are strictly prohibited for plan files: '{plan_path}'")
        if not os.path.exists(plan_path):
            raise FileNotFoundError(f"Plan file not found: '{plan_path}'")
        try:
            with open(plan_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise MalformedPlanError(f"Failed to parse plan JSON: {str(e)}")
        return cls.analyze_plan_dict(data)


# =============================================================================
# Phase 3: Blast-Radius Controls & Destruction Policy
# =============================================================================
class BlastRadiusPolicy:
    """
    Evaluates destructive changes against blast-radius thresholds:
    - Maximum allowable resource deletions
    - Maximum allowable resource replacements
    - Strict protection of security-critical resources
    - Environment scoping (Production defaults to 0 deletions)
    - Untrusted caller overrides strictly bounded
    - Trusted authorizer allowlist verification
    - Platform hard guardrail ceilings (preventing rogue policy elevation)
    """

    def __init__(
        self,
        environment: str = "production",
        max_deletions: Optional[int] = None,
        max_replacements: Optional[int] = None,
        allow_security_critical_destruction: bool = False,
        allow_state_wide_destroy: bool = False,
        require_confirmation: bool = True,
        protected_types: Optional[Set[str]] = None,
        trusted_authorizers: Optional[Set[str]] = None,
    ):
        self.environment = environment.lower().strip()
        self.is_production = self.environment in ("production", "prod")

        # Default limits based on environment
        if self.is_production:
            # Production default: 0 deletions allowed without explicit trusted policy
            default_max_del = 0
            default_max_rep = 2
            default_req_conf = True
        else:
            default_max_del = 5
            default_max_rep = 10
            default_req_conf = True

        self.max_deletions = max_deletions if max_deletions is not None else default_max_del
        self.max_replacements = max_replacements if max_replacements is not None else default_max_rep
        self.allow_security_critical_destruction = allow_security_critical_destruction
        self.allow_state_wide_destroy = allow_state_wide_destroy
        self.require_confirmation = require_confirmation
        self.protected_types = set(protected_types) if protected_types else set(SECURITY_CRITICAL_RESOURCE_TYPES)
        self.trusted_authorizers = set(trusted_authorizers) if trusted_authorizers else None

    @classmethod
    def from_file(cls, policy_path: str, environment: str = "production") -> "BlastRadiusPolicy":
        """Loads policy from a trusted JSON file, rejecting symlinks and enforcing platform ceilings."""
        if os.path.islink(policy_path):
            raise DestructionAssessmentError(
                f"Symlinks are strictly prohibited for policy files: '{policy_path}'", "SYMLINK_PROHIBITED"
            )
        if not os.path.exists(policy_path):
            raise DestructionAssessmentError(
                f"Destruction policy file not found: '{policy_path}'", "POLICY_NOT_FOUND"
            )
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise DestructionAssessmentError(
                f"Failed to parse policy JSON: {str(e)}", "INVALID_POLICY"
            )

        if not isinstance(data, dict):
            raise DestructionAssessmentError("Policy root must be an object", "INVALID_POLICY")

        schema_ver = data.get("schema_version")
        if schema_ver != DESTRUCTION_POLICY_SCHEMA_VERSION:
            raise DestructionAssessmentError(
                f"Unsupported policy schema_version '{schema_ver}'; expected '{DESTRUCTION_POLICY_SCHEMA_VERSION}'",
                "INVALID_POLICY",
            )

        policy_env = str(data.get("environment", "")).lower().strip()
        req_env = environment.lower().strip()
        if policy_env and policy_env != req_env and policy_env != "*":
            raise DestructionAssessmentError(
                f"Policy environment '{policy_env}' does not match target environment '{req_env}'",
                "POLICY_ENV_MISMATCH",
            )

        max_del = data.get("max_deletions")
        max_rep = data.get("max_replacements")
        is_prod = req_env in ("production", "prod")

        # Enforce Platform Hard Ceilings against Consumer Elevation
        if is_prod:
            if max_del is not None and max_del > PLATFORM_MAX_DELETIONS_CEILING:
                raise DestructionAssessmentError(
                    f"Policy max_deletions ({max_del}) exceeds platform production ceiling of {PLATFORM_MAX_DELETIONS_CEILING}",
                    "POLICY_CEILING_EXCEEDED",
                )
            if max_rep is not None and max_rep > PLATFORM_MAX_REPLACEMENTS_CEILING:
                raise DestructionAssessmentError(
                    f"Policy max_replacements ({max_rep}) exceeds platform production ceiling of {PLATFORM_MAX_REPLACEMENTS_CEILING}",
                    "POLICY_CEILING_EXCEEDED",
                )
            if data.get("allow_state_wide_destroy", False) is True:
                raise DestructionAssessmentError(
                    "State-wide destruction cannot be enabled via repository policy file in production",
                    "POLICY_CEILING_EXCEEDED",
                )

        raw_auth = data.get("trusted_authorizers")
        trusted_auth = set(raw_auth) if isinstance(raw_auth, list) else None

        return cls(
            environment=environment,
            max_deletions=max_del,
            max_replacements=max_rep,
            allow_security_critical_destruction=data.get("allow_security_critical_destruction", False),
            allow_state_wide_destroy=data.get("allow_state_wide_destroy", False),
            require_confirmation=data.get("require_confirmation", True),
            protected_types=set(data.get("protected_types", SECURITY_CRITICAL_RESOURCE_TYPES)),
            trusted_authorizers=trusted_auth,
        )

    def apply_caller_bounds(self, caller_max_del: Optional[int], caller_max_rep: Optional[int]) -> "BlastRadiusPolicy":
        """
        Applies caller parameters while strictly preventing elevation of privileges.
        The effective limit is min(policy_limit, caller_limit).
        """
        eff_del = self.max_deletions
        if caller_max_del is not None and caller_max_del >= 0:
            eff_del = min(self.max_deletions, caller_max_del)

        eff_rep = self.max_replacements
        if caller_max_rep is not None and caller_max_rep >= 0:
            eff_rep = min(self.max_replacements, caller_max_rep)

        return BlastRadiusPolicy(
            environment=self.environment,
            max_deletions=eff_del,
            max_replacements=eff_rep,
            allow_security_critical_destruction=self.allow_security_critical_destruction,
            allow_state_wide_destroy=self.allow_state_wide_destroy,
            require_confirmation=self.require_confirmation,
            protected_types=self.protected_types,
            trusted_authorizers=self.trusted_authorizers,
        )

    def evaluate(self, metrics: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Evaluates metrics against policy.
        Returns (is_allowed, decision_code, reason).
        """
        pure_deletions = metrics.get("pure_deletions", 0)
        replacements = metrics.get("replacements", 0)
        is_state_wide = metrics.get("is_state_wide_destroy", False)
        sec_crit_changes = metrics.get("security_critical_changes", [])

        # 1. State-wide destroy protection
        if is_state_wide and not self.allow_state_wide_destroy:
            return (
                False,
                "STATE_WIDE_DESTROY_BLOCKED",
                f"State-wide destruction detected ({pure_deletions} deletions); prohibited by policy for '{self.environment}'",
            )

        # 2. Security-critical resource protection
        if len(sec_crit_changes) > 0 and not self.allow_security_critical_destruction:
            crit_names = [f"{c['address']} ({c['type']})" for c in sec_crit_changes[:3]]
            return (
                False,
                "SECURITY_CRITICAL_DESTRUCTION_BLOCKED",
                f"Destruction of security-critical resources is prohibited: {', '.join(crit_names)}",
            )

        # 3. Maximum deletions threshold
        if pure_deletions > self.max_deletions:
            return (
                False,
                "DELETION_LIMIT_EXCEEDED",
                f"Plan specifies {pure_deletions} pure deletions; exceeds maximum allowed limit of {self.max_deletions} for '{self.environment}'",
            )

        # 4. Maximum replacements threshold
        if replacements > self.max_replacements:
            return (
                False,
                "REPLACEMENT_LIMIT_EXCEEDED",
                f"Plan specifies {replacements} replacements; exceeds maximum allowed limit of {self.max_replacements} for '{self.environment}'",
            )

        return True, "WITHIN_LIMITS", "Destructive changes are within allowed policy limits"


# =============================================================================
# Phase 4: Plan-Specific Destruction Confirmation Contract
# =============================================================================
class DestructionConfirmationValidator:
    """
    Validates cryptographically bound destruction confirmation tokens.
    Requires exact binding to:
    - plan_id
    - plan_digest_sha256
    - source_repository
    - target_environment
    - change_summary (pure_deletions and replacements match)
    - non-expired timestamp
    - authorized identity
    """

    @staticmethod
    def create_token(
        plan_id: str,
        plan_digest_sha256: str,
        source_repository: str,
        target_environment: str,
        pure_deletions: int,
        replacements: int,
        authorized_by: str,
        validity_seconds: int = 3600,
        current_time: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """Generates a valid, structured confirmation token dictionary."""
        now = get_current_utc(current_time)
        expires_at = now + datetime.timedelta(seconds=validity_seconds)

        return {
            "schema_version": DESTRUCTION_CONFIRMATION_SCHEMA_VERSION,
            "plan_id": plan_id,
            "plan_digest_sha256": plan_digest_sha256.lower().strip(),
            "source_repository": source_repository.strip(),
            "target_environment": target_environment.strip().lower(),
            "change_summary": {
                "pure_deletions": pure_deletions,
                "replacements": replacements,
            },
            "authorized_by": authorized_by.strip(),
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }

    @staticmethod
    def validate_token(
        token_input: Any,
        expected_plan_id: str,
        expected_plan_digest: str,
        expected_repo: str,
        expected_environment: str,
        actual_pure_deletions: int,
        actual_replacements: int,
        trusted_authorizers: Optional[Set[str]] = None,
        current_time: Optional[datetime.datetime] = None,
    ) -> Tuple[bool, str, str]:
        """
        Validates token against plan context.
        Returns (is_valid, decision_code, reason).
        """
        # 1. Parse token
        token_data: Dict[str, Any] = {}
        if isinstance(token_input, str):
            token_str = token_input.strip()
            # Reject generic strings
            if token_str.lower() in GENERIC_CONFIRMATION_BLOCKLIST or not token_str:
                return (
                    False,
                    "INVALID_CONFIRMATION_TOKEN",
                    f"Generic token '{token_str}' is strictly rejected; requires plan-specific confirmation contract",
                )
            try:
                token_data = json.loads(token_str)
            except json.JSONDecodeError:
                return (
                    False,
                    "INVALID_CONFIRMATION_TOKEN",
                    "Confirmation token must be a valid JSON contract",
                )
        elif isinstance(token_input, dict):
            token_data = token_input
        else:
            return (
                False,
                "INVALID_CONFIRMATION_TOKEN",
                "Confirmation token must be a JSON string or object",
            )

        if not isinstance(token_data, dict):
            return False, "INVALID_CONFIRMATION_TOKEN", "Confirmation token root must be an object"

        # 2. Check schema version
        schema_ver = token_data.get("schema_version")
        if schema_ver != DESTRUCTION_CONFIRMATION_SCHEMA_VERSION:
            return (
                False,
                "INVALID_CONFIRMATION_TOKEN",
                f"Unsupported confirmation schema '{schema_ver}'; expected '{DESTRUCTION_CONFIRMATION_SCHEMA_VERSION}'",
            )

        # 3. Plan ID binding
        token_plan_id = str(token_data.get("plan_id", "")).strip()
        if token_plan_id != expected_plan_id.strip():
            return (
                False,
                "CONFIRMATION_PLAN_MISMATCH",
                f"Confirmation plan_id '{token_plan_id}' does not match expected '{expected_plan_id}'",
            )

        # 4. Plan digest binding
        token_digest = str(token_data.get("plan_digest_sha256", "")).lower().strip()
        expected_digest_clean = expected_plan_digest.lower().strip()
        if token_digest != expected_digest_clean:
            return (
                False,
                "CONFIRMATION_DIGEST_MISMATCH",
                f"Confirmation digest '{token_digest}' does not match plan digest '{expected_digest_clean}'",
            )

        # 5. Repository binding
        token_repo = str(token_data.get("source_repository", "")).strip()
        if token_repo != expected_repo.strip():
            return (
                False,
                "CONFIRMATION_REPO_MISMATCH",
                f"Confirmation repository '{token_repo}' does not match calling repository '{expected_repo}'",
            )

        # 6. Environment binding
        token_env = str(token_data.get("target_environment", "")).lower().strip()
        expected_env_clean = expected_environment.lower().strip()
        if token_env != expected_env_clean:
            return (
                False,
                "CONFIRMATION_ENV_MISMATCH",
                f"Confirmation environment '{token_env}' does not match target '{expected_env_clean}'",
            )

        # 7. Change summary binding
        change_summary = token_data.get("change_summary")
        if not isinstance(change_summary, dict):
            return False, "CONFIRMATION_SUMMARY_MISMATCH", "Confirmation token missing change_summary"

        tok_del = change_summary.get("pure_deletions")
        tok_rep = change_summary.get("replacements")

        if tok_del != actual_pure_deletions or tok_rep != actual_replacements:
            return (
                False,
                "CONFIRMATION_SUMMARY_MISMATCH",
                f"Confirmation change summary (del={tok_del}, rep={tok_rep}) does not match actual plan (del={actual_pure_deletions}, rep={actual_replacements})",
            )

        # 8. Authorized by check
        authorized_by = str(token_data.get("authorized_by", "")).strip()
        if not authorized_by or authorized_by.lower() in GENERIC_CONFIRMATION_BLOCKLIST:
            return False, "INVALID_AUTHORIZER", "Confirmation token missing valid 'authorized_by' identity"

        if trusted_authorizers is not None and len(trusted_authorizers) > 0:
            if authorized_by not in trusted_authorizers:
                return (
                    False,
                    "UNAUTHORIZED_AUTHORIZER",
                    f"Authorizer '{authorized_by}' is not in policy trusted authorizers allowlist",
                )

        # 9. Expiration check
        expires_at_str = token_data.get("expires_at")
        try:
            expires_at = parse_rfc3339_utc(expires_at_str)
        except Exception:
            return False, "MALFORMED_EXPIRATION", f"Invalid expires_at in confirmation: '{expires_at_str}'"

        now = get_current_utc(current_time)
        if now > expires_at:
            return (
                False,
                "CONFIRMATION_EXPIRED",
                f"Confirmation token expired at {expires_at.isoformat()} (current time {now.isoformat()})",
            )

        return True, "CONFIRMATION_VALID", f"Confirmation token validated successfully (authorized by '{authorized_by}')"


# =============================================================================
# Phase 6 & 7: Execution State Machine & Safe Failure Recovery
# =============================================================================
class ExecutionRecoveryManager:
    """
    Manages plan execution state machine, failure boundaries, and safe recovery:
    - Distinguishes states: NOT_STARTED, VERIFICATION_FAILED, RESERVED,
      SIMULATION_COMPLETED, SIMULATION_FAILED, OUTCOME_UNCERTAIN, REJECTED.
    - Prevents automated retries on OUTCOME_UNCERTAIN.
    - Explicitly blocks automatic rollback.
    - Manages temporary file cleanup securely.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS plan_recovery_ledger (
                    plan_id TEXT PRIMARY KEY,
                    plan_digest_sha256 TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    state TEXT NOT NULL,
                    decision_code TEXT,
                    details TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def transition_state(
        self,
        plan_id: str,
        plan_digest_sha256: str,
        repository: str,
        environment: str,
        new_state: str,
        decision_code: Optional[str] = None,
        details: Optional[str] = None,
        current_time: Optional[datetime.datetime] = None,
    ) -> None:
        """
        Transitions plan state with strict state machine transition validation.
        """
        if new_state not in VALID_EXECUTION_STATES:
            raise ValueError(f"Invalid execution state: '{new_state}'")

        now = get_current_utc(current_time).isoformat()

        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute("SELECT state FROM plan_recovery_ledger WHERE plan_id = ?", (plan_id,))
            row = cursor.fetchone()

            if row:
                current_state = row["state"]

                # Enforce: OUTCOME_UNCERTAIN cannot transition back to RESERVED or NOT_STARTED
                if current_state == STATE_OUTCOME_UNCERTAIN and new_state in (STATE_RESERVED, STATE_NOT_STARTED):
                    raise DestructionAssessmentError(
                        f"State transition blocked: Plan '{plan_id}' is in '{STATE_OUTCOME_UNCERTAIN}' and requires manual investigation",
                        "UNCERTAIN_STATE_LOCKED",
                    )

                cursor.execute(
                    """
                    UPDATE plan_recovery_ledger
                    SET state = ?, decision_code = ?, details = ?, updated_at = ?
                    WHERE plan_id = ?
                    """,
                    (new_state, decision_code, details, now, plan_id),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO plan_recovery_ledger (
                        plan_id, plan_digest_sha256, repository, environment, state,
                        decision_code, details, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan_id,
                        plan_digest_sha256,
                        repository,
                        environment,
                        new_state,
                        decision_code,
                        details,
                        now,
                        now,
                    ),
                )

    def get_state(self, plan_id: str) -> Optional[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM plan_recovery_ledger WHERE plan_id = ?", (plan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)


# =============================================================================
# Primary Assessment Coordinator
# =============================================================================
class DestructivePlanAssessmentEngine:
    """Coordinates full destruction assessment, blast-radius checks, and confirmation."""

    @classmethod
    def assess(
        cls,
        plan_data: Dict[str, Any],
        expected_plan_id: str,
        expected_plan_digest: str,
        repository: str,
        environment: str = "production",
        policy: Optional[BlastRadiusPolicy] = None,
        confirmation_token: Optional[Any] = None,
        current_time: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end destructive change assessment.
        Returns structured decision dictionary.
        """
        # 1. Analyze plan metrics
        metrics = DestructivePlanClassifier.analyze_plan_dict(plan_data)
        total_destructive = metrics["total_destructive"]
        pure_deletions = metrics["pure_deletions"]
        replacements = metrics["replacements"]

        # 2. Establish policy
        active_policy = policy if policy is not None else BlastRadiusPolicy(environment=environment)

        # 3. If plan has zero destructive changes, automatically authorized for simulation
        if total_destructive == 0:
            return {
                "schema_version": ASSESSMENT_DECISION_SCHEMA_VERSION,
                "plan_id": expected_plan_id,
                "plan_digest_sha256": expected_plan_digest,
                "environment": environment,
                "repository": repository,
                "has_destructive_changes": False,
                "decision": DECISION_AUTHORIZED,
                "decision_code": "SAFE_NON_DESTRUCTIVE_PLAN",
                "reason": "Plan contains 0 deletions and 0 replacements; safe for execution simulation",
                "metrics": metrics,
                "policy_evaluation": {
                    "is_allowed": True,
                    "decision_code": "WITHIN_LIMITS",
                    "reason": "No destructive changes",
                },
                "confirmation_evaluation": {
                    "is_required": False,
                    "is_valid": True,
                    "status": "not-required",
                    "decision_code": "NOT_REQUIRED",
                    "reason": "Plan is non-destructive",
                },
            }

        # 4. Evaluate Blast-Radius Policy
        is_policy_allowed, pol_code, pol_reason = active_policy.evaluate(metrics)
        if not is_policy_allowed:
            return {
                "schema_version": ASSESSMENT_DECISION_SCHEMA_VERSION,
                "plan_id": expected_plan_id,
                "plan_digest_sha256": expected_plan_digest,
                "environment": environment,
                "repository": repository,
                "has_destructive_changes": True,
                "decision": DECISION_REJECTED,
                "decision_code": pol_code,
                "reason": pol_reason,
                "metrics": metrics,
                "policy_evaluation": {
                    "is_allowed": False,
                    "decision_code": pol_code,
                    "reason": pol_reason,
                },
                "confirmation_evaluation": {
                    "is_required": active_policy.require_confirmation,
                    "is_valid": False,
                    "status": "blocked-by-policy",
                    "decision_code": "BLOCKED_BY_POLICY",
                    "reason": "Policy limits exceeded prior to confirmation verification",
                },
            }

        # 5. Evaluate Confirmation Token if required
        is_conf_required = active_policy.require_confirmation
        conf_eval = {
            "is_required": is_conf_required,
            "is_valid": True,
            "status": "not-required",
            "decision_code": "NOT_REQUIRED",
            "reason": "Confirmation waived by policy",
        }

        if is_conf_required:
            if confirmation_token is None:
                return {
                    "schema_version": ASSESSMENT_DECISION_SCHEMA_VERSION,
                    "plan_id": expected_plan_id,
                    "plan_digest_sha256": expected_plan_digest,
                    "environment": environment,
                    "repository": repository,
                    "has_destructive_changes": True,
                    "decision": DECISION_REJECTED,
                    "decision_code": "MISSING_DESTRUCTION_CONFIRMATION",
                    "reason": f"Plan specifies {pure_deletions} deletions and {replacements} replacements; plan-specific confirmation token is required",
                    "metrics": metrics,
                    "policy_evaluation": {
                        "is_allowed": True,
                        "decision_code": pol_code,
                        "reason": pol_reason,
                    },
                    "confirmation_evaluation": {
                        "is_required": True,
                        "is_valid": False,
                        "status": "missing",
                        "decision_code": "MISSING_DESTRUCTION_CONFIRMATION",
                        "reason": "Confirmation token was not provided",
                    },
                }

            is_conf_valid, conf_code, conf_reason = DestructionConfirmationValidator.validate_token(
                token_input=confirmation_token,
                expected_plan_id=expected_plan_id,
                expected_plan_digest=expected_plan_digest,
                expected_repo=repository,
                expected_environment=environment,
                actual_pure_deletions=pure_deletions,
                actual_replacements=replacements,
                trusted_authorizers=active_policy.trusted_authorizers,
                current_time=current_time,
            )

            conf_eval = {
                "is_required": True,
                "is_valid": is_conf_valid,
                "status": "verified" if is_conf_valid else "rejected",
                "decision_code": conf_code,
                "reason": conf_reason,
            }

            if not is_conf_valid:
                return {
                    "schema_version": ASSESSMENT_DECISION_SCHEMA_VERSION,
                    "plan_id": expected_plan_id,
                    "plan_digest_sha256": expected_plan_digest,
                    "environment": environment,
                    "repository": repository,
                    "has_destructive_changes": True,
                    "decision": DECISION_REJECTED,
                    "decision_code": conf_code,
                    "reason": conf_reason,
                    "metrics": metrics,
                    "policy_evaluation": {
                        "is_allowed": True,
                        "decision_code": pol_code,
                        "reason": pol_reason,
                    },
                    "confirmation_evaluation": conf_eval,
                }

        # 6. Both Policy and Confirmation Succeeded -> Authorized for Simulation
        return {
            "schema_version": ASSESSMENT_DECISION_SCHEMA_VERSION,
            "plan_id": expected_plan_id,
            "plan_digest_sha256": expected_plan_digest,
            "environment": environment,
            "repository": repository,
            "has_destructive_changes": True,
            "decision": DECISION_AUTHORIZED,
            "decision_code": "AUTHORIZED_SIMULATION_WITH_CONFIRMATION",
            "reason": f"Plan destructive changes ({pure_deletions} deletions, {replacements} replacements) verified within policy and authorized with confirmation",
            "metrics": metrics,
            "policy_evaluation": {
                "is_allowed": True,
                "decision_code": pol_code,
                "reason": pol_reason,
            },
            "confirmation_evaluation": conf_eval,
        }


# =============================================================================
# CLI Interface
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="InfraFlow — Controlled Destruction, Blast-Radius Protection & Failure Recovery"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: assess
    assess_parser = subparsers.add_parser("assess", help="Assess a Terraform plan JSON for destructive changes")
    assess_parser.add_argument("--plan-file", required=True, help="Path to Terraform plan JSON file")
    assess_parser.add_argument("--policy-file", default=None, help="Path to trusted destruction policy JSON")
    assess_parser.add_argument("--confirmation-file", default=None, help="Path to confirmation token JSON file")
    assess_parser.add_argument("--confirmation-token", default=None, help="Raw confirmation token string")
    assess_parser.add_argument("--expected-plan-id", required=True, help="Expected plan identifier")
    assess_parser.add_argument("--expected-digest", required=True, help="Expected plan SHA-256 digest")
    assess_parser.add_argument("--expected-repo", required=True, help="Expected calling repository")
    assess_parser.add_argument("--environment", default="production", help="Deployment environment context")
    assess_parser.add_argument("--max-deletions", type=int, default=None, help="Caller-specified maximum deletions limit")
    assess_parser.add_argument("--max-replacements", type=int, default=None, help="Caller-specified maximum replacements limit")
    assess_parser.add_argument("--trusted-authorizers", default=None, help="Comma-separated allowlist of trusted authorizers")
    assess_parser.add_argument("--output-json", default=None, help="Path to write assessment decision JSON")

    # Subcommand: create-confirmation
    create_conf_parser = subparsers.add_parser("create-confirmation", help="Create a synthetic confirmation token")
    create_conf_parser.add_argument("--plan-id", required=True)
    create_conf_parser.add_argument("--plan-digest", required=True)
    create_conf_parser.add_argument("--repo", required=True)
    create_conf_parser.add_argument("--environment", required=True)
    create_conf_parser.add_argument("--pure-deletions", type=int, required=True)
    create_conf_parser.add_argument("--replacements", type=int, required=True)
    create_conf_parser.add_argument("--authorized-by", required=True)
    create_conf_parser.add_argument("--ttl-seconds", type=int, default=3600)
    create_conf_parser.add_argument("--output-file", default=None)

    args = parser.parse_args()

    if args.command == "create-confirmation":
        token = DestructionConfirmationValidator.create_token(
            plan_id=args.plan_id,
            plan_digest_sha256=args.plan_digest,
            source_repository=args.repo,
            target_environment=args.environment,
            pure_deletions=args.pure_deletions,
            replacements=args.replacements,
            authorized_by=args.authorized_by,
            validity_seconds=args.ttl_seconds,
        )
        token_str = json.dumps(token, indent=2)
        if args.output_file:
            # Enforce restrictive 0600 file permissions
            fd = os.open(args.output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(token_str)
        else:
            print(token_str)
        sys.exit(0)

    elif args.command == "assess":
        try:
            # 1. Reject symlinks on all input files
            for fp, desc in [
                (args.plan_file, "plan file"),
                (args.policy_file, "policy file"),
                (args.confirmation_file, "confirmation file"),
            ]:
                if fp and os.path.islink(fp):
                    print(json.dumps({
                        "decision": DECISION_REJECTED,
                        "decision_code": "SYMLINK_PROHIBITED",
                        "reason": f"Symlinks are strictly prohibited for {desc}: '{fp}'"
                    }, indent=2))
                    sys.exit(1)

            # 2. Load plan
            if not os.path.exists(args.plan_file):
                print(json.dumps({
                    "decision": DECISION_REJECTED,
                    "decision_code": "PLAN_FILE_NOT_FOUND",
                    "reason": f"Plan file not found: {args.plan_file}"
                }, indent=2))
                sys.exit(1)

            with open(args.plan_file, "r", encoding="utf-8") as f:
                plan_data = json.load(f)

            # 3. Load policy
            policy: Optional[BlastRadiusPolicy] = None
            if args.policy_file:
                policy = BlastRadiusPolicy.from_file(args.policy_file, environment=args.environment)
            else:
                policy = BlastRadiusPolicy(environment=args.environment)

            # Apply caller bounds (min(policy, caller))
            policy = policy.apply_caller_bounds(args.max_deletions, args.max_replacements)

            # Apply trusted authorizers if passed via CLI
            if args.trusted_authorizers:
                auth_set = {a.strip() for a in args.trusted_authorizers.split(",") if a.strip()}
                if policy.trusted_authorizers:
                    policy.trusted_authorizers = policy.trusted_authorizers.intersection(auth_set)
                else:
                    policy.trusted_authorizers = auth_set

            # 4. Load confirmation token if provided
            token_input: Optional[Any] = None
            if args.confirmation_file and os.path.exists(args.confirmation_file):
                with open(args.confirmation_file, "r", encoding="utf-8") as cf:
                    token_input = json.load(cf)
            elif args.confirmation_token:
                token_input = args.confirmation_token

            # 5. Assess
            assessment = DestructivePlanAssessmentEngine.assess(
                plan_data=plan_data,
                expected_plan_id=args.expected_plan_id,
                expected_plan_digest=args.expected_digest,
                repository=args.expected_repo,
                environment=args.environment,
                policy=policy,
                confirmation_token=token_input,
            )

            result_str = json.dumps(assessment, indent=2)
            if args.output_json:
                fd = os.open(args.output_json, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(result_str)

            print(result_str)

            if assessment["decision"] == DECISION_AUTHORIZED:
                sys.exit(0)
            else:
                sys.exit(1)

        except DestructionAssessmentError as e:
            err_dict = {
                "decision": DECISION_REJECTED,
                "decision_code": e.decision_code,
                "reason": str(e),
            }
            print(json.dumps(err_dict, indent=2))
            sys.exit(1)
        except Exception as e:
            err_dict = {
                "decision": DECISION_REJECTED,
                "decision_code": "UNEXPECTED_ERROR",
                "reason": str(e),
            }
            print(json.dumps(err_dict, indent=2))
            sys.exit(1)


if __name__ == "__main__":
    main()
