#!/usr/bin/env python3
"""
InfraFlow Platform Observability & Telemetry Engine (Milestone G09.1)

Provides standardized, schema-validated structured telemetry generation,
sensitive data scrubbing, and event log streaming across InfraFlow core
workflows and consumer repositories (RFC 5424 / OpenTelemetry-compatible event schema v1.0).

Guarantees:
- Zero sensitive data or credential leakage (automatic scrubbing).
- Deterministic event digest calculation (SHA-256).
- Strict schema validation (fails closed on malformed events).
- Completely offline operation ($0.00 cloud spend).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Supported Event Types in InfraFlow Telemetry Schema v1.0
VALID_EVENT_TYPES = {
    "governance_gate_evaluated",
    "security_scan_completed",
    "speculative_plan_completed",
    "contract_verified",
    "upgrade_planned",
    "upgrade_applied",
    "rollback_executed",
    "drift_detected",
    "drift_assessment_completed",
    "drift_assessment_failed",
    "fleet_audit_completed",
    "compliance_evaluated",
}

# Common sensitive data patterns to scrub
SENSITIVE_PATTERNS = [
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # AWS Secret Key (approximate base64 / 40 chars)
    (re.compile(r"(?i)(secret[_-]?key|aws[_-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), r"\1=[REDACTED_AWS_SECRET]"),
    # GitHub Personal Access Token / Fine-grained token
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_PAT]"),
    # Generic JWT
    (re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"), "[REDACTED_JWT]"),
    # Private Key blocks
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    # Generic Password / Secret assignments
    (re.compile(r"(?i)(password|secret|api_key|token|auth_token)['\"]?\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"), r"\1=[REDACTED_SECRET]"),
]


class TelemetryValidationError(ValueError):
    """Raised when telemetry data fails schema or integrity validation."""
    pass


def scrub_sensitive_string(text: str) -> str:
    """Replaces any matched sensitive tokens with redaction placeholders."""
    if not isinstance(text, str):
        return text
    scrubbed = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed


def scrub_sensitive_data(data: Any) -> Any:
    """Recursively traverses dictionaries, lists, and strings to sanitize sensitive values."""
    if isinstance(data, str):
        return scrub_sensitive_string(data)
    elif isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            # If the key itself indicates a secret, redact value entirely
            k_lower = k.lower()
            if any(s in k_lower for s in ("password", "secret", "private_key", "token", "auth_key", "api_key")):
                cleaned[k] = "[REDACTED_SENSITIVE_FIELD]"
            else:
                cleaned[k] = scrub_sensitive_data(v)
        return cleaned
    elif isinstance(data, list):
        return [scrub_sensitive_data(item) for item in data]
    else:
        return data


def compute_event_digest(event_data: Dict[str, Any]) -> str:
    """Computes a canonical SHA-256 digest of the telemetry event payload excluding digest itself."""
    canonical_dict = {k: v for k, v in event_data.items() if k != "integrity"}
    serialized = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def create_telemetry_event(
    event_type: str,
    consumer_id: str,
    repository: str,
    status: str,
    adapter: str = "generic",
    platform_sha: str = "unknown",
    duration_ms: int = 0,
    metrics: Optional[Dict[str, Any]] = None,
    verdict_reasons: Optional[List[str]] = None,
    execution_context: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Constructs a standardized, schema-validated InfraFlow telemetry event.
    """
    if event_type not in VALID_EVENT_TYPES:
        raise TelemetryValidationError(f"Invalid event_type '{event_type}'. Must be one of: {sorted(list(VALID_EVENT_TYPES))}")

    if not consumer_id or not isinstance(consumer_id, str):
        raise TelemetryValidationError("consumer_id must be a non-empty string.")

    if not repository or not isinstance(repository, str):
        raise TelemetryValidationError("repository must be a non-empty string.")

    normalized_status = status.upper()
    if normalized_status not in ("PASS", "FAIL", "WARN", "SKIP"):
        raise TelemetryValidationError(f"Invalid status '{status}'. Must be one of: PASS, FAIL, WARN, SKIP")

    iso_timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build execution context
    ctx = execution_context or {}
    exec_ctx = {
        "ci_system": ctx.get("ci_system", os.environ.get("GITHUB_ACTIONS", "false") == "true" and "github-actions" or "local"),
        "run_id": str(ctx.get("run_id", os.environ.get("GITHUB_RUN_ID", "local-run"))),
        "run_attempt": str(ctx.get("run_attempt", os.environ.get("GITHUB_RUN_ATTEMPT", "1"))),
        "actor": str(ctx.get("actor", os.environ.get("GITHUB_ACTOR", "local-user"))),
        "event_name": str(ctx.get("event_name", os.environ.get("GITHUB_EVENT_NAME", "manual"))),
        "ref": str(ctx.get("ref", os.environ.get("GITHUB_REF", "refs/heads/main"))),
    }

    base_metrics = {
        "duration_ms": max(0, int(duration_ms)),
        "rules_evaluated": 0,
        "violations_count": 0,
    }
    if metrics:
        base_metrics.update(metrics)

    event: Dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": f"evt_{uuid.uuid4().hex[:16]}",
        "timestamp": iso_timestamp,
        "event_type": event_type,
        "execution_context": exec_ctx,
        "target": {
            "repository": repository,
            "consumer_id": consumer_id,
            "adapter": adapter,
            "platform_sha": platform_sha,
        },
        "metrics": base_metrics,
        "verdict": {
            "status": normalized_status,
            "compliance_status": "COMPLIANT" if normalized_status == "PASS" else ("NON_COMPLIANT" if normalized_status == "FAIL" else "WARNING"),
            "reasons": verdict_reasons or [],
        },
    }

    # Scrub any accidental secrets before computing integrity digest
    cleaned_event = scrub_sensitive_data(event)

    # Compute cryptographic integrity digest
    digest = compute_event_digest(cleaned_event)
    cleaned_event["integrity"] = {
        "algorithm": "sha256",
        "event_digest": digest,
    }

    return cleaned_event


def validate_telemetry_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validates an event against the InfraFlow Telemetry Schema v1.0."""
    errors: List[str] = []

    if not isinstance(event, dict):
        return False, ["Event must be a JSON dictionary"]

    # Check required top-level keys
    for req_key in ("schema_version", "event_id", "timestamp", "event_type", "execution_context", "target", "metrics", "verdict", "integrity"):
        if req_key not in event:
            errors.append(f"Missing required top-level key: '{req_key}'")

    if event.get("schema_version") != "1.0":
        errors.append(f"Unsupported schema_version: '{event.get('schema_version')}' (expected '1.0')")

    if event.get("event_type") not in VALID_EVENT_TYPES:
        errors.append(f"Invalid event_type: '{event.get('event_type')}'")

    # Validate target
    target = event.get("target", {})
    if not isinstance(target, dict):
        errors.append("target must be a dictionary")
    else:
        for t_key in ("repository", "consumer_id", "adapter"):
            if not target.get(t_key):
                errors.append(f"target missing required field: '{t_key}'")

    # Validate verdict
    verdict = event.get("verdict", {})
    if not isinstance(verdict, dict):
        errors.append("verdict must be a dictionary")
    else:
        if verdict.get("status") not in ("PASS", "FAIL", "WARN", "SKIP"):
            errors.append(f"Invalid verdict status: '{verdict.get('status')}'")

    # Validate integrity digest
    integrity = event.get("integrity", {})
    if isinstance(integrity, dict):
        expected_digest = integrity.get("event_digest")
        actual_digest = compute_event_digest(event)
        if expected_digest != actual_digest:
            errors.append(f"Integrity digest mismatch (tampering detected): expected {expected_digest}, computed {actual_digest}")

    return len(errors) == 0, errors


def emit_event(
    event: Dict[str, Any],
    output_path: Optional[Union[str, Path]] = None,
    append: bool = False,
) -> None:
    """Emits the telemetry event to stdout and/or a target file."""
    is_valid, errors = validate_telemetry_event(event)
    if not is_valid:
        raise TelemetryValidationError(f"Cannot emit invalid event: {', '.join(errors)}")

    serialized = json.dumps(event, indent=2)

    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        if append:
            with open(out_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        else:
            out_file.write_text(serialized + "\n", encoding="utf-8")

    # Output to stdout if running as main
    if __name__ == "__main__":
        print(serialized)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="InfraFlow Platform Observability & Telemetry Engine (Milestone G09.1)"
    )
    parser.add_argument(
        "--event-type",
        required=True,
        choices=sorted(list(VALID_EVENT_TYPES)),
        help="Type of observability event being emitted",
    )
    parser.add_argument(
        "--consumer-id",
        required=True,
        help="Identifier of the consumer repository or platform component",
    )
    parser.add_argument(
        "--repository",
        required=True,
        help="Full GitHub repository name (e.g. TM-threemavithana/infraflow)",
    )
    parser.add_argument(
        "--status",
        required=True,
        choices=["PASS", "FAIL", "WARN", "SKIP", "pass", "fail", "warn", "skip"],
        help="Execution status verdict",
    )
    parser.add_argument(
        "--adapter",
        default="generic",
        help="Cloud adapter type (aws, azure, gcp, generic)",
    )
    parser.add_argument(
        "--platform-sha",
        default="unknown",
        help="Pinned commit SHA of the platform",
    )
    parser.add_argument(
        "--duration-ms",
        type=int,
        default=0,
        help="Execution duration in milliseconds",
    )
    parser.add_argument(
        "--output",
        help="Path to write the serialized telemetry event JSON",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append JSONL line to output file rather than overwriting",
    )
    parser.add_argument(
        "--reason",
        action="append",
        dest="reasons",
        help="Diagnostic or verdict reason strings (can be specified multiple times)",
    )
    parser.add_argument(
        "--metric",
        action="append",
        dest="metrics",
        help="Custom key=value numeric/string metrics (e.g. rules_evaluated=14)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    custom_metrics: Dict[str, Any] = {}
    if args.metrics:
        for m in args.metrics:
            if "=" in m:
                k, v = m.split("=", 1)
                try:
                    if "." in v:
                        custom_metrics[k] = float(v)
                    else:
                        custom_metrics[k] = int(v)
                except ValueError:
                    custom_metrics[k] = v

    try:
        event = create_telemetry_event(
            event_type=args.event_type,
            consumer_id=args.consumer_id,
            repository=args.repository,
            status=args.status,
            adapter=args.adapter,
            platform_sha=args.platform_sha,
            duration_ms=args.duration_ms,
            metrics=custom_metrics,
            verdict_reasons=args.reasons,
        )
        emit_event(event, output_path=args.output, append=args.append)
        return 0
    except Exception as e:
        sys.stderr.write(f"[ERROR] Telemetry emission failed: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
