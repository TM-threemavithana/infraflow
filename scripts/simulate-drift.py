#!/usr/bin/env python3
"""
InfraFlow — Continuous State & Speculative Drift Detection Simulator (Milestone G09.2)

Evaluates infrastructure state snapshots (Expected vs Observed) to detect, classify,
and report infrastructure drift without making live cloud API calls ($0.00 cloud spend).

Deterministic Classifications:
  - NO_DRIFT: Resource exists in both states with matching attributes.
  - ATTRIBUTE_DRIFT: Resource exists in both, but configuration attributes differ.
  - UNTRACKED_RESOURCE: Resource exists only in observed state (out-of-band creation / shadow IT).
  - RESOURCE_DELETED: Resource exists in expected state, but missing from observed state.
  - UNKNOWN_RESOURCE: Resource has unsupported provider, malformed ID, or invalid schema.
  - STATE_INCONSISTENCY: Schema violation, repository/workspace identity mismatch, or corrupted snapshot.

Security Controls:
  - Strict JSON schema validation (v1.0).
  - Explicit symlink rejection (os.path.islink).
  - Repository & workspace identity binding.
  - Automatic sensitive data regex scrubbing.
  - Deterministic canonical sorting.
  - Read-only simulation: strictly no automatic infrastructure modification or remediation.
"""

import argparse
import copy
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Supported Cloud Providers in InfraFlow
SUPPORTED_PROVIDERS = {"aws", "azure", "gcp"}

# Provider Aliases
PROVIDER_ALIASES = {
    "azurerm": "azure",
    "google": "gcp",
}

# Supported Drift Categories
VALID_DRIFT_CATEGORIES = {
    "NO_DRIFT",
    "ATTRIBUTE_DRIFT",
    "UNTRACKED_RESOURCE",
    "RESOURCE_DELETED",
    "UNKNOWN_RESOURCE",
    "STATE_INCONSISTENCY",
}

# Security-critical attribute keys that trigger CRITICAL or HIGH severity
CRITICAL_SECURITY_ATTRIBUTES = {
    "sse_algorithm",
    "kms_master_key_id",
    "uniform_bucket_level_access",
    "min_tls_version",
    "allow_nested_items_to_be_public",
    "acl",
    "public_network_access_enabled",
    "enable_key_rotation",
    "versioning_enabled",
    "point_in_time_recovery",
}

HIGH_SECURITY_ATTRIBUTES = {
    "ingress",
    "egress",
    "cidr_blocks",
    "rules",
    "role",
    "members",
    "ip_configuration",
}

# Common sensitive data regex patterns to scrub
SENSITIVE_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)(aws_secret_access_key|secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), r"\1=[REDACTED_AWS_SECRET]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(password|secret|token|client_secret|api_key|auth_token)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"), r"\1=[REDACTED_SECRET]"),
]


class DriftSecurityError(Exception):
    """Raised when security boundaries (symlinks, path traversal, identity mismatch) are violated."""
    pass


class DriftValidationError(Exception):
    """Raised when input state files fail schema validation."""
    pass


def scrub_sensitive_data(val: Any, key_hint: str = "") -> Any:
    """Recursively redacts sensitive credentials and tokens from values."""
    if isinstance(val, str):
        scrubbed = val
        for pattern, replacement in SENSITIVE_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        if scrubbed != val:
            return scrubbed
        if key_hint and any(s in key_hint.lower() for s in ("secret", "token", "password", "api_key", "credential", "private_key")):
            return "[REDACTED_SECRET]"
        return scrubbed
    elif isinstance(val, dict):
        new_dict = {}
        for k, v in val.items():
            scrubbed_v = scrub_sensitive_data(v, key_hint=k)
            if any(s in k.lower() for s in ("secret", "token", "password", "api_key", "credential", "private_key")) and scrubbed_v == v:
                new_dict[k] = "[REDACTED_SECRET]"
            else:
                new_dict[k] = scrubbed_v
        return new_dict
    elif isinstance(val, list):
        return [scrub_sensitive_data(item, key_hint=key_hint) for item in val]
    return val


def validate_iso8601_timestamp(ts_str: str) -> bool:
    """Validates that a string is a valid ISO 8601 UTC timestamp."""
    if not isinstance(ts_str, str):
        return False
    try:
        if ts_str.endswith("Z"):
            datetime.fromisoformat(ts_str[:-1] + "+00:00")
            return True
        datetime.fromisoformat(ts_str)
        return True
    except (ValueError, TypeError):
        return False


def normalize_provider(prov: str) -> str:
    """Normalizes provider name to canonical form."""
    p = str(prov).lower().strip()
    return PROVIDER_ALIASES.get(p, p)


def safe_load_state_file(file_path: Path) -> Dict[str, Any]:
    """Safely loads and validates a JSON state file with symlink and schema checks."""
    # 1. Symlink check
    if file_path.is_symlink() or os.path.islink(file_path):
        raise DriftSecurityError(f"Security rejection: Symlink detected at '{file_path}'. Symlinks are strictly prohibited.")

    if not file_path.exists():
        raise DriftValidationError(f"State file does not exist: '{file_path}'")

    if not file_path.is_file():
        raise DriftValidationError(f"Path is not a regular file: '{file_path}'")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise DriftValidationError(f"Invalid JSON in state file '{file_path}': {e}")
    except Exception as e:
        raise DriftValidationError(f"Error reading state file '{file_path}': {e}")

    # 2. Strict Schema Validation
    if not isinstance(data, dict):
        raise DriftValidationError(f"State root must be a JSON object, got {type(data).__name__}")

    if data.get("schema_version") != "1.0":
        raise DriftValidationError(f"Unsupported schema_version '{data.get('schema_version')}'. Expected '1.0'")

    for req_key in ("provider", "repository", "workspace", "timestamp", "resources"):
        if req_key not in data:
            raise DriftValidationError(f"Missing mandatory field '{req_key}' in state file '{file_path}'")

    norm_prov = normalize_provider(data["provider"])
    if norm_prov not in SUPPORTED_PROVIDERS:
        raise DriftValidationError(f"Unsupported provider '{data['provider']}'. Must be one of: {sorted(list(SUPPORTED_PROVIDERS))}")

    if not validate_iso8601_timestamp(data["timestamp"]):
        raise DriftValidationError(f"Invalid timestamp '{data['timestamp']}'. Must be valid ISO 8601")

    if not isinstance(data["resources"], list):
        raise DriftValidationError(f"'resources' field must be a list, got {type(data['resources']).__name__}")

    # Validate each resource
    seen_ids: Set[str] = set()
    for idx, r in enumerate(data["resources"]):
        if not isinstance(r, dict):
            raise DriftValidationError(f"Resource at index {idx} must be a JSON object")
        for r_key in ("resource_id", "provider", "resource_type", "attributes"):
            if r_key not in r:
                raise DriftValidationError(f"Resource at index {idx} missing mandatory key '{r_key}'")

        r_id = r["resource_id"]
        if not isinstance(r_id, str) or not r_id.strip():
            raise DriftValidationError(f"Resource at index {idx} has invalid resource_id")

        if r_id in seen_ids:
            raise DriftValidationError(f"Duplicate resource_id '{r_id}' detected in state file '{file_path}'")
        seen_ids.add(r_id)

        if not isinstance(r["attributes"], dict):
            raise DriftValidationError(f"Resource '{r_id}' attributes must be a dictionary")

    return data


def compute_attribute_diffs(
    expected_attrs: Dict[str, Any],
    observed_attrs: Dict[str, Any],
    prefix: str = "",
) -> List[Dict[str, Any]]:
    """Recursively computes attribute differences between expected and observed state."""
    diffs: List[Dict[str, Any]] = []

    all_keys = sorted(set(list(expected_attrs.keys()) + list(observed_attrs.keys())))

    for k in all_keys:
        curr_path = f"{prefix}.{k}" if prefix else k

        if k not in expected_attrs:
            diffs.append({
                "attribute_path": curr_path,
                "change_type": "ADDED",
                "expected_value": None,
                "observed_value": scrub_sensitive_data(observed_attrs[k], key_hint=k),
            })
        elif k not in observed_attrs:
            diffs.append({
                "attribute_path": curr_path,
                "change_type": "DELETED",
                "expected_value": scrub_sensitive_data(expected_attrs[k], key_hint=k),
                "observed_value": None,
            })
        else:
            exp_val = expected_attrs[k]
            obs_val = observed_attrs[k]

            if isinstance(exp_val, dict) and isinstance(obs_val, dict):
                child_diffs = compute_attribute_diffs(exp_val, obs_val, prefix=curr_path)
                diffs.extend(child_diffs)
            elif exp_val != obs_val:
                diffs.append({
                    "attribute_path": curr_path,
                    "change_type": "MODIFIED",
                    "expected_value": scrub_sensitive_data(exp_val, key_hint=k),
                    "observed_value": scrub_sensitive_data(obs_val, key_hint=k),
                })

    return sorted(diffs, key=lambda d: d["attribute_path"])


def determine_attribute_drift_severity(attribute_diffs: List[Dict[str, Any]]) -> str:
    """Calculates severity for an attribute drift finding based on affected attributes."""
    has_critical = False
    has_high = False

    for diff in attribute_diffs:
        path = diff["attribute_path"].lower()
        key_name = path.split(".")[-1]

        if key_name in CRITICAL_SECURITY_ATTRIBUTES or any(c in path for c in ("security", "encryption", "tls", "acl", "access")):
            has_critical = True
        elif key_name in HIGH_SECURITY_ATTRIBUTES or any(h in path for h in ("network", "firewall", "role", "iam")):
            has_high = True

    if has_critical:
        return "CRITICAL"
    if has_high:
        return "HIGH"
    return "MEDIUM"


def assess_state_drift(
    expected_data: Dict[str, Any],
    observed_data: Dict[str, Any],
    expected_file: Optional[Path] = None,
    observed_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Compares expected and observed infrastructure states and classifies all drift.
    Returns a deterministic structured drift report dictionary.
    """
    # 1. Identity & Context Binding Checks
    exp_repo = expected_data.get("repository")
    obs_repo = observed_data.get("repository")
    if exp_repo != obs_repo:
        raise DriftSecurityError(
            f"Repository identity mismatch: Expected '{exp_repo}' vs Observed '{obs_repo}'. "
            "State comparisons across different repositories are strictly forbidden."
        )

    exp_ws = expected_data.get("workspace")
    obs_ws = observed_data.get("workspace")
    if exp_ws != obs_ws:
        raise DriftSecurityError(
            f"Workspace identity mismatch: Expected '{exp_ws}' vs Observed '{obs_ws}'. "
            "Cross-workspace state comparison is rejected fail-closed."
        )

    exp_prov = normalize_provider(expected_data.get("provider", ""))
    obs_prov = normalize_provider(observed_data.get("provider", ""))
    if exp_prov != obs_prov:
        raise DriftSecurityError(
            f"Provider mismatch: Expected '{exp_prov}' vs Observed '{obs_prov}'."
        )

    expected_resources: Dict[str, Dict[str, Any]] = {
        r["resource_id"]: r for r in expected_data.get("resources", [])
    }
    observed_resources: Dict[str, Dict[str, Any]] = {
        r["resource_id"]: r for r in observed_data.get("resources", [])
    }

    drift_items: List[Dict[str, Any]] = []
    clean_resources_count = 0

    all_ids = sorted(set(list(expected_resources.keys()) + list(observed_resources.keys())))

    for r_id in all_ids:
        in_exp = r_id in expected_resources
        in_obs = r_id in observed_resources

        if in_exp and not in_obs:
            # RESOURCE_DELETED
            exp_res = expected_resources[r_id]
            drift_items.append({
                "resource_id": r_id,
                "provider": normalize_provider(exp_res.get("provider", exp_prov)),
                "resource_type": exp_res.get("resource_type", "unknown"),
                "drift_category": "RESOURCE_DELETED",
                "severity": "CRITICAL",
                "expected_state": scrub_sensitive_data(exp_res),
                "observed_state": None,
                "attribute_diffs": [],
                "remediation_hint": f"Resource '{r_id}' was deleted remotely out-of-band. Run speculative plan to reconcile.",
            })

        elif in_obs and not in_exp:
            # UNTRACKED_RESOURCE
            obs_res = observed_resources[r_id]
            drift_items.append({
                "resource_id": r_id,
                "provider": normalize_provider(obs_res.get("provider", obs_prov)),
                "resource_type": obs_res.get("resource_type", "unknown"),
                "drift_category": "UNTRACKED_RESOURCE",
                "severity": "HIGH",
                "expected_state": None,
                "observed_state": scrub_sensitive_data(obs_res),
                "attribute_diffs": [],
                "remediation_hint": f"Resource '{r_id}' was created out-of-band (shadow IT). Import into Terraform or delete.",
            })

        else:
            # Present in both
            exp_res = expected_resources[r_id]
            obs_res = observed_resources[r_id]

            # Check structural consistency
            if exp_res.get("resource_type") != obs_res.get("resource_type"):
                drift_items.append({
                    "resource_id": r_id,
                    "provider": exp_prov,
                    "resource_type": exp_res.get("resource_type", "unknown"),
                    "drift_category": "STATE_INCONSISTENCY",
                    "severity": "CRITICAL",
                    "expected_state": scrub_sensitive_data(exp_res),
                    "observed_state": scrub_sensitive_data(obs_res),
                    "attribute_diffs": [],
                    "remediation_hint": f"Type mismatch between expected ({exp_res.get('resource_type')}) and observed ({obs_res.get('resource_type')}).",
                })
                continue

            diffs = compute_attribute_diffs(
                exp_res.get("attributes", {}),
                obs_res.get("attributes", {}),
            )

            if diffs:
                severity = determine_attribute_drift_severity(diffs)
                drift_items.append({
                    "resource_id": r_id,
                    "provider": exp_prov,
                    "resource_type": exp_res.get("resource_type", "unknown"),
                    "drift_category": "ATTRIBUTE_DRIFT",
                    "severity": severity,
                    "expected_state": scrub_sensitive_data(exp_res),
                    "observed_state": scrub_sensitive_data(obs_res),
                    "attribute_diffs": diffs,
                    "remediation_hint": f"Attribute modifications detected on '{r_id}'. Run speculative plan to review drift.",
                })
            else:
                clean_resources_count += 1

    # Sort drift items deterministically by resource_id
    drift_items = sorted(drift_items, key=lambda item: item["resource_id"])

    # Aggregate breakdown
    drift_breakdown = {cat: 0 for cat in sorted(list(VALID_DRIFT_CATEGORIES))}
    for item in drift_items:
        drift_breakdown[item["drift_category"]] += 1

    severities = [item["severity"] for item in drift_items]
    if "CRITICAL" in severities:
        highest_severity = "CRITICAL"
    elif "HIGH" in severities:
        highest_severity = "HIGH"
    elif "MEDIUM" in severities:
        highest_severity = "MEDIUM"
    elif "LOW" in severities:
        highest_severity = "LOW"
    else:
        highest_severity = "NONE"

    verdict = "DRIFT_DETECTED" if drift_items else "NO_DRIFT"

    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evaluation_context": {
            "repository": exp_repo,
            "workspace": exp_ws,
            "provider": exp_prov,
            "expected_state_file": str(expected_file) if expected_file else "in-memory",
            "observed_state_file": str(observed_file) if observed_file else "in-memory",
        },
        "summary": {
            "verdict": verdict,
            "total_resources_evaluated": len(all_ids),
            "drifted_resources_count": len(drift_items),
            "clean_resources_count": clean_resources_count,
            "drift_breakdown": drift_breakdown,
            "highest_severity": highest_severity,
        },
        "drift_items": drift_items,
    }

    return report


def render_markdown_drift_report(report: Dict[str, Any]) -> str:
    """Renders a GitHub Step Summary Markdown report from a drift assessment."""
    summary = report["summary"]
    ctx = report["evaluation_context"]
    verdict = summary["verdict"]

    verdict_badge = "🟢 **NO DRIFT DETECTED**" if verdict == "NO_DRIFT" else "🔴 **INFRASTRUCTURE DRIFT IDENTIFIED**"
    severity_badge = f"`{summary['highest_severity']}`"

    lines = [
        "## 🔍 InfraFlow Speculative Drift Detection Assessment",
        "",
        f"**Status**: {verdict_badge} | **Highest Severity**: {severity_badge}",
        f"**Repository**: `{ctx.get('repository')}` | **Workspace**: `{ctx.get('workspace')}` | **Provider**: `{ctx.get('provider')}`",
        "",
        "### Summary Metrics",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Total Resources Evaluated** | `{summary['total_resources_evaluated']}` |",
        f"| **Clean (Synchronized) Resources** | `{summary['clean_resources_count']}` |",
        f"| **Drifted Resources** | `{summary['drifted_resources_count']}` |",
        f"| **Attribute Drift** | `{summary['drift_breakdown'].get('ATTRIBUTE_DRIFT', 0)}` |",
        f"| **Untracked Resources (Shadow IT)** | `{summary['drift_breakdown'].get('UNTRACKED_RESOURCE', 0)}` |",
        f"| **Remote Deletions** | `{summary['drift_breakdown'].get('RESOURCE_DELETED', 0)}` |",
        f"| **State Inconsistencies** | `{summary['drift_breakdown'].get('STATE_INCONSISTENCY', 0)}` |",
        "",
    ]

    drift_items = report.get("drift_items", [])
    if drift_items:
        lines.append("### Detailed Drift Findings")
        lines.append("")
        lines.append("| Resource ID | Type | Provider | Drift Category | Severity | Remediation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for item in drift_items:
            lines.append(
                f"| `{item['resource_id']}` | `{item['resource_type']}` | `{item['provider']}` | "
                f"**`{item['drift_category']}`** | `{item['severity']}` | {item['remediation_hint']} |"
            )
        lines.append("")

        lines.append("### Attribute Differences")
        lines.append("")
        for item in drift_items:
            diffs = item.get("attribute_diffs", [])
            if diffs:
                lines.append(f"<details><summary><b>Diff for {item['resource_id']}</b> ({len(diffs)} attributes modified)</summary>")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(diffs, indent=2))
                lines.append("```")
                lines.append("</details>")
                lines.append("")
    else:
        lines.append("> [!TIP]")
        lines.append("> Infrastructure state is fully synchronized. Zero drift detected across all evaluated resources.")

    return "\n".join(lines)


def emit_drift_telemetry(
    report: Dict[str, Any],
    output_path: Optional[Path] = None,
) -> None:
    """Emits structured telemetry events via emit-telemetry.py CLI or programmatic call."""
    summary = report["summary"]
    ctx = report["evaluation_context"]
    repo = ctx.get("repository", "unknown")
    prov = ctx.get("provider", "unknown")
    drift_items = report.get("drift_items", [])

    # We call scripts/emit-telemetry.py directly via import if available
    try:
        from importlib.util import module_from_spec, spec_from_file_location
        emit_script = Path(__file__).parent / "emit-telemetry.py"
        if emit_script.exists():
            spec = spec_from_file_location("emit_telemetry", emit_script)
            if spec and spec.loader:
                mod = module_from_spec(spec)
                spec.loader.exec_module(mod)

                # Emit individual drift_detected events for each drifted resource
                for item in drift_items:
                    evt = mod.create_telemetry_event(
                        event_type="drift_detected",
                        consumer_id=item["resource_id"],
                        repository=repo,
                        status="WARN" if item["severity"] in ("MEDIUM", "LOW") else "FAIL",
                        adapter=prov,
                        verdict_reasons=[f"{item['drift_category']} detected on {item['resource_id']}"],
                        metrics={
                            "attributes_drifted": len(item.get("attribute_diffs", [])),
                        },
                    )
                    # Enrich event target
                    evt["target"]["drift_category"] = item["drift_category"]
                    evt["target"]["severity"] = item["severity"]
                    # Recompute integrity
                    evt["integrity"]["event_digest"] = mod.compute_event_digest(evt)

                    if output_path:
                        with open(output_path, "a", encoding="utf-8") as f:
                            f.write(json.dumps(evt) + "\n")

                # Emit overall drift_assessment_completed
                overall_status = "PASS" if summary["verdict"] == "NO_DRIFT" else "FAIL"
                summary_evt = mod.create_telemetry_event(
                    event_type="drift_assessment_completed",
                    consumer_id=repo.split("/")[-1],
                    repository=repo,
                    status=overall_status,
                    adapter=prov,
                    metrics={
                        "total_resources_evaluated": summary["total_resources_evaluated"],
                        "drifted_resources_count": summary["drifted_resources_count"],
                        "clean_resources_count": summary["clean_resources_count"],
                    },
                    verdict_reasons=[f"Verdict: {summary['verdict']} (Highest Severity: {summary['highest_severity']})"],
                )
                summary_evt["integrity"]["event_digest"] = mod.compute_event_digest(summary_evt)
                if output_path:
                    with open(output_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(summary_evt) + "\n")
    except Exception as e:
        sys.stderr.write(f"[WARNING] Failed emitting telemetry: {e}\n")


def build_argument_parser() -> argparse.ArgumentParser:
    """Constructs command line argument parser."""
    parser = argparse.ArgumentParser(
        description="InfraFlow — Continuous State & Speculative Drift Detection Simulator (Milestone G09.2)"
    )
    parser.add_argument(
        "--expected",
        type=Path,
        required=True,
        help="Path to expected state JSON file",
    )
    parser.add_argument(
        "--observed",
        type=Path,
        required=True,
        help="Path to observed state JSON file",
    )
    parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp"],
        help="Optional provider validation filter",
    )
    parser.add_argument(
        "--repository",
        help="Expected repository identity binding",
    )
    parser.add_argument(
        "--workspace",
        help="Expected workspace identity binding",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Path to export machine-readable JSON drift report",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        help="Path to export markdown drift summary",
    )
    parser.add_argument(
        "--emit-telemetry",
        action="store_true",
        help="Emit structured telemetry events",
    )
    parser.add_argument(
        "--telemetry-output",
        type=Path,
        help="Destination JSONL file for telemetry append",
    )
    parser.add_argument(
        "--enforce-zero-drift",
        action="store_true",
        help="Exit with code 1 if any infrastructure drift is detected",
    )
    return parser


def main() -> None:
    """Main CLI entrypoint."""
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        # Load state files
        expected_data = safe_load_state_file(args.expected)
        observed_data = safe_load_state_file(args.observed)

        # CLI-level binding assertions
        if args.provider:
            exp_p = normalize_provider(expected_data["provider"])
            obs_p = normalize_provider(observed_data["provider"])
            if exp_p != args.provider or obs_p != args.provider:
                raise DriftSecurityError(f"Provider flag '--provider {args.provider}' does not match state providers ({exp_p}, {obs_p})")

        if args.repository:
            if expected_data["repository"] != args.repository or observed_data["repository"] != args.repository:
                raise DriftSecurityError(f"Repository flag '--repository {args.repository}' does not match state repository")

        if args.workspace:
            if expected_data["workspace"] != args.workspace or observed_data["workspace"] != args.workspace:
                raise DriftSecurityError(f"Workspace flag '--workspace {args.workspace}' does not match state workspace")

        # Assess drift
        report = assess_state_drift(
            expected_data,
            observed_data,
            expected_file=args.expected,
            observed_file=args.observed,
        )

        # JSON Export
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"JSON drift report written to: {args.output_json}")
        else:
            print(json.dumps(report, indent=2))

        # Markdown Export
        if args.output_markdown:
            args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
            md_content = render_markdown_drift_report(report)
            with open(args.output_markdown, "w", encoding="utf-8") as f:
                f.write(md_content)
            print(f"Markdown drift report written to: {args.output_markdown}")

        # Telemetry
        if args.emit_telemetry:
            telemetry_dest = args.telemetry_output or Path("reports/telemetry.jsonl")
            telemetry_dest.parent.mkdir(parents=True, exist_ok=True)
            emit_drift_telemetry(report, output_path=telemetry_dest)
            print(f"Emitted drift telemetry to: {telemetry_dest}")

        # Exit code evaluation
        if args.enforce_zero_drift and report["summary"]["verdict"] != "NO_DRIFT":
            sys.stderr.write(f"\n[FAIL] Drift gate failed: {report['summary']['drifted_resources_count']} drifted resources detected.\n")
            sys.exit(1)

        sys.exit(0)

    except DriftSecurityError as e:
        sys.stderr.write(f"[SECURITY ERROR] {e}\n")
        # Try emitting failure telemetry
        sys.exit(2)
    except DriftValidationError as e:
        sys.stderr.write(f"[VALIDATION ERROR] {e}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"[UNEXPECTED ERROR] {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
