#!/usr/bin/env python3
"""
InfraFlow Consumer Repository Onboarding Validator (Milestone G08.1)

Validates consumer repository configuration (infraflow.config.yaml), workflow
security permissions, directory containment, and platform dependency pinning
against InfraFlow enterprise adoption contracts.

Exit Codes:
  0 - All validation checks passed cleanly.
  1 - One or more validation errors detected.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ==============================================================================
# Contract Schemas & Regular Expressions
# ==============================================================================

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
SUPPORTED_WORKLOAD_TYPES = {"networking", "application", "data-platform", "general"}
SUPPORTED_ENVIRONMENTS = {"dev", "staging", "prod"}
SUPPORTED_ADAPTERS = {"provider-neutral", "aws", "gcp", "azure", "apply-simulation"}
CANONICAL_PLATFORM_REF = "TM-threemavithana/infraflow"

RE_CONSUMER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
RE_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
RE_SEMVER = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-[a-zA-Z0-9.]+)?$")
RE_PATH_TRAVERSAL = re.compile(r"(^|[\\/])\.\.([\\/]|$)")

KNOWN_CONFIG_KEYS = {
    "version",
    "consumer_id",
    "team",
    "workload_type",
    "terraform_dir",
    "environment",
    "adapter",
    "platform_ref",
    "platform_sha",
    "terraform_version",
    "security_controls",
}

KNOWN_SECURITY_CONTROL_KEYS = {
    "enforce_mandatory_scanners",
    "fail_on_destructive",
    "max_allowed_deletions",
}

DISALLOWED_CLOUD_AUTH_KEYS = {
    "enable-aws-auth",
    "enable-gcp-auth",
    "enable-azure-auth",
    "enable_aws_auth",
    "enable_gcp_auth",
    "enable_azure_auth",
}


# ==============================================================================
# Validation Result Logger
# ==============================================================================

class ValidationResult:
    def __init__(self):
        self.passes: List[str] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def record_pass(self, check: str):
        self.passes.append(check)

    def record_fail(self, check: str, detail: str):
        self.errors.append(f"{check}: {detail}")

    def record_warn(self, check: str, detail: str):
        self.warnings.append(f"{check}: {detail}")

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def print_report(self, quiet: bool = False):
        if not quiet:
            for p in self.passes:
                print(f"  [ PASS ] {p}")
            for w in self.warnings:
                print(f"  [ WARN ] {w}")
            for e in self.errors:
                print(f"  [ FAIL ] {e}")
            print("=" * 70)
            print(f"Total Checks: {len(self.passes) + len(self.errors)}")
            print(f"Passed: {len(self.passes)} | Failed: {len(self.errors)} | Warnings: {len(self.warnings)}")
            if self.is_valid:
                print(">>> ALL CONSUMER ONBOARDING CHECKS PASSED <<<")
            else:
                print(">>> CONSUMER ONBOARDING VALIDATION FAILED <<<")


# ==============================================================================
# Lightweight YAML Parser Fallback (When PyYAML is absent)
# ==============================================================================

def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Basic line-based parser supporting simple key: value and 1-level nested dicts."""
    data: Dict[str, Any] = {}
    current_dict = data
    current_parent_key = None

    for line_num, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent > 0 and current_parent_key is not None:
            # Sub-key
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip().split("#")[0].strip()
                parsed_v = _parse_yaml_scalar(v)
                if isinstance(data.get(current_parent_key), dict):
                    data[current_parent_key][k] = parsed_v
            continue

        if ":" in stripped:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip().split("#")[0].strip()
            if not v:
                # Parent key of a block
                current_parent_key = k
                data[k] = {}
            else:
                current_parent_key = None
                data[k] = _parse_yaml_scalar(v)

    return data


def _parse_yaml_scalar(val: str) -> Any:
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    if val.startswith("'") and val.endswith("'"):
        return val[1:-1]
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.lower() == "null":
        return None
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val


def load_config_file(config_path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not config_path.is_file():
        return None, f"Configuration file not found: {config_path}"

    try:
        content = config_path.read_text(encoding="utf-8")
    except Exception as e:
        return None, f"Failed to read configuration file: {e}"

    if HAS_YAML:
        try:
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                return None, f"Configuration root must be a YAML dictionary, got {type(parsed).__name__}"
            return parsed, None
        except Exception as e:
            return None, f"Malformed YAML syntax in {config_path.name}: {e}"
    else:
        try:
            parsed = parse_simple_yaml(content)
            return parsed, None
        except Exception as e:
            return None, f"Failed parsing YAML: {e}"


# ==============================================================================
# Configuration Schema Validator
# ==============================================================================

def validate_consumer_config(config: Dict[str, Any], result: ValidationResult):
    # 1. Unknown / unexpected top-level keys
    unknown_keys = set(config.keys()) - KNOWN_CONFIG_KEYS
    if unknown_keys:
        result.record_fail("Config Schema", f"Unknown configuration keys detected: {sorted(list(unknown_keys))}")
    else:
        result.record_pass("Config Schema: No unknown keys")

    # 2. Check for disallowed cloud authentication keys (fail-closed)
    for bad_key in DISALLOWED_CLOUD_AUTH_KEYS:
        if bad_key in config or (isinstance(config.get("security_controls"), dict) and bad_key in config["security_controls"]):
            result.record_fail("Cloud Auth Safety", f"Disallowed cloud auth setting '{bad_key}' found. Live cloud auth is strictly forbidden.")

    # 3. Schema version
    version = str(config.get("version", "")).strip()
    if not version:
        result.record_fail("Contract Version", "Missing mandatory 'version' attribute")
    elif version not in SUPPORTED_SCHEMA_VERSIONS:
        result.record_fail("Contract Version", f"Unsupported schema version '{version}'. Supported: {sorted(list(SUPPORTED_SCHEMA_VERSIONS))}")
    else:
        result.record_pass(f"Contract Version: Valid ({version})")

    # 4. Consumer ID
    consumer_id = str(config.get("consumer_id", "")).strip()
    if not consumer_id:
        result.record_fail("Consumer Identity", "Missing mandatory 'consumer_id' attribute")
    elif not RE_CONSUMER_ID.match(consumer_id):
        result.record_fail("Consumer Identity", f"Invalid consumer_id '{consumer_id}'. Must match regex ^[a-z0-9][a-z0-9-]{{1,62}}[a-z0-9]$")
    else:
        result.record_pass(f"Consumer Identity: Valid ({consumer_id})")

    # 5. Team
    team = str(config.get("team", "")).strip()
    if not team:
        result.record_fail("Consumer Team", "Missing mandatory 'team' attribute")
    elif len(team) < 2 or len(team) > 64:
        result.record_fail("Consumer Team", f"Team name '{team}' length must be between 2 and 64 characters")
    else:
        result.record_pass(f"Consumer Team: Valid ({team})")

    # 6. Workload Type
    workload_type = str(config.get("workload_type", "")).strip().lower()
    if not workload_type:
        result.record_fail("Workload Type", "Missing mandatory 'workload_type' attribute")
    elif workload_type not in SUPPORTED_WORKLOAD_TYPES:
        result.record_fail("Workload Type", f"Invalid workload_type '{workload_type}'. Must be one of: {sorted(list(SUPPORTED_WORKLOAD_TYPES))}")
    else:
        result.record_pass(f"Workload Type: Valid ({workload_type})")

    # 7. Environment
    environment = str(config.get("environment", "")).strip().lower()
    if not environment:
        result.record_fail("Environment", "Missing mandatory 'environment' attribute")
    elif environment not in SUPPORTED_ENVIRONMENTS:
        result.record_fail("Environment", f"Invalid environment '{environment}'. Must be one of: {sorted(list(SUPPORTED_ENVIRONMENTS))}")
    else:
        result.record_pass(f"Environment: Valid ({environment})")

    # 8. Target Adapter
    adapter = str(config.get("adapter", "")).strip().lower()
    if not adapter:
        result.record_fail("Adapter", "Missing mandatory 'adapter' attribute")
    elif adapter not in SUPPORTED_ADAPTERS:
        result.record_fail("Adapter", f"Unsupported adapter '{adapter}'. Must be one of: {sorted(list(SUPPORTED_ADAPTERS))}")
    else:
        result.record_pass(f"Adapter: Valid ({adapter})")

    # 9. Platform Reference & Commit SHA Pinning
    platform_ref = str(config.get("platform_ref", "")).strip()
    if not platform_ref:
        result.record_fail("Platform Reference", "Missing mandatory 'platform_ref' attribute")
    elif platform_ref != CANONICAL_PLATFORM_REF:
        result.record_fail("Platform Reference", f"Invalid platform_ref '{platform_ref}'. Must match '{CANONICAL_PLATFORM_REF}'")
    else:
        result.record_pass(f"Platform Reference: Canonical ({platform_ref})")

    platform_sha = str(config.get("platform_sha", "")).strip()
    if not platform_sha:
        result.record_fail("Platform Pinning", "Missing mandatory 'platform_sha' attribute")
    elif platform_sha in {"main", "master", "latest", "dev", "HEAD", "v0.5.0", "v0.4.0", "v1"}:
        result.record_fail("Platform Pinning", f"Mutable reference '{platform_sha}' rejected. Must pin an immutable 40-character hexadecimal commit SHA")
    elif not RE_COMMIT_SHA.match(platform_sha):
        result.record_fail("Platform Pinning", f"Invalid commit SHA '{platform_sha}'. Must be exactly 40 lowercase hexadecimal characters")
    else:
        result.record_pass(f"Platform Pinning: Immutable 40-char SHA ({platform_sha[:8]}...)")

    # 10. Terraform Version Constraint
    tf_version = str(config.get("terraform_version", "")).strip()
    if not tf_version:
        result.record_fail("Terraform Version", "Missing mandatory 'terraform_version' attribute")
    else:
        m = RE_SEMVER.match(tf_version)
        if not m:
            result.record_fail("Terraform Version", f"Invalid SemVer format '{tf_version}'")
        else:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if major < 1 or (major == 1 and minor < 6):
                result.record_fail("Terraform Version", f"Version '{tf_version}' < 1.6.0. InfraFlow requires Terraform >= 1.6.0")
            else:
                result.record_pass(f"Terraform Version: Valid ({tf_version})")

    # 11. Terraform Working Directory Path Sanitization
    tf_dir = str(config.get("terraform_dir", "")).strip()
    if not tf_dir:
        result.record_fail("Terraform Directory", "Missing mandatory 'terraform_dir' attribute")
    elif tf_dir.startswith("/") or tf_dir.startswith("\\") or (len(tf_dir) > 1 and tf_dir[1] == ":"):
        result.record_fail("Terraform Directory", f"Absolute path '{tf_dir}' rejected. Path must be relative to repository root")
    elif tf_dir.startswith("~"):
        result.record_fail("Terraform Directory", f"Tilde path '{tf_dir}' rejected. Path must be relative to repository root")
    elif RE_PATH_TRAVERSAL.search(tf_dir):
        result.record_fail("Terraform Directory", f"Path traversal ('..') in '{tf_dir}' rejected")
    else:
        result.record_pass(f"Terraform Directory: Path format valid ('{tf_dir}')")

    # 12. Security Controls Block
    sec_ctrls = config.get("security_controls")
    if sec_ctrls is None:
        result.record_fail("Security Controls", "Missing mandatory 'security_controls' section")
    elif not isinstance(sec_ctrls, dict):
        result.record_fail("Security Controls", f"'security_controls' must be a dictionary, got {type(sec_ctrls).__name__}")
    else:
        unknown_sec_keys = set(sec_ctrls.keys()) - KNOWN_SECURITY_CONTROL_KEYS
        if unknown_sec_keys:
            result.record_fail("Security Controls", f"Unknown keys in security_controls: {sorted(list(unknown_sec_keys))}")

        # Mandatory scanners cannot be disabled
        enforce_scanners = sec_ctrls.get("enforce_mandatory_scanners")
        if enforce_scanners is not True:
            result.record_fail("Mandatory Scanners", "enforce_mandatory_scanners must be strictly 'true'. Security gates cannot be bypassed.")
        else:
            result.record_pass("Security Controls: Mandatory scanners enforced")

        # Deletion limits
        max_deletions = sec_ctrls.get("max_allowed_deletions", 25)
        if not isinstance(max_deletions, int) or max_deletions < 0 or max_deletions > 25:
            result.record_fail("Deletion Ceiling", f"max_allowed_deletions '{max_deletions}' must be an integer between 0 and 25")
        else:
            result.record_pass(f"Security Controls: Deletion ceiling valid ({max_deletions})")


# ==============================================================================
# Filesystem & Workflow Security Validator
# ==============================================================================

def validate_consumer_filesystem(config: Dict[str, Any], repo_dir: Path, result: ValidationResult):
    repo_dir = repo_dir.resolve()

    # 1. Terraform Directory Containment & Content
    tf_dir_rel = str(config.get("terraform_dir", "")).strip()
    if tf_dir_rel:
        raw_tf_dir = repo_dir / tf_dir_rel
        if raw_tf_dir.is_symlink():
            result.record_fail("Workspace Containment", f"Terraform directory '{tf_dir_rel}' cannot be a symlink")
            return

        target_tf_dir = raw_tf_dir.resolve()
        try:
            # Check containment within repo_dir
            target_tf_dir.relative_to(repo_dir)
        except ValueError:
            result.record_fail("Workspace Containment", f"Terraform directory '{tf_dir_rel}' resolves outside repository root")
            return

        if not target_tf_dir.is_dir():
            result.record_fail("Terraform Directory", f"Terraform directory '{tf_dir_rel}' does not exist inside repository")
        else:
            tf_files = list(target_tf_dir.glob("*.tf"))
            if not tf_files:
                result.record_warn("Terraform Content", f"No '.tf' files found in '{tf_dir_rel}'")
            else:
                result.record_pass(f"Terraform Workspace: Contained ({len(tf_files)} .tf files found)")

    # 2. GitHub Actions Workflow Inspection
    workflows_dir = repo_dir / ".github" / "workflows"
    if not workflows_dir.is_dir():
        result.record_warn("Workflow Directory", "No '.github/workflows/' directory found in repository")
        return

    workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    if not workflow_files:
        result.record_warn("Workflows", "No workflow YAML files found in '.github/workflows/'")
        return

    expected_sha = config.get("platform_sha", "")
    for wf in workflow_files:
        _inspect_workflow_security(wf, expected_sha, result)


def _inspect_workflow_security(wf_path: Path, expected_sha: str, result: ValidationResult):
    try:
        content = wf_path.read_text(encoding="utf-8")
    except Exception as e:
        result.record_fail("Workflow Read", f"Failed reading workflow {wf_path.name}: {e}")
        return

    # Check for excessive permissions
    if re.search(r"^\s*permissions:\s*write-all", content, re.MULTILINE):
        result.record_fail(f"Permissions ({wf_path.name})", "Excessive permissions detected: 'write-all' is strictly forbidden.")

    # Check for pull_request_target
    if re.search(r"^\s*pull_request_target:", content, re.MULTILINE):
        result.record_fail(f"Trigger Safety ({wf_path.name})", "'pull_request_target' trigger is strictly forbidden due to privilege escalation risks.")

    # Check if workflow calls InfraFlow reusable workflow
    infraflow_call_matches = re.findall(r"uses:\s*TM-threemavithana/infraflow/\.github/workflows/([^@\s]+)@([^\s#]+)", content)
    for wf_name, ref in infraflow_call_matches:
        if ref in {"main", "master", "latest", "dev"}:
            result.record_fail(f"Platform Pinning ({wf_path.name})", f"Reusable workflow '{wf_name}' references mutable ref '@{ref}'. Must pin immutable 40-character commit SHA.")
        elif not RE_COMMIT_SHA.match(ref):
            result.record_fail(f"Platform Pinning ({wf_path.name})", f"Reusable workflow '{wf_name}' reference '@{ref}' is not a valid 40-character hex commit SHA.")
        elif expected_sha and ref != expected_sha:
            result.record_fail(f"Platform Pinning ({wf_path.name})", f"Workflow references SHA '{ref[:8]}...' but infraflow.config.yaml specifies '{expected_sha[:8]}...'. Hashes must match.")
        else:
            result.record_pass(f"Workflow Pinning ({wf_path.name}): Pinned to immutable SHA ({ref[:8]}...)")


# ==============================================================================
# CLI Entrypoint
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="InfraFlow Consumer Repository Onboarding Validator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        "-c",
        required=True,
        type=Path,
        help="Path to consumer configuration file (infraflow.config.yaml)",
    )
    parser.add_argument(
        "--repo-dir",
        "-r",
        type=Path,
        default=None,
        help="Root path to consumer repository (defaults to config parent directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON payload",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress verbose pass output",
    )

    args = parser.parse_args()

    config_path = args.config.resolve()
    repo_dir = args.repo_dir.resolve() if args.repo_dir else config_path.parent

    result = ValidationResult()

    config_data, err = load_config_file(config_path)
    if err:
        result.record_fail("Configuration Loading", err)
    else:
        validate_consumer_config(config_data, result)
        validate_consumer_filesystem(config_data, repo_dir, result)

    if args.json:
        payload = {
            "valid": result.is_valid,
            "passes": result.passes,
            "errors": result.errors,
            "warnings": result.warnings,
            "summary": {
                "total": len(result.passes) + len(result.errors),
                "passed": len(result.passes),
                "failed": len(result.errors),
                "warnings": len(result.warnings),
            },
        }
        print(json.dumps(payload, indent=2))
    else:
        result.print_report(quiet=args.quiet)

    sys.exit(0 if result.is_valid else 1)


if __name__ == "__main__":
    main()
