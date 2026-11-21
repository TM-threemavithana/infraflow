#!/usr/bin/env python3
"""
InfraFlow Consumer Repository Onboarding & Governance Validator (Milestone G08.3)

Validates consumer repository configuration (infraflow.config.yaml), workflow
security permissions, directory containment, platform dependency pinning, and
mandatory adapter workflow invocations against InfraFlow enterprise governance contracts.

Exit Codes:
  0 - All validation checks passed cleanly.
  1 - One or more validation errors detected.
"""

import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml
    from yaml.constructor import ConstructorError
    from yaml.resolver import BaseResolver
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ==============================================================================
# Contract Schemas & Regular Expressions
# ==============================================================================

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
SUPPORTED_WORKLOAD_TYPES = {
    "networking",
    "application",
    "data-platform",
    "general",
    "database",
    "mlops",
    "shared-services",
    "test",
}
SUPPORTED_ENVIRONMENTS = {"dev", "staging", "prod", "sand", "test"}
SUPPORTED_ADAPTERS = {"provider-neutral", "aws", "gcp", "azure", "apply-simulation", "generic"}
CANONICAL_PLATFORM_REF = "TM-threemavithana/infraflow"

ADAPTER_WORKFLOW_MAP = {
    "aws": "reusable-tf-aws.yml",
    "azure": "reusable-tf-azure.yml",
    "gcp": "reusable-tf-gcp.yml",
    "provider-neutral": "reusable-tf-validate.yml",
    "generic": "reusable-tf-validate.yml",
    "apply-simulation": "reusable-tf-apply.yml",
}

ALLOWED_PLATFORM_WORKFLOWS = {
    "reusable-tf-aws.yml",
    "reusable-tf-azure.yml",
    "reusable-tf-gcp.yml",
    "reusable-tf-validate.yml",
    "reusable-tf-security.yml",
    "reusable-tf-plan.yml",
    "reusable-tf-apply.yml",
    "reusable-tf-governance.yml",
}

CLOUD_ADAPTER_WORKFLOWS = {
    "reusable-tf-aws.yml",
    "reusable-tf-azure.yml",
    "reusable-tf-gcp.yml",
}

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
# Secure YAML Parser with Duplicate Key Detection
# ==============================================================================

if HAS_YAML:
    class DuplicateKeyCheckLoader(yaml.SafeLoader):
        """SafeLoader that detects and rejects duplicate keys in any mapping."""
        pass

    def _construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"Duplicate key '{key}' detected in YAML document",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    DuplicateKeyCheckLoader.add_constructor(
        BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_mapping,
    )


def load_config_file(config_path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not config_path.is_file():
        return None, f"Configuration file not found: {config_path}"

    try:
        content = config_path.read_text(encoding="utf-8")
    except Exception as e:
        return None, f"Failed to read configuration file: {e}"

    if not HAS_YAML:
        return None, "PyYAML parser library is required for authoritative configuration loading. Failing closed."

    try:
        parsed = yaml.load(content, Loader=DuplicateKeyCheckLoader)
        if not isinstance(parsed, dict):
            return None, f"Configuration root must be a YAML dictionary, got {type(parsed).__name__}"
        return parsed, None
    except Exception as e:
        return None, f"Malformed YAML or duplicate key in {config_path.name}: {e}"


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

    # 2. GitHub Actions Workflow Inspection (GOV-G08-01: Must fail closed if missing)
    workflows_dir = repo_dir / ".github" / "workflows"
    if not workflows_dir.is_dir():
        result.record_fail(
            "Workflow Directory",
            "Missing mandatory '.github/workflows/' directory. Consumer repository must declare at least one active InfraFlow workflow.",
        )
        return

    workflow_files = sorted(list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")))
    if not workflow_files:
        result.record_fail(
            "Workflows",
            "No workflow YAML files found in '.github/workflows/'. Consumer repository must define an active InfraFlow caller workflow.",
        )
        return

    if not HAS_YAML:
        result.record_fail(
            "YAML Parser",
            "PyYAML parser library is required for authoritative workflow security parsing. Failing closed.",
        )
        return

    expected_sha = config.get("platform_sha", "")
    expected_adapter = str(config.get("adapter", "")).strip().lower()
    expected_adapter_wf = ADAPTER_WORKFLOW_MAP.get(expected_adapter)

    all_called_workflows: Set[str] = set()

    for wf in workflow_files:
        called = _inspect_workflow_security(wf, expected_sha, expected_adapter, result)
        all_called_workflows.update(called)

    # 3. Adapter Workflow Invocation Verification (GOV-G08-02)
    if not all_called_workflows:
        result.record_fail(
            "Platform Invocation",
            "No InfraFlow reusable workflows are invoked in repository workflows. Configuration claims InfraFlow adoption while skipping its execution.",
        )
        return

    if expected_adapter_wf and expected_adapter_wf not in all_called_workflows:
        result.record_fail(
            "Adapter Invocation",
            f"Config specifies adapter '{expected_adapter}' (requires '{expected_adapter_wf}'), but no workflow in '.github/workflows/' invokes this reusable workflow.",
        )
    else:
        result.record_pass(f"Adapter Invocation: Expected workflow '{expected_adapter_wf}' invoked")

    # Check for contradictory cloud adapters (e.g. AWS repo invoking GCP adapter)
    called_cloud_adapters = all_called_workflows.intersection(CLOUD_ADAPTER_WORKFLOWS)
    if expected_adapter_wf in CLOUD_ADAPTER_WORKFLOWS:
        contradictory = called_cloud_adapters - {expected_adapter_wf}
        if contradictory:
            result.record_fail(
                "Contradictory Adapter Invocation",
                f"Config specifies adapter '{expected_adapter}' but workflow invokes contradictory cloud adapter(s): {sorted(list(contradictory))}",
            )


def _inspect_workflow_security(
    wf_path: Path, expected_sha: str, expected_adapter: str, result: ValidationResult
) -> Set[str]:
    called_platform_workflows: Set[str] = set()

    try:
        content = wf_path.read_text(encoding="utf-8")
    except Exception as e:
        result.record_fail(f"Workflow Read ({wf_path.name})", f"Failed reading workflow: {e}")
        return called_platform_workflows

    # Structural YAML parsing with duplicate key check (GOV-G08-03)
    try:
        doc = yaml.load(content, Loader=DuplicateKeyCheckLoader)
    except Exception as e:
        result.record_fail(f"Workflow Syntax ({wf_path.name})", f"Malformed YAML syntax or duplicate key: {e}")
        return called_platform_workflows

    if not isinstance(doc, dict):
        result.record_fail(f"Workflow Structure ({wf_path.name})", f"Root element must be a mapping, got {type(doc).__name__}")
        return called_platform_workflows

    # 1. Trigger Inspection (Handle PyYAML parsing 'on:' as boolean True or string 'on')
    triggers = doc.get("on") if "on" in doc else doc.get(True)
    if triggers is not None:
        trigger_names: Set[str] = set()
        if isinstance(triggers, dict):
            trigger_names = set(triggers.keys())
        elif isinstance(triggers, list):
            trigger_names = set(triggers)
        elif isinstance(triggers, str):
            trigger_names = {triggers}

        if "pull_request_target" in trigger_names:
            result.record_fail(
                f"Trigger Safety ({wf_path.name})",
                "'pull_request_target' trigger is strictly forbidden due to privilege escalation risks.",
            )

    # 2. Workflow-Level Permissions Inspection
    wf_perms = doc.get("permissions")
    _inspect_permissions(wf_perms, f"Workflow Permissions ({wf_path.name})", result)

    # 3. Jobs Inspection
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        result.record_fail(f"Workflow Structure ({wf_path.name})", "Missing or empty 'jobs' dictionary in workflow.")
        return called_platform_workflows

    for job_id, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue

        # Check job-level permissions
        job_perms = job_data.get("permissions")
        _inspect_permissions(job_perms, f"Job Permissions ({wf_path.name} -> {job_id})", result)

        # Check secrets inheritance
        if job_data.get("secrets") == "inherit":
            result.record_fail(
                f"Secret Safety ({wf_path.name} -> {job_id})",
                "Job specifies 'secrets: inherit'. Secret inheritance is strictly forbidden in consumer workflows.",
            )

        # Check reusable workflow invocation
        uses_ref = str(job_data.get("uses", "")).strip()
        if not uses_ref:
            continue

        match = re.match(r"^([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)/\.github/workflows/([^@\s]+)@([^\s#]+)", uses_ref)
        if match:
            repo_name = match.group(1)
            wf_name = match.group(2)
            ref_sha = match.group(3)

            # Check repo boundary
            if repo_name != CANONICAL_PLATFORM_REF:
                result.record_fail(
                    f"Platform Repository ({wf_path.name} -> {job_id})",
                    f"Workflow calls unauthorized repository '{repo_name}'. Expected '{CANONICAL_PLATFORM_REF}'.",
                )
                continue

            # Check allowed workflows
            if wf_name not in ALLOWED_PLATFORM_WORKFLOWS:
                result.record_fail(
                    f"Platform Workflow ({wf_path.name} -> {job_id})",
                    f"Workflow calls unknown platform workflow '{wf_name}'. Must be one of: {sorted(list(ALLOWED_PLATFORM_WORKFLOWS))}",
                )
                continue

            called_platform_workflows.add(wf_name)

            # Check immutable SHA pinning
            if ref_sha in {"main", "master", "latest", "dev", "HEAD", "v0.5.0", "v0.4.0", "v1"}:
                result.record_fail(
                    f"Platform Pinning ({wf_path.name} -> {job_id})",
                    f"Reusable workflow '{wf_name}' references mutable ref '@{ref_sha}'. Must pin immutable 40-character commit SHA.",
                )
            elif not RE_COMMIT_SHA.match(ref_sha):
                result.record_fail(
                    f"Platform Pinning ({wf_path.name} -> {job_id})",
                    f"Reusable workflow '{wf_name}' reference '@{ref_sha}' is not a valid 40-character hex commit SHA.",
                )
            elif expected_sha and ref_sha != expected_sha:
                result.record_fail(
                    f"Platform Pinning ({wf_path.name} -> {job_id})",
                    f"Workflow references SHA '{ref_sha[:8]}...' but infraflow.config.yaml specifies '{expected_sha[:8]}...'. Hashes must match.",
                )
            else:
                result.record_pass(f"Workflow Pinning ({wf_path.name} -> {job_id}): Pinned to immutable SHA ({ref_sha[:8]}...)")

            # Check job inputs in 'with:'
            inputs = job_data.get("with", {})
            if isinstance(inputs, dict):
                for bad_key in DISALLOWED_CLOUD_AUTH_KEYS:
                    if inputs.get(bad_key) is True:
                        result.record_fail(
                            f"Cloud Auth Safety ({wf_path.name} -> {job_id})",
                            f"Input '{bad_key}: true' attempts to enable live cloud authentication. Live cloud auth is strictly forbidden.",
                        )

    return called_platform_workflows


def _inspect_permissions(perms: Any, context: str, result: ValidationResult):
    if perms is None:
        return

    if perms == "write-all":
        result.record_fail(context, "Excessive permissions detected: 'write-all' is strictly forbidden.")
        return

    if isinstance(perms, dict):
        if perms.get("id-token") == "write":
            result.record_fail(context, "Excessive permissions detected: 'id-token: write' is strictly forbidden in cloud-free consumer workflows.")

        for perm_name, perm_val in perms.items():
            if perm_val in {"write", "write-all"}:
                result.record_fail(context, f"Excessive permission '{perm_name}: {perm_val}' detected. Consumer workflows must strictly enforce read-only permissions.")


# ==============================================================================
# Normalized Governance Payload Generator (For OPA / Conftest)
# ==============================================================================

def generate_governance_payload(config: Dict[str, Any], repo_dir: Path) -> Dict[str, Any]:
    """Generates normalized JSON document consumed by policies/governance/consumer_governance.rego."""
    repo_dir = repo_dir.resolve()
    workflows_dir = repo_dir / ".github" / "workflows"

    workflow_calls = []
    triggers = set()
    permissions_summary = {}

    if workflows_dir.is_dir():
        for wf in sorted(list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))):
            try:
                content = wf.read_text(encoding="utf-8")
                doc = yaml.load(content, Loader=DuplicateKeyCheckLoader) if HAS_YAML else {}
                if isinstance(doc, dict):
                    wf_trig = doc.get("on") if "on" in doc else doc.get(True)
                    if isinstance(wf_trig, dict):
                        triggers.update(wf_trig.keys())
                    elif isinstance(wf_trig, list):
                        triggers.update(wf_trig)
                    elif isinstance(wf_trig, str):
                        triggers.add(wf_trig)

                    if isinstance(doc.get("permissions"), dict):
                        permissions_summary.update(doc.get("permissions"))
                    elif isinstance(doc.get("permissions"), str):
                        permissions_summary["_root"] = doc.get("permissions")

                    jobs = doc.get("jobs", {})
                    if isinstance(jobs, dict):
                        for job_id, job_info in jobs.items():
                            if isinstance(job_info, dict):
                                uses = str(job_info.get("uses", ""))
                                m = re.match(r"^([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)/\.github/workflows/([^@\s]+)@([^\s#]+)", uses)
                                if m:
                                    workflow_calls.append({
                                        "workflow_file": wf.name,
                                        "job_id": job_id,
                                        "platform_repo": m.group(1),
                                        "platform_workflow": m.group(2),
                                        "platform_sha": m.group(3),
                                        "inputs": job_info.get("with", {}),
                                        "permissions": job_info.get("permissions", {}),
                                        "secrets": job_info.get("secrets", ""),
                                    })
            except Exception:
                pass

    return {
        "version": config.get("version"),
        "consumer_id": config.get("consumer_id"),
        "team": config.get("team"),
        "workload_type": config.get("workload_type"),
        "environment": config.get("environment"),
        "adapter": config.get("adapter"),
        "platform_ref": config.get("platform_ref"),
        "platform_sha": config.get("platform_sha"),
        "terraform_version": config.get("terraform_version"),
        "terraform_dir": config.get("terraform_dir"),
        "security_controls": config.get("security_controls", {}),
        "workflow_calls": workflow_calls,
        "triggers": sorted(list(triggers)),
        "permissions": permissions_summary,
    }


# ==============================================================================
# CLI Entrypoint
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="InfraFlow Consumer Repository Onboarding & Governance Validator",
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
        "--export-governance-payload",
        type=Path,
        default=None,
        help="Export normalized governance JSON payload for OPA/Conftest evaluation",
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

    if args.export_governance_payload:
        out_path = args.export_governance_payload
        if config_data:
            gov_payload = generate_governance_payload(config_data, repo_dir)
            out_path.write_text(json.dumps(gov_payload, indent=2), encoding="utf-8")

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
