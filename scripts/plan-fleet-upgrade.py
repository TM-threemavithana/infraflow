#!/usr/bin/env python3
"""
InfraFlow Fleet Upgrade Planner, Drift Detector & Rollback Orchestrator (Milestone G08.4)

Provides:
1. Fleet inventory and version discovery across registered consumers.
2. Configuration, version, and governance drift detection.
3. Platform workflow and contract compatibility checks.
4. Upgrade execution planning and dry-run generation.
5. Controlled local upgrade execution (canary, progressive rollout, rollback).

Invariants:
- Exactly $0.00 cloud infrastructure spend; zero live credentials.
- Strict 40-character hexadecimal commit SHA enforcement.
- Immutable platform reference: TM-threemavithana/infraflow.
- Separation of config/version/governance drift from live cloud infrastructure drift.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

RE_SHA = re.compile(r"^[0-9a-f]{40}$")
MUTABLE_REFS = {"main", "master", "latest", "dev", "HEAD", "v0.5.0", "v0.4.0", "v1"}
VALID_ADAPTERS = {"aws", "azure", "gcp", "generic", "provider-neutral", "apply-simulation"}
VALID_WORKLOADS = {"networking", "application", "data-platform", "general", "database", "mlops", "shared-services", "test"}
VALID_STAGES = {"inventory", "compatibility", "canary", "progressive", "fleet-verified", "rollback"}

ADAPTER_WORKFLOW_MAP = {
    "aws": "reusable-tf-aws.yml",
    "azure": "reusable-tf-azure.yml",
    "gcp": "reusable-tf-gcp.yml",
    "generic": "reusable-tf-validate.yml",
    "provider-neutral": "reusable-tf-validate.yml",
    "apply-simulation": "reusable-tf-apply.yml",
}


class ManifestValidationError(Exception):
    """Raised when fleet manifest fails schema validation."""
    pass


class CompatibilityError(Exception):
    """Raised when platform candidate is incompatible with consumer."""
    pass


def load_manifest(manifest_path: Path) -> Dict[str, Any]:
    """Loads and validates fleet-manifest.yaml against strict schema rules."""
    if not manifest_path.is_file():
        raise ManifestValidationError(f"Manifest file not found: {manifest_path}")

    if yaml is None:
        raise ManifestValidationError("PyYAML is required to parse fleet-manifest.yaml")

    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ManifestValidationError(f"YAML parsing error in manifest: {e}")

    if not isinstance(data, dict):
        raise ManifestValidationError("Manifest root must be a mapping dictionary")

    # 1. Schema Version
    schema_ver = data.get("schema_version")
    if schema_ver != "1.0":
        raise ManifestValidationError(f"Unsupported schema_version '{schema_ver}'. Expected '1.0'.")

    # 2. Platform Block
    platform = data.get("platform")
    if not isinstance(platform, dict):
        raise ManifestValidationError("Missing or invalid 'platform' block")

    if platform.get("repository") != "TM-threemavithana/infraflow":
        raise ManifestValidationError(f"Invalid platform repository: '{platform.get('repository')}'")

    candidate_sha = platform.get("candidate_sha", "")
    if not RE_SHA.match(str(candidate_sha)):
        raise ManifestValidationError(f"Invalid candidate_sha '{candidate_sha}'. Must be 40-char hex.")

    rollback_sha = platform.get("known_good_rollback_sha", "")
    if not RE_SHA.match(str(rollback_sha)):
        raise ManifestValidationError(f"Invalid known_good_rollback_sha '{rollback_sha}'. Must be 40-char hex.")

    # 3. Consumers Block
    consumers = data.get("consumers")
    if not isinstance(consumers, list) or not consumers:
        raise ManifestValidationError("Manifest must define at least one consumer in 'consumers' list")

    seen_repos: Set[str] = set()
    seen_ids: Set[str] = set()

    for idx, c in enumerate(consumers):
        if not isinstance(c, dict):
            raise ManifestValidationError(f"Consumer #{idx} must be a dictionary")

        repo = c.get("repository", "")
        cid = c.get("consumer_id", "")
        adapter = c.get("adapter", "")
        workload = c.get("workload_type", "")
        c_sha = c.get("current_sha", "")
        t_sha = c.get("target_sha", "")
        r_sha = c.get("rollback_sha", "")

        if not repo or not cid:
            raise ManifestValidationError(f"Consumer #{idx} missing 'repository' or 'consumer_id'")

        if repo in seen_repos:
            raise ManifestValidationError(f"Duplicate repository identity detected: '{repo}'")
        seen_repos.add(repo)

        if cid in seen_ids:
            raise ManifestValidationError(f"Duplicate consumer_id detected: '{cid}'")
        seen_ids.add(cid)

        if adapter not in VALID_ADAPTERS:
            raise ManifestValidationError(f"Consumer '{cid}' has invalid adapter: '{adapter}'")

        if workload not in VALID_WORKLOADS:
            raise ManifestValidationError(f"Consumer '{cid}' has invalid workload_type: '{workload}'")

        for name, sha_val in [("current_sha", c_sha), ("target_sha", t_sha), ("rollback_sha", r_sha)]:
            if not RE_SHA.match(str(sha_val)):
                raise ManifestValidationError(f"Consumer '{cid}' has invalid {name}: '{sha_val}'")

        max_del = c.get("max_allowed_deletions")
        if max_del is not None:
            if not isinstance(max_del, int) or max_del < 0 or max_del > 25:
                raise ManifestValidationError(f"Consumer '{cid}' invalid max_allowed_deletions: {max_del}")

    return data


def inspect_consumer_repo(
    repo_path: Path, manifest_entry: Dict[str, Any]
) -> Dict[str, Any]:
    """Inspects a local consumer repository for live files, SHAs, and workflows."""
    report: Dict[str, Any] = {
        "repository": manifest_entry["repository"],
        "consumer_id": manifest_entry["consumer_id"],
        "adapter": manifest_entry["adapter"],
        "path": str(repo_path),
        "exists_locally": repo_path.is_dir(),
        "config_found": False,
        "config_sha": None,
        "config_adapter": None,
        "config_scanners_enforced": False,
        "workflow_files": [],
        "called_workflows": {},
        "governance_gate_present": False,
        "adapter_workflow_present": False,
        "workflow_sha_consistent": True,
        "permissions_compliant": True,
        "triggers_compliant": True,
        "drift_detected": False,
        "drift_details": [],
    }

    if not repo_path.is_dir():
        report["drift_detected"] = True
        report["drift_details"].append("Local repository clone not found")
        return report

    # 1. Config Inspection
    config_file = repo_path / "infraflow.config.yaml"
    if config_file.is_file():
        report["config_found"] = True
        try:
            if yaml:
                cfg = yaml.safe_load(config_file.read_text(encoding="utf-8"))
                if isinstance(cfg, dict):
                    report["config_sha"] = cfg.get("platform_sha")
                    report["config_adapter"] = cfg.get("adapter")
                    sec = cfg.get("security_controls", {})
                    if isinstance(sec, dict):
                        report["config_scanners_enforced"] = (sec.get("enforce_mandatory_scanners") is True)
        except Exception as e:
            report["drift_detected"] = True
            report["drift_details"].append(f"Failed parsing infraflow.config.yaml: {e}")

    # 2. Workflow Inspection
    wf_dir = repo_path / ".github" / "workflows"
    if not wf_dir.is_dir():
        report["drift_detected"] = True
        report["drift_details"].append("Missing .github/workflows directory")
        return report

    wf_files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
    report["workflow_files"] = [f.name for f in wf_files]

    expected_adapter_wf = ADAPTER_WORKFLOW_MAP.get(manifest_entry["adapter"])
    shas_seen: Set[str] = set()

    for wf in wf_files:
        try:
            content = wf.read_text(encoding="utf-8")
        except Exception:
            continue

        # Check triggers
        if "pull_request_target" in content:
            report["triggers_compliant"] = False
            report["drift_detected"] = True
            report["drift_details"].append(f"Workflow '{wf.name}' uses forbidden 'pull_request_target' trigger")

        # Check permissions
        if "write-all" in content:
            report["permissions_compliant"] = False
            report["drift_detected"] = True
            report["drift_details"].append(f"Workflow '{wf.name}' specifies forbidden 'write-all' permissions")

        if "id-token: write" in content:
            report["permissions_compliant"] = False
            report["drift_detected"] = True
            report["drift_details"].append(f"Workflow '{wf.name}' specifies forbidden 'id-token: write' in cloud-free mode")

        # Inspect uses
        for line in content.splitlines():
            line_str = line.strip()
            if "uses:" in line_str and "TM-threemavithana/infraflow/.github/workflows/" in line_str:
                m = re.search(r"TM-threemavithana/infraflow/\.github/workflows/([^@\s]+)@([^\s#]+)", line_str)
                if m:
                    wf_name = m.group(1)
                    wf_sha = m.group(2)
                    report["called_workflows"][wf_name] = wf_sha
                    shas_seen.add(wf_sha)

                    if wf_name == "reusable-tf-governance.yml":
                        report["governance_gate_present"] = True
                    if wf_name == expected_adapter_wf:
                        report["adapter_workflow_present"] = True

    # 3. Drift Evaluation
    # Check if governance gate is missing
    if not report["governance_gate_present"]:
        report["drift_detected"] = True
        report["drift_details"].append("Missing reusable-tf-governance.yml invocation")

    # Check if adapter workflow is missing
    if not report["adapter_workflow_present"]:
        report["drift_detected"] = True
        report["drift_details"].append(f"Missing required adapter workflow '{expected_adapter_wf}' invocation")

    # Check for mutable references
    for s in shas_seen:
        if s in MUTABLE_REFS or not RE_SHA.match(s):
            report["drift_detected"] = True
            report["drift_details"].append(f"Workflow references mutable/invalid ref '@{s}'")

    # Check workflow SHA consistency (all called platform workflows should pin the same SHA)
    if len(shas_seen) > 1:
        report["workflow_sha_consistent"] = False
        report["drift_detected"] = True
        report["drift_details"].append(f"Conflicting SHAs called in workflows: {sorted(list(shas_seen))}")

    # Check config vs workflow SHA consistency
    wf_sha = next(iter(shas_seen)) if shas_seen else None
    if report["config_sha"] and wf_sha and report["config_sha"] != wf_sha:
        report["drift_detected"] = True
        report["drift_details"].append(
            f"Config SHA ({report['config_sha'][:8]}...) differs from workflow SHA ({wf_sha[:8]}...)"
        )

    # Check if config adapter matches manifest
    if report["config_adapter"] and report["config_adapter"] != manifest_entry["adapter"]:
        report["drift_detected"] = True
        report["drift_details"].append(
            f"Config adapter '{report['config_adapter']}' differs from manifest '{manifest_entry['adapter']}'"
        )

    # Check if scanners are enforced
    if not report["config_scanners_enforced"]:
        report["drift_detected"] = True
        report["drift_details"].append("Mandatory security scanners are disabled in config")

    return report


def check_platform_compatibility(platform_dir: Path, manifest: Dict[str, Any]) -> List[str]:
    """Evaluates candidate platform workflows against consumer requirements."""
    incompatibilities: List[str] = []
    wf_dir = platform_dir / ".github" / "workflows"

    if not wf_dir.is_dir():
        incompatibilities.append(f"Platform workflow directory not found: {wf_dir}")
        return incompatibilities

    contracts = manifest.get("workflow_contracts", {})

    for adapter, c_data in contracts.items():
        wf_file = wf_dir / c_data["workflow"]
        if not wf_file.is_file():
            incompatibilities.append(f"Required workflow '{c_data['workflow']}' missing from platform")
            continue

        content = wf_file.read_text(encoding="utf-8")
        # Check mandatory outputs
        for out in c_data.get("mandatory_outputs", []):
            if f"{out}:" not in content and f'"{out}":' not in content:
                incompatibilities.append(f"Workflow '{c_data['workflow']}' missing mandatory output '{out}'")

    # Check governance workflow presence
    gov_wf = wf_dir / "reusable-tf-governance.yml"
    if not gov_wf.is_file():
        incompatibilities.append("Platform missing reusable-tf-governance.yml")

    return incompatibilities


def generate_upgrade_plan(
    manifest: Dict[str, Any], fleet_reports: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Generates a structured upgrade plan following the staged rollout model."""
    candidate_sha = manifest["platform"]["candidate_sha"]
    rollback_sha = manifest["platform"]["known_good_rollback_sha"]

    plan: Dict[str, Any] = {
        "candidate_sha": candidate_sha,
        "rollback_sha": rollback_sha,
        "staged_rollout": {
            "canary": [],
            "progressive": [],
        },
        "actions_required": [],
        "rollback_reference": rollback_sha,
    }

    report_by_cid = {r["consumer_id"]: r for r in fleet_reports}

    for c in manifest["consumers"]:
        cid = c["consumer_id"]
        role = c.get("upgrade_role", "progressive")
        cur_report = report_by_cid.get(cid, {})

        current_active = cur_report.get("config_sha") or c["current_sha"]
        target = c["target_sha"]

        item = {
            "consumer_id": cid,
            "repository": c["repository"],
            "adapter": c["adapter"],
            "current_sha": current_active,
            "target_sha": target,
            "files_to_update": [
                "infraflow.config.yaml",
                c.get("caller_workflow", ".github/workflows/infraflow-ci.yml"),
            ],
            "upgrade_needed": (current_active != target),
        }

        if role == "canary":
            plan["staged_rollout"]["canary"].append(item)
        else:
            plan["staged_rollout"]["progressive"].append(item)

        if current_active != target:
            plan["actions_required"].append(
                f"Upgrade {cid} from {current_active[:8]}... to {target[:8]}..."
            )

    return plan


def apply_consumer_upgrade(
    repo_path: Path, target_sha: str, is_rollback: bool = False
) -> Tuple[bool, List[str]]:
    """Updates local consumer repository config and workflows to target_sha."""
    logs: List[str] = []
    if not repo_path.is_dir():
        return False, [f"Repository directory does not exist: {repo_path}"]

    # 1. Update infraflow.config.yaml
    config_file = repo_path / "infraflow.config.yaml"
    if not config_file.is_file():
        return False, [f"Config file not found: {config_file}"]

    try:
        content = config_file.read_text(encoding="utf-8")
        new_content = re.sub(
            r'platform_sha:\s*"[0-9a-fA-F]{40}"',
            f'platform_sha: "{target_sha}"',
            content,
        )
        if new_content == content and target_sha not in content:
            # Fallback for plain unquoted
            new_content = re.sub(
                r'platform_sha:\s*[0-9a-fA-F]{40}',
                f'platform_sha: "{target_sha}"',
                content,
            )
        config_file.write_text(new_content, encoding="utf-8")
        action = "Rolled back" if is_rollback else "Updated"
        logs.append(f"{action} {config_file.name} to {target_sha[:8]}...")
    except Exception as e:
        return False, [f"Failed updating {config_file}: {e}"]

    # 2. Update workflows in .github/workflows
    wf_dir = repo_path / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
            try:
                wf_content = wf.read_text(encoding="utf-8")
                updated_wf = re.sub(
                    r'(TM-threemavithana/infraflow/\.github/workflows/[^@\s]+)@[0-9a-fA-F]{40}',
                    r'\g<1>@' + target_sha,
                    wf_content,
                )
                # Also replace platform-sha input if present
                updated_wf = re.sub(
                    r'(platform-sha:\s*)"[0-9a-fA-F]{40}"',
                    r'\g<1>"' + target_sha + '"',
                    updated_wf,
                )
                wf.write_text(updated_wf, encoding="utf-8")
                logs.append(f"{action} {wf.name} references to {target_sha[:8]}...")
            except Exception as e:
                return False, [f"Failed updating workflow {wf.name}: {e}"]

    return True, logs


def main():
    parser = argparse.ArgumentParser(
        description="InfraFlow Fleet Upgrade Planner, Drift Detector & Rollback Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--manifest",
        "-m",
        type=Path,
        default=Path("config/fleet-manifest.yaml"),
        help="Path to fleet-manifest.yaml",
    )
    parser.add_argument(
        "--fleet-root",
        type=Path,
        default=Path("/home/tharuka/projects"),
        help="Root directory containing cloned consumer repositories",
    )
    parser.add_argument(
        "--platform-dir",
        type=Path,
        default=Path("/home/tharuka/projects/infraflow"),
        help="Path to InfraFlow platform repository",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List registered consumers from manifest",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="Inspect fleet repositories and report current platform SHAs",
    )
    parser.add_argument(
        "--check-drift",
        action="store_true",
        help="Perform comprehensive 15-point configuration, version, and governance drift check",
    )
    parser.add_argument(
        "--compatibility",
        action="store_true",
        help="Validate platform candidate compatibility with consumer contracts",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Generate staged upgrade execution plan (dry-run)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply upgrade to local repository clones",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Rollback specified or all consumers to their known-good rollback SHA",
    )
    parser.add_argument(
        "--stage",
        choices=["canary", "progressive", "all"],
        default="all",
        help="Rollout stage for --apply or --plan",
    )
    parser.add_argument(
        "--consumer",
        type=str,
        default="",
        help="Target a specific consumer by consumer_id",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results in structured JSON format",
    )

    args = parser.parse_args()

    # Load and validate manifest
    try:
        manifest = load_manifest(args.manifest)
    except ManifestValidationError as e:
        print(f"[ERROR] Manifest validation failure: {e}", file=sys.stderr)
        sys.exit(1)

    # 1. Action: --list
    if args.list:
        if args.json:
            print(json.dumps(manifest["consumers"], indent=2))
        else:
            print("==============================================================================")
            print(">>> InfraFlow Fleet Inventory (Registered Consumers)")
            print("==============================================================================")
            for c in manifest["consumers"]:
                print(f"• ID: {c['consumer_id']:<26} Adapter: {c['adapter']:<10} Role: {c.get('upgrade_role', 'progressive'):<12}")
                print(f"  Repo: {c['repository']}")
                print(f"  Current SHA:  {c['current_sha'][:8]}... -> Target: {c['target_sha'][:8]}...")
            print("==============================================================================")
        sys.exit(0)

    # 2. Inspect Fleet Repositories
    fleet_reports: List[Dict[str, Any]] = []
    has_drift = False

    for c in manifest["consumers"]:
        repo_name = c["repository"].split("/")[-1]
        repo_path = args.fleet_root / repo_name
        report = inspect_consumer_repo(repo_path, c)
        if report["drift_detected"]:
            has_drift = True
        fleet_reports.append(report)

    # 3. Action: --inventory
    if args.inventory:
        if args.json:
            print(json.dumps(fleet_reports, indent=2))
        else:
            print("==============================================================================")
            print(">>> InfraFlow Fleet Inventory & Version Status")
            print("==============================================================================")
            for r in fleet_reports:
                status = "LOCAL" if r["exists_locally"] else "MISSING"
                cfg_sha = r["config_sha"][:8] + "..." if r["config_sha"] else "none"
                gov = "ACTIVE" if r["governance_gate_present"] else "MISSING"
                adp = "ACTIVE" if r["adapter_workflow_present"] else "MISSING"
                print(f"[{status}] {r['consumer_id']} ({r['adapter']})")
                print(f"       Config SHA:     {cfg_sha}")
                print(f"       Governance WF:  {gov}")
                print(f"       Adapter WF:     {adp}")
                if r["drift_detected"]:
                    print(f"       Drift Warning:  {', '.join(r['drift_details'])}")
            print("==============================================================================")
        sys.exit(0)

    # 4. Action: --check-drift
    if args.check_drift:
        drift_summary = {
            "drift_detected": has_drift,
            "consumers_audited": len(fleet_reports),
            "reports": fleet_reports,
            "drift_categories": {
                "version_drift": [r["consumer_id"] for r in fleet_reports if r["config_sha"] != manifest["platform"]["candidate_sha"]],
                "governance_drift": [r["consumer_id"] for r in fleet_reports if not r["governance_gate_present"]],
                "configuration_drift": [r["consumer_id"] for r in fleet_reports if r["drift_detected"]],
                "infrastructure_drift": "Not observable in cloud-free simulation mode (requires live cloud APIs)",
            },
        }
        if args.json:
            print(json.dumps(drift_summary, indent=2))
        else:
            print("==============================================================================")
            print(">>> InfraFlow Configuration & Version Drift Audit Report")
            print("==============================================================================")
            for r in fleet_reports:
                state = "DRIFT DETECTED" if r["drift_detected"] else "IN-SPEC"
                print(f"[{state}] {r['consumer_id']} ({r['repository']})")
                if r["drift_details"]:
                    for d in r["drift_details"]:
                        print(f"        • {d}")
            print("------------------------------------------------------------------------------")
            print("Note: Live cloud infrastructure drift detection requires authenticated cloud APIs")
            print("      and live state, which is outside cloud-free platform governance scope.")
            print("==============================================================================")
            print(f"Fleet Drift Verdict: {'DRIFT IDENTIFIED' if has_drift else 'CLEAN (NO DRIFT)'}")
            print("==============================================================================")
        sys.exit(1 if has_drift else 0)

    # 5. Action: --compatibility
    if args.compatibility:
        incompatibilities = check_platform_compatibility(args.platform_dir, manifest)
        is_compat = len(incompatibilities) == 0
        if args.json:
            print(json.dumps({"compatible": is_compat, "issues": incompatibilities}, indent=2))
        else:
            print("==============================================================================")
            print(">>> InfraFlow Platform Candidate Compatibility Evaluation")
            print("==============================================================================")
            print(f"Candidate SHA: {manifest['platform']['candidate_sha']}")
            if is_compat:
                print("Status: 100% COMPATIBLE across all consumer workflow contracts.")
            else:
                print("Status: INCOMPATIBLE ISSUES DETECTED:")
                for issue in incompatibilities:
                    print(f"  • [FAIL] {issue}")
            print("==============================================================================")
        sys.exit(0 if is_compat else 1)

    # 6. Action: --apply or --rollback
    if args.apply or args.rollback:
        target_stage = args.stage
        target_consumer = args.consumer
        is_rollback = args.rollback
        applied_actions: List[str] = []
        all_ok = True

        for c in manifest["consumers"]:
            cid = c["consumer_id"]
            if target_consumer and cid != target_consumer:
                continue

            role = c.get("upgrade_role", "progressive")
            if target_stage == "canary" and role != "canary":
                continue
            if target_stage == "progressive" and role != "progressive":
                continue

            repo_name = c["repository"].split("/")[-1]
            repo_path = args.fleet_root / repo_name
            target_sha = c["rollback_sha"] if is_rollback else c["target_sha"]

            ok, logs = apply_consumer_upgrade(repo_path, target_sha, is_rollback=is_rollback)
            if not ok:
                all_ok = False
            applied_actions.extend([f"[{cid}] {log}" for log in logs])

        if args.json:
            print(json.dumps({"success": all_ok, "actions": applied_actions}, indent=2))
        else:
            action_name = "ROLLBACK" if is_rollback else "UPGRADE"
            print("==============================================================================")
            print(f">>> InfraFlow Fleet {action_name} Execution Summary")
            print("==============================================================================")
            for act in applied_actions:
                print(f"  • {act}")
            print("==============================================================================")
            print(f"Execution Result: {'SUCCESS' if all_ok else 'FAILED'}")
            print("==============================================================================")
        sys.exit(0 if all_ok else 1)

    # 7. Action: --plan (Default)
    plan = generate_upgrade_plan(manifest, fleet_reports)
    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print("==============================================================================")
        print(">>> InfraFlow Fleet Upgrade Plan (Dry-Run)")
        print("==============================================================================")
        print(f"Target Candidate SHA: {plan['candidate_sha']}")
        print(f"Rollback Reference:   {plan['rollback_sha']}")
        print("------------------------------------------------------------------------------")
        print("Stage 1 — Canary Rollout:")
        for item in plan["staged_rollout"]["canary"]:
            action = "UPGRADE" if item["upgrade_needed"] else "ALIGNED"
            print(f"  • [{action}] {item['consumer_id']} ({item['adapter']}): {item['current_sha'][:8]}... -> {item['target_sha'][:8]}...")
        print("Stage 2 — Progressive Rollout (Pending Canary Verification):")
        for item in plan["staged_rollout"]["progressive"]:
            action = "UPGRADE" if item["upgrade_needed"] else "ALIGNED"
            print(f"  • [{action}] {item['consumer_id']} ({item['adapter']}): {item['current_sha'][:8]}... -> {item['target_sha'][:8]}...")
        print("==============================================================================")
        print(f"Total Actions Required: {len(plan['actions_required'])}")
        print("==============================================================================")


if __name__ == "__main__":
    main()
