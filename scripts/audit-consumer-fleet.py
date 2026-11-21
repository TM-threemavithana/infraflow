#!/usr/bin/env python3
"""
InfraFlow Central Consumer Fleet Governance Auditor (Milestone G08.3)

Provides centralized monitoring and audit capabilities across all participating
consumer repositories (Layer D of the InfraFlow Governance Defense-in-Depth Model).

Audits:
1. Consumer configuration presence and schema validity.
2. Mandatory caller workflow presence in .github/workflows/.
3. Central governance workflow (reusable-tf-governance.yml) invocation.
4. Server-side GitHub branch protection / ruleset enforcement status.
5. Pinned platform commit SHA consistency across the fleet.

Exit Codes:
  0 - All fleet repositories compliant with governance standards.
  1 - One or more governance violations or unmonitored bypasses detected.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_CONSUMER_REPOS = [
    {
        "name": "infraflow-consumer-networking",
        "owner": "TM-threemavithana",
        "workload": "networking",
        "expected_adapter": "aws",
    },
    {
        "name": "infraflow-consumer-application",
        "owner": "TM-threemavithana",
        "workload": "application",
        "expected_adapter": "azure",
    },
    {
        "name": "infraflow-consumer-data-platform",
        "owner": "TM-threemavithana",
        "workload": "data-platform",
        "expected_adapter": "gcp",
    },
]


def audit_local_consumer(repo_path: Path, expected_adapter: str, validator_path: Path) -> Dict[str, Any]:
    """Audits a locally cloned consumer repository using validate-consumer.py."""
    report: Dict[str, Any] = {
        "repository": repo_path.name,
        "path": str(repo_path),
        "config_present": False,
        "workflows_present": False,
        "governance_workflow_invoked": False,
        "adapter_workflow_invoked": False,
        "ruleset_status": "local_inspection_only",
        "passed": False,
        "errors": [],
    }

    config_file = repo_path / "infraflow.config.yaml"
    if not config_file.is_file():
        report["errors"].append("Missing infraflow.config.yaml")
        return report
    report["config_present"] = True
    try:
        if yaml:
            cfg = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            if isinstance(cfg, dict):
                report["config_sha"] = cfg.get("platform_sha")
    except Exception:
        pass

    workflows_dir = repo_path / ".github" / "workflows"
    if not workflows_dir.is_dir():
        report["errors"].append("Missing .github/workflows directory")
        return report

    wf_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    if not wf_files:
        report["errors"].append("No workflow files found in .github/workflows")
        return report
    report["workflows_present"] = True

    # Check for reusable-tf-governance.yml in workflows
    for wf in wf_files:
        try:
            content = wf.read_text(encoding="utf-8")
            if "reusable-tf-governance.yml" in content:
                report["governance_workflow_invoked"] = True
            if f"reusable-tf-{expected_adapter}.yml" in content or (expected_adapter == "generic" and "reusable-tf-validate.yml" in content):
                report["adapter_workflow_invoked"] = True
        except Exception as e:
            report["errors"].append(f"Failed reading {wf.name}: {e}")

    # Run validator
    if validator_path.is_file():
        cmd = [sys.executable, str(validator_path), "--config", str(config_file), "--repo-dir", str(repo_path), "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            try:
                data = json.loads(proc.stdout)
                report["errors"].extend(data.get("errors", ["Validator failed"]))
            except Exception:
                report["errors"].append(proc.stderr.strip() or "Validator error")
        else:
            report["passed"] = True
    else:
        report["errors"].append(f"Validator script not found at {validator_path}")

    return report


def audit_remote_rulesets(owner: str, repo_name: str) -> Dict[str, Any]:
    """Inspects GitHub branch rulesets, protections, and latest CI status via gh CLI."""
    ruleset_info: Dict[str, Any] = {
        "rulesets_active": False,
        "ruleset_ids": [],
        "branch_protection_active": False,
        "required_status_checks": [],
        "server_side_status": "unverified",
        "latest_ci_run": None,
        "details": "",
    }

    # 1. Query rulesets
    res = subprocess.run(["gh", "api", f"repos/{owner}/{repo_name}/rulesets"], capture_output=True, text=True)
    if res.returncode == 0:
        try:
            rulesets = json.loads(res.stdout)
            if isinstance(rulesets, list) and rulesets:
                ruleset_info["rulesets_active"] = True
                ruleset_info["ruleset_ids"] = [r.get("id") for r in rulesets if isinstance(r, dict)]
                ruleset_info["details"] = f"{len(rulesets)} active ruleset(s)"
                ruleset_info["server_side_status"] = "enforced"
            else:
                ruleset_info["rulesets_active"] = False
        except Exception:
            ruleset_info["server_side_status"] = "unknown"
    else:
        ruleset_info["server_side_status"] = "inaccessible"

    # 2. Query branch protection (legacy API check to ensure protections aren't overlooked)
    res_bp = subprocess.run(["gh", "api", f"repos/{owner}/{repo_name}/branches/main/protection"], capture_output=True, text=True)
    if res_bp.returncode == 0:
        try:
            bp = json.loads(res_bp.stdout)
            if isinstance(bp, dict):
                ruleset_info["branch_protection_active"] = True
                checks = bp.get("required_status_checks", {}).get("contexts", [])
                ruleset_info["required_status_checks"] = checks
                ruleset_info["server_side_status"] = "enforced"
        except Exception:
            pass
    elif res.returncode == 0 and not ruleset_info["rulesets_active"]:
        ruleset_info["server_side_status"] = "not_enforced"

    # 3. Query latest CI run
    res_ci = subprocess.run(
        ["gh", "run", "list", "--repo", f"{owner}/{repo_name}", "-L", "1", "--json", "status,conclusion,url,headSha"],
        capture_output=True,
        text=True,
    )
    if res_ci.returncode == 0:
        try:
            runs = json.loads(res_ci.stdout)
            if isinstance(runs, list) and runs:
                ruleset_info["latest_ci_run"] = runs[0]
        except Exception:
            pass

    return ruleset_info


def calculate_drift_severity(report: Dict[str, Any], expected_sha: str) -> str:
    """Calculates drift severity: CRITICAL, HIGH, LOW, or NONE."""
    if not report.get("governance_workflow_invoked") or not report.get("passed"):
        return "CRITICAL"

    config_sha = report.get("config_sha")
    if not config_sha or config_sha in {"main", "master", "latest", "dev", "HEAD", "v0.5.0", "v0.4.0"}:
        return "CRITICAL"

    if expected_sha and config_sha != expected_sha:
        return "HIGH"

    if report.get("errors"):
        return "HIGH"

    return "NONE"


def main():
    parser = argparse.ArgumentParser(
        description="InfraFlow Central Consumer Fleet Governance Auditor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "repos",
        nargs="*",
        type=Path,
        help="Specific repository directory paths to audit (overrides default fleet scan)",
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
        "--check-remote",
        action="store_true",
        help="Query GitHub API for server-side ruleset status",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON payload",
    )

    args = parser.parse_args()

    validator_path = args.platform_dir / "scripts" / "validate-consumer.py"
    fleet_reports: List[Dict[str, Any]] = []
    all_compliant = True

    # Attempt to load authoritative expected SHAs from fleet manifest
    manifest_file = args.platform_dir / "config" / "fleet-manifest.yaml"
    expected_shas: Dict[str, str] = {}
    if manifest_file.is_file() and yaml:
        try:
            m_data = yaml.safe_load(manifest_file.read_text(encoding="utf-8"))
            if isinstance(m_data, dict):
                p_cand = m_data.get("platform", {}).get("candidate_sha", "")
                for c in m_data.get("consumers", []):
                    c_repo = c.get("repository", "")
                    c_target = c.get("target_sha") or p_cand
                    if c_repo and c_target:
                        expected_shas[c_repo] = c_target
                        expected_shas[c_repo.split("/")[-1]] = c_target
        except Exception:
            pass

    if args.repos:
        for repo_dir in args.repos:
            repo_path = repo_dir.resolve()
            if not repo_path.is_dir():
                fleet_reports.append({
                    "repository": str(repo_path),
                    "status": "missing_directory",
                    "passed": False,
                    "errors": [f"Specified repository directory not found: {repo_path}"],
                })
                all_compliant = False
                continue

            config_file = repo_path / "infraflow.config.yaml"
            adapter = ""
            if config_file.is_file():
                try:
                    if yaml:
                        cfg = yaml.safe_load(config_file.read_text(encoding="utf-8"))
                    if isinstance(cfg, dict):
                        adapter = cfg.get("adapter", "")
                except Exception:
                    pass

            report = audit_local_consumer(repo_path, adapter, validator_path)
            if not report["passed"]:
                all_compliant = False
            fleet_reports.append(report)
    else:
        for item in DEFAULT_CONSUMER_REPOS:
            repo_dir = args.fleet_root / item["name"]
            if not repo_dir.is_dir():
                fleet_reports.append({
                    "repository": item["name"],
                    "status": "missing_local_clone",
                    "passed": False,
                    "errors": [f"Local repository directory not found: {repo_dir}"],
                })
                all_compliant = False
                continue

            report = audit_local_consumer(repo_dir, item["expected_adapter"], validator_path)
            exp_sha = expected_shas.get(item["name"]) or expected_shas.get(f"{item['owner']}/{item['name']}") or ""
            report["drift_severity"] = calculate_drift_severity(report, expected_sha=exp_sha)

            if args.check_remote:
                remote_info = audit_remote_rulesets(item["owner"], item["name"])
                report["remote_governance"] = remote_info

            if not report["passed"]:
                all_compliant = False

            fleet_reports.append(report)

    if args.json:
        payload = {
            "compliant": all_compliant,
            "total_repositories": len(fleet_reports),
            "reports": fleet_reports,
        }
        print(json.dumps(payload, indent=2))
    else:
        print("==============================================================================")
        print(">>> InfraFlow Central Consumer Fleet Governance Audit Report")
        print("==============================================================================")
        for r in fleet_reports:
            status = "PASS" if r.get("passed") else "VIOLATION"
            sev = r.get("drift_severity", "UNKNOWN")
            print(f"[{status}] {r['repository']} (Drift Severity: {sev})")
            if r.get("errors"):
                for err in r["errors"]:
                    print(f"       - Error: {err}")
            if "remote_governance" in r:
                rg = r["remote_governance"]
                active = "Active" if (rg.get("rulesets_active") or rg.get("branch_protection_active")) else "NOT ACTIVE (unverified)"
                print(f"       - Server-Side Protection: {active}")
                if rg.get("latest_ci_run"):
                    ci = rg["latest_ci_run"]
                    print(f"       - Latest CI: {ci.get('conclusion', ci.get('status'))} ({ci.get('url')})")
        print("==============================================================================")
        print(f"Fleet Status: {'COMPLIANT' if all_compliant else 'NON-COMPLIANT'}")
        print("==============================================================================")

    sys.exit(0 if all_compliant else 1)


if __name__ == "__main__":
    main()
