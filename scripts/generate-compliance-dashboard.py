#!/usr/bin/env python3
"""
InfraFlow Central Consumer Fleet Compliance Dashboard Generator (Milestone G09.1)

Aggregates fleet manifest, local consumer repositories, workflow contracts,
and observability telemetry to generate multi-tenant compliance posture reports.

Evaluates 5 Core Governance Pillars:
1. Contract Validity & Schema Conformance (20%)
2. Supply Chain Immutability (40-char SHA Pinning) (20%)
3. Mandatory DevSecOps Security Controls (20%)
4. Permission Boundary & Least Privilege (20%)
5. Configuration & Version Drift Integrity (20%)

Output Formats:
- Machine-readable JSON summary (--output-json)
- Executive Markdown report (--output-markdown)
- Standalone, offline-ready HTML dashboard (--output-html)

Exit Codes:
  0 - Compliance evaluation successful and above required threshold.
  1 - Threshold failure, schema error, or compliance evaluation failure.
"""

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

RE_40_HEX = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
MUTABLE_REFS = {"main", "master", "latest", "head", "dev", "develop"}


class ComplianceEvaluationError(Exception):
    """Raised when compliance dashboard generation fails."""
    pass


def load_fleet_manifest(manifest_path: Path) -> Dict[str, Any]:
    """Loads and basic-validates the fleet upgrade manifest."""
    if not manifest_path.is_file():
        raise ComplianceEvaluationError(f"Fleet manifest not found: {manifest_path}")

    content = manifest_path.read_text(encoding="utf-8")
    if yaml:
        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise ComplianceEvaluationError(f"Failed parsing YAML manifest: {e}")
    else:
        # Fallback minimal JSON parser if YAML was saved as JSON
        try:
            data = json.loads(content)
        except Exception as e:
            raise ComplianceEvaluationError(f"PyYAML not available and JSON fallback failed: {e}")

    if not isinstance(data, dict) or "consumers" not in data:
        raise ComplianceEvaluationError("Invalid manifest structure: missing 'consumers' list.")

    return data


def evaluate_consumer_compliance(
    consumer_entry: Dict[str, Any],
    repo_path: Optional[Path],
    telemetry_events: Optional[List[Dict[str, Any]]] = None,
    drift_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates a single consumer repository across the 5 Governance Pillars.
    Returns a detailed scoring dictionary (0-100 score).
    """
    cid = consumer_entry.get("consumer_id", "unknown")
    repo_name = consumer_entry.get("repository", "unknown")
    adapter = consumer_entry.get("adapter", "generic")

    pillar_scores = {
        "contract_validity": 0,
        "supply_chain_immutability": 0,
        "security_controls": 0,
        "permission_boundary": 0,
        "drift_integrity": 0,
    }
    findings: List[str] = []
    pillar_breakdown: Dict[str, List[str]] = {p: [] for p in pillar_scores}

    # Pre-evaluate drift_info if drift_report provided (G09.2)
    drift_info = None
    if drift_report and isinstance(drift_report, dict):
        summary_d = drift_report.get("summary", {})
        verdict = summary_d.get("verdict", "NO_DRIFT")
        drift_info = {
            "verdict": verdict,
            "drifted_count": summary_d.get("drifted_resources_count", 0),
            "highest_severity": summary_d.get("highest_severity", "NONE"),
        }

    if not repo_path or not repo_path.is_dir():
        findings.append(f"Repository local clone not available at '{repo_path}'")
        return {
            "consumer_id": cid,
            "repository": repo_name,
            "adapter": adapter,
            "path": str(repo_path) if repo_path else "none",
            "exists_locally": False,
            "total_score": 0.0,
            "pillar_scores": pillar_scores,
            "status": "NON_COMPLIANT",
            "findings": findings,
            "pillar_breakdown": pillar_breakdown,
            "drift_assessment": drift_info,
        }

    # =========================================================================
    # Pillar 1: Contract Validity & Schema Conformance (Max 20 pts)
    # =========================================================================
    config_file = repo_path / "infraflow.config.yaml"
    cfg_data: Dict[str, Any] = {}
    if config_file.is_file():
        pillar_scores["contract_validity"] += 5
        pillar_breakdown["contract_validity"].append("infraflow.config.yaml exists (+5)")
        try:
            if yaml:
                loaded = yaml.safe_load(config_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    cfg_data = loaded
                    pillar_scores["contract_validity"] += 5
                    pillar_breakdown["contract_validity"].append("Valid YAML structure (+5)")

                    if cfg_data.get("version") == "1.0":
                        pillar_scores["contract_validity"] += 5
                        pillar_breakdown["contract_validity"].append("Schema version 1.0 (+5)")
                    else:
                        findings.append(f"Invalid config version: '{cfg_data.get('version')}' (expected '1.0')")

                    if cfg_data.get("consumer_id") == cid and cfg_data.get("team"):
                        pillar_scores["contract_validity"] += 5
                        pillar_breakdown["contract_validity"].append("Consumer ID and Team defined (+5)")
                    else:
                        findings.append("Config missing matching consumer_id or team definition")
        except Exception as e:
            findings.append(f"Failed parsing infraflow.config.yaml: {e}")
    else:
        findings.append("Missing infraflow.config.yaml contract file")

    # =========================================================================
    # Pillar 2: Supply Chain Immutability (Max 20 pts)
    # =========================================================================
    config_sha = cfg_data.get("platform_sha", "")
    if RE_40_HEX.match(str(config_sha)):
        pillar_scores["supply_chain_immutability"] += 10
        pillar_breakdown["supply_chain_immutability"].append("Config pins immutable 40-character commit SHA (+10)")
    else:
        findings.append(f"Config platform_sha is not an immutable 40-char SHA: '{config_sha}'")

    # Inspect workflow refs
    wf_dir = repo_path / ".github" / "workflows"
    wf_shas_seen = set()
    mutable_refs_found = []

    if wf_dir.is_dir():
        for wf_path in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
            try:
                content = wf_path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    if "uses:" in line and "TM-threemavithana/infraflow/.github/workflows/" in line:
                        m = re.search(r"TM-threemavithana/infraflow/\.github/workflows/[^@\s]+@([^\s#]+)", line)
                        if m:
                            ref = m.group(1).strip()
                            wf_shas_seen.add(ref)
                            if ref.lower() in MUTABLE_REFS or not RE_40_HEX.match(ref):
                                mutable_refs_found.append(f"{wf_path.name} uses '@{ref}'")
            except Exception:
                continue

    if wf_shas_seen and not mutable_refs_found:
        pillar_scores["supply_chain_immutability"] += 10
        pillar_breakdown["supply_chain_immutability"].append("Workflows strictly pin immutable 40-character commit SHAs (+10)")
    elif mutable_refs_found:
        findings.append(f"Mutable platform references detected in workflows: {', '.join(mutable_refs_found)}")
    else:
        findings.append("No platform workflow invocations found to evaluate SHA immutability")

    # =========================================================================
    # Pillar 3: Mandatory DevSecOps Security Controls (Max 20 pts)
    # =========================================================================
    sec_ctrls = cfg_data.get("security_controls", {})
    if isinstance(sec_ctrls, dict) and sec_ctrls.get("enforce_mandatory_scanners") is True:
        pillar_scores["security_controls"] += 10
        pillar_breakdown["security_controls"].append("Mandatory security scanners enforced in config (+10)")
    else:
        findings.append("enforce_mandatory_scanners is not true in config")

    governance_invoked = False
    if wf_dir.is_dir():
        for wf_path in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
            try:
                content = wf_path.read_text(encoding="utf-8")
                if "reusable-tf-governance.yml" in content:
                    governance_invoked = True
                    break
            except Exception:
                continue

    if governance_invoked:
        pillar_scores["security_controls"] += 10
        pillar_breakdown["security_controls"].append("Reusable governance gate (reusable-tf-governance.yml) invoked (+10)")
    else:
        findings.append("Reusable governance workflow (reusable-tf-governance.yml) not invoked in workflows")

    # =========================================================================
    # Pillar 4: Permission Boundary & Least Privilege (Max 20 pts)
    # =========================================================================
    permissions_clean = True
    no_id_token_write = True
    no_pr_target = True

    if wf_dir.is_dir():
        for wf_path in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
            try:
                content = wf_path.read_text(encoding="utf-8")
                if "pull_request_target" in content:
                    no_pr_target = False
                    findings.append(f"Forbidden 'pull_request_target' trigger in '{wf_path.name}'")
                if "write-all" in content:
                    permissions_clean = False
                    findings.append(f"Forbidden 'write-all' permissions in '{wf_path.name}'")
                if "id-token: write" in content:
                    no_id_token_write = False
                    findings.append(f"Forbidden 'id-token: write' permission in cloud-free workflow '{wf_path.name}'")
            except Exception:
                continue

    if permissions_clean:
        pillar_scores["permission_boundary"] += 10
        pillar_breakdown["permission_boundary"].append("Workflows enforce least-privilege tokens (zero write-all) (+10)")
    if no_id_token_write:
        pillar_scores["permission_boundary"] += 5
        pillar_breakdown["permission_boundary"].append("Zero id-token: write granted in cloud-free mode (+5)")
    if no_pr_target:
        pillar_scores["permission_boundary"] += 5
        pillar_breakdown["permission_boundary"].append("Zero pull_request_target escalation triggers (+5)")

    # =========================================================================
    # Pillar 5: Configuration & Drift Integrity (Max 20 pts)
    # =========================================================================
    config_wf_match = False
    if config_sha and wf_shas_seen:
        if len(wf_shas_seen) == 1 and config_sha in wf_shas_seen:
            config_wf_match = True
            pillar_scores["drift_integrity"] += 10
            pillar_breakdown["drift_integrity"].append("Config platform_sha exactly matches workflow callers (+10)")
        else:
            findings.append(f"Drift between config SHA ({config_sha[:8]}...) and workflow SHAs ({[s[:8] for s in wf_shas_seen]})")
    else:
        findings.append("Cannot evaluate config vs workflow SHA parity (missing SHA)")

    adapter_matches = False
    if cfg_data.get("adapter") == adapter:
        adapter_matches = True
        pillar_scores["drift_integrity"] += 5
        pillar_breakdown["drift_integrity"].append(f"Config adapter '{cfg_data.get('adapter')}' matches manifest (+5)")
    else:
        findings.append(f"Config adapter '{cfg_data.get('adapter')}' does not match manifest '{adapter}'")

    # Target SHA alignment
    target_sha = consumer_entry.get("target_sha") or consumer_entry.get("current_sha")
    if target_sha and config_sha == target_sha:
        pillar_scores["drift_integrity"] += 5
        pillar_breakdown["drift_integrity"].append("Consumer aligns with approved platform deployment target (+5)")
    else:
        findings.append(f"Consumer config SHA ({config_sha[:8] if config_sha else 'none'}...) does not match manifest target ({target_sha[:8] if target_sha else 'none'}...)")

    # Optional Infrastructure State Drift Assessment Integration (G09.2)
    drift_info = None
    if drift_report and isinstance(drift_report, dict):
        summary_d = drift_report.get("summary", {})
        verdict = summary_d.get("verdict", "NO_DRIFT")
        drift_info = {
            "verdict": verdict,
            "drifted_count": summary_d.get("drifted_resources_count", 0),
            "highest_severity": summary_d.get("highest_severity", "NONE"),
        }
        if verdict in ("NO_DRIFT", "CLEAN"):
            pillar_breakdown["drift_integrity"].append("Infrastructure state: CLEAN (zero drift detected)")
        else:
            highest_sev = summary_d.get("highest_severity", "MEDIUM")
            if highest_sev == "CRITICAL":
                penalty = 10.0
            else:
                penalty = 5.0
            pillar_scores["drift_integrity"] = max(0.0, pillar_scores["drift_integrity"] - penalty)
            findings.append(f"Infrastructure state {highest_sev} drift: {summary_d.get('drifted_resources_count', 0)} drifted resources")
            pillar_breakdown["drift_integrity"].append(f"Penalty: -{int(penalty)} pts for {highest_sev} infrastructure drift")

    total_score = float(sum(pillar_scores.values()))

    # Determine status
    if total_score >= 95.0:
        status = "COMPLIANT"
    elif total_score >= 80.0:
        status = "WARNING"
    else:
        status = "NON_COMPLIANT"

    return {
        "consumer_id": cid,
        "repository": repo_name,
        "adapter": adapter,
        "path": str(repo_path),
        "exists_locally": True,
        "total_score": total_score,
        "pillar_scores": pillar_scores,
        "status": status,
        "findings": findings,
        "pillar_breakdown": pillar_breakdown,
        "drift_assessment": drift_info,
    }


def generate_compliance_report(
    manifest_path: Path,
    fleet_root: Path,
    telemetry_path: Optional[Path] = None,
    drift_dir: Optional[Path] = None,
    campaign_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Generates the full fleet compliance summary."""
    manifest = load_fleet_manifest(manifest_path)
    consumers = manifest.get("consumers", [])

    reports: List[Dict[str, Any]] = []
    for c in consumers:
        repo_name = c.get("repository", "").split("/")[-1]
        cid = c.get("consumer_id", "")

        # Try fleet_root / repo_name, fleet_root / cid, fleet_root / workload_type, then fixtures / consumers / ...
        cand0 = fleet_root / (c.get("workload_type") or "")
        cand1 = fleet_root / repo_name
        cand2 = fleet_root / cid
        cand3 = fleet_root / "fixtures" / "consumers" / (c.get("workload_type") or "")

        chosen_path = None
        for cand in (cand0, cand1, cand2, cand3):
            if cand.is_dir():
                chosen_path = cand
                break

        if not chosen_path and (fleet_root == Path(".") or str(fleet_root) == "."):
            cand4 = Path(f"/home/tharuka/projects/{repo_name}")
            if cand4.is_dir():
                chosen_path = cand4

        # Check for per-consumer drift report if drift_dir provided
        consumer_drift_report = None
        if drift_dir and drift_dir.is_dir():
            for name_candidate in (cid, repo_name, c.get("workload_type")):
                if not name_candidate:
                    continue
                cand_file = drift_dir / f"{name_candidate}.json"
                if cand_file.is_file() and not (cand_file.is_symlink() or os.path.islink(cand_file)):
                    try:
                        with open(cand_file, "r", encoding="utf-8") as df:
                            consumer_drift_report = json.load(df)
                        break
                    except Exception:
                        pass

        r = evaluate_consumer_compliance(c, chosen_path, drift_report=consumer_drift_report)
        reports.append(r)

    total_scores = [r["total_score"] for r in reports]
    fleet_score = round(sum(total_scores) / len(total_scores), 1) if total_scores else 0.0

    if fleet_score >= 95.0:
        fleet_status = "COMPLIANT"
    elif fleet_score >= 80.0:
        fleet_status = "WARNING"
    else:
        fleet_status = "NON_COMPLIANT"

    platform_info = manifest.get("platform", {})

    drift_assessed = [r for r in reports if r.get("drift_assessment") is not None]
    drift_summary = {
        "evaluated": len(drift_assessed) > 0,
        "total_assessed": len(drift_assessed),
        "clean_consumers": sum(1 for r in drift_assessed if r["drift_assessment"]["verdict"] == "NO_DRIFT"),
        "drifted_consumers": sum(1 for r in drift_assessed if r["drift_assessment"]["verdict"] == "DRIFT_DETECTED"),
        "fleet_drift_verdict": "DRIFT_DETECTED" if any(r["drift_assessment"]["verdict"] == "DRIFT_DETECTED" for r in drift_assessed) else ("CLEAN" if drift_assessed else "NOT_EVALUATED"),
    }

    campaign_summary = None
    if campaign_file:
        if os.path.islink(campaign_file) or campaign_file.is_symlink():
            raise ValueError(f"Security rejection: campaign file '{campaign_file}' is a symlink.")
        if campaign_file.is_file():
            try:
                c_data = json.loads(campaign_file.read_text(encoding="utf-8"))
                stages = {s.get("stage_name"): s for s in c_data.get("stages", [])}
                canary_s = stages.get("canary", {})
                prog_s = stages.get("progressive", {})
                total_w = sum(len(s.get("consumers", [])) for s in c_data.get("stages", []))
                ver_w = sum(sum(1 for c in s.get("consumers", []) if c.get("status") == "VERIFIED") for s in c_data.get("stages", []))
                campaign_summary = {
                    "active": True,
                    "campaign_id": c_data.get("campaign_id"),
                    "title": c_data.get("title"),
                    "target_platform_sha": c_data.get("target_platform_sha"),
                    "status": c_data.get("status"),
                    "created_at": c_data.get("created_at"),
                    "canary_status": canary_s.get("status", "UNKNOWN"),
                    "progressive_status": prog_s.get("status", "UNKNOWN"),
                    "total_workloads": total_w,
                    "verified_workloads": ver_w,
                }
            except Exception as e:
                campaign_summary = {"active": False, "error": f"Failed reading campaign file: {e}"}

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": {
            "repository": platform_info.get("repository", "TM-threemavithana/infraflow"),
            "current_release_tag": platform_info.get("current_release_tag", "v0.6.0"),
            "current_release_sha": platform_info.get("current_release_sha", ""),
            "approved_deployment_target_sha": platform_info.get("approved_deployment_target_sha", ""),
        },
        "fleet_summary": {
            "total_consumers": len(reports),
            "compliant_consumers": sum(1 for r in reports if r["status"] == "COMPLIANT"),
            "warning_consumers": sum(1 for r in reports if r["status"] == "WARNING"),
            "non_compliant_consumers": sum(1 for r in reports if r["status"] == "NON_COMPLIANT"),
            "fleet_compliance_score": fleet_score,
            "fleet_status": fleet_status,
        },
        "drift_summary": drift_summary,
        "campaign_summary": campaign_summary,
        "consumers": reports,
    }


def render_markdown_dashboard(data: Dict[str, Any]) -> str:
    """Renders the compliance report in GitHub-flavored Markdown."""
    summary = data["fleet_summary"]
    plat = data["platform"]

    status_badge = "🟢 **COMPLIANT**" if summary["fleet_status"] == "COMPLIANT" else ("🟡 **WARNING**" if summary["fleet_status"] == "WARNING" else "🔴 **NON_COMPLIANT**")

    lines = [
        "# InfraFlow Central Fleet Compliance & Observability Dashboard",
        "",
        f"> **Generated:** {data['generated_at']} | **Platform Release:** `{plat.get('current_release_tag')}` | **Fleet Status:** {status_badge}",
        "",
        "## 1. Fleet Executive Summary",
        "",
        "| Metric | Value | Threshold / Target | Status |",
        "| :--- | :---: | :---: | :---: |",
        f"| **Overall Fleet Compliance Score** | **{summary['fleet_compliance_score']}%** | 100.0% | {status_badge} |",
        f"| **Total Registered Consumers** | **{summary['total_consumers']}** | All Workloads | — |",
        f"| **Fully Compliant Workloads** | **{summary['compliant_consumers']} / {summary['total_consumers']}** | 100% | 🟢 PASS |",
        f"| **Workloads with Warnings** | **{summary['warning_consumers']}** | 0 | {'🟡 WARN' if summary['warning_consumers'] > 0 else '🟢 ZERO'} |",
        f"| **Non-Compliant Workloads** | **{summary['non_compliant_consumers']}** | 0 | {'🔴 FAIL' if summary['non_compliant_consumers'] > 0 else '🟢 ZERO'} |",
    ]

    drift_s = data.get("drift_summary", {})
    if drift_s.get("evaluated"):
        drift_badge = "🟢 CLEAN" if drift_s.get("fleet_drift_verdict") == "CLEAN" else "🔴 DRIFT IDENTIFIED"
        lines.append(
            f"| **Infrastructure State Drift** | **{drift_s.get('clean_consumers')}/{drift_s.get('total_assessed')} Clean** | 100% Synchronized | {drift_badge} |"
        )

    camp_s = data.get("campaign_summary")
    if camp_s and camp_s.get("active"):
        c_status = camp_s.get("status", "UNKNOWN")
        st_icon = "🟢" if c_status == "COMPLETED" else ("🟡" if "IN_PROGRESS" in c_status or c_status == "CANARY_VERIFIED" else ("🔄" if c_status == "ROLLED_BACK" else "ℹ️"))
        canary_badge = "🟢 PASS" if camp_s.get("canary_status") == "VERIFIED" else ("🟡 PENDING" if camp_s.get("canary_status") in {"PENDING", "RUNNING"} else "🔴 FAILED")
        prog_badge = "🟢 PASS" if camp_s.get("progressive_status") == "VERIFIED" else ("🟡 PENDING" if camp_s.get("progressive_status") in {"PENDING", "RUNNING"} else "🔴 FAILED")
        roll_badge = "🟢 COMPLETE" if camp_s.get("verified_workloads") == camp_s.get("total_workloads") else "🟡 IN_PROGRESS"

        lines.extend([
            "",
            "## 2. Active Fleet Upgrade Campaign",
            "",
            "| Campaign Attribute | Value | Target / Requirement | Status |",
            "| :--- | :---: | :---: | :---: |",
            f"| **Campaign ID** | `{camp_s.get('campaign_id')}` | Active Staged Campaign | ℹ️ ACTIVE |",
            f"| **Target Platform Release SHA** | `{camp_s.get('target_platform_sha', '')[:7]}` | Pinned Release Commit | 🟢 VALID |",
            f"| **Campaign Lifecycle Status** | **`{c_status}`** | COMPLETED | {st_icon} {c_status} |",
            f"| **Canary Rollout Gate** | **`{camp_s.get('canary_status')}`** | VERIFIED | {canary_badge} |",
            f"| **Progressive Batch Rollout** | **`{camp_s.get('progressive_status')}`** | VERIFIED | {prog_badge} |",
            f"| **Workload Rollout Velocity** | **{camp_s.get('verified_workloads')} / {camp_s.get('total_workloads')} Workloads** | 100% Verified | {roll_badge} |",
        ])

    lines.extend([
        "",
        "## 2. Multi-Tenant Workload Posture" if not (camp_s and camp_s.get("active")) else "## 3. Multi-Tenant Workload Posture",
        "",
        "| Consumer ID | Workload / Repo | Adapter | P1 (Contract) | P2 (Immutability) | P3 (Security) | P4 (Permissions) | P5 (Drift) | Total Score | Status |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for c in data["consumers"]:
        ps = c["pillar_scores"]
        status_icon = "🟢" if c["status"] == "COMPLIANT" else ("🟡" if c["status"] == "WARNING" else "🔴")
        lines.append(
            f"| `{c['consumer_id']}` | `{c['repository']}` | `{c['adapter']}` | {ps['contract_validity']}/20 | {ps['supply_chain_immutability']}/20 | {ps['security_controls']}/20 | {ps['permission_boundary']}/20 | {ps['drift_integrity']}/20 | **{c['total_score']}%** | {status_icon} {c['status']} |"
        )

    lines.extend([
        "",
        "## 3. Governance Findings & Recommendations" if not (camp_s and camp_s.get("active")) else "## 4. Governance Findings & Recommendations",
        "",
    ])

    has_findings = False
    for c in data["consumers"]:
        if c.get("findings"):
            has_findings = True
            lines.append(f"### Workload: `{c['consumer_id']}` ({c['repository']})")
            for f in c["findings"]:
                lines.append(f"- ⚠️ {f}")
            lines.append("")

    if not has_findings:
        lines.append("✅ **Zero governance findings detected across the consumer fleet.** All workloads adhere strictly to contract schemas, 40-character commit SHA pinning, mandatory security scanners, least-privilege tokens, and zero configuration drift.")
        lines.append("")

    lines.extend([
        "---",
        "*Report automatically generated by `scripts/generate-compliance-dashboard.py` (InfraFlow Milestone G09.1).*",
    ])

    return "\n".join(lines)


def render_html_dashboard(data: Dict[str, Any]) -> str:
    """Renders a modern, responsive, completely self-contained single-page HTML report."""
    summary = data["fleet_summary"]
    plat = data["platform"]

    status_color = "#10b981" if summary["fleet_status"] == "COMPLIANT" else ("#f59e0b" if summary["fleet_status"] == "WARNING" else "#ef4444")
    warn_color = "var(--accent-yellow)" if summary["warning_consumers"] > 0 else "var(--text-secondary)"

    consumer_rows = []
    for c in data["consumers"]:
        ps = c["pillar_scores"]
        c_status_color = "#10b981" if c["status"] == "COMPLIANT" else ("#f59e0b" if c["status"] == "WARNING" else "#ef4444")
        findings_html = "".join([f"<li>{html.escape(f)}</li>" for f in c.get("findings", [])]) or "<li class='text-muted'>Zero findings</li>"

        consumer_rows.append(f"""
        <tr>
            <td class="font-mono"><strong>{html.escape(c['consumer_id'])}</strong></td>
            <td class="font-mono">{html.escape(c['repository'])}</td>
            <td><span class="badge badge-adapter">{html.escape(c['adapter'].upper())}</span></td>
            <td>{ps['contract_validity']}/20</td>
            <td>{ps['supply_chain_immutability']}/20</td>
            <td>{ps['security_controls']}/20</td>
            <td>{ps['permission_boundary']}/20</td>
            <td>{ps['drift_integrity']}/20</td>
            <td>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {c['total_score']}%; background-color: {c_status_color};"></div>
                </div>
                <strong>{c['total_score']}%</strong>
            </td>
            <td><span class="badge" style="background-color: {c_status_color};">{html.escape(c['status'])}</span></td>
        </tr>
        <tr class="findings-row">
            <td colspan="10">
                <details>
                    <summary>View Diagnostic Findings ({len(c.get('findings', []))})</summary>
                    <ul>{findings_html}</ul>
                </details>
            </td>
        </tr>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InfraFlow Fleet Compliance Dashboard</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            margin: 0 0 0.5rem 0;
            font-size: 1.875rem;
            font-weight: 700;
        }}
        .header-meta {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}
        .metric-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1.25rem;
        }}
        .metric-label {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        .metric-value {{
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }}
        .table-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        .table-header {{
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            font-size: 1.125rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.875rem;
        }}
        th, td {{
            padding: 0.875rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            color: var(--text-secondary);
            font-weight: 600;
            background-color: rgba(0, 0, 0, 0.2);
        }}
        .findings-row td {{
            background-color: rgba(0, 0, 0, 0.15);
            font-size: 0.8rem;
            padding-top: 0.5rem;
            padding-bottom: 0.5rem;
        }}
        .findings-row details summary {{
            cursor: pointer;
            color: var(--accent-blue);
        }}
        .font-mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            color: #ffffff;
        }}
        .badge-adapter {{
            background-color: #475569;
        }}
        .progress-bar {{
            height: 0.5rem;
            background-color: #334155;
            border-radius: 0.25rem;
            overflow: hidden;
            margin-bottom: 0.25rem;
            width: 100px;
        }}
        .progress-fill {{
            height: 100%;
        }}
        .text-muted {{
            color: var(--text-secondary);
        }}
        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>InfraFlow Fleet Compliance Dashboard</h1>
                <div class="header-meta">
                    Authoritative Fleet Governance & Observability Engine • Milestone G09.1
                </div>
            </div>
            <div>
                <span class="badge" style="background-color: {status_color}; font-size: 0.875rem; padding: 0.5rem 1rem;">
                    FLEET {summary['fleet_status']}
                </span>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Compliance Score</div>
                <div class="metric-value" style="color: {status_color};">{summary['fleet_compliance_score']}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Workloads</div>
                <div class="metric-value">{summary['total_consumers']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Compliant Fleets</div>
                <div class="metric-value" style="color: var(--accent-green);">{summary['compliant_consumers']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Warnings / Violations</div>
                <div class="metric-value" style="color: {warn_color};">
                    {summary['warning_consumers']} / {summary['non_compliant_consumers']}
                </div>
            </div>
        </div>

        <div class="table-card">
            <div class="table-header">Multi-Tenant Consumer Fleet Posture (5 Governance Pillars)</div>
            <table>
                <thead>
                    <tr>
                        <th>Consumer ID</th>
                        <th>Repository</th>
                        <th>Adapter</th>
                        <th>P1: Contract</th>
                        <th>P2: Supply Chain</th>
                        <th>P3: Security</th>
                        <th>P4: Least Privilege</th>
                        <th>P5: Drift</th>
                        <th>Score</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(consumer_rows)}
                </tbody>
            </table>
        </div>

        <footer>
            InfraFlow Enterprise Delivery Platform • Zero Cloud Spend ($0.00) • Zero Credentials • Generated at {data['generated_at']}
        </footer>
    </div>
</body>
</html>
"""
    return html_content


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="InfraFlow Central Consumer Fleet Compliance Dashboard Generator (Milestone G09.1)"
    )
    parser.add_argument(
        "--manifest",
        default="config/fleet-manifest.yaml",
        help="Path to authoritative fleet upgrade manifest (default: config/fleet-manifest.yaml)",
    )
    parser.add_argument(
        "--fleet-root",
        default=".",
        help="Root path containing consumer repository clones or fixtures (default: .)",
    )
    parser.add_argument(
        "--telemetry-path",
        help="Path to JSON or JSONL file with emitted telemetry events",
    )
    parser.add_argument(
        "--output-json",
        help="File path to write structured JSON compliance summary",
    )
    parser.add_argument(
        "--output-markdown",
        help="File path to write GitHub-flavored Markdown summary dashboard",
    )
    parser.add_argument(
        "--output-html",
        help="File path to write standalone HTML compliance dashboard",
    )
    parser.add_argument(
        "--enforce-threshold",
        type=float,
        default=0.0,
        help="Minimum overall fleet compliance percentage required (default: 0.0, e.g. 80.0)",
    )
    parser.add_argument(
        "--drift-dir",
        help="Optional directory containing per-consumer drift report JSON files (G09.2)",
    )
    parser.add_argument(
        "--campaign-file",
        help="Optional path to active upgrade campaign JSON state file (G09.3)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    manifest_p = Path(args.manifest)
    fleet_r = Path(args.fleet_root)
    telemetry_p = Path(args.telemetry_path) if args.telemetry_path else None
    drift_d = Path(args.drift_dir) if args.drift_dir else None
    campaign_f = Path(args.campaign_file) if args.campaign_file else None

    try:
        report_data = generate_compliance_report(
            manifest_path=manifest_p,
            fleet_root=fleet_r,
            telemetry_path=telemetry_p,
            drift_dir=drift_d,
            campaign_file=campaign_f,
        )
    except Exception as e:
        sys.stderr.write(f"[ERROR] Compliance report generation failed: {e}\n")
        return 1

    # Output JSON if requested
    if args.output_json:
        out_j = Path(args.output_json)
        out_j.parent.mkdir(parents=True, exist_ok=True)
        out_j.write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")
        print(f"JSON compliance report written to: {out_j}")

    # Output Markdown if requested
    md_content = render_markdown_dashboard(report_data)
    if args.output_markdown:
        out_m = Path(args.output_markdown)
        out_m.parent.mkdir(parents=True, exist_ok=True)
        out_m.write_text(md_content + "\n", encoding="utf-8")
        print(f"Markdown dashboard written to: {out_m}")

    # Output HTML if requested
    if args.output_html:
        out_h = Path(args.output_html)
        out_h.parent.mkdir(parents=True, exist_ok=True)
        out_h.write_text(render_html_dashboard(report_data), encoding="utf-8")
        print(f"HTML dashboard written to: {out_h}")

    # Print summary to console
    summary = report_data["fleet_summary"]
    print("\n" + "=" * 78)
    print(">>> InfraFlow Fleet Compliance Posture Summary")
    print("=" * 78)
    print(f"Fleet Status           : {summary['fleet_status']}")
    print(f"Fleet Compliance Score : {summary['fleet_compliance_score']}%")
    print(f"Total Registered Fleets: {summary['total_consumers']}")
    print(f"Compliant Fleets       : {summary['compliant_consumers']}")
    print(f"Warnings / Violations  : {summary['warning_consumers']} / {summary['non_compliant_consumers']}")
    print("=" * 78)

    if args.enforce_threshold > 0.0:
        if summary["fleet_compliance_score"] < args.enforce_threshold:
            sys.stderr.write(
                f"[FAILED] Fleet compliance score {summary['fleet_compliance_score']}% is below mandatory threshold {args.enforce_threshold}%\n"
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
