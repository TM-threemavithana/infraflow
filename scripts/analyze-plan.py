#!/usr/bin/env python3
"""
InfraFlow — Plan Analysis & Sensitive Data Protection Engine
Parses and analyzes Terraform execution plan JSON:
- Canonical resource change classification (create, update, replace, delete, no-op, read)
- Schema-aware sensitive data protection respecting before_sensitive and after_sensitive
- Deep recursive redaction of nested maps, lists, and non-obvious attribute keys
- Sensitive output detection and redaction
- Structured metrics calculation and sanitized Markdown summary generation for GitHub Actions
"""

import argparse
import json
import os
import re
import sys

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|secret|token|key|credential|private|cert|auth)",
    re.IGNORECASE
)

ACTION_ICONS = {
    "create": "➕ Create",
    "update": "📝 Update",
    "replace": "🔄 Replace",
    "delete": "❌ Delete",
    "no-op": "⏸️ No-op",
    "read": "📖 Read",
    "unknown": "⚠️ Unknown"
}

def classify_actions(actions):
    """Classifies Terraform change actions into canonical lifecycle operations."""
    if not actions:
        return "no-op"
    if actions == ["no-op"]:
        return "no-op"
    if actions == ["create"]:
        return "create"
    if actions == ["update"]:
        return "update"
    if actions == ["delete"]:
        return "delete"
    if set(actions) == {"delete", "create"}:
        return "replace"
    if actions == ["read"]:
        return "read"
    return "unknown"

def redact_sensitive(data, sensitive_mask):
    """
    Recursively redacts sensitive values respecting Terraform plan JSON metadata
    (before_sensitive and after_sensitive), combined with regex key matching.
    Handles nested dictionaries, lists, and non-obvious field names.
    """
    if sensitive_mask is True:
        return "(sensitive value redacted)"

    if isinstance(data, dict):
        redacted_dict = {}
        mask_dict = sensitive_mask if isinstance(sensitive_mask, dict) else {}
        for k, v in data.items():
            k_mask = mask_dict.get(k, False)
            if k_mask is True or SENSITIVE_KEY_PATTERN.search(str(k)):
                redacted_dict[k] = "(sensitive value redacted)"
            else:
                redacted_dict[k] = redact_sensitive(v, k_mask)
        return redacted_dict

    if isinstance(data, list):
        mask_list = sensitive_mask if isinstance(sensitive_mask, list) else []
        redacted_list = []
        for i, item in enumerate(data):
            item_mask = mask_list[i] if i < len(mask_list) else False
            if item_mask is True:
                redacted_list.append("(sensitive value redacted)")
            else:
                redacted_list.append(redact_sensitive(item, item_mask))
        return redacted_list

    return data

def analyze_plan(plan_json_path):
    """Loads and inspects the Terraform plan JSON, redacting sensitive data."""
    if not os.path.exists(plan_json_path):
        raise FileNotFoundError(f"Plan JSON file not found: {plan_json_path}")

    try:
        with open(plan_json_path, "r", encoding="utf-8") as f:
            plan_data = json.load(f)
    except Exception as e:
        raise ValueError(f"Malformed plan JSON: {str(e)}")

    if not isinstance(plan_data, dict):
        raise ValueError("Plan JSON root must be a JSON object")

    format_version = plan_data.get("format_version", "unknown")
    terraform_version = plan_data.get("terraform_version", "unknown")
    is_errored = plan_data.get("errored", False)

    if is_errored:
        raise ValueError("Plan generation was marked as errored in plan JSON")

    resource_changes = plan_data.get("resource_changes", [])

    metrics = {
        "create": 0,
        "update": 0,
        "replace": 0,
        "delete": 0,
        "no-op": 0,
        "read": 0,
        "unknown": 0,
        "total_changes": 0
    }

    classified_resources = []

    for rc in resource_changes:
        if not isinstance(rc, dict):
            continue

        address = rc.get("address", "unknown")
        res_type = rc.get("type", "unknown")
        res_name = rc.get("name", "unknown")
        module_address = rc.get("module_address", "")
        change = rc.get("change", {})

        if not isinstance(change, dict):
            actions = ["unknown"]
            before_val = None
            after_val = None
            before_sensitive = {}
            after_sensitive = {}
            after_unknown = {}
        else:
            actions = change.get("actions", ["unknown"])
            before_val = change.get("before")
            after_val = change.get("after")
            before_sensitive = change.get("before_sensitive", {})
            after_sensitive = change.get("after_sensitive", {})
            after_unknown = change.get("after_unknown", {})

        action_type = classify_actions(actions)
        metrics[action_type] = metrics.get(action_type, 0) + 1

        if action_type in ["create", "update", "replace", "delete"]:
            metrics["total_changes"] += 1

        # Check for unknown computed attributes
        unknown_attrs = [k for k, v in after_unknown.items() if v is True] if isinstance(after_unknown, dict) else []

        # Recursively redact attributes
        redacted_before = redact_sensitive(before_val, before_sensitive) if before_val is not None else None
        redacted_after = redact_sensitive(after_val, after_sensitive) if after_val is not None else None

        has_sensitive_data = bool(
            (isinstance(before_sensitive, dict) and any(before_sensitive.values())) or
            (isinstance(after_sensitive, dict) and any(after_sensitive.values())) or
            before_sensitive is True or after_sensitive is True
        )

        classified_resources.append({
            "address": address,
            "type": res_type,
            "name": res_name,
            "module_address": module_address,
            "action": action_type,
            "action_display": ACTION_ICONS.get(action_type, action_type),
            "raw_actions": actions,
            "unknown_attributes": unknown_attrs,
            "has_sensitive_attributes": has_sensitive_data,
            "redacted_after": redacted_after
        })

    # Classify and redact output changes
    output_changes = plan_data.get("output_changes", {})
    classified_outputs = []

    if isinstance(output_changes, dict):
        for out_name, out_data in output_changes.items():
            if not isinstance(out_data, dict):
                continue
            out_actions = out_data.get("actions", ["unknown"])
            out_after = out_data.get("after")
            out_after_sensitive = out_data.get("after_sensitive", False)
            out_action_type = classify_actions(out_actions)

            is_sensitive_out = (
                out_after_sensitive is True or
                (isinstance(out_after_sensitive, dict) and any(out_after_sensitive.values())) or
                bool(SENSITIVE_KEY_PATTERN.search(out_name))
            )

            if is_sensitive_out:
                display_val = "(sensitive output redacted)"
            elif out_after is None:
                display_val = "null"
            elif isinstance(out_after, (dict, list)):
                display_val = redact_sensitive(out_after, out_after_sensitive)
            else:
                display_val = str(out_after)

            classified_outputs.append({
                "name": out_name,
                "action": out_action_type,
                "action_display": ACTION_ICONS.get(out_action_type, out_action_type),
                "sensitive": is_sensitive_out,
                "display_value": display_val
            })

    has_changes = metrics["total_changes"] > 0
    has_destructive_changes = (metrics["delete"] > 0) or (metrics["replace"] > 0)

    summary = {
        "format_version": format_version,
        "terraform_version": terraform_version,
        "metrics": metrics,
        "has_changes": has_changes,
        "has_destructive_changes": has_destructive_changes,
        "resources": classified_resources,
        "outputs": classified_outputs
    }

    return summary

def generate_markdown_summary(summary, title="Terraform Execution Plan Summary"):
    """Renders a clean, sanitized Markdown summary suitable for GitHub Step Summary."""
    metrics = summary["metrics"]
    lines = []
    lines.append(f"## 📋 {title}\n")
    lines.append(f"- **Terraform Version**: `{summary['terraform_version']}`")
    lines.append(f"- **Plan Format Version**: `{summary['format_version']}`")
    lines.append(f"- **Status**: {'⚠️ Changes Planned' if summary['has_changes'] else '✅ No Changes Required'}\n")

    lines.append("### 📊 Change Metrics\n")
    lines.append("| Operation | Count |")
    lines.append("|---|---|")
    lines.append(f"| {ACTION_ICONS['create']} | **{metrics['create']}** |")
    lines.append(f"| {ACTION_ICONS['update']} | **{metrics['update']}** |")
    lines.append(f"| {ACTION_ICONS['replace']} | **{metrics['replace']}** |")
    lines.append(f"| {ACTION_ICONS['delete']} | **{metrics['delete']}** |")
    lines.append(f"| {ACTION_ICONS['no-op']} | {metrics['no-op']} |")
    lines.append(f"| **Total Modifying Changes** | **{metrics['total_changes']}** |\n")

    if summary["has_destructive_changes"]:
        lines.append("> [!WARNING]")
        lines.append("> **Destructive Actions Detected**: This plan includes resource deletions or replacements. Review carefully before approval.\n")

    if summary["resources"]:
        lines.append("### 🔍 Planned Resource Operations\n")
        lines.append("| Resource Address | Resource Type | Action | Computed Unknowns | Sensitive Data |")
        lines.append("|---|---|---|---|---|")
        for res in summary["resources"]:
            unknown_str = ", ".join(f"`{a}`" for a in res["unknown_attributes"]) if res["unknown_attributes"] else "—"
            sensitive_str = "🔒 Yes (Redacted)" if res["has_sensitive_attributes"] else "No"
            lines.append(f"| `{res['address']}` | `{res['type']}` | {res['action_display']} | {unknown_str} | {sensitive_str} |")
        lines.append("")
    else:
        lines.append("_No resources modified in this execution plan._\n")

    if summary.get("outputs"):
        lines.append("### 📤 Output Changes\n")
        lines.append("| Output Name | Action | Sensitivity | Display Value |")
        lines.append("|---|---|---|---|")
        for out in summary["outputs"]:
            sens_badge = "🔒 Sensitive" if out["sensitive"] else "Public"
            val_str = out["display_value"] if not out["sensitive"] else "`(redacted)`"
            lines.append(f"| `{out['name']}` | {out['action_display']} | {sens_badge} | {val_str} |")
        lines.append("")

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="InfraFlow Plan Analysis Engine")
    parser.add_argument("--plan-json", required=True, help="Path to input Terraform plan JSON")
    parser.add_argument("--output-json", help="Path to write structured metrics JSON")
    parser.add_argument("--output-markdown", help="Path to write sanitized Markdown summary")
    parser.add_argument("--fail-on-destructive", action="store_true", help="Exit 1 if deletions or replacements occur")

    args = parser.parse_args()

    try:
        summary = analyze_plan(args.plan_json)
    except Exception as e:
        sys.stderr.write(f"[ERROR] Plan Analysis Failed: {str(e)}\n")
        sys.exit(1)

    if args.output_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_json)), exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    markdown_content = generate_markdown_summary(summary)

    if args.output_markdown:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_markdown)), exist_ok=True)
        with open(args.output_markdown, "w", encoding="utf-8") as f:
            f.write(markdown_content)

    # Print clean Markdown summary to stdout (NEVER raw plan JSON)
    print(markdown_content)

    if args.fail_on_destructive and summary["has_destructive_changes"]:
        sys.stderr.write("[ERROR] Plan contains destructive changes (delete/replace) and --fail-on-destructive was requested\n")
        sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
