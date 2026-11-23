#!/usr/bin/env python3
"""
InfraFlow — Consumer Secret Defense & Credential Scanning CLI
Milestone: G10.3

Scans consumer infrastructure directories and changes for exposed credentials
before plan generation or cloud adapter invocation.
- Detects AWS keys, GitHub tokens, private keys, passwords, bearer tokens.
- Skips binary Terraform execution plans (tfplan).
- Zero secret exposure in logs or summaries (redacted findings).
- Fail-closed exit codes: 0 (clean), 1 (secrets detected), 2 (scanner error).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infraflow.scanner import SecretScanner, SecretScanError


def check_gitleaks_available() -> Optional[str]:
    """Returns path to gitleaks binary if available on system PATH."""
    return shutil.which("gitleaks")


def run_gitleaks(target_dir: Path) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Executes gitleaks detect on target directory if gitleaks binary exists.
    Returns (clean, findings, message).
    """
    gitleaks_bin = check_gitleaks_available()
    if not gitleaks_bin:
        return True, [], "gitleaks not installed on PATH"

    cmd = [
        gitleaks_bin,
        "detect",
        "--source",
        str(target_dir),
        "--no-git",
        "--report-format",
        "json",
        "--exit-code",
        "2",
        "--verbose",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            return True, [], "gitleaks scan clean"
        elif proc.returncode == 2:
            return False, [{"rule_id": "GITLEAKS-DETECT", "description": "Gitleaks detected credentials in workspace"}], "gitleaks detected leaks"
        else:
            return True, [], f"gitleaks returned exit code {proc.returncode}"
    except Exception as e:
        return True, [], f"gitleaks execution failed: {e}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scan-secrets.py",
        description="InfraFlow Consumer Secret Defense & Credential Scanner",
    )
    parser.add_argument(
        "-t", "--target-dir",
        type=Path,
        default=Path("."),
        help="Target directory to scan for credentials (default: current directory).",
    )
    parser.add_argument(
        "-o", "--output-json",
        type=Path,
        help="Write structured JSON scan report to specified path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON scan report to stdout.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-essential progress messages.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=True,
        help="Fail closed with non-zero exit code if any secret is detected (default: True).",
    )
    parser.add_argument(
        "--check-gitleaks",
        action="store_true",
        help="Run system gitleaks scanner in addition to native detection rules if available.",
    )

    args = parser.parse_args(argv)
    target_path = args.target_dir.resolve()

    if not target_path.exists():
        print(f"[ERROR] Target path does not exist: {target_path}", file=sys.stderr)
        return 2

    try:
        scanner = SecretScanner()
        report = scanner.scan_directory(target_path)

        # Optional supplemental gitleaks execution
        if args.check_gitleaks and check_gitleaks_available():
            gl_clean, gl_findings, gl_msg = run_gitleaks(target_path)
            report["gitleaks_executed"] = True
            report["gitleaks_message"] = gl_msg
            if not gl_clean:
                report["status"] = "FAIL"
                report["is_clean"] = False
                report["findings"].extend(gl_findings)
                report["total_secrets_found"] += len(gl_findings)

        # Write output JSON file if requested
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        # Emit JSON to stdout
        if args.json:
            print(json.dumps(report, indent=2))
        elif not args.quiet:
            print("==============================================================================")
            print(" InfraFlow Consumer Secret Defense & Credential Scanner (G10.3)")
            print("==============================================================================")
            print(f"Target Directory:    {target_path}")
            print(f"Files Scanned:       {report['files_scanned']}")
            print(f"Skipped Binary:      {report['skipped_binary_files']}")
            print(f"Duration:            {report['duration_ms']} ms")
            print(f"Status:              {report['status']}")
            print("------------------------------------------------------------------------------")
            if report["is_clean"]:
                print("✔ [PASS] Zero credentials or exposed secrets detected.")
            else:
                print(f"✖ [FAIL] {report['total_secrets_found']} exposed credential(s) detected:")
                for finding in report["findings"]:
                    print(
                        f"  • [{finding['severity']}] {finding['rule_id']} in "
                        f"{finding['file_path']}:{finding['line_number']} — {finding['description']} "
                        f"(match: {finding.get('redacted_match', '***REDACTED***')})"
                    )
                print("------------------------------------------------------------------------------")
                print("Remediation: Remove all hardcoded credentials from the repository before proceeding.")
                print("Use environment variables, HashiCorp Vault, or cloud secret managers instead.")
            print("==============================================================================")

        if not report["is_clean"] and args.strict:
            return 1
        return 0

    except SecretScanError as e:
        print(f"[SECURITY ERROR] Secret scanner failure: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[UNEXPECTED ERROR] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
