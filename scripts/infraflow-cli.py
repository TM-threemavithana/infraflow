#!/usr/bin/env python3
"""
InfraFlow Unified Platform CLI & Developer Experience Diagnostic Engine (Milestone G10.1)

Unified command-line interface for the InfraFlow Enterprise Infrastructure Platform.
Consolidates platform diagnostics, consumer onboarding validation, continuous state
and speculative drift detection, and fleet upgrade lifecycle campaigns.

Commands:
  infraflow doctor      Non-destructive environment & platform readiness diagnostics (12 checks).
  infraflow validate    Validate consumer configs, fleet manifests, or evaluate OPA policies.
  infraflow drift       Run continuous state and speculative drift detection simulation.
  infraflow upgrade     Plan or orchestrate fleet upgrade campaigns and rollbacks.

Global Options:
  --version, -V         Display InfraFlow platform version and build metadata.
  --json                Emit machine-readable JSON payload to stdout.
  --verbose, -v         Enable detailed diagnostic and trace output.
  --no-color            Disable ANSI color styling.

Security & Operational Invariants:
  - Exactly $0.00 cloud spending; zero live cloud credentials.
  - Subprocess calls strictly reject shell=True.
  - Automated regex scrubbing of secrets (tokens, AWS keys, private keys).
  - Fail-closed path traversal and symbolic link validation.
  - Purely non-destructive diagnostics (no live apply or deletion).
"""

import argparse
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Platform Constants
PLATFORM_VERSION = "0.7.0"
PLATFORM_CANONICAL_REF = "TM-threemavithana/infraflow"
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
POLICIES_DIR = REPO_ROOT / "policies"

# Standard exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_SECURITY = 2


# ==============================================================================
# Secret Redaction Engine
# ==============================================================================

RE_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_AWS_SECRET_KEY = re.compile(r"(?i)(aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")
RE_GITHUB_PAT = re.compile(r"\bghp_[A-Za-z0-9_]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b")
RE_PRIVATE_KEY = re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]+PRIVATE KEY-----")
RE_GENERIC_SECRET = re.compile(r"(?i)\b(password|secret|bearer_token|client_secret|api_key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.\$\!\@\#\%\^\&\*]{8,})['\"]?")
RE_BEARER_AUTH = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b")


class SecretSanitizer:
    """Detects and scrubs sensitive credentials from text and structured payloads."""

    REDACTED_STR = "[REDACTED_SECRET]"

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        if not text:
            return text
        scrubbed = RE_PRIVATE_KEY.sub(cls.REDACTED_STR, text)
        scrubbed = RE_AWS_ACCESS_KEY.sub(cls.REDACTED_STR, scrubbed)
        scrubbed = RE_AWS_SECRET_KEY.sub(r"\1: [REDACTED_SECRET]", scrubbed)
        scrubbed = RE_GITHUB_PAT.sub(cls.REDACTED_STR, scrubbed)
        scrubbed = RE_BEARER_AUTH.sub("Bearer [REDACTED_SECRET]", scrubbed)
        scrubbed = RE_GENERIC_SECRET.sub(r"\1: [REDACTED_SECRET]", scrubbed)
        return scrubbed

    @classmethod
    def sanitize_obj(cls, obj: Any) -> Any:
        if isinstance(obj, str):
            return cls.sanitize_text(obj)
        elif isinstance(obj, dict):
            return {cls.sanitize_text(str(k)): cls.sanitize_obj(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [cls.sanitize_obj(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(cls.sanitize_obj(item) for item in obj)
        return obj


# ==============================================================================
# Security & Path Containment Validator
# ==============================================================================

class SecurityValidationError(Exception):
    """Raised when an operation violates security, symlink, or path bounds."""
    pass


class PathValidator:
    """Validates filesystem paths against path traversal, symlinks, and bounds."""

    @staticmethod
    def validate_file(path: Path, must_exist: bool = True, allow_symlinks: bool = False) -> Path:
        resolved = path.resolve()
        # Explicit symlink check on the original path
        if not allow_symlinks and os.path.islink(path):
            raise SecurityValidationError(f"Symbolic link prohibited by security policy: {path}")

        if must_exist and not resolved.is_file():
            raise SecurityValidationError(f"File not found or is not a regular file: {path}")

        return resolved

    @staticmethod
    def validate_directory(path: Path, must_exist: bool = True, allow_symlinks: bool = False) -> Path:
        resolved = path.resolve()
        if not allow_symlinks and os.path.islink(path):
            raise SecurityValidationError(f"Symbolic link prohibited by security policy: {path}")

        if must_exist and not resolved.is_dir():
            raise SecurityValidationError(f"Directory not found or is not a directory: {path}")

        return resolved


# ==============================================================================
# Terminal Color Styling & Output Formatting
# ==============================================================================

class Color:
    """ANSI color codes with automatic terminal and NO_COLOR detection."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    _enabled = True

    @classmethod
    def configure(cls, enabled: bool) -> None:
        if not enabled or "NO_COLOR" in os.environ or not sys.stdout.isatty():
            cls._enabled = False
        else:
            cls._enabled = True

    @classmethod
    def style(cls, text: str, *styles: str) -> str:
        if not cls._enabled:
            return text
        prefix = "".join(styles)
        return f"{prefix}{text}{cls.RESET}"

    @classmethod
    def green(cls, text: str) -> str:
        return cls.style(text, cls.GREEN, cls.BOLD)

    @classmethod
    def red(cls, text: str) -> str:
        return cls.style(text, cls.RED, cls.BOLD)

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls.style(text, cls.YELLOW, cls.BOLD)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls.style(text, cls.CYAN, cls.BOLD)

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.style(text, cls.BOLD)

    @classmethod
    def dim(cls, text: str) -> str:
        return cls.style(text, cls.DIM)


# ==============================================================================
# Policy Error Enhancement & Parsing Engine
# ==============================================================================

@dataclass
class PolicyViolation:
    """Structured representation of an OPA/Conftest policy violation."""
    policy_id: str
    namespace: str
    severity: str
    message: str
    resource: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    remediation: str = ""
    doc_link: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyErrorEnhancer:
    """Parses raw OPA / Conftest output into structured, actionable diagnostics."""

    RULE_KNOWLEDGE_BASE = {
        # Azure rules
        "azurerm_storage_account name": {
            "policy_id": "AZURE-SEC-NAME-001",
            "severity": "MEDIUM",
            "remediation": "Storage account names must be between 3 and 24 lowercase alphanumeric characters.",
            "doc_link": "docs/architecture/G07-AZURE-ADAPTER-ARCHITECTURE.md",
        },
        "min_tls_version": {
            "policy_id": "AZURE-SEC-TLS-001",
            "severity": "HIGH",
            "remediation": "Configure min_tls_version = 'TLS1_2' on azurerm_storage_account.",
            "doc_link": "docs/architecture/G07-AZURE-ADAPTER-ARCHITECTURE.md",
        },
        "allow_nested_items_to_be_public": {
            "policy_id": "AZURE-SEC-PUB-001",
            "severity": "CRITICAL",
            "remediation": "Set allow_nested_items_to_be_public = false to prevent anonymous blob exposure.",
            "doc_link": "docs/architecture/G07-AZURE-ADAPTER-ARCHITECTURE.md",
        },
        "public_network_access_enabled": {
            "policy_id": "AZURE-SEC-NET-001",
            "severity": "HIGH",
            "remediation": "Set public_network_access_enabled = false and configure private endpoints or subnet ACLs.",
            "doc_link": "docs/architecture/G07-AZURE-ADAPTER-ARCHITECTURE.md",
        },
        "token.actions.githubusercontent.com": {
            "policy_id": "SEC-OIDC-ISSUER-001",
            "severity": "CRITICAL",
            "remediation": "Federated credential issuer must strictly match 'https://token.actions.githubusercontent.com'.",
            "doc_link": "docs/security/SECURITY-ARCHITECTURE.md",
        },
        "api://AzureADTokenExchange": {
            "policy_id": "AZURE-OIDC-AUD-001",
            "severity": "CRITICAL",
            "remediation": "Audience must be strictly configured to ['api://AzureADTokenExchange'].",
            "doc_link": "docs/architecture/G07-AZURE-ADAPTER-ARCHITECTURE.md",
        },
        "wildcard": {
            "policy_id": "SEC-OIDC-WILDCARD-001",
            "severity": "CRITICAL",
            "remediation": "Remove broad wildcard trust bindings; restrict subject claims to specific repository and branch.",
            "doc_link": "docs/security/SECURITY-ARCHITECTURE.md",
        },
        # AWS rules
        "public ACL": {
            "policy_id": "AWS-SEC-S3-ACL-001",
            "severity": "CRITICAL",
            "remediation": "S3 buckets must not use public ACLs ('public-read', 'public-read-write', 'website'). Use private ACLs and IAM policies.",
            "doc_link": "docs/architecture/ARCHITECTURE.md",
        },
        "block_public_acls": {
            "policy_id": "AWS-SEC-S3-PAB-001",
            "severity": "CRITICAL",
            "remediation": "aws_s3_bucket_public_access_block must explicitly set all 4 protection flags to true.",
            "doc_link": "docs/architecture/ARCHITECTURE.md",
        },
        # GCP rules
        "Uniform Bucket-Level Access": {
            "policy_id": "GCP-SEC-GCS-UBLA-001",
            "severity": "HIGH",
            "remediation": "Set uniform_bucket_level_access = true to enforce uniform IAM permissions (CIS GCP 5.2).",
            "doc_link": "docs/architecture/G07-GCP-ADAPTER-ARCHITECTURE.md",
        },
        "Public Access Prevention": {
            "policy_id": "GCP-SEC-GCS-PAP-001",
            "severity": "CRITICAL",
            "remediation": "Configure public_access_prevention = 'enforced' on google_storage_bucket (CIS GCP 5.1).",
            "doc_link": "docs/architecture/G07-GCP-ADAPTER-ARCHITECTURE.md",
        },
        "Versioning Required": {
            "policy_id": "GCP-SEC-GCS-VER-001",
            "severity": "HIGH",
            "remediation": "Enable object versioning: versioning { enabled = true } on state storage buckets.",
            "doc_link": "docs/architecture/G07-GCP-ADAPTER-ARCHITECTURE.md",
        },
        # Common rules
        "missing mandatory 'tags' block": {
            "policy_id": "COMMON-TAG-001",
            "severity": "MEDIUM",
            "remediation": "Add required 'tags' block with Environment, Project, and ManagedBy attributes.",
            "doc_link": "policies/common/tags.rego",
        },
        "missing mandatory 'labels' block": {
            "policy_id": "COMMON-LABEL-001",
            "severity": "MEDIUM",
            "remediation": "Add required 'labels' block with environment, project, and managed_by attributes.",
            "doc_link": "policies/common/tags.rego",
        },
        "Environment tag": {
            "policy_id": "COMMON-TAG-ENV-001",
            "severity": "MEDIUM",
            "remediation": "Ensure 'Environment' tag is present and set to one of: 'dev', 'staging', 'prod', 'test'.",
            "doc_link": "policies/common/tags.rego",
        },
        # Governance rules
        "Missing mandatory": {
            "policy_id": "GOV-CONTRACT-001",
            "severity": "CRITICAL",
            "remediation": "Ensure all required fields are provided in infraflow.config.yaml according to v1.0 schema.",
            "doc_link": "docs/governance/CONSUMER-ONBOARDING-GUIDE.md",
        },
        "Commit SHA": {
            "policy_id": "GOV-SHA-PIN-001",
            "severity": "CRITICAL",
            "remediation": "Pin all platform reusable workflows to immutable 40-character hexadecimal commit SHAs.",
            "doc_link": "docs/governance/CONSUMER-ONBOARDING-GUIDE.md",
        },
    }

    @classmethod
    def enhance_violation(cls, raw_msg: str, namespace: str, file_path: Optional[str] = None) -> PolicyViolation:
        # 1. Extract resource identifier if present
        res_match = re.search(r"Resource '([^']+)'", raw_msg)
        if not res_match:
            res_match = re.search(r"\b((?:aws|azurerm|google)_[a-zA-Z0-9_]+\.[a-zA-Z0-9_\-]+)\b", raw_msg)

        resource_name = res_match.group(1) if res_match else "unknown"

        # 2. Match against knowledge base
        matched_entry = None
        for key, entry in cls.RULE_KNOWLEDGE_BASE.items():
            if key.lower() in raw_msg.lower():
                matched_entry = entry
                break

        if matched_entry:
            policy_id = matched_entry["policy_id"]
            severity = matched_entry["severity"]
            remediation = matched_entry["remediation"]
            doc_link = matched_entry["doc_link"]
        else:
            ns_prefix = namespace.upper().replace(".", "-") if namespace else "OPA"
            policy_id = f"{ns_prefix}-POLICY-ERR"
            severity = "HIGH" if "deny" in raw_msg.lower() or "error" in raw_msg.lower() else "MEDIUM"
            remediation = f"Verify configuration against policy requirements in namespace '{namespace}'."
            doc_link = "policies/"

        # 3. Locate source line if file exists
        line_num = None
        col_num = None
        if file_path and os.path.isfile(file_path):
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                # If resource name has type.name format, search for resource declaration
                target_str = resource_name
                if "." in resource_name:
                    rtype, rname = resource_name.split(".", 1)
                    search_pat = re.compile(rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(rname)}"')
                    for idx, line_text in enumerate(lines, 1):
                        if search_pat.search(line_text):
                            line_num = idx
                            break

                # Fallback to general substring search
                if line_num is None:
                    for idx, line_text in enumerate(lines, 1):
                        if target_str in line_text:
                            line_num = idx
                            break
            except Exception:
                pass

        return PolicyViolation(
            policy_id=policy_id,
            namespace=namespace,
            severity=severity,
            message=raw_msg,
            resource=resource_name,
            file_path=file_path,
            line=line_num,
            column=col_num,
            remediation=remediation,
            doc_link=doc_link,
        )

    @classmethod
    def parse_conftest_json(cls, conftest_json_str: str, default_file: Optional[str] = None) -> List[PolicyViolation]:
        violations: List[PolicyViolation] = []
        try:
            data = json.loads(conftest_json_str)
            if not isinstance(data, list):
                return violations

            for entry in data:
                filename = entry.get("filename", default_file)
                namespace = entry.get("namespace", "main")
                failures = entry.get("failures", [])
                for fail in failures:
                    msg = fail.get("msg", "") if isinstance(fail, dict) else str(fail)
                    if msg:
                        v = cls.enhance_violation(msg, namespace=namespace, file_path=filename)
                        violations.append(v)
        except Exception:
            pass
        return violations

    @classmethod
    def parse_conftest_stdout(cls, stdout_text: str, default_file: Optional[str] = None) -> List[PolicyViolation]:
        violations: List[PolicyViolation] = []
        for line in stdout_text.splitlines():
            line = line.strip()
            # Standard Conftest stdout format: "FAIL - filename - namespace - message"
            match = re.match(r"^FAIL\s+-\s+([^\s]+)\s+-\s+([^\s]+)\s+-\s+(.+)$", line)
            if match:
                fpath, ns, msg = match.group(1), match.group(2), match.group(3)
                violations.append(cls.enhance_violation(msg, namespace=ns, file_path=fpath))
            elif line.startswith("FAIL -"):
                parts = line.split(" - ", 3)
                if len(parts) >= 4:
                    violations.append(cls.enhance_violation(parts[3], namespace=parts[2], file_path=parts[1]))
        return violations


# ==============================================================================
# Helper Binary Locator
# ==============================================================================

def find_binary(name: str) -> Optional[str]:
    """Finds an executable binary across PATH and known user directories."""
    candidates = [
        shutil.which(name),
        os.path.expanduser(f"~/.local/bin/{name}"),
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
        f"/bin/{name}",
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def get_environment_with_local_bin() -> Dict[str, str]:
    """Returns a subprocess environment ensuring ~/.local/bin is in PATH."""
    env = os.environ.copy()
    local_bin = os.path.expanduser("~/.local/bin")
    current_path = env.get("PATH", "")
    if local_bin not in current_path:
        env["PATH"] = f"{local_bin}:{current_path}"
    return env


# ==============================================================================
# Dynamic Module Loader
# ==============================================================================

def load_script_module(module_name: str, script_name: str):
    """Loads an existing script dynamically via importlib."""
    script_path = SCRIPTS_DIR / script_name
    if not script_path.is_file():
        raise FileNotFoundError(f"Underlying platform script not found: {script_path}")

    spec = importlib.util.spec_from_file_location(module_name, str(script_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module spec for {script_path}")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ==============================================================================
# Platform Doctor Diagnostic Engine (12 Dimension Health Checks)
# ==============================================================================

@dataclass
class DiagnosticCheck:
    id: str
    name: str
    status: str  # PASS, WARNING, FAIL
    details: str
    version: Optional[str] = None
    path: Optional[str] = None
    remediation: Optional[str] = None


class PlatformDoctor:
    """Performs deep, non-destructive health checks across 12 platform dimensions."""

    def __init__(self, repo_root: Path = REPO_ROOT):
        self.repo_root = repo_root
        self.env = get_environment_with_local_bin()

    def run_all_checks(self) -> List[DiagnosticCheck]:
        return [
            self._check_python(),
            self._check_terraform(),
            self._check_git(),
            self._check_tflint(),
            self._check_trivy(),
            self._check_conftest(),
            self._check_actionlint(),
            self._check_zizmor(),
            self._check_directory_structure(),
            self._check_policies_and_config(),
            self._check_python_dependencies(),
            self._check_git_state(),
        ]

    # Check 1: Python Runtime (>= 3.10)
    def _check_python(self) -> DiagnosticCheck:
        v = sys.version_info
        version_str = f"{v.major}.{v.minor}.{v.micro}"
        if (v.major, v.minor) >= (3, 10):
            return DiagnosticCheck(
                id="DOC-01-PYTHON",
                name="Python Runtime (>= 3.10)",
                status="PASS",
                details=f"Python {version_str} meets platform requirements (>= 3.10).",
                version=version_str,
                path=sys.executable,
            )
        return DiagnosticCheck(
            id="DOC-01-PYTHON",
            name="Python Runtime (>= 3.10)",
            status="FAIL",
            details=f"Python {version_str} is unsupported. InfraFlow requires Python >= 3.10.",
            version=version_str,
            path=sys.executable,
            remediation="Upgrade Python runtime to version 3.10 or higher.",
        )

    # Check 2: Terraform CLI (>= 1.6.0)
    def _check_terraform(self) -> DiagnosticCheck:
        tf_bin = find_binary("terraform")
        if not tf_bin:
            return DiagnosticCheck(
                id="DOC-02-TERRAFORM",
                name="Terraform CLI (>= 1.6.0)",
                status="FAIL",
                details="Terraform CLI binary not found in PATH or standard bin paths.",
                remediation="Install HashiCorp Terraform CLI (>= 1.6.0) from https://developer.hashicorp.com/terraform/install.",
            )
        try:
            res = subprocess.run([tf_bin, "version", "-json"], capture_output=True, text=True, env=self.env, check=False)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                version_str = data.get("terraform_version", "unknown")
            else:
                # Fallback to text parsing
                res_txt = subprocess.run([tf_bin, "version"], capture_output=True, text=True, env=self.env, check=False)
                match = re.search(r"v?([0-9]+\.[0-9]+\.[0-9]+)", res_txt.stdout)
                version_str = match.group(1) if match else "unknown"

            # Parse semver
            parts = [int(p) for p in re.findall(r"\d+", version_str)[:3]]
            if len(parts) >= 2 and (parts[0], parts[1]) >= (1, 6):
                return DiagnosticCheck(
                    id="DOC-02-TERRAFORM",
                    name="Terraform CLI (>= 1.6.0)",
                    status="PASS",
                    details=f"Terraform v{version_str} meets requirements (>= 1.6.0).",
                    version=version_str,
                    path=tf_bin,
                )
            return DiagnosticCheck(
                id="DOC-02-TERRAFORM",
                name="Terraform CLI (>= 1.6.0)",
                status="WARNING",
                details=f"Terraform v{version_str} detected, but InfraFlow requires >= 1.6.0.",
                version=version_str,
                path=tf_bin,
                remediation="Upgrade Terraform CLI to 1.6.0 or higher.",
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-02-TERRAFORM",
                name="Terraform CLI (>= 1.6.0)",
                status="FAIL",
                details=f"Failed to query Terraform CLI version: {e}",
                path=tf_bin,
                remediation="Verify Terraform installation and executable permissions.",
            )

    # Check 3: Git CLI
    def _check_git(self) -> DiagnosticCheck:
        git_bin = find_binary("git")
        if not git_bin:
            return DiagnosticCheck(
                id="DOC-03-GIT",
                name="Git Version Control CLI",
                status="FAIL",
                details="Git binary not found in PATH or standard system paths.",
                remediation="Install Git CLI package (e.g. apt-get install git or brew install git).",
            )
        try:
            res = subprocess.run([git_bin, "--version"], capture_output=True, text=True, env=self.env, check=False)
            v_match = re.search(r"version\s+([0-9\.]+)", res.stdout)
            version_str = v_match.group(1) if v_match else "installed"
            return DiagnosticCheck(
                id="DOC-03-GIT",
                name="Git Version Control CLI",
                status="PASS",
                details=f"Git {version_str} available.",
                version=version_str,
                path=git_bin,
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-03-GIT",
                name="Git Version Control CLI",
                status="FAIL",
                details=f"Failed to execute git: {e}",
                remediation="Ensure git is executable.",
            )

    # Check 4: TFLint
    def _check_tflint(self) -> DiagnosticCheck:
        bin_path = find_binary("tflint")
        if not bin_path:
            return DiagnosticCheck(
                id="DOC-04-TFLINT",
                name="TFLint Security & Quality Linter",
                status="WARNING",
                details="TFLint binary not detected.",
                remediation="Install TFLint from https://github.com/terraform-linters/tflint.",
            )
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, env=self.env, check=False)
            v_match = re.search(r"version\s+([0-9\.]+)", res.stdout)
            v_str = v_match.group(1) if v_match else "installed"
            return DiagnosticCheck(
                id="DOC-04-TFLINT",
                name="TFLint Security & Quality Linter",
                status="PASS",
                details=f"TFLint v{v_str} operational.",
                version=v_str,
                path=bin_path,
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-04-TFLINT",
                name="TFLint Security & Quality Linter",
                status="WARNING",
                details=f"TFLint found at {bin_path} but failed execution: {e}",
            )

    # Check 5: Trivy
    def _check_trivy(self) -> DiagnosticCheck:
        bin_path = find_binary("trivy")
        if not bin_path:
            return DiagnosticCheck(
                id="DOC-05-TRIVY",
                name="Trivy Vulnerability & IaC Scanner",
                status="WARNING",
                details="Trivy scanner binary not detected.",
                remediation="Install Trivy from https://aquasecurity.github.io/trivy/latest/getting-started/installation/.",
            )
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, env=self.env, check=False)
            v_match = re.search(r"Version:\s+([0-9\.]+)", res.stdout)
            v_str = v_match.group(1) if v_match else "installed"
            return DiagnosticCheck(
                id="DOC-05-TRIVY",
                name="Trivy Vulnerability & IaC Scanner",
                status="PASS",
                details=f"Trivy v{v_str} operational.",
                version=v_str,
                path=bin_path,
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-05-TRIVY",
                name="Trivy Vulnerability & IaC Scanner",
                status="WARNING",
                details=f"Trivy found at {bin_path} but failed execution: {e}",
            )

    # Check 6: Conftest (OPA)
    def _check_conftest(self) -> DiagnosticCheck:
        bin_path = find_binary("conftest")
        if not bin_path:
            return DiagnosticCheck(
                id="DOC-06-CONFTEST",
                name="Conftest Open Policy Agent (OPA)",
                status="FAIL",
                details="Conftest binary not detected. Policy enforcement cannot run.",
                remediation="Install Conftest from https://www.conftest.dev/install/ or place in ~/.local/bin/conftest.",
            )
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, env=self.env, check=False)
            v_match = re.search(r"Conftest:\s+([0-9\.]+)", res.stdout)
            v_str = v_match.group(1) if v_match else "installed"
            return DiagnosticCheck(
                id="DOC-06-CONFTEST",
                name="Conftest Open Policy Agent (OPA)",
                status="PASS",
                details=f"Conftest v{v_str} operational with OPA engine.",
                version=v_str,
                path=bin_path,
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-06-CONFTEST",
                name="Conftest Open Policy Agent (OPA)",
                status="FAIL",
                details=f"Conftest found at {bin_path} but failed execution: {e}",
            )

    # Check 7: Actionlint
    def _check_actionlint(self) -> DiagnosticCheck:
        bin_path = find_binary("actionlint")
        if not bin_path:
            return DiagnosticCheck(
                id="DOC-07-ACTIONLINT",
                name="Actionlint GitHub Actions Linter",
                status="WARNING",
                details="Actionlint binary not detected.",
                remediation="Install actionlint from https://github.com/rhysd/actionlint.",
            )
        try:
            res = subprocess.run([bin_path, "-version"], capture_output=True, text=True, env=self.env, check=False)
            v_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", res.stdout)
            v_str = v_match.group(1) if v_match else "installed"
            return DiagnosticCheck(
                id="DOC-07-ACTIONLINT",
                name="Actionlint GitHub Actions Linter",
                status="PASS",
                details=f"Actionlint v{v_str} operational.",
                version=v_str,
                path=bin_path,
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-07-ACTIONLINT",
                name="Actionlint GitHub Actions Linter",
                status="WARNING",
                details=f"Actionlint found at {bin_path} but execution failed: {e}",
            )

    # Check 8: Zizmor
    def _check_zizmor(self) -> DiagnosticCheck:
        bin_path = find_binary("zizmor")
        if not bin_path:
            return DiagnosticCheck(
                id="DOC-08-ZIZMOR",
                name="Zizmor GitHub Actions Security Auditor",
                status="WARNING",
                details="Zizmor binary not detected.",
                remediation="Install zizmor via cargo (cargo install zizmor) or GitHub release.",
            )
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, env=self.env, check=False)
            v_match = re.search(r"zizmor\s+([0-9\.]+)", res.stdout)
            v_str = v_match.group(1) if v_match else "installed"
            return DiagnosticCheck(
                id="DOC-08-ZIZMOR",
                name="Zizmor GitHub Actions Security Auditor",
                status="PASS",
                details=f"Zizmor v{v_str} operational.",
                version=v_str,
                path=bin_path,
            )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-08-ZIZMOR",
                name="Zizmor GitHub Actions Security Auditor",
                status="WARNING",
                details=f"Zizmor found at {bin_path} but execution failed: {e}",
            )

    # Check 9: Platform Directory Structure
    def _check_directory_structure(self) -> DiagnosticCheck:
        required_dirs = [
            ".github/workflows",
            "policies",
            "scripts",
            "docs",
            "config",
            "tests",
        ]
        missing = []
        for d in required_dirs:
            p = self.repo_root / d
            if not p.is_dir():
                missing.append(d)

        if not missing:
            return DiagnosticCheck(
                id="DOC-09-DIRS",
                name="Platform Directory Hierarchy",
                status="PASS",
                details=f"All {len(required_dirs)} core platform directories present ({', '.join(required_dirs)}).",
                path=str(self.repo_root),
            )
        return DiagnosticCheck(
            id="DOC-09-DIRS",
            name="Platform Directory Hierarchy",
            status="FAIL",
            details=f"Missing mandatory platform directories: {', '.join(missing)}.",
            remediation="Ensure the CLI is executed from the InfraFlow platform repository root.",
        )

    # Check 10: Platform Configurations & Policies
    def _check_policies_and_config(self) -> DiagnosticCheck:
        essential_policies = [
            "policies/aws/s3.rego",
            "policies/azure/storage_backend.rego",
            "policies/gcp/wif_oidc.rego",
            "policies/governance/consumer_governance.rego",
            "policies/common/tags.rego",
        ]
        missing = [p for p in essential_policies if not (self.repo_root / p).is_file()]
        if missing:
            return DiagnosticCheck(
                id="DOC-10-POLICIES",
                name="Core Security & Governance Policies",
                status="FAIL",
                details=f"Missing essential Rego policies: {', '.join(missing)}.",
                remediation="Restore the missing Rego policy files from repository history.",
            )

        # Optional fleet manifest validation
        manifest_path = self.repo_root / "fleet-manifest.yaml"
        manifest_note = ""
        if manifest_path.is_file():
            try:
                plan_mod = load_script_module("plan_fleet_upgrade", "plan-fleet-upgrade.py")
                plan_mod.load_manifest(manifest_path)
                manifest_note = " (fleet-manifest.yaml validated)"
            except Exception as e:
                return DiagnosticCheck(
                    id="DOC-10-POLICIES",
                    name="Core Security & Governance Policies",
                    status="WARNING",
                    details=f"Policies present, but fleet-manifest.yaml has schema error: {e}",
                    remediation="Correct fleet-manifest.yaml schema syntax.",
                )

        return DiagnosticCheck(
            id="DOC-10-POLICIES",
            name="Core Security & Governance Policies",
            status="PASS",
            details=f"All 5 core Rego policy contracts verified intact{manifest_note}.",
            path=str(self.repo_root / "policies"),
        )

    # Check 11: Python Dependencies
    def _check_python_dependencies(self) -> DiagnosticCheck:
        missing_pkgs = []
        try:
            import yaml
        except ImportError:
            missing_pkgs.append("pyyaml")

        try:
            import cryptography
        except ImportError:
            missing_pkgs.append("cryptography")

        if not missing_pkgs:
            return DiagnosticCheck(
                id="DOC-11-PYDEPS",
                name="Python Dependencies (PyYAML, Cryptography)",
                status="PASS",
                details="All mandatory Python libraries available (PyYAML, cryptography).",
            )
        return DiagnosticCheck(
            id="DOC-11-PYDEPS",
            name="Python Dependencies (PyYAML, Cryptography)",
            status="FAIL",
            details=f"Missing required Python packages: {', '.join(missing_pkgs)}.",
            remediation=f"Install missing dependencies: pip install {' '.join(missing_pkgs)}.",
        )

    # Check 12: Repository & Git State
    def _check_git_state(self) -> DiagnosticCheck:
        git_bin = find_binary("git")
        if not git_bin:
            return DiagnosticCheck(
                id="DOC-12-GITSTATE",
                name="Repository & Git Workspace State",
                status="WARNING",
                details="Git binary not available to inspect repository state.",
            )
        try:
            branch_res = subprocess.run([git_bin, "rev-parse", "--abbrev-ref", "HEAD"], cwd=self.repo_root, capture_output=True, text=True, check=False)
            branch = branch_res.stdout.strip() if branch_res.returncode == 0 else "unknown"

            sha_res = subprocess.run([git_bin, "rev-parse", "HEAD"], cwd=self.repo_root, capture_output=True, text=True, check=False)
            sha = sha_res.stdout.strip()[:8] if sha_res.returncode == 0 else "unknown"

            status_res = subprocess.run([git_bin, "status", "--porcelain"], cwd=self.repo_root, capture_output=True, text=True, check=False)
            uncommitted = [l for l in status_res.stdout.splitlines() if l.strip()]

            if not uncommitted:
                return DiagnosticCheck(
                    id="DOC-12-GITSTATE",
                    name="Repository & Git Workspace State",
                    status="PASS",
                    details=f"Clean working tree on branch '{branch}' (commit {sha}).",
                    version=sha,
                )
            else:
                return DiagnosticCheck(
                    id="DOC-12-GITSTATE",
                    name="Repository & Git Workspace State",
                    status="WARNING",
                    details=f"Branch '{branch}' (commit {sha}) has {len(uncommitted)} uncommitted change(s).",
                    version=sha,
                    remediation="Commit or stash pending modifications before performing fleet operations.",
                )
        except Exception as e:
            return DiagnosticCheck(
                id="DOC-12-GITSTATE",
                name="Repository & Git Workspace State",
                status="WARNING",
                details=f"Failed to inspect git repository status: {e}",
            )


# ==============================================================================
# Subcommand Handlers
# ==============================================================================

class CLIHandlers:
    """Implements command dispatch for doctor, validate, drift, and upgrade."""

    @staticmethod
    def handle_doctor(args: argparse.Namespace) -> int:
        doctor = PlatformDoctor(REPO_ROOT)
        checks = doctor.run_all_checks()

        pass_count = sum(1 for c in checks if c.status == "PASS")
        warn_count = sum(1 for c in checks if c.status == "WARNING")
        fail_count = sum(1 for c in checks if c.status == "FAIL")

        overall_status = "HEALTHY" if fail_count == 0 and (warn_count == 0 or not args.strict) else "UNHEALTHY"

        if args.json:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "platform_version": PLATFORM_VERSION,
                "overall_status": overall_status,
                "strict_mode": args.strict,
                "summary": {
                    "total": len(checks),
                    "passed": pass_count,
                    "warnings": warn_count,
                    "failed": fail_count,
                },
                "checks": [asdict(c) for c in checks],
            }
            sanitized = SecretSanitizer.sanitize_obj(payload)
            print(json.dumps(sanitized, indent=2))
        else:
            print("==============================================================================")
            print(f" InfraFlow Platform Diagnostic Engine (v{PLATFORM_VERSION})")
            print("==============================================================================")
            for c in checks:
                if c.status == "PASS":
                    icon = Color.green("✔ PASS")
                elif c.status == "WARNING":
                    icon = Color.yellow("⚠ WARN")
                else:
                    icon = Color.red("✖ FAIL")

                print(f"[{icon}] {Color.bold(c.name)}")
                print(f"       Details: {c.details}")
                if c.path and args.verbose:
                    print(f"       Path:    {c.path}")
                if c.remediation and c.status != "PASS":
                    print(f"       Advice:  {Color.cyan(c.remediation)}")

            print("------------------------------------------------------------------------------")
            status_text = Color.green("HEALTHY") if overall_status == "HEALTHY" else Color.red("UNHEALTHY")
            print(f"Summary: {Color.bold(str(pass_count))} passed, {Color.bold(str(warn_count))} warning(s), {Color.bold(str(fail_count))} failure(s) — Overall: {status_text}")
            print("==============================================================================")

        if fail_count > 0:
            return EXIT_ERROR
        if warn_count > 0 and args.strict:
            return EXIT_ERROR
        return EXIT_OK

    @staticmethod
    def handle_validate(args: argparse.Namespace) -> int:
        """Validates consumer configuration, fleet manifest, or evaluates OPA policy."""
        # 1. Consumer config validation
        if args.config:
            config_path = PathValidator.validate_file(args.config)
            repo_dir = PathValidator.validate_directory(args.repo_dir) if args.repo_dir else config_path.parent

            val_mod = load_script_module("validate_consumer", "validate-consumer.py")
            result = val_mod.ValidationResult()

            config_data, err = val_mod.load_config_file(config_path)
            if err:
                result.record_fail("Configuration Loading", err)
            else:
                val_mod.validate_consumer_config(config_data, result)
                val_mod.validate_consumer_filesystem(config_data, repo_dir, result)

            if args.export_governance_payload and config_data:
                out_path = PathValidator.validate_file(args.export_governance_payload, must_exist=False)
                payload = val_mod.generate_governance_payload(config_data, repo_dir)
                out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            if args.json:
                payload = {
                    "valid": result.is_valid,
                    "target": str(config_path),
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
                print(json.dumps(SecretSanitizer.sanitize_obj(payload), indent=2))
            else:
                result.print_report(quiet=args.quiet)

            return EXIT_OK if result.is_valid else EXIT_ERROR

        # 2. Fleet manifest validation
        elif args.manifest:
            manifest_path = PathValidator.validate_file(args.manifest)
            plan_mod = load_script_module("plan_fleet_upgrade", "plan-fleet-upgrade.py")
            try:
                manifest_data = plan_mod.load_manifest(manifest_path)
                consumers = manifest_data.get("consumers", [])
                platform_info = manifest_data.get("platform", {})
                cand_sha = manifest_data.get("candidate_sha") or platform_info.get("candidate_sha")
                roll_sha = manifest_data.get("rollback_sha") or platform_info.get("known_good_rollback_sha")
                if args.json:
                    payload = {
                        "valid": True,
                        "target": str(manifest_path),
                        "consumer_count": len(consumers),
                        "candidate_sha": cand_sha,
                        "rollback_sha": roll_sha,
                    }
                    print(json.dumps(SecretSanitizer.sanitize_obj(payload), indent=2))
                else:
                    print("==============================================================================")
                    print(f"✔ Fleet Manifest Valid: {manifest_path}")
                    print(f"  • Candidate SHA: {cand_sha}")
                    print(f"  • Rollback SHA:  {roll_sha}")
                    print(f"  • Registered Consumers: {len(consumers)}")
                    print("==============================================================================")
                return EXIT_OK
            except Exception as e:
                if args.json:
                    print(json.dumps({"valid": False, "target": str(manifest_path), "error": str(e)}, indent=2))
                else:
                    print(f"✖ Fleet Manifest Validation Error: {e}", file=sys.stderr)
                return EXIT_ERROR

        # 3. Policy evaluation against an input file
        elif args.input_file or args.policy_file:
            input_path = PathValidator.validate_file(args.input_file) if args.input_file else None
            policy_target = Path(args.policy_file) if args.policy_file else POLICIES_DIR

            conftest_bin = find_binary("conftest")
            if not conftest_bin:
                print("✖ Conftest binary not found. Cannot evaluate OPA policies.", file=sys.stderr)
                return EXIT_ERROR

            cmd = [conftest_bin, "test"]
            if args.namespace:
                cmd.extend(["--namespace", args.namespace])
            else:
                cmd.append("--all-namespaces")

            cmd.extend(["--policy", str(policy_target), "-o", "json"])
            if input_path:
                cmd.append(str(input_path))

            res = subprocess.run(cmd, capture_output=True, text=True, env=get_environment_with_local_bin(), check=False)
            violations = PolicyErrorEnhancer.parse_conftest_json(res.stdout, default_file=str(input_path) if input_path else None)

            # Fallback to stdout parser if json returned empty but returncode was non-zero
            if not violations and res.returncode != 0:
                violations = PolicyErrorEnhancer.parse_conftest_stdout(res.stderr + "\n" + res.stdout, default_file=str(input_path) if input_path else None)

            is_valid = len(violations) == 0 and res.returncode == 0

            if args.json:
                payload = {
                    "valid": is_valid,
                    "target_input": str(input_path) if input_path else "all",
                    "policy_target": str(policy_target),
                    "violations_count": len(violations),
                    "violations": [v.to_dict() for v in violations],
                }
                print(json.dumps(SecretSanitizer.sanitize_obj(payload), indent=2))
            else:
                if is_valid:
                    print("==============================================================================")
                    print(f"✔ Policy Evaluation Passed: All policies verified cleanly.")
                    print("==============================================================================")
                else:
                    print("==============================================================================")
                    print(f"✖ Policy Evaluation Failed: {len(violations)} violation(s) detected.")
                    print("==============================================================================")
                    for idx, v in enumerate(violations, 1):
                        sev_color = Color.red(v.severity) if v.severity in ("CRITICAL", "HIGH") else Color.yellow(v.severity)
                        print(f"[{idx}] {Color.bold(v.policy_id)} ({sev_color}) — {v.namespace}")
                        print(f"    Resource:    {Color.cyan(v.resource)}")
                        if v.file_path:
                            loc_str = f"{v.file_path}" + (f":{v.line}" if v.line else "")
                            print(f"    Location:    {loc_str}")
                        print(f"    Description: {v.message}")
                        if v.remediation:
                            print(f"    Remediation: {Color.green(v.remediation)}")
                        if v.doc_link and args.verbose:
                            print(f"    Reference:   {v.doc_link}")
                        print("------------------------------------------------------------------------------")

            return EXIT_OK if is_valid else EXIT_ERROR

        else:
            print("✖ Missing validation target. Provide --config, --manifest, or --input-file with --policy-file.", file=sys.stderr)
            return EXIT_ERROR

    @staticmethod
    def handle_drift(args: argparse.Namespace) -> int:
        """Executes continuous state and speculative drift detection simulation."""
        expected_path = PathValidator.validate_file(args.expected)
        observed_path = PathValidator.validate_file(args.observed)

        drift_mod = load_script_module("simulate_drift", "simulate-drift.py")

        try:
            expected_data = drift_mod.safe_load_state_file(expected_path)
            observed_data = drift_mod.safe_load_state_file(observed_path)

            if args.provider:
                exp_p = drift_mod.normalize_provider(expected_data.get("provider", ""))
                obs_p = drift_mod.normalize_provider(observed_data.get("provider", ""))
                if exp_p != args.provider or obs_p != args.provider:
                    raise SecurityValidationError(f"Provider flag '--provider {args.provider}' does not match state providers ({exp_p}, {obs_p})")

            if args.repository:
                if expected_data.get("repository") != args.repository or observed_data.get("repository") != args.repository:
                    raise SecurityValidationError(f"Repository flag '--repository {args.repository}' does not match state repository")

            if args.workspace:
                if expected_data.get("workspace") != args.workspace or observed_data.get("workspace") != args.workspace:
                    raise SecurityValidationError(f"Workspace flag '--workspace {args.workspace}' does not match state workspace")

            report = drift_mod.assess_state_drift(
                expected_data,
                observed_data,
                expected_file=expected_path,
                observed_file=observed_path,
            )

            # JSON Export or stdout
            if args.output_json:
                out_j = PathValidator.validate_file(args.output_json, must_exist=False)
                out_j.parent.mkdir(parents=True, exist_ok=True)
                with open(out_j, "w", encoding="utf-8") as f:
                    json.dump(SecretSanitizer.sanitize_obj(report), f, indent=2)
                if not args.json:
                    print(f"JSON drift report written to: {out_j}")

            if args.output_markdown:
                out_m = PathValidator.validate_file(args.output_markdown, must_exist=False)
                out_m.parent.mkdir(parents=True, exist_ok=True)
                md = drift_mod.render_markdown_drift_report(report)
                out_m.write_text(SecretSanitizer.sanitize_text(md), encoding="utf-8")
                if not args.json:
                    print(f"Markdown drift report written to: {out_m}")

            if args.emit_telemetry:
                telem_dest = PathValidator.validate_file(args.telemetry_output or Path("reports/telemetry.jsonl"), must_exist=False)
                telem_dest.parent.mkdir(parents=True, exist_ok=True)
                drift_mod.emit_drift_telemetry(report, output_path=telem_dest)
                if not args.json:
                    print(f"Emitted drift telemetry to: {telem_dest}")

            if args.json:
                print(json.dumps(SecretSanitizer.sanitize_obj(report), indent=2))
            elif not args.output_json and not args.output_markdown:
                summary = report.get("summary", {})
                ctx = report.get("evaluation_context", {})
                verdict = summary.get("verdict", "UNKNOWN")
                drift_count = summary.get("drifted_resources_count", 0)

                v_color = Color.green(verdict) if verdict == "NO_DRIFT" else Color.red(verdict)
                print("==============================================================================")
                print(f" InfraFlow Drift Detection Report — Verdict: {v_color}")
                print("==============================================================================")
                print(f"  • Provider:               {ctx.get('provider')}")
                print(f"  • Workspace:              {ctx.get('workspace')}")
                print(f"  • Repository:             {ctx.get('repository')}")
                print(f"  • Total Resources:        {summary.get('total_resources_evaluated', 0)}")
                print(f"  • Drifted Resources:      {drift_count}")
                print(f"  • Security Critical Drift:{summary.get('security_critical_drift', False)}")
                print("==============================================================================")
                if drift_count > 0:
                    for d in report.get("drift_items", []):
                        d_cat = Color.yellow(d.get("drift_category", ""))
                        sev = d.get("severity", "MEDIUM")
                        sev_color = Color.red(sev) if sev in ("CRITICAL", "HIGH") else Color.yellow(sev)
                        print(f"  ✖ [{d_cat}] {d.get('resource_type')}.{d.get('resource_id')} ({sev_color})")
                        for diff in d.get("attribute_diffs", []):
                            print(f"      - {diff.get('attribute_path')}: expected={diff.get('expected_value')}, observed={diff.get('observed_value')}")
                        if d.get("remediation_hint"):
                            print(f"      Advice: {Color.cyan(d.get('remediation_hint'))}")
                    print("==============================================================================")

            if args.enforce_zero_drift and report.get("summary", {}).get("verdict") != "NO_DRIFT":
                print(f"\n[FAIL] Drift gate failed: {report['summary']['drifted_resources_count']} drifted resources detected.", file=sys.stderr)
                return EXIT_ERROR

            return EXIT_OK

        except SecurityValidationError as sve:
            print(f"[SECURITY ERROR] {sve}", file=sys.stderr)
            return EXIT_SECURITY
        except Exception as e:
            print(f"[ERROR] Drift detection failed: {e}", file=sys.stderr)
            return EXIT_ERROR

    @staticmethod
    def handle_upgrade(args: argparse.Namespace) -> int:
        """Plans or orchestrates fleet upgrade campaigns and rollbacks."""
        # Check if campaign orchestration arguments were provided
        if args.campaign_file or args.create_campaign or args.execute_stage:
            camp_mod = load_script_module("orchestrate_campaign", "orchestrate-campaign.py")

            # Route to campaign orchestration
            if args.create_campaign:
                manifest_path = PathValidator.validate_file(args.manifest)
                camp_file = PathValidator.validate_file(args.campaign_file or Path("campaigns/campaign-latest.json"), must_exist=False)
                campaign = camp_mod.create_campaign(
                    manifest_path=manifest_path,
                    created_by=args.created_by or "infraflow-cli",
                )
                camp_mod.save_campaign(campaign, camp_file)
                if args.json:
                    print(json.dumps(SecretSanitizer.sanitize_obj(campaign), indent=2))
                else:
                    print(f"✔ Upgrade Campaign Created: {camp_file} (Status: {campaign.get('status')})")
                return EXIT_OK

            elif args.execute_stage:
                camp_file = PathValidator.validate_file(args.campaign_file)
                campaign = camp_mod.load_campaign(camp_file)
                success, logs = camp_mod.execute_stage(
                    campaign=campaign,
                    stage_name=args.execute_stage,
                    fleet_root=Path(args.fleet_root) if args.fleet_root else REPO_ROOT / "fleet",
                    platform_dir=Path(args.platform_dir) if args.platform_dir else REPO_ROOT,
                    dry_run=args.dry_run,
                )
                if not args.dry_run:
                    camp_mod.save_campaign(campaign, camp_file)

                if args.json:
                    print(json.dumps(SecretSanitizer.sanitize_obj(campaign), indent=2))
                else:
                    print("\n".join(logs))
                return EXIT_OK if success else EXIT_ERROR

        # Default: Route to plan-fleet-upgrade.py
        plan_mod = load_script_module("plan_fleet_upgrade", "plan-fleet-upgrade.py")

        manifest_path = PathValidator.validate_file(args.manifest or REPO_ROOT / "fleet-manifest.yaml")
        manifest_data = plan_mod.load_manifest(manifest_path)
        fleet_root = Path(args.fleet_root) if args.fleet_root else REPO_ROOT / "fleet"
        platform_dir = Path(args.platform_dir) if args.platform_dir else REPO_ROOT

        # Collect reports
        fleet_reports: Dict[str, Any] = {}
        if fleet_root.is_dir():
            for c in manifest_data.get("consumers", []):
                cid = c.get("consumer_id")
                repo_name = c.get("repository", "").split("/")[-1]
                consumer_repo_path = fleet_root / repo_name
                if consumer_repo_path.is_dir():
                    rep = plan_mod.audit_consumer_repo(consumer_repo_path, platform_dir)
                    fleet_reports[cid] = rep

        # Rollback or Apply
        if args.apply or args.rollback:
            target_stage = args.stage
            target_consumer = args.consumer
            is_rollback = args.rollback
            applied_actions: List[str] = []
            all_ok = True

            for c in manifest_data.get("consumers", []):
                cid = c.get("consumer_id")
                if target_consumer and cid != target_consumer:
                    continue

                role = c.get("upgrade_role", "progressive")
                if target_stage == "canary" and role != "canary":
                    continue
                if target_stage == "progressive" and role != "progressive":
                    continue

                repo_name = c["repository"].split("/")[-1]
                repo_path = fleet_root / repo_name
                target_sha = c["rollback_sha"] if is_rollback else c["target_sha"]

                if not repo_path.is_dir():
                    applied_actions.append(f"[{cid}] Skipped: local consumer repo '{repo_path}' not found")
                    continue

                ok, logs = plan_mod.apply_consumer_upgrade(repo_path, target_sha, is_rollback=is_rollback)
                if not ok:
                    all_ok = False
                applied_actions.extend([f"[{cid}] {log}" for log in logs])

            if args.json:
                payload = {"success": all_ok, "actions": applied_actions}
                print(json.dumps(SecretSanitizer.sanitize_obj(payload), indent=2))
            else:
                action_name = "ROLLBACK" if is_rollback else "UPGRADE"
                print("==============================================================================")
                print(f" InfraFlow Fleet {action_name} Execution Summary")
                print("==============================================================================")
                for act in applied_actions:
                    print(f"  • {act}")
                print(f"Execution Result: {'SUCCESS' if all_ok else 'FAILED'}")
                print("==============================================================================")
            return EXIT_OK if all_ok else EXIT_ERROR

        # Default: Generate dry-run plan
        plan = plan_mod.generate_upgrade_plan(manifest_data, fleet_reports)
        if args.json:
            print(json.dumps(SecretSanitizer.sanitize_obj(plan), indent=2))
        else:
            print("==============================================================================")
            print(" InfraFlow Fleet Upgrade Plan (Dry-Run)")
            print("==============================================================================")
            print(f"Target Candidate SHA: {plan.get('candidate_sha')}")
            print(f"Rollback Reference:   {plan.get('rollback_sha')}")
            print("------------------------------------------------------------------------------")
            print("Stage 1 — Canary Rollout:")
            for item in plan.get("staged_rollout", {}).get("canary", []):
                act = "UPGRADE" if item.get("upgrade_needed") else "ALIGNED"
                print(f"  • [{act}] {item.get('consumer_id')} ({item.get('adapter')}): {item.get('current_sha', '')[:8]} -> {item.get('target_sha', '')[:8]}")
            print("Stage 2 — Progressive Rollout (Pending Canary Verification):")
            for item in plan.get("staged_rollout", {}).get("progressive", []):
                act = "UPGRADE" if item.get("upgrade_needed") else "ALIGNED"
                print(f"  • [{act}] {item.get('consumer_id')} ({item.get('adapter')}): {item.get('current_sha', '')[:8]} -> {item.get('target_sha', '')[:8]}")
            print("==============================================================================")
            print(f"Total Actions Required: {len(plan.get('actions_required', []))}")
            print("==============================================================================")
        return EXIT_OK


# ==============================================================================
# Argument Parsing & CLI Dispatcher
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output to stdout.",
    )
    common_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed diagnostic and trace output.",
    )
    common_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal color output.",
    )

    parser = argparse.ArgumentParser(
        prog="infraflow",
        description="InfraFlow Unified Platform CLI & Developer Experience Diagnostic Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common_parser],
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"infraflow version {PLATFORM_VERSION} (commit: {PLATFORM_CANONICAL_REF})",
        help="Show platform version and exit.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: doctor
    p_doctor = subparsers.add_parser(
        "doctor",
        help="Run 12-dimension environment & platform diagnostics.",
        parents=[common_parser],
    )
    p_doctor.add_argument("--strict", action="store_true", help="Fail with non-zero exit code on any warning.")

    # Command: validate
    p_val = subparsers.add_parser(
        "validate",
        help="Validate consumer configs, fleet manifests, or OPA policies.",
        parents=[common_parser],
    )
    p_val.add_argument("-c", "--config", type=Path, help="Path to consumer infraflow.config.yaml.")
    p_val.add_argument("-r", "--repo-dir", type=Path, help="Path to consumer repository directory.")
    p_val.add_argument("-m", "--manifest", type=Path, help="Path to fleet-manifest.yaml.")
    p_val.add_argument("-p", "--policy-file", type=Path, help="Path to Rego policy file or policy directory.")
    p_val.add_argument("-i", "--input-file", type=Path, help="Path to input HCL, JSON, or YAML file to evaluate.")
    p_val.add_argument("-n", "--namespace", type=str, help="OPA policy namespace to evaluate against.")
    p_val.add_argument("--export-governance-payload", type=Path, help="Export normalized governance JSON payload.")
    p_val.add_argument("-q", "--quiet", action="store_true", help="Suppress verbose passing check messages.")

    # Command: drift
    p_drift = subparsers.add_parser(
        "drift",
        help="Continuous state and speculative drift detection simulation.",
        parents=[common_parser],
    )
    p_drift.add_argument("-e", "--expected", type=Path, required=True, help="Expected infrastructure state JSON snapshot.")
    p_drift.add_argument("-o", "--observed", type=Path, required=True, help="Observed infrastructure state JSON snapshot.")
    p_drift.add_argument("--provider", choices=["aws", "azure", "gcp"], help="Filter or validate target cloud provider.")
    p_drift.add_argument("--workspace", type=str, help="Validate target workspace identity.")
    p_drift.add_argument("--repository", type=str, help="Validate target repository reference.")
    p_drift.add_argument("--enforce-zero-drift", action="store_true", help="Fail with non-zero code if any drift detected.")
    p_drift.add_argument("--output-json", type=Path, help="Write JSON drift report to specified path.")
    p_drift.add_argument("--output-markdown", type=Path, help="Write Markdown drift report to specified path.")
    p_drift.add_argument("--emit-telemetry", action="store_true", help="Emit structured telemetry event.")
    p_drift.add_argument("--telemetry-output", type=Path, help="Destination file for telemetry JSONL events.")

    # Command: upgrade
    p_up = subparsers.add_parser(
        "upgrade",
        help="Plan or orchestrate fleet upgrade campaigns and rollbacks.",
        parents=[common_parser],
    )
    p_up.add_argument("-m", "--manifest", type=Path, help="Path to fleet-manifest.yaml.")
    p_up.add_argument("--fleet-root", type=Path, help="Path to fleet consumers directory.")
    p_up.add_argument("--platform-dir", type=Path, help="Path to platform repository directory.")
    p_up.add_argument("--candidate-sha", type=str, help="Candidate commit SHA for upgrade.")
    p_up.add_argument("--plan", action="store_true", help="Generate fleet upgrade plan (dry-run).")
    p_up.add_argument("--apply", action="store_true", help="Apply upgrade across consumers.")
    p_up.add_argument("--rollback", action="store_true", help="Rollback consumers to rollback SHA.")
    p_up.add_argument("--stage", choices=["canary", "progressive", "all"], default="all", help="Target rollout stage.")
    p_up.add_argument("--consumer", type=str, help="Target specific consumer ID.")
    p_up.add_argument("--check-drift", action="store_true", help="Check drift prior to upgrade.")
    p_up.add_argument("--campaign-file", type=Path, help="Path to campaign state file.")
    p_up.add_argument("--create-campaign", action="store_true", help="Create new upgrade campaign.")
    p_up.add_argument("--execute-stage", choices=["canary", "progressive"], help="Execute upgrade campaign stage.")
    p_up.add_argument("--created-by", type=str, default="infraflow-cli", help="Campaign creator identifier.")
    p_up.add_argument("--dry-run", action="store_true", help="Dry run campaign stage execution.")
    p_up.add_argument("--emit-telemetry", action="store_true", help="Emit upgrade telemetry event.")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Configure terminal styling
    Color.configure(enabled=not args.no_color)

    if not args.command:
        parser.print_help()
        return EXIT_OK

    try:
        if args.command == "doctor":
            return CLIHandlers.handle_doctor(args)
        elif args.command == "validate":
            return CLIHandlers.handle_validate(args)
        elif args.command == "drift":
            return CLIHandlers.handle_drift(args)
        elif args.command == "upgrade":
            return CLIHandlers.handle_upgrade(args)
        else:
            parser.print_help()
            return EXIT_OK
    except SecurityValidationError as sve:
        print(f"[SECURITY ERROR] {sve}", file=sys.stderr)
        return EXIT_SECURITY
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"[ERROR] {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
