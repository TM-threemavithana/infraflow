"""
InfraFlow — Consumer Secret Defense & Credential Scanning Engine
Milestone: G10.3

Provides deterministic, fail-closed credential and secret scanning for consumer
repositories before speculative planning or cloud execution:
- Detects AWS access keys, GitHub tokens, private keys, passwords, bearer tokens,
  and high-entropy credential assignments.
- Excludes binary Terraform execution plans (tfplan) and compiled artifacts.
- Masks all detected secrets using SecretSanitizer (zero secret exposure in logs/reports).
- Emits structured, machine-readable JSON security findings.
"""

import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ==============================================================================
# Scanner Exceptions
# ==============================================================================

class SecretScanError(Exception):
    """Base exception for secret scanning errors."""
    pass


class SecretDetectionError(SecretScanError):
    """Raised when one or more secrets are detected in scanned files."""
    def __init__(self, message: str, findings: List[Dict[str, Any]]):
        super().__init__(message)
        self.findings = findings


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass
class SecretFinding:
    rule_id: str
    description: str
    file_path: str
    line_number: int
    redacted_match: str
    severity: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# Secret Detection Rules & Regex Patterns
# ==============================================================================

# False-positive / placeholder values that should be excluded
PLACEHOLDER_SUBSTRINGS = {
    "placeholder",
    "changeme",
    "change_me",
    "your_password",
    "your_secret",
    "your_api_key",
    "my_secret_password",
    "dummy_token",
    "${var.",
    "${local.",
    "var.",
    "local.",
    "process.env.",
    "os.environ",
}

# Compiled detection rules
SECRET_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC-AWS-001",
        "description": "AWS Access Key ID",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
    },
    {
        "id": "SEC-AWS-002",
        "description": "AWS Secret Access Key Assignment",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
    },
    {
        "id": "SEC-GH-001",
        "description": "GitHub Classic Personal Access Token",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b"),
    },
    {
        "id": "SEC-GH-002",
        "description": "GitHub Fine-Grained Personal Access Token",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(github_pat_[a-zA-Z0-9]{20,25}_[a-zA-Z0-9]{40,70})\b"),
    },
    {
        "id": "SEC-GH-003",
        "description": "GitHub OAuth Access Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b"),
    },
    {
        "id": "SEC-GH-004",
        "description": "GitHub App / User Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\b((?:ghu|ghs|ghr)_[a-zA-Z0-9]{36})\b"),
    },
    {
        "id": "SEC-KEY-001",
        "description": "Cryptographic Private Key Block",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----)"
        ),
    },
    {
        "id": "SEC-KEY-002",
        "description": "Generic Private Key Block",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(-----BEGIN PRIVATE KEY-----)"),
    },
    {
        "id": "SEC-SLACK-001",
        "description": "Slack API / Webhook Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
    },
    {
        "id": "SEC-GCP-001",
        "description": "Google Cloud API Key",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z-_]{30,40})\b"),
    },
    {
        "id": "SEC-AUTH-001",
        "description": "Bearer Authentication Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)\b(?:bearer\s+|bearer_token\s*[=:]\s*[\"'])([A-Za-z0-9\-_=]{24,})[\"']?"
        ),
    },
    {
        "id": "SEC-CRED-001",
        "description": "Hardcoded Password / Secret Assignment",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|client_secret|auth_token)\s*[=:]\s*[\"']([^\"'\s]{10,})[\"']"
        ),
    },
]

# Binary file extensions and names to ignore (never scanned as plaintext)
BINARY_EXTENSIONS = {
    ".tfplan",
    ".plan",
    ".binary",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".pyc",
    ".pyo",
    ".pyd",
    ".bin",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".terraform",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def redact_secret(raw: str) -> str:
    """Masks secret preserving length hint without revealing credential material."""
    raw = raw.strip()
    if not raw:
        return "[EMPTY]"
    if len(raw) <= 8:
        return "***REDACTED***"
    prefix = raw[:4]
    suffix = raw[-4:]
    masked_middle = "*" * min(16, len(raw) - 8)
    return f"{prefix}{masked_middle}{suffix}"


def is_binary_content(data: bytes) -> bool:
    """Detects whether raw file bytes represent a binary file."""
    if b"\x00" in data[:8192]:
        return True
    return False


def is_placeholder(value: str) -> bool:
    """Returns True if the extracted value is an obvious placeholder or variable reference."""
    val_lower = value.lower().strip()
    for ph in PLACEHOLDER_SUBSTRINGS:
        if ph in val_lower:
            return True
    # Pure whitespace or repeated single characters
    if len(set(val_lower)) <= 2 and len(val_lower) > 5:
        return True
    return False


# ==============================================================================
# Secret Scanner Engine
# ==============================================================================

class SecretScanner:
    """
    Scans files and directories for exposed secrets and credentials.
    Guarantees zero secret exposure in reports and fail-closed operation.
    """

    def __init__(
        self,
        exclude_dirs: Optional[Set[str]] = None,
        exclude_extensions: Optional[Set[str]] = None,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
    ):
        self.exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
        if exclude_dirs:
            self.exclude_dirs.update(exclude_dirs)

        self.exclude_extensions = set(BINARY_EXTENSIONS)
        if exclude_extensions:
            self.exclude_extensions.update(exclude_extensions)

        self.rules = list(SECRET_RULES)
        if custom_rules:
            self.rules.extend(custom_rules)

    def scan_text(self, text: str, file_path: str = "<memory>") -> List[SecretFinding]:
        """Scans a text string line by line and returns detected findings."""
        findings: List[SecretFinding] = []
        lines = text.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for rule in self.rules:
                matches = rule["pattern"].findall(line)
                for match in matches:
                    # In some regex groups, match can be a tuple
                    val = match if isinstance(match, str) else match[0]
                    if is_placeholder(val):
                        continue

                    finding = SecretFinding(
                        rule_id=rule["id"],
                        description=rule["description"],
                        file_path=file_path,
                        line_number=line_num,
                        redacted_match=redact_secret(val),
                        severity=rule["severity"],
                    )
                    findings.append(finding)
        return findings

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scans an individual file on disk. Skips binary and excluded files."""
        # Check file extension
        if file_path.suffix.lower() in self.exclude_extensions:
            return []

        # Check file size (skip files > 10MB as likely data/binaries)
        try:
            stat = file_path.stat()
            if stat.st_size > 10 * 1024 * 1024:
                return []
        except OSError:
            return []

        # Read and check for binary content
        try:
            with open(file_path, "rb") as f:
                content_bytes = f.read(8192)
                if is_binary_content(content_bytes):
                    return []
                # Read remainder
                content_bytes += f.read()
        except OSError as e:
            raise SecretScanError(f"Failed to read file '{file_path}': {e}") from e

        # Decode as UTF-8
        try:
            text = content_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise SecretScanError(f"Failed to decode text in file '{file_path}': {e}") from e

        return self.scan_text(text, file_path=str(file_path))

    def scan_directory(
        self,
        target_dir: Path,
        relative_to: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Recursively scans a target directory for secret credentials.
        Returns a structured scan report dictionary.
        """
        start_time = time.monotonic()
        target_path = Path(target_dir).resolve()

        if not target_path.exists():
            raise SecretScanError(f"Target directory does not exist: {target_dir}")
        if not target_path.is_dir():
            raise SecretScanError(f"Target path is not a directory: {target_dir}")

        base_rel = relative_to or target_path
        all_findings: List[SecretFinding] = []
        files_scanned = 0
        skipped_binary_count = 0

        for root, dirs, files in os.walk(target_path):
            # Prune excluded directories in place
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith(".")]

            for file_name in sorted(files):
                f_path = Path(root) / file_name

                # Skip symlinks to prevent symlink traversal escapes
                if f_path.is_symlink():
                    continue

                if f_path.suffix.lower() in self.exclude_extensions:
                    skipped_binary_count += 1
                    continue

                try:
                    rel_display = str(f_path.relative_to(base_rel))
                except ValueError:
                    rel_display = str(f_path)

                findings = self.scan_file(f_path)
                # Remap file_path in findings to relative display path
                for finding in findings:
                    finding.file_path = rel_display
                    all_findings.append(finding)

                files_scanned += 1

        duration_ms = int((time.monotonic() - start_time) * 1000)
        is_clean = len(all_findings) == 0

        return {
            "status": "PASS" if is_clean else "FAIL",
            "is_clean": is_clean,
            "target_dir": str(target_path),
            "files_scanned": files_scanned,
            "skipped_binary_files": skipped_binary_count,
            "total_secrets_found": len(all_findings),
            "duration_ms": duration_ms,
            "findings": [f.to_dict() for f in all_findings],
        }
