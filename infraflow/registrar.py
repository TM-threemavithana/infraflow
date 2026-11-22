#!/usr/bin/env python3
"""
InfraFlow Consumer Registration Engine (Milestone G10.2).

Validates and atomically registers new consumer repositories into the central
fleet upgrade manifest (config/fleet-manifest.yaml).

Safety Invariants:
- Mandatory pre-flight consumer configuration and filesystem validation.
- Enforces unique consumer_id and repository identities across the fleet.
- Rejects symbolic links, path traversals, and unapproved mutable references.
- Atomic file replacement (NamedTemporaryFile + fsync + pre-commit schema check + os.replace).
- Complete rollback and preservation of existing fleet entries on any failure.
"""

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

RE_CONSUMER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
RE_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
VALID_ADAPTERS = {"aws", "azure", "gcp", "generic", "provider-neutral", "apply-simulation"}
VALID_STAGES = {"inventory", "compatibility", "canary", "progressive", "fleet-verified", "rollback"}


class RegistrationError(Exception):
    """Raised when consumer registration fails operational or schema validation."""
    pass


class RegistrationSecurityError(Exception):
    """Raised when registration violates safety or security boundaries."""
    pass


class ConsumerRegistrar:
    """Manages validated, atomic registration of consumer repositories in fleet-manifest.yaml (G10.2)."""

    def __init__(
        self,
        config_path: Path,
        manifest_path: Optional[Path] = None,
        stage: str = "progressive",
        status: str = "registered",
        max_allowed_deletions: Optional[int] = None,
        caller_workflow: Optional[str] = None,
        repository_override: Optional[str] = None,
    ):
        self.caller_workflow = caller_workflow
        self.repository_override = repository_override

        # Check raw paths for symlinks BEFORE resolving
        if config_path.is_symlink() or os.path.islink(config_path):
            raise RegistrationSecurityError(f"Symbolic link prohibited by security policy: {config_path}")
        if manifest_path is not None and (manifest_path.is_symlink() or os.path.islink(manifest_path)):
            raise RegistrationSecurityError(f"Symbolic link prohibited by security policy: {manifest_path}")

        self.config_path = self._resolve_config_path(config_path)
        self.repo_dir = self.config_path.parent
        self.manifest_path = self._resolve_manifest_path(manifest_path)
        self.stage = (stage or "progressive").strip().lower()
        self.status = (status or "registered").strip().lower()
        self.max_allowed_deletions = max_allowed_deletions

        self._validate_security_invariants()

    def _resolve_config_path(self, raw_path: Path) -> Path:
        """Resolves and validates the consumer configuration path."""
        p = raw_path.resolve()
        if p.is_dir():
            p = p / "infraflow.config.yaml"
        return p

    def _resolve_manifest_path(self, raw_path: Optional[Path]) -> Path:
        """Locates the central fleet manifest path."""
        if raw_path is not None:
            return raw_path.resolve()

        # Discovery hierarchy
        current_file = Path(__file__).resolve()
        candidates = [
            current_file.parent.parent / "config" / "fleet-manifest.yaml",
            Path.cwd() / "config" / "fleet-manifest.yaml",
            Path.cwd() / "fleet-manifest.yaml",
        ]
        for c in candidates:
            if c.is_file():
                return c.resolve()

        return (current_file.parent.parent / "config" / "fleet-manifest.yaml").resolve()

    def _validate_security_invariants(self) -> None:
        """Enforces path traversal, symlink, and existence invariants."""
        # 1. Config path checks
        cfg_str = str(self.config_path)
        if ".." in cfg_str:
            raise RegistrationSecurityError(f"Path traversal detected in config path: {cfg_str}")
        if self.config_path.is_symlink():
            raise RegistrationSecurityError(f"Symbolic link prohibited by security policy: {cfg_str}")
        if not self.config_path.is_file():
            raise RegistrationError(f"Consumer configuration file not found: {cfg_str}")

        # 2. Manifest path checks
        man_str = str(self.manifest_path)
        if ".." in man_str:
            raise RegistrationSecurityError(f"Path traversal detected in manifest path: {man_str}")
        if self.manifest_path.is_symlink():
            raise RegistrationSecurityError(f"Symbolic link prohibited by security policy: {man_str}")
        if not self.manifest_path.is_file():
            raise RegistrationError(f"Fleet manifest file not found: {man_str}")

        # 3. Stage check
        if self.stage not in ("canary", "progressive"):
            raise RegistrationError(f"Invalid rollout stage '{self.stage}'. Allowed: canary, progressive.")

    def _run_preflight_validation(self) -> Dict[str, Any]:
        """Runs the complete G08.3 consumer validation engine on the target consumer."""
        try:
            # Load validate-consumer module
            import importlib.util
            script_path = self.manifest_path.parent.parent / "scripts" / "validate-consumer.py"
            if not script_path.is_file():
                script_path = Path.cwd() / "scripts" / "validate-consumer.py"

            if not script_path.is_file():
                raise RegistrationError("validate-consumer.py engine not found")

            spec = importlib.util.spec_from_file_location("val_consumer", str(script_path))
            val_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(val_mod)

            config_data, err = val_mod.load_config_file(self.config_path)
            if err:
                raise RegistrationError(f"Consumer configuration syntax error: {err}")

            result = val_mod.ValidationResult()
            val_mod.validate_consumer_config(config_data, result)
            val_mod.validate_consumer_filesystem(config_data, self.repo_dir, result)

            if not result.is_valid:
                errors_summary = "\n  • " + "\n  • ".join(result.errors)
                raise RegistrationError(f"Consumer failed onboarding governance validation:{errors_summary}")

            return config_data
        except RegistrationError:
            raise
        except Exception as e:
            raise RegistrationError(f"Pre-flight consumer validation encountered an error: {e}")

    def register(self, dry_run: bool = False) -> Dict[str, Any]:
        """Executes atomic registration into fleet-manifest.yaml."""
        if yaml is None:
            raise RegistrationError("PyYAML is required for fleet manifest registration")

        # 1. Pre-flight consumer validation
        config_data = self._run_preflight_validation()

        consumer_id = config_data.get("consumer_id", "")
        if not RE_CONSUMER_ID.match(consumer_id):
            raise RegistrationSecurityError(f"Invalid consumer_id format: '{consumer_id}'")

        # 2. Determine repository identity
        repo_identity = (
            self.repository_override
            or config_data.get("repository")
            or f"TM-threemavithana/infraflow-{consumer_id}"
        )
        if not repo_identity.startswith("TM-threemavithana/"):
            raise RegistrationSecurityError(
                f"Unauthorized repository identity '{repo_identity}'. Must begin with 'TM-threemavithana/'."
            )

        # 3. Load and parse existing manifest
        try:
            manifest_content = self.manifest_path.read_text(encoding="utf-8")
            manifest_data = yaml.safe_load(manifest_content)
        except Exception as e:
            raise RegistrationError(f"Failed to parse fleet manifest YAML: {e}")

        if not isinstance(manifest_data, dict) or "consumers" not in manifest_data:
            raise RegistrationError("Invalid fleet manifest structure: missing 'consumers' block")

        existing_consumers = manifest_data.get("consumers", [])
        if not isinstance(existing_consumers, list):
            raise RegistrationError("Invalid fleet manifest structure: 'consumers' must be a list")

        # 4. Enforce Uniqueness & Prevent Duplicates
        for idx, existing in enumerate(existing_consumers):
            if not isinstance(existing, dict):
                continue
            ex_id = existing.get("consumer_id")
            ex_repo = existing.get("repository")

            if ex_id == consumer_id:
                raise RegistrationError(
                    f"Duplicate consumer_id detected: '{consumer_id}' is already registered in fleet manifest (entry #{idx + 1})."
                )
            if ex_repo == repo_identity:
                raise RegistrationError(
                    f"Duplicate repository identity detected: '{repo_identity}' is already registered in fleet manifest (entry #{idx + 1})."
                )

        # 5. Determine platform baseline & target SHAs
        platform_block = manifest_data.get("platform", {})
        cand_sha = platform_block.get("candidate_sha") or config_data.get("platform_sha")
        rollback_sha = platform_block.get("known_good_rollback_sha") or config_data.get("platform_sha")
        platform_sha = config_data.get("platform_sha")

        # Determine caller workflow
        caller_wf = self.caller_workflow
        if not caller_wf:
            # Check if .github/workflows/infraflow-ci.yml exists
            candidate_wf = self.repo_dir / ".github" / "workflows" / "infraflow-ci.yml"
            if candidate_wf.is_file():
                caller_wf = ".github/workflows/infraflow-ci.yml"
            else:
                caller_wf = ".github/workflows/infraflow.yml"

        # Determine deletion threshold
        max_del = self.max_allowed_deletions
        if max_del is None:
            max_del = config_data.get("security_controls", {}).get("max_allowed_deletions", 10)

        # 6. Construct new consumer manifest entry
        new_entry: Dict[str, Any] = {
            "repository": repo_identity,
            "consumer_id": consumer_id,
            "team": config_data.get("team", "platform-engineering"),
            "workload_type": config_data.get("workload_type", "general"),
            "adapter": config_data.get("adapter", "provider-neutral"),
            "terraform_dir": config_data.get("terraform_dir", "terraform"),
            "environment": config_data.get("environment", "dev"),
            "historical_baseline_sha": platform_sha,
            "current_sha": platform_sha,
            "target_sha": cand_sha,
            "rollback_sha": rollback_sha,
            "upgrade_role": self.stage,
            "status": self.status,
            "max_allowed_deletions": max_del,
            "caller_workflow": caller_wf,
        }

        # 7. Dry-Run / Preview Mode
        if dry_run:
            return {
                "dry_run": True,
                "manifest_path": str(self.manifest_path),
                "consumer_id": consumer_id,
                "repository": repo_identity,
                "proposed_entry": new_entry,
                "existing_consumer_count": len(existing_consumers),
                "projected_consumer_count": len(existing_consumers) + 1,
            }

        # 8. Atomic Manifest File Replacement
        existing_consumers.append(new_entry)
        manifest_data["consumers"] = existing_consumers

        manifest_dir = self.manifest_path.parent
        temp_file = None
        try:
            # Create temp file in same directory to guarantee atomic rename across filesystems
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=manifest_dir,
                prefix=".fleet-manifest-",
                suffix=".tmp",
                delete=False,
                encoding="utf-8",
            ) as tf:
                temp_file = Path(tf.name)

                # Write canonical header
                tf.write('schema_version: "1.0"\n\n')
                tf.write("# ==============================================================================\n")
                tf.write("# INFRAFLOW FLEET UPGRADE MANIFEST\n")
                tf.write("# Authoritative registry of registered consumer repositories, expected adapters,\n")
                tf.write("# platform release references, and rollout configuration.\n")
                tf.write("# ==============================================================================\n\n")

                # Remove schema_version from dict to avoid duplication with header
                dump_data = dict(manifest_data)
                dump_data.pop("schema_version", None)

                yaml.dump(
                    dump_data,
                    tf,
                    sort_keys=False,
                    default_flow_style=False,
                    indent=2,
                )
                tf.flush()
                os.fsync(tf.fileno())

            # 9. Pre-commit Schema Validation: Verify written temp file using plan-fleet-upgrade
            self._verify_manifest_temp_file(temp_file)

            # 10. Atomic Replacement
            os.replace(temp_file, self.manifest_path)
            temp_file = None  # Successfully replaced

            return {
                "dry_run": False,
                "registered": True,
                "manifest_path": str(self.manifest_path),
                "consumer_id": consumer_id,
                "repository": repo_identity,
                "upgrade_role": self.stage,
                "status": self.status,
                "registered_entry": new_entry,
                "previous_count": len(existing_consumers) - 1,
                "new_count": len(existing_consumers),
            }

        except Exception as e:
            if temp_file and temp_file.is_file():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            raise RegistrationError(f"Atomic fleet manifest registration failed: {e}")

    def _verify_manifest_temp_file(self, temp_file_path: Path) -> None:
        """Verifies that the newly generated manifest passes strict load_manifest validation."""
        import importlib.util
        script_path = self.manifest_path.parent.parent / "scripts" / "plan-fleet-upgrade.py"
        if not script_path.is_file():
            script_path = Path.cwd() / "scripts" / "plan-fleet-upgrade.py"

        if script_path.is_file():
            spec = importlib.util.spec_from_file_location("pfu_verifier", str(script_path))
            pfu_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(pfu_mod)
            pfu_mod.load_manifest(temp_file_path)
