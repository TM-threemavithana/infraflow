#!/usr/bin/env python3
"""
InfraFlow Self-Service Consumer Project Scaffolding Engine (Milestone G10.2).

Generates production-grade, 100% cloud-free, security-governed consumer
infrastructure repositories with:
1. Validated consumer configuration (infraflow.config.yaml).
2. Pinned GitHub Actions delivery workflows (.github/workflows/infraflow-ci.yml).
3. Cloud-free testable Terraform configuration (terraform/).
4. Consumer-local security policy templates (policies/).
5. Professional README.md and scaffolding metadata.

Safety Invariants:
- Strictly immutable 40-character hexadecimal platform SHA pinning.
- Refuses to overwrite non-empty directories without explicit --force.
- Rejects symbolic links, absolute escapes, and path traversal attempts.
- $0.00 cloud spending guarantee.
"""

import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RE_CONSUMER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
RE_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
MUTABLE_REFS = {"main", "master", "latest", "dev", "HEAD", "v0.5.0", "v0.4.0", "v1"}
SUPPORTED_ADAPTERS = {"aws", "azure", "gcp", "provider-neutral", "generic"}
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
DEFAULT_PLATFORM_REF = "TM-threemavithana/infraflow"
DEFAULT_PLATFORM_SHA = "be51718f06a2662099500a710e93e6e8201b4f1c"
DEFAULT_TERRAFORM_VERSION = "1.10.4"


class ScaffoldingError(Exception):
    """Raised when consumer project scaffolding fails operational validation."""
    pass


class ScaffoldingSecurityError(Exception):
    """Raised when scaffolding violates safety or security boundaries."""
    pass


class ConsumerScaffolder:
    """Orchestrates self-service consumer project scaffolding (G10.2)."""

    def __init__(
        self,
        consumer_id: str,
        adapter: str = "provider-neutral",
        environment: str = "dev",
        workload_type: str = "general",
        team: str = "platform-engineering",
        repository: Optional[str] = None,
        output_dir: Optional[Path] = None,
        platform_ref: str = DEFAULT_PLATFORM_REF,
        platform_sha: Optional[str] = None,
        terraform_version: str = DEFAULT_TERRAFORM_VERSION,
        force: bool = False,
    ):
        self.consumer_id = (consumer_id or "").strip().lower()
        self.adapter = (adapter or "provider-neutral").strip().lower()
        self.environment = (environment or "dev").strip().lower()
        self.workload_type = (workload_type or "general").strip().lower()
        self.team = (team or "platform-engineering").strip()
        self.repository = (repository or f"TM-threemavithana/infraflow-{self.consumer_id}").strip()
        self.output_dir = output_dir or Path.cwd() / self.consumer_id
        self.platform_ref = (platform_ref or DEFAULT_PLATFORM_REF).strip()
        self.platform_sha = (platform_sha or self._discover_platform_sha()).strip().lower()
        self.terraform_version = (terraform_version or DEFAULT_TERRAFORM_VERSION).strip()
        self.force = force

        self._validate_inputs()

    def _discover_platform_sha(self) -> str:
        """Discovers the active platform SHA from central fleet manifest or fallback."""
        try:
            # Look up fleet manifest relative to repository
            current_file = Path(__file__).resolve()
            candidates = [
                current_file.parent.parent / "config" / "fleet-manifest.yaml",
                Path.cwd() / "config" / "fleet-manifest.yaml",
                Path.cwd() / "fleet-manifest.yaml",
            ]
            for manifest_path in candidates:
                if manifest_path.is_file():
                    import yaml
                    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
                    cand = data.get("platform", {}).get("candidate_sha")
                    if cand and RE_COMMIT_SHA.match(str(cand)):
                        return str(cand)
                    curr = data.get("platform", {}).get("current_release_sha")
                    if curr and RE_COMMIT_SHA.match(str(curr)):
                        return str(curr)
        except Exception:
            pass
        return DEFAULT_PLATFORM_SHA

    def _validate_inputs(self) -> None:
        """Validates all scaffolding parameters against enterprise security policies."""
        # 1. Consumer ID
        if not self.consumer_id or not RE_CONSUMER_ID.match(self.consumer_id):
            raise ScaffoldingSecurityError(
                f"Invalid consumer_id '{self.consumer_id}'. Must be 3-64 characters of lowercase alphanumeric and hyphens."
            )

        # 2. Adapter
        if self.adapter not in SUPPORTED_ADAPTERS:
            raise ScaffoldingError(
                f"Unsupported adapter '{self.adapter}'. Allowed: {', '.join(sorted(SUPPORTED_ADAPTERS))}."
            )

        # 3. Environment
        if self.environment not in SUPPORTED_ENVIRONMENTS:
            raise ScaffoldingError(
                f"Unsupported environment '{self.environment}'. Allowed: {', '.join(sorted(SUPPORTED_ENVIRONMENTS))}."
            )

        # 4. Workload Type
        if self.workload_type not in SUPPORTED_WORKLOAD_TYPES:
            raise ScaffoldingError(
                f"Unsupported workload_type '{self.workload_type}'. Allowed: {', '.join(sorted(SUPPORTED_WORKLOAD_TYPES))}."
            )

        # 5. Team
        if len(self.team) < 2 or len(self.team) > 64:
            raise ScaffoldingError("Team name must be between 2 and 64 characters.")

        # 6. Repository identity
        if not re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", self.repository):
            raise ScaffoldingSecurityError(
                f"Invalid repository identity '{self.repository}'. Expected format 'owner/repo'."
            )

        # 7. Platform Ref
        if self.platform_ref != DEFAULT_PLATFORM_REF:
            raise ScaffoldingSecurityError(
                f"Invalid platform_ref '{self.platform_ref}'. Must be '{DEFAULT_PLATFORM_REF}'."
            )

        # 8. Platform SHA (Strict 40-char Hex, No Mutable Refs)
        if self.platform_sha in MUTABLE_REFS or not RE_COMMIT_SHA.match(self.platform_sha):
            raise ScaffoldingSecurityError(
                f"Platform SHA '{self.platform_sha}' is mutable or invalid. Must be an immutable 40-character hexadecimal commit SHA."
            )

        # 9. Output Directory Security & Overwrite Protection
        out_str = str(self.output_dir)
        if ".." in out_str:
            raise ScaffoldingSecurityError(f"Path traversal detected in output directory: {out_str}")

        if self.output_dir.is_symlink():
            raise ScaffoldingSecurityError(f"Output directory is a symbolic link: {out_str}")

        # Check if destination directory exists and is non-empty
        if self.output_dir.is_dir():
            existing_items = list(self.output_dir.iterdir())
            if existing_items and not self.force:
                raise ScaffoldingSecurityError(
                    f"Destination directory '{self.output_dir}' already exists and contains {len(existing_items)} item(s). "
                    "Use --force to allow overwriting."
                )

    def scaffold(self) -> Dict[str, Any]:
        """Generates the complete consumer project structure and files."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        generated_files: List[Path] = []

        # 1. Create directory hierarchy
        dirs = [
            self.output_dir / "terraform" / "tests",
            self.output_dir / ".github" / "workflows",
            self.output_dir / "policies",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

        # 2. Generate infraflow.config.yaml
        config_path = self.output_dir / "infraflow.config.yaml"
        config_path.write_text(self._generate_config_content(), encoding="utf-8")
        generated_files.append(config_path)

        # 3. Generate .github/workflows/infraflow-ci.yml
        workflow_path = self.output_dir / ".github" / "workflows" / "infraflow-ci.yml"
        workflow_path.write_text(self._generate_workflow_content(), encoding="utf-8")
        generated_files.append(workflow_path)

        # 4. Generate Terraform project files
        tf_files = {
            "versions.tf": self._generate_tf_versions(),
            "main.tf": self._generate_tf_main(),
            "variables.tf": self._generate_tf_variables(),
            "outputs.tf": self._generate_tf_outputs(),
            "tests/unit.tftest.hcl": self._generate_tf_tests(),
        }
        for rel_name, content in tf_files.items():
            f_path = self.output_dir / "terraform" / rel_name
            f_path.parent.mkdir(parents=True, exist_ok=True)
            f_path.write_text(content, encoding="utf-8")
            generated_files.append(f_path)

        # 5. Generate policies/local_governance.rego
        policy_path = self.output_dir / "policies" / "local_governance.rego"
        policy_path.write_text(self._generate_local_policy(), encoding="utf-8")
        generated_files.append(policy_path)

        # 6. Generate README.md
        readme_path = self.output_dir / "README.md"
        readme_path.write_text(self._generate_readme(), encoding="utf-8")
        generated_files.append(readme_path)

        # 7. Generate .infraflow-metadata.json
        meta_path = self.output_dir / ".infraflow-metadata.json"
        metadata = {
            "template_version": "1.0",
            "scaffolded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "consumer_id": self.consumer_id,
            "repository": self.repository,
            "adapter": self.adapter,
            "workload_type": self.workload_type,
            "environment": self.environment,
            "team": self.team,
            "platform_ref": self.platform_ref,
            "platform_sha": self.platform_sha,
            "terraform_version": self.terraform_version,
        }
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        generated_files.append(meta_path)

        return {
            "consumer_id": self.consumer_id,
            "repository": self.repository,
            "adapter": self.adapter,
            "environment": self.environment,
            "output_dir": str(self.output_dir),
            "platform_sha": self.platform_sha,
            "files_created": [str(f.relative_to(self.output_dir)) for f in generated_files],
            "total_files": len(generated_files),
        }

    def _generate_config_content(self) -> str:
        return f"""version: "1.0"

# Unique identifier for the consuming repository (lowercase alphanumeric with hyphens)
consumer_id: "{self.consumer_id}"

# Owning engineering team
team: "{self.team}"

# Workload category: networking | application | data-platform | general | database | mlops | shared-services | test
workload_type: "{self.workload_type}"

# Relative path to Terraform configuration (must be within repository workspace)
terraform_dir: "terraform"

# Deployment target environment: dev | staging | prod | sand | test
environment: "{self.environment}"

# Target cloud adapter: provider-neutral | aws | gcp | azure | generic
adapter: "{self.adapter}"

# Platform repository reference
platform_ref: "{self.platform_ref}"

# Immutable 40-character commit SHA (must match target release on platform main)
platform_sha: "{self.platform_sha}"

# Minimum supported Terraform CLI version (enforced >= 1.6.0)
terraform_version: "{self.terraform_version}"

# Mandatory security controls
security_controls:
  enforce_mandatory_scanners: true
  fail_on_destructive: false
  max_allowed_deletions: 10
"""

    def _generate_workflow_content(self) -> str:
        adapter_block = self._get_adapter_workflow_job()
        return f"""name: "InfraFlow CI"

on:
  pull_request:
    branches: [main]
    paths:
      - "terraform/**"
      - "infraflow.config.yaml"
      - ".github/workflows/infraflow-ci.yml"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  governance-gate:
    name: "InfraFlow Governance Gate"
    uses: {self.platform_ref}/.github/workflows/reusable-tf-governance.yml@{self.platform_sha}
    with:
      config-file: "infraflow.config.yaml"
      working-directory: "."
      platform-sha: "{self.platform_sha}"
      expected-adapter: "{self.adapter}"

{adapter_block}
"""

    def _get_adapter_workflow_job(self) -> str:
        sha = self.platform_sha
        ref = self.platform_ref
        tf_ver = self.terraform_version
        env = self.environment
        cid = self.consumer_id

        if self.adapter == "aws":
            return f"""  aws-speculative-plan:
    name: "AWS Speculative Plan (Cloud-Free)"
    needs: [governance-gate]
    uses: {ref}/.github/workflows/reusable-tf-aws.yml@{sha}
    with:
      aws-region: "us-east-1"
      terraform-version: "{tf_ver}"
      working-directory: "terraform"
      environment: "{env}"
      backend-bucket: "{cid}-tfstate"
      backend-key: "env/{env}/terraform.tfstate"
      enable-aws-auth: false"""

        elif self.adapter == "azure":
            clean_cid = re.sub(r"[^a-z0-9]", "", cid)[:16]
            clean_env = re.sub(r"[^a-z0-9]", "", env)[:4]
            return f"""  azure-speculative-plan:
    name: "Azure Speculative Plan (Cloud-Free)"
    needs: [governance-gate]
    uses: {ref}/.github/workflows/reusable-tf-azure.yml@{sha}
    with:
      azure-subscription-id: "00000000-0000-0000-0000-000000000001"
      azure-resource-group-name: "rg-{cid}-{env}"
      azure-storage-account-name: "st{clean_cid}{clean_env}"
      azure-storage-container-name: "tfstate"
      azure-backend-key: "env/{env}/terraform.tfstate"
      azure-region: "eastus"
      terraform-version: "{tf_ver}"
      working-directory: "terraform"
      environment: "{env}"
      enable-azure-auth: false"""

        elif self.adapter == "gcp":
            return f"""  gcp-speculative-plan:
    name: "GCP Speculative Plan (Cloud-Free)"
    needs: [governance-gate]
    uses: {ref}/.github/workflows/reusable-tf-gcp.yml@{sha}
    with:
      gcp-project-id: "infraflow-{cid}-01"
      gcp-region: "us-central1"
      backend-bucket: "gcs-{cid}-tfstate"
      backend-prefix: "env/{env}"
      terraform-version: "{tf_ver}"
      working-directory: "terraform"
      environment: "{env}"
      enable-gcp-auth: false"""

        else:  # provider-neutral or generic
            return f"""  validate-terraform:
    name: "Validate Terraform"
    needs: [governance-gate]
    uses: {ref}/.github/workflows/reusable-tf-validate.yml@{sha}
    with:
      terraform-version: "{tf_ver}"
      working-directory: "terraform"
      enable-fmt-check: true
      enable-validate: true
      enable-test: true"""

    def _generate_tf_versions(self) -> str:
        return """terraform {
  required_version = ">= 1.6.0"
}
"""

    def _generate_tf_main(self) -> str:
        return """# InfraFlow Consumer Reference Module — 100% Cloud-Free
# Uses terraform_data to eliminate live cloud provider and credential dependencies ($0.00 spend).

resource "terraform_data" "workload" {
  input = {
    workload_name = var.workload_name
    environment   = var.environment
    managed_by    = "infraflow"
  }

  lifecycle {
    create_before_destroy = true
  }
}
"""

    def _generate_tf_variables(self) -> str:
        return f"""variable "workload_name" {{
  type        = string
  description = "Name of the workload or service"
  default     = "{self.consumer_id}"

  validation {{
    condition     = can(regex("^[a-z0-9][a-z0-9-]{{1,62}}[a-z0-9]$", var.workload_name))
    error_message = "workload_name must be a valid lowercase alphanumeric identifier."
  }}
}}

variable "environment" {{
  type        = string
  description = "Target deployment environment"
  default     = "{self.environment}"

  validation {{
    condition     = contains(["dev", "staging", "prod", "sand", "test"], var.environment)
    error_message = "environment must be one of: dev, staging, prod, sand, test."
  }}
}}

variable "tags" {{
  type        = map(string)
  description = "Mandatory resource tags for governance compliance"
  default = {{
    Environment = "{self.environment}"
    ManagedBy   = "infraflow"
    Service     = "{self.consumer_id}"
  }}

  validation {{
    condition     = contains(keys(var.tags), "Environment") && contains(keys(var.tags), "ManagedBy")
    error_message = "tags must include both 'Environment' and 'ManagedBy' keys."
  }}
}}
"""

    def _generate_tf_outputs(self) -> str:
        return """output "workload_id" {
  value       = terraform_data.workload.id
  description = "Unique identifier of the provisioned workload resource"
}

output "environment" {
  value       = var.environment
  description = "Configured target deployment environment"
}

output "managed_by" {
  value       = "infraflow"
  description = "Authoritative platform delivery orchestrator"
}
"""

    def _generate_tf_tests(self) -> str:
        return f"""# InfraFlow Native Unit Test Suite
# Validates module inputs and outputs offline without cloud credentials ($0.00 spend).

run "verify_workload_defaults" {{
  command = plan

  assert {{
    condition     = var.environment == "{self.environment}"
    error_message = "Default environment mismatch."
  }}

  assert {{
    condition     = var.workload_name == "{self.consumer_id}"
    error_message = "Default workload_name mismatch."
  }}

  assert {{
    condition     = var.tags["ManagedBy"] == "infraflow"
    error_message = "Mandatory tag 'ManagedBy' must be set to 'infraflow'."
  }}
}}
"""

    def _generate_local_policy(self) -> str:
        return """package consumer.governance

import rego.v1

# Consumer-local governance rule: enforce 'infraflow' management marker
deny contains msg if {
	input.resource.terraform_data.workload.input.managed_by != "infraflow"
	msg := "Consumer Workload: Resource must specify managed_by = 'infraflow'"
}
"""

    def _generate_readme(self) -> str:
        return f"""# {self.consumer_id} — InfraFlow Consumer Repository

This repository delivers infrastructure managed and governed by the **InfraFlow Platform**.

## Platform Configuration
- **Consumer ID:** `{self.consumer_id}`
- **Adapter:** `{self.adapter}`
- **Workload Type:** `{self.workload_type}`
- **Environment:** `{self.environment}`
- **Owning Team:** `{self.team}`
- **Platform Reference:** `{self.platform_ref}`
- **Platform SHA:** `{self.platform_sha}`

## Local Development & Validation

Ensure the InfraFlow CLI is installed:
```bash
# Validate consumer onboarding governance contract
infraflow validate --config infraflow.config.yaml

# Run offline Terraform tests ($0.00 cloud spend)
cd terraform
terraform init -backend=false
terraform test
```

## CI/CD Pipeline
Every pull request to `main` triggers `.github/workflows/infraflow-ci.yml`, which executes:
1. **Governance Gate:** Enforces contract versioning, adapter compatibility, and least-privilege token permissions.
2. **Adapter Speculative Plan:** Executes cloud-free speculative planning under adapter `{self.adapter}`.
"""
