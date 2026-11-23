#!/usr/bin/env python3
"""
InfraFlow Unified Platform CLI Wrapper (Milestone G10.1 / G10.1.1)

Executable entrypoint forwarding to the canonical infraflow.cli engine.
Preserves backward compatibility with existing direct script invocations.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path for direct execution without installation
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Re-export all public API components from infraflow.cli for backward compatibility
from infraflow.cli import (
    PLATFORM_VERSION,
    PLATFORM_CANONICAL_REF,
    EXIT_OK,
    EXIT_ERROR,
    EXIT_SECURITY,
    REPO_ROOT,
    SCRIPTS_DIR,
    POLICIES_DIR,
    SecretSanitizer,
    SecurityValidationError,
    PathValidator,
    Color,
    PolicyViolation,
    PolicyErrorEnhancer,
    DiagnosticCheck,
    PlatformDoctor,
    CLIHandlers,
    build_parser,
    find_binary,
    get_environment_with_local_bin,
    load_script_module,
    main,
)

if __name__ == "__main__":
    sys.exit(main())
