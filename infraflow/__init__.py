"""
InfraFlow Unified Platform CLI & Developer Experience Diagnostic Engine.

Official Python package for the InfraFlow enterprise platform.
Provides non-destructive environment diagnostics, consumer onboarding validation,
continuous state drift simulation, and fleet upgrade lifecycle campaigns.
"""

__version__ = "0.7.0"
__author__ = "InfraFlow Platform Engineering Team"
__canonical_ref__ = "TM-threemavithana/infraflow"
__license__ = "Apache-2.0"

from infraflow.scaffold import ConsumerScaffolder, ScaffoldingError, ScaffoldingSecurityError
from infraflow.registrar import ConsumerRegistrar, RegistrationError, RegistrationSecurityError
from infraflow.scanner import SecretScanner, SecretScanError, SecretDetectionError, SecretFinding

__all__ = [
    "__version__",
    "__author__",
    "__canonical_ref__",
    "__license__",
    "ConsumerScaffolder",
    "ScaffoldingError",
    "ScaffoldingSecurityError",
    "ConsumerRegistrar",
    "RegistrationError",
    "RegistrationSecurityError",
    "SecretScanner",
    "SecretScanError",
    "SecretDetectionError",
    "SecretFinding",
]
