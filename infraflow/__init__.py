"""
InfraFlow Unified Platform CLI & Developer Experience Diagnostic Engine.

Official Python package for the InfraFlow enterprise platform.
Provides non-destructive environment diagnostics, consumer onboarding validation,
continuous state drift simulation, fleet upgrade lifecycle campaigns, and
distributed state locking engine.
"""

__version__ = "0.8.0"
__author__ = "InfraFlow Platform Engineering Team"
__canonical_ref__ = "TM-threemavithana/infraflow"
__license__ = "Apache-2.0"

from infraflow.scaffold import ConsumerScaffolder, ScaffoldingError, ScaffoldingSecurityError
from infraflow.registrar import ConsumerRegistrar, RegistrationError, RegistrationSecurityError
from infraflow.scanner import SecretScanner, SecretScanError, SecretDetectionError, SecretFinding
from infraflow.locking import (
    DistributedLockDriver,
    LocalFSDriver,
    MockDistributedDriver,
    LockManager,
    LockHandle,
    LockDescriptor,
    LeaseState,
    LockRecord,
    LockResult,
    derive_canonical_lock_identity,
    validate_lock_metadata,
    check_metadata_secrets,
    LockError,
    LockAcquisitionError,
    LockHeldError,
    ContentionTimeoutError,
    ResourceIdentityError,
    LockLostError,
    LeaseExpiredError,
    StaleOwnerError,
    StaleFencingTokenError,
    LeaseGenerationMismatchError,
    LeaseRenewalError,
    HeartbeatTimeoutError,
    MaxRenewalsExceededError,
    ClockSkewExceededError,
    UncertainOutcomeError,
    AdministrativeOverrideError,
    SecurityViolationError,
)

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
    # Distributed Locking (Milestone G10.4)
    "DistributedLockDriver",
    "LocalFSDriver",
    "MockDistributedDriver",
    "LockManager",
    "LockHandle",
    "LockDescriptor",
    "LeaseState",
    "LockRecord",
    "LockResult",
    "derive_canonical_lock_identity",
    "validate_lock_metadata",
    "check_metadata_secrets",
    "LockError",
    "LockAcquisitionError",
    "LockHeldError",
    "ContentionTimeoutError",
    "ResourceIdentityError",
    "LockLostError",
    "LeaseExpiredError",
    "StaleOwnerError",
    "StaleFencingTokenError",
    "LeaseGenerationMismatchError",
    "LeaseRenewalError",
    "HeartbeatTimeoutError",
    "MaxRenewalsExceededError",
    "ClockSkewExceededError",
    "UncertainOutcomeError",
    "AdministrativeOverrideError",
    "SecurityViolationError",
]
