#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography - Mathematical Suite Package
==================================================

Post-quantum cryptographic security system with rigorous mathematical foundations.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Version: 2.1.2

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import importlib as _importlib
from typing import TYPE_CHECKING, Any

__version__ = "2.1.2"
__author__ = "Andrew E. A., Steel Security Advisors LLC"

# FIPS 140-3 Power-On Self-Tests — run at module import time.
# Sets module state to OPERATIONAL or ERROR.
from ama_cryptography._self_test import _run_self_tests as _post
from ama_cryptography._self_test import (  # noqa: F401 — re-exported public API symbols (INIT-001)
    check_operational,
    module_error_reason,
    module_self_test_results,
    module_status,
    post_duration_ms,
    reset_module,
    secure_token_bytes,
)
from ama_cryptography.exceptions import (
    AmaHSMUnavailableError as AmaHSMUnavailableError,  # noqa: F401 — re-exported for public API (INIT-005)
    CryptoModuleError as CryptoModuleError,
)  # noqa: F401 — re-exported for public API (INIT-002)

_post()

# Eagerly import math modules (double_helix_engine, equations) — they carry
# no availability-check side effects and are the most frequently used exports.
from .double_helix_engine import AmaEquationEngine
from .equations import (
    CODE_NAMES,
    CODES_INDIVIDUAL,
    ETHICAL_VECTOR,
    HELIX_PARAMS,
    LAMBDA_DECAY,
    MASTER_CODES,
    MASTER_CODES_STR,
    MASTER_HELIX_PARAMS,
    OMNI_CODES,
    PHI,
    PHI_CUBED,
    PHI_SQUARED,
    SIGMA_QUADRATIC_THRESHOLD,
    calculate_sigma_quadratic,
    enforce_sigma_quadratic_threshold,
    golden_ratio_convergence_proof,
    helix_curvature,
    helix_torsion,
    initialize_ethical_matrix,
    lyapunov_function,
    lyapunov_stability_proof,
    verify_all_codes,
    verify_mathematical_foundations,
)
from .exceptions import (
    QuantumSignatureRequiredError,
)  # noqa: F401 — re-exported for public API (INIT-003)

# ---------------------------------------------------------------------------
# Optional-dependency modules — imported with try/except so that
# `import ama_cryptography` never fails due to a missing optional dep.
# ---------------------------------------------------------------------------

# === Secure Channel ===
try:
    from .secure_channel import (  # noqa: F401
        ChannelError,
        ChannelState,
        HandshakeError,
        ReplayError,
        SecureChannelInitiator,
        SecureChannelResponder,
        SecureSession,
        SessionExpiredError as ChannelSessionExpiredError,
    )

    _SECURE_CHANNEL_AVAILABLE = True
except ImportError:
    _SECURE_CHANNEL_AVAILABLE = False

# === Session Management ===
try:
    from .session import (  # noqa: F401
        ReplayDetectedError,
        ReplayWindow,
        SessionExpiredError,
        SessionLimitError,
        SessionNotFoundError,
        SessionState,
        SessionStore,
    )

    _SESSION_AVAILABLE = True
except ImportError:
    _SESSION_AVAILABLE = False

# === Adaptive Security Posture ===
try:
    from .adaptive_posture import (  # noqa: F401
        CryptoPostureController,
        PendingAction,
        PostureAction,
        PostureEvaluation,
        PostureEvaluator,
        ThreatLevel,
    )

    _ADAPTIVE_POSTURE_AVAILABLE = True
except ImportError:
    _ADAPTIVE_POSTURE_AVAILABLE = False

# === Key Management ===
try:
    from .key_management import (  # noqa: F401
        HDKeyDerivation,
        HSM_AVAILABLE,
        HSMKeyStorage,
        KeyRotationManager,
        SecureKeyStorage,
    )

    _KEY_MANAGEMENT_AVAILABLE = True
except (ImportError, RuntimeError):
    # RuntimeError: INVARIANT-7 fires if native C library isn't built.
    # In that scenario the module is already in ERROR state (POST failed).
    _KEY_MANAGEMENT_AVAILABLE = False
    HSM_AVAILABLE = False  # type: ignore[assignment]

# === RFC 3161 Timestamping ===
try:
    from .rfc3161_timestamp import (  # noqa: F401
        RFC3161_AVAILABLE,
        TimestampError,
        TimestampResult,
        TimestampUnavailableError,
        get_timestamp,
    )

    _RFC3161_AVAILABLE = RFC3161_AVAILABLE
except ImportError:
    RFC3161_AVAILABLE = False  # type: ignore[assignment]
    _RFC3161_AVAILABLE = False

# === Hybrid Combiner ===
try:
    from .hybrid_combiner import HybridCombiner  # noqa: F401

    _HYBRID_COMBINER_AVAILABLE = True
except ImportError:
    _HYBRID_COMBINER_AVAILABLE = False

# === Secure Memory ===
try:
    from .secure_memory import (  # noqa: F401
        SecureBuffer,
        constant_time_compare,
        secure_memzero,
    )

    _SECURE_MEMORY_AVAILABLE = True
except ImportError:
    _SECURE_MEMORY_AVAILABLE = False

# crypto_api exports are lazy-loaded to avoid side-effect warnings at
# import time (PQC availability checks, HMAC/HKDF warnings, etc.).
_CRYPTO_API_EXPORTS = frozenset(
    {
        "AlgorithmType",
        "AmaCryptography",
        "AMA_ADAPTIVE_POSTURE_ENABLED",
        "CryptoPackageConfig",
        "FROSTProvider",
        "KeypairCache",
        "SecureChannelProvider",
        "batch_verify_ed25519",
        "create_crypto_package",
        "verify_crypto_package",
    }
)

if TYPE_CHECKING:
    from .crypto_api import (  # noqa: F401 — TYPE_CHECKING re-exports for static analysis (INIT-004)
        AMA_ADAPTIVE_POSTURE_ENABLED,
        AlgorithmType,
        AmaCryptography,
        CryptoPackageConfig,
        FROSTProvider,
        KeypairCache,
        SecureChannelProvider,
        batch_verify_ed25519,
        create_crypto_package,
        verify_crypto_package,
    )


def __getattr__(name: str) -> Any:
    """Lazy-load crypto_api symbols on first access."""
    if name in _CRYPTO_API_EXPORTS:
        mod = _importlib.import_module("ama_cryptography.crypto_api")
        val: Any = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module 'ama_cryptography' has no attribute {name!r}")


__all__ = [
    # =========================================================================
    # PACKAGE METADATA
    # =========================================================================
    "__version__",
    "__author__",
    # =========================================================================
    # MODULE HEALTH & SELF-TESTS (FIPS 140-3 POST)
    # =========================================================================
    "CryptoModuleError",
    "check_operational",
    "module_status",
    "module_error_reason",
    "module_self_test_results",
    "post_duration_ms",
    "reset_module",
    "secure_token_bytes",
    # =========================================================================
    # CRYPTOGRAPHIC API (core — lazy-loaded from crypto_api.py)
    # =========================================================================
    "AlgorithmType",
    "AmaCryptography",
    "AMA_ADAPTIVE_POSTURE_ENABLED",
    "CryptoPackageConfig",
    "KeypairCache",
    "batch_verify_ed25519",
    "create_crypto_package",
    "verify_crypto_package",
    # =========================================================================
    # SECURE CHANNEL (Noise-NK PQ-hybrid protocol)
    # =========================================================================
    "SecureChannelProvider",
    "SecureChannelInitiator",
    "SecureChannelResponder",
    "SecureSession",
    "ChannelState",
    "ChannelError",
    "HandshakeError",
    "ReplayError",
    "ChannelSessionExpiredError",
    # =========================================================================
    # SESSION MANAGEMENT (replay protection, lifecycle)
    # =========================================================================
    "SessionStore",
    "SessionState",
    "ReplayWindow",
    "ReplayDetectedError",
    "SessionExpiredError",
    "SessionNotFoundError",
    "SessionLimitError",
    # =========================================================================
    # ADAPTIVE SECURITY POSTURE
    # =========================================================================
    "CryptoPostureController",
    "PostureEvaluator",
    "PostureEvaluation",
    "PostureAction",
    "PendingAction",
    "ThreatLevel",
    # =========================================================================
    # FROST THRESHOLD SIGNATURES (RFC 9591)
    # =========================================================================
    "FROSTProvider",
    # =========================================================================
    # KEY MANAGEMENT
    # =========================================================================
    "HDKeyDerivation",
    "KeyRotationManager",
    "SecureKeyStorage",
    "HSMKeyStorage",
    "HSM_AVAILABLE",
    "AmaHSMUnavailableError",
    # =========================================================================
    # RFC 3161 TIMESTAMPING
    # =========================================================================
    "RFC3161_AVAILABLE",
    "TimestampResult",
    "TimestampError",
    "TimestampUnavailableError",
    "get_timestamp",
    # =========================================================================
    # HYBRID COMBINER
    # =========================================================================
    "HybridCombiner",
    # =========================================================================
    # SECURE MEMORY
    # =========================================================================
    "SecureBuffer",
    "constant_time_compare",
    "secure_memzero",
    # =========================================================================
    # EXCEPTIONS
    # =========================================================================
    "QuantumSignatureRequiredError",
    # =========================================================================
    # MATHEMATICAL CONSTANTS (from equations.py)
    # =========================================================================
    "PHI",
    "PHI_SQUARED",
    "PHI_CUBED",
    "SIGMA_QUADRATIC_THRESHOLD",
    "LAMBDA_DECAY",
    "OMNI_CODES",
    "HELIX_PARAMS",
    "CODES_INDIVIDUAL",
    "MASTER_HELIX_PARAMS",
    "MASTER_CODES",
    "CODE_NAMES",
    "MASTER_CODES_STR",
    "ETHICAL_VECTOR",
    "helix_curvature",
    "helix_torsion",
    "verify_all_codes",
    "lyapunov_function",
    "lyapunov_stability_proof",
    "golden_ratio_convergence_proof",
    "calculate_sigma_quadratic",
    "enforce_sigma_quadratic_threshold",
    "initialize_ethical_matrix",
    "verify_mathematical_foundations",
    # =========================================================================
    # ANALYTICAL / MODELING UTILITIES (non-cryptographic)
    # These modules provide mathematical modeling and system analytics.
    # They are NOT cryptographic primitives and do not provide security
    # guarantees.  Do NOT use for security-critical operations.
    # =========================================================================
    "AmaEquationEngine",
]
