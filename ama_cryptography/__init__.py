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
from ama_cryptography._self_test import (
    check_operational as check_operational,
)
from ama_cryptography._self_test import (
    module_error_reason as module_error_reason,
)
from ama_cryptography._self_test import (
    module_self_test_results as module_self_test_results,
)
from ama_cryptography._self_test import (
    module_status as module_status,
)
from ama_cryptography._self_test import (
    post_duration_ms as post_duration_ms,
)
from ama_cryptography._self_test import (
    reset_module as reset_module,
)
from ama_cryptography._self_test import (
    secure_token_bytes as secure_token_bytes,
)
from ama_cryptography.exceptions import (
    CryptoModuleError as CryptoModuleError,
)

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
    QuantumSignatureRequiredError as QuantumSignatureRequiredError,
)

# crypto_api exports are lazy-loaded to avoid side-effect warnings at
# import time (PQC availability checks, HMAC/HKDF warnings, etc.).
_CRYPTO_API_EXPORTS = frozenset(
    {
        "AlgorithmType",
        "AmaCryptography",
        "CryptoPackageConfig",
        "KeypairCache",
        "batch_verify_ed25519",
        "create_crypto_package",
        "verify_crypto_package",
    }
)

if TYPE_CHECKING:
    from .crypto_api import (
        AlgorithmType as AlgorithmType,
    )
    from .crypto_api import (
        AmaCryptography as AmaCryptography,
    )
    from .crypto_api import (
        CryptoPackageConfig as CryptoPackageConfig,
    )
    from .crypto_api import (
        KeypairCache as KeypairCache,
    )
    from .crypto_api import (
        batch_verify_ed25519 as batch_verify_ed25519,
    )
    from .crypto_api import (
        create_crypto_package as create_crypto_package,
    )
    from .crypto_api import (
        verify_crypto_package as verify_crypto_package,
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
    "__version__",
    "__author__",
    "CryptoModuleError",
    "check_operational",
    "module_status",
    "module_error_reason",
    "module_self_test_results",
    "post_duration_ms",
    "reset_module",
    "secure_token_bytes",
    "AlgorithmType",
    "AmaCryptography",
    "CryptoPackageConfig",
    "KeypairCache",
    "batch_verify_ed25519",
    "create_crypto_package",
    "verify_crypto_package",
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
    "QuantumSignatureRequiredError",
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
    "AmaEquationEngine",
]
