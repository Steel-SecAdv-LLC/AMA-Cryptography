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
Version: 2.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

__version__ = "2.0"
__author__ = "Andrew E. A., Steel Security Advisors LLC"

import importlib as _importlib

# Eagerly import math modules when numpy is available.
# When numpy is NOT installed, __getattr__ provides a clear ImportError
# mentioning numpy (tested by test_lazy_imports.py).
_EQUATIONS_EXPORTS = frozenset(
    {
        "HELIX_PARAMS",
        "LAMBDA_DECAY",
        "OMNI_CODES",
        "PHI",
        "PHI_CUBED",
        "PHI_SQUARED",
        "SIGMA_QUADRATIC_THRESHOLD",
        "calculate_sigma_quadratic",
        "enforce_sigma_quadratic_threshold",
        "golden_ratio_convergence_proof",
        "helix_curvature",
        "helix_torsion",
        "initialize_ethical_matrix",
        "lyapunov_function",
        "lyapunov_stability_proof",
        "verify_all_codes",
        "verify_mathematical_foundations",
    }
)
_ENGINE_EXPORTS = frozenset({"AmaEquationEngine"})
try:
    from ama_cryptography.double_helix_engine import AmaEquationEngine
    from ama_cryptography.equations import (
        HELIX_PARAMS,
        LAMBDA_DECAY,
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

except (ImportError, ModuleNotFoundError):
    pass


def __getattr__(name: str) -> object:
    """Provide a clear error when math symbols are accessed without numpy."""
    if name in _EQUATIONS_EXPORTS:
        mod = _importlib.import_module("ama_cryptography.equations")
        val = getattr(mod, name)
        globals()[name] = val
        return val
    if name in _ENGINE_EXPORTS:
        mod = _importlib.import_module("ama_cryptography.double_helix_engine")
        val = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module 'ama_cryptography' has no attribute {name!r}")


__all__ = [
    "__version__",
    "__author__",
    "PHI",
    "PHI_SQUARED",
    "PHI_CUBED",
    "SIGMA_QUADRATIC_THRESHOLD",
    "LAMBDA_DECAY",
    "OMNI_CODES",
    "HELIX_PARAMS",
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
