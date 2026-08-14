#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography - Mathematical Suite Package
==================================================

Post-quantum cryptographic security system with rigorous mathematical foundations.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Version: 5.0.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import importlib as _importlib
import logging as _logging
import os as _os
import sys as _sys
from typing import TYPE_CHECKING, Any

__version__ = "5.0.0"
__author__ = "Andrew E. A., Steel Security Advisors LLC"

# Windows DLL search-path registration (Python 3.8+).
#
# On Windows, Python's loader for compiled extensions (`.pyd` files) does
# NOT search the package's own directory for transitive DLL dependencies
# unless that directory has been registered via ``os.add_dll_directory``.
# Our Cython binding extensions (sha3_binding, ed25519_binding, etc.)
# NEEDED-link against ``ama_cryptography.dll`` which the CMake build
# (D-1, 2026-04-27 audit) bundles next to them in this package's
# directory.  Without this registration the loader cannot find that DLL
# and every binding import dies with ``ImportError: DLL load failed``
# (PR #277 Windows ci.yml regression).
#
# `os.add_dll_directory` returns an opaque cookie object whose ``close()``
# method is invoked at GC time, at which point the directory is removed
# from the AddDllDirectory search list (see Python docs for
# ``os.add_dll_directory`` and Win32 ``AddDllDirectory``).  Discarding the
# return value lets the cookie become unreachable as soon as this module's
# top-level frame finishes evaluating, after which a later
# ``import ama_cryptography.sha3_binding`` (etc.) can intermittently die
# with ``ImportError: DLL load failed`` once the GC closes the cookie.
# Copilot review #11/#21 flagged this; we now append the cookie to a
# module-level list (``_AMA_DLL_DIR_COOKIES``) so it lives for the
# interpreter's lifetime — the package directory stays resolvable for as
# long as ``ama_cryptography`` is importable.  Linux and macOS resolve
# transitive deps via DT_RUNPATH=$ORIGIN baked into each binding
# extension, so this branch is a no-op there.
#
# We use a *list* rather than a single name because (a) it's the
# documented Python pattern for retaining N AddDllDirectory cookies
# (see CPython issue #87466 / docs example) and (b) ``.append()`` is a
# read-use that CodeQL's "py/unused-global-variable" query recognises,
# whereas a write-only single name (the previous form) tripped the
# analyser even though the side effect on the Win32 search path is the
# whole point.  Concretely closes CodeQL findings #504/#505/#506 from
# the PR-285 scan without needing any suppression marker.
_AMA_DLL_DIR_COOKIES: list[Any] = []  # Windows-only; entries kept alive for process lifetime
if _sys.platform == "win32":
    _here = _os.path.dirname(_os.path.abspath(__file__))
    if _os.path.isdir(_here):
        try:
            _AMA_DLL_DIR_COOKIES.append(
                _os.add_dll_directory(_here)  # type: ignore[attr-defined]  # Windows-only API; mypy on Linux/macOS (where strict CI runs) does not see it (WIN-001)
            )
        except (OSError, AttributeError):
            # AttributeError on Python <3.8 (we require >=3.10 so this is
            # defence in depth); OSError on the rare case the directory
            # is unreadable.  Either way, fall through and let the
            # downstream import surface a clear error.  The list stays
            # empty so callers can introspect registration state.
            pass

# FIPS 140-3 Power-On Self-Tests — run at module import time.
# Sets module state to OPERATIONAL or ERROR.
from ama_cryptography._self_test import _run_self_tests as _post
from ama_cryptography._self_test import (
    check_crypto_permitted as check_crypto_permitted,
)
from ama_cryptography._self_test import (
    check_operational as check_operational,
)
from ama_cryptography._self_test import (
    module_attestation as module_attestation,
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
    AmaCryptographyError as AmaCryptographyError,
)
from ama_cryptography.exceptions import (
    CryptoModuleError as CryptoModuleError,
)

# FIPS 140-3 §4.9.2: a module whose power-on self-tests failed must not
# present itself as usable.
#
# This return value used to be discarded.  POST would log
# ``CRITICAL: FIPS 140-3 POST FAILURE: ...``, set the module state to ERROR —
# and then ``import ama_cryptography`` would succeed, with exit code 0.  Every
# build script, CI smoke test and health check that treated a clean import as
# proof of a working module therefore reported success over the top of a
# module that had just announced its own failure.  The failure was in the log
# and the success was in the exit code, and the exit code is what tooling
# reads.  A self-test whose failure cannot fail anything is not a self-test.
#
# Import now raises.  The error message carries the root cause and the POST
# result table, because a raising import leaves nothing behind to introspect:
# the partially-initialised module is dropped from ``sys.modules``, so
# ``module_error_reason()`` is not reachable afterwards and the text is the
# only artefact the operator gets.
#
# ``AMA_POST_DIAGNOSTIC_IMPORT=1`` is the triage escape hatch: the import
# completes so an operator can call ``module_attestation()`` and read the full
# picture, but the module stays in ERROR and ``check_crypto_permitted()``
# refuses every cryptographic operation.  It buys introspection, not crypto.
if not _post():
    _reason = module_error_reason() or "unknown"
    _results = module_self_test_results()
    _rows = "\n".join(
        f"    {_name:<24} {'PASS' if _ok else ('SKIP' if _ok is None else 'FAIL')}  {_detail}"
        for _name, _ok, _detail in _results
    )
    _diag_env = "AMA_POST_DIAGNOSTIC_IMPORT"
    _build_env = "AMA_BUILD_PIPELINE"
    _TRUE = {"1", "true", "yes", "on"}

    # The tools that REPAIR a failed integrity check — ``_build_sign`` and
    # ``integrity --update`` — live inside this package, so a hard raise here
    # would wall them off behind the very fault they exist to clear: edit a
    # .py file, the digest goes stale, and the command that refreshes it can
    # no longer import the package that contains it.  Both are already gated
    # on AMA_BUILD_PIPELINE=1, and that flag already confers the power to
    # rewrite the integrity artefacts outright, so honouring it here grants no
    # capability an attacker did not already have.
    #
    # It is honoured ONLY for an integrity-stage failure, which is the one
    # POST outcome a signing run legitimately expects to see in a tree it is
    # about to re-sign.  A failed KAT, a timing leak or an RNG fault has
    # nothing to do with a stale artefact and still hard-fails, so a release
    # container — which has AMA_BUILD_PIPELINE=1 set for its whole lifetime —
    # cannot smoke-test a genuinely broken wheel and call it built.
    _integrity_stage_failed = any(
        _name == "integrity" and _ok is False for _name, _ok, _ in _results
    )

    if _os.environ.get(_diag_env, "").strip().lower() in _TRUE:
        _logging.getLogger(__name__).critical(
            "FIPS 140-3 POST FAILED and %s is set: completing the import for "
            "diagnosis only. The module is in the ERROR state and every "
            "cryptographic operation will be refused. Root cause: %s",
            _diag_env,
            _reason,
        )
    elif _integrity_stage_failed and _os.environ.get(_build_env, "").strip().lower() in _TRUE:
        _logging.getLogger(__name__).critical(
            "FIPS 140-3 POST integrity stage FAILED and %s=1: completing the "
            "import so the build-pipeline integrity tooling can run. The "
            "module is in the ERROR state and every cryptographic operation "
            "through the public surface will be refused. Root cause: %s",
            _build_env,
            _reason,
        )
    else:
        raise CryptoModuleError(
            "ama_cryptography refused to initialise: FIPS 140-3 power-on "
            f"self-tests FAILED.\n\n  Root cause: {_reason}\n\n"
            f"  POST results:\n{_rows}\n\n"
            "  All cryptographic operations are inhibited (FIPS 140-3 "
            "§4.9.2). Correct the fault and re-import.\n\n"
            f"  Diagnosis: set {_diag_env}=1 to import anyway (crypto stays "
            "refused) and call module_attestation().\n"
            "  Stale digest after editing package sources? Refresh it with:\n"
            f"      {_build_env}=1 python -m ama_cryptography.integrity --update --sign"
        )

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
    KeyFormatError as KeyFormatError,
)
from .exceptions import (
    QuantumSignatureRequiredError as QuantumSignatureRequiredError,
)
from .exceptions import (
    UnsupportedKeyFormatError as UnsupportedKeyFormatError,
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

# key_formats exports are lazy-loaded for the same reason, and because
# importing it eagerly would pull the native backend in on `import
# ama_cryptography` for every caller, most of whom never touch a key file.
#
# Wired up here because the whole point of the module is interoperability, and
# an interoperability API you cannot reach from the package namespace is one
# nobody finds: `ama_cryptography.load_pkcs8` did not exist, and neither did
# `from ama_cryptography import key_formats` as anything the package declared.
_KEY_FORMAT_EXPORTS = frozenset(
    {
        "ALGORITHMS",
        "CONVENTIONAL_PUBLIC_KEY",
        "PQ_CONSISTENCY_ENV",
        "PrivateKey",
        "PublicKey",
        "conventional_include_public_key",
        "cose_to_private_key",
        "cose_to_public_key",
        "decode_pem",
        "encode_pem",
        "get_pq_import_consistency",
        "jwk_thumbprint",
        "jwk_to_private_key",
        "jwk_to_public_key",
        "load_pkcs8",
        "load_spki",
        "pq_import_consistency",
        "private_key_to_cose",
        "private_key_to_jwk",
        "public_key_to_cose",
        "public_key_to_jwk",
        "set_pq_import_consistency",
    }
)

# Every name in the two lazy sets above is bound again here, under
# ``TYPE_CHECKING``, and the binding must be exhaustive.
#
# PEP 562 makes ``__getattr__`` invisible to anything that does not run the
# module: mypy, IDEs, and static analysers see ``__all__`` promising a name and
# no definition producing it. The consequence is not cosmetic — a name reachable
# only through ``__getattr__`` is typed ``Any``, so every call through it is
# silently unchecked, and "go to definition" lands nowhere. This block was
# previously partial (13 of 31 names), which is the worst of both: the covered
# names type-checked and the rest quietly did not, with nothing marking the
# boundary.
#
# ``tests/test_lazy_exports.py`` holds the three declarations to each other, so
# adding an export to one and forgetting the others fails rather than degrading.
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
    from .key_formats import (
        ALGORITHMS as ALGORITHMS,
    )
    from .key_formats import (
        CONVENTIONAL_PUBLIC_KEY as CONVENTIONAL_PUBLIC_KEY,
    )
    from .key_formats import (
        PQ_CONSISTENCY_ENV as PQ_CONSISTENCY_ENV,
    )
    from .key_formats import (
        PrivateKey as PrivateKey,
    )
    from .key_formats import (
        PublicKey as PublicKey,
    )
    from .key_formats import (
        conventional_include_public_key as conventional_include_public_key,
    )
    from .key_formats import (
        cose_to_private_key as cose_to_private_key,
    )
    from .key_formats import (
        cose_to_public_key as cose_to_public_key,
    )
    from .key_formats import (
        decode_pem as decode_pem,
    )
    from .key_formats import (
        encode_pem as encode_pem,
    )
    from .key_formats import (
        get_pq_import_consistency as get_pq_import_consistency,
    )
    from .key_formats import (
        jwk_thumbprint as jwk_thumbprint,
    )
    from .key_formats import (
        jwk_to_private_key as jwk_to_private_key,
    )
    from .key_formats import (
        jwk_to_public_key as jwk_to_public_key,
    )
    from .key_formats import (
        load_pkcs8 as load_pkcs8,
    )
    from .key_formats import (
        load_spki as load_spki,
    )
    from .key_formats import (
        pq_import_consistency as pq_import_consistency,
    )
    from .key_formats import (
        private_key_to_cose as private_key_to_cose,
    )
    from .key_formats import (
        private_key_to_jwk as private_key_to_jwk,
    )
    from .key_formats import (
        public_key_to_cose as public_key_to_cose,
    )
    from .key_formats import (
        public_key_to_jwk as public_key_to_jwk,
    )
    from .key_formats import (
        set_pq_import_consistency as set_pq_import_consistency,
    )


def __getattr__(name: str) -> Any:
    """Lazy-load crypto_api and key_formats symbols on first access."""
    if name in _CRYPTO_API_EXPORTS:
        mod = _importlib.import_module("ama_cryptography.crypto_api")
        val: Any = getattr(mod, name)
        globals()[name] = val
        return val
    if name in _KEY_FORMAT_EXPORTS:
        mod = _importlib.import_module("ama_cryptography.key_formats")
        val = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module 'ama_cryptography' has no attribute {name!r}")


__all__ = [
    "__version__",
    "__author__",
    "AmaCryptographyError",
    "CryptoModuleError",
    "check_crypto_permitted",
    "check_operational",
    "module_attestation",
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
    # Key interoperability formats (ama_cryptography.key_formats), lazily
    # loaded — see _KEY_FORMAT_EXPORTS.
    "ALGORITHMS",
    "CONVENTIONAL_PUBLIC_KEY",
    "KeyFormatError",
    "PQ_CONSISTENCY_ENV",
    "PrivateKey",
    "PublicKey",
    "UnsupportedKeyFormatError",
    "conventional_include_public_key",
    "cose_to_private_key",
    "cose_to_public_key",
    "decode_pem",
    "encode_pem",
    "get_pq_import_consistency",
    "jwk_thumbprint",
    "jwk_to_private_key",
    "jwk_to_public_key",
    "load_pkcs8",
    "load_spki",
    "pq_import_consistency",
    "private_key_to_cose",
    "private_key_to_jwk",
    "public_key_to_cose",
    "public_key_to_jwk",
    "set_pq_import_consistency",
]
