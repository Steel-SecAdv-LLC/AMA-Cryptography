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


# ---------------------------------------------------------------------------
# PRE-IMPORT binding-extension gate.
#
# The POST integrity stage verifies every compiled binding extension against
# the signed artefact — but a binding extension is an ordinary Python
# extension module, so importing it runs its module-init function, and POST
# runs after the imports that pull them in.  That made binding verification
# post-load DETECTION where the native library already had pre-load REFUSAL:
# a tampered ``sha3_binding`` executed and only then moved the module to the
# ERROR state.
#
# This closes that asymmetry for the case that is unambiguous tampering — a
# file the artefact SIGNS whose bytes differ.  It runs here, at the top of
# package initialisation, before any submodule import, so it is ahead of
# every binding import in the tree (all are lazy inside functions except
# ``monitoring``'s ``math_engine``, which this still precedes).  Verified by
# construction: importing ``ama_cryptography.sha3_binding`` directly
# initialises this package first, so there is no import path that reaches a
# binding without passing through here.
#
# Scope is deliberately narrow.
#
#   * digest MISMATCH -> raise now, before the module-init function runs.
#     Always fatal, on every build, exactly as the POST stage treats it.
#   * inventory drift (listed-but-missing, present-but-uncovered) -> NOT
#     handled here.  It is not tampering, its correct severity depends on
#     whether the build is anchored, and answering that needs the trust
#     anchor from the native library — which means loading it, which is the
#     work this gate exists to run ahead of.  POST still applies the full
#     anchored/developer split afterwards.
#
# Reading ``_integrity_signature`` is safe this early: it is generated source
# containing only literals and imports nothing from this package.  What that
# does NOT establish is its authenticity, and the boundary is worth stating
# exactly, because an earlier revision of this comment overstated it.
#
# This gate compares each binding against a digest THE ARTEFACT SUPPLIES.  So
# it detects any tampering that leaves the artefact intact — the realistic
# case, since a rebuilt or swapped extension does not update a signed file.
# It cannot, by construction, detect an attacker who rewrites the extension
# AND the artefact together: the forged artefact simply lists the forged
# digest and the comparison succeeds.
#
# The earlier comment claimed that case "is caught by the signature check, as
# before".  That holds only while the NATIVE LIBRARY is authentic, because the
# trust anchor the signature is checked against is compiled into that library
# (`ama_integrity_trust_anchor_pubkey_hex`, see `_self_test.
# _load_integrity_trust_anchor`) and the library itself is admitted by a digest
# the same artefact supplies.  An attacker with write access to the installed
# tree who replaces the library, the artefact and the extensions coherently
# therefore validates against their own key at every step.
#
# So the honest statement of this chain, matching SECURITY.md's "Boundary
# (shared with the trust anchor)" and `tools/verify_install_oob.py`'s
# UNANCHORED verdict: in-tree verification establishes INTERNAL CONSISTENCY,
# not authenticity.  Authenticity requires an anchor from OUTSIDE the tree —
# `tools/verify_install_oob.py --expected-pubkey <key held elsewhere>`, or the
# wheel's own Sigstore/PyPI attestation.  What this gate adds over POST is
# real and narrower than "authenticity": it moves the detection of the
# single-file case to BEFORE the extension's module-init function runs, which
# is the only point at which detection still prevents execution.
def _refuse_tampered_bindings_before_import() -> None:
    import hashlib as _hashlib
    from pathlib import Path as _Path

    from ama_cryptography._artefact_source import (
        ArtefactSourceError as _ArtefactSourceError,
    )
    from ama_cryptography._artefact_source import load_artefact_fields as _load_fields

    # The digest map is read from the artefact's SOURCE TEXT, not imported.
    #
    # `from ama_cryptography import _integrity_signature` reads
    # `__pycache__/_integrity_signature.cpython-3XX.pyc` whenever a cache
    # exists whose PEP 552 header matches the source's (mtime, size) — and
    # nothing has validated that cache here, because the POST stage that binds
    # cached bytecode to signed source runs long after this gate returns.
    # Writing one poisoned `.pyc`, with `_integrity_signature.py` left
    # byte-identical and its signature still valid, made this gate compare a
    # tampered extension against the tampered extension's own digest and let it
    # execute.  Measured, not theorised — see `_artefact_source`'s docstring for
    # the reproduction.  Parsing the source removes the import system from the
    # path entirely, so the literals come from bytes the signature covers.
    try:
        _sig = _load_fields()
    except _ArtefactSourceError as exc:
        # Present but not a file of literals any more.  Never a fallback: the
        # one file every digest check trusts has stopped being what it claims.
        raise ImportError(
            "ama_cryptography refused to initialise: the signed integrity "
            f"artefact could not be read as generated source.\n\n  {exc}\n\n"
            "  This file is generated and contains only literal assignments. "
            "Restore it from the wheel, or remove it and re-sign:\n"
            "      rm <package-dir>/_integrity_signature.py && "
            "AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity "
            "--update --sign"
        ) from exc
    if _sig is None:
        # No artefact (editable install, source checkout before the first
        # sign): nothing is signed, so nothing here is tampering. POST
        # reports the missing artefact.
        return

    signed = getattr(_sig, "INTEGRITY_BINDING_DIGESTS_HEX", None)
    if not isinstance(signed, dict) or not signed:
        return

    pkg_dir = _Path(__file__).resolve().parent
    tampered = []
    for name, digest_hex in sorted(signed.items()):
        path = pkg_dir / name
        if not path.is_file():
            # Listed-but-missing is inventory drift, not tampering. POST.
            continue
        try:
            actual = _hashlib.sha3_256(path.read_bytes()).hexdigest()
        except OSError as exc:
            # Bytes that cannot be read cannot be verified.  The artefact
            # signs this file, so refusing is the same fail-closed rule the
            # native-library read-error path applies.
            tampered.append(f"{name}: unreadable ({exc})")
            continue
        if not isinstance(digest_hex, str) or actual != digest_hex.lower():
            tampered.append(f"{name}: digest MISMATCH — bytes differ from the signed build")

    if tampered:
        # The remediation below must be executable AS WRITTEN from the state
        # the reader is in.  An earlier revision recommended running the
        # signer directly — but `python -m ama_cryptography.integrity`
        # imports this package, which lands right back in this gate against
        # the same stale digests, so the advertised way out provably could
        # not run (and AMA_POST_DIAGNOSTIC_IMPORT deliberately does not
        # demote this gate: importing a tampered binding for "diagnosis"
        # executes it).  Removing the stale artefact first is the working
        # recipe: with no artefact nothing is signed, nothing reads as
        # tampering, the unsigned digest file still pins the .py sources,
        # and the signer can then import and re-sign — the same
        # delete-then-sign order tools/resign_wheel.py uses.
        raise ImportError(
            "ama_cryptography refused to initialise: a signed binding "
            "extension does not match the artefact, and a binding extension "
            "executes its module-init function the moment it is imported.\n\n"
            "  " + "\n  ".join(tampered) + "\n\n"
            "  Refused BEFORE any binding was imported.\n"
            "  If you rebuilt the extensions from source, remove the stale "
            "artefact and re-sign:\n"
            "      rm <package-dir>/_integrity_signature.py && "
            "AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity "
            "--update --sign\n"
            "  For an installed wheel, reinstall it (pip install "
            "--force-reinstall) — a wheel's bindings never legitimately "
            "change beneath its signature."
        )


_refuse_tampered_bindings_before_import()

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
    # Still named here because the remediation string below quotes it: the
    # signer's own entry points require it alongside their launch identity.
    # It is no longer read as a condition of this gate.
    _build_env = "AMA_BUILD_PIPELINE"
    _TRUE = {"1", "true", "yes", "on"}

    def _process_is_the_signer() -> bool:
        """True when this process IS the signing tool, running to write.

        This gate used to read ``AMA_BUILD_PIPELINE`` directly, and that was
        the last place in the import path where a bare environment variable
        still bought execution.  With the variable present — a Dockerfile
        ``ENV``, a CI environment, a systemd unit; SECURITY.md itself tells
        release deployments to set ``AMA_FIPS_STRICT``, and build images
        routinely carry the pipeline flag beside it — an attacker with write
        access to the installed tree could edit any module imported after
        POST, have ``_verify_signed_integrity`` classify the resulting .py
        digest mismatch as a repairable stale binding
        (``_self_test._parse_signature_fields``), and get the import to
        complete with exit 0 in every process in that environment.  Nothing
        the attacker had to run; the variable was already there.

        Rounds 1 and 2 of this branch moved the native-load and signature
        paths off the variable and onto launch identity
        (``pqc_backends._process_is_the_integrity_signer``).  This site was
        left on the variable, which made the surrounding comment — that no
        environment variable may buy execution — stale prose rather than a
        description of the code.  It is the same test now.

        Secure-execution mode revokes it, at the call site, exactly as it
        does for the native-load escape: a set-uid/set-gid or file-capability
        process runs on behalf of a less-privileged caller, and that caller
        must not be able to steer this decision at all.

        Failing closed on any error is deliberate: an escape hatch that
        cannot prove it is entitled to open is closed.
        """
        try:
            from ama_cryptography.pqc_backends import (
                _in_secure_execution_mode as _secure_mode,
            )
            from ama_cryptography.pqc_backends import (
                _process_is_the_integrity_signer as _is_signer,
            )

            return bool(_is_signer()) and not _secure_mode()
        except Exception:  # pragma: no cover - fail closed on any lookup fault
            return False

    # The tools that REPAIR a failed integrity check — ``_build_sign`` and
    # ``integrity --update`` — live inside this package, so a hard raise here
    # would wall them off behind the very fault they exist to clear: edit a
    # .py file, the digest goes stale, and the command that refreshes it can
    # no longer import the package that contains it.  Both are already gated
    # on AMA_BUILD_PIPELINE=1, and that flag already confers the power to
    # rewrite the integrity artefacts outright, so honouring it here grants no
    # capability an attacker did not already have.
    #
    # It is honoured ONLY for the POST outcomes a signing run legitimately
    # expects to see in a tree it is about to re-sign.  A failed KAT, a timing
    # leak or an RNG fault has nothing to do with a stale artefact and still
    # hard-fails, so a release container — which has AMA_BUILD_PIPELINE=1 set
    # for its whole lifetime — cannot smoke-test a genuinely broken wheel and
    # call it built.
    #
    # There are two such outcomes, not one:
    #
    #   integrity      — a local build output the artefact binds changed: a .py
    #                    file or POST KAT vector, the native library, or a
    #                    binding extension.  The signed artefact itself is
    #                    intact; it simply describes the previous build.
    #   native-backend — the native library changed, so its signed digest is
    #                    stale and the PRE-LOAD check refuses to map it.
    #
    # The integrity side is narrowed by integrity_failure_was_stale_binding(),
    # the counterpart of native_backend_refused_on_digest(), and for the same
    # reason: the test used to be `any(integrity row failed)`, which the failing
    # row itself witnesses, so the conjunct was a tautology that excluded
    # nothing.  Under it, a wheel whose Ed25519 signature did not verify — or
    # whose trust anchor did not match, or whose artefact was malformed —
    # imported with exit code 0 inside a release container, which is the
    # "failure in the log, success in the exit code" fail-open this whole block
    # exists to close.  Those verdicts are tampering, re-signing would launder
    # them, and they now hard-fail on every path.
    #
    # The second used to be absent from this list because it could not happen:
    # AMA_BUILD_PIPELINE=1 mapped the mismatching library anyway, which kept
    # POST green at the cost of executing unverified code — the fail-open that
    # check exists to prevent.  With the refusal now unconditional, a rebuilt
    # library legitimately leaves the backend absent, and the repair flow (which
    # only READS the library) must still be able to import the package that
    # contains it.
    #
    # native_backend_refused_on_digest() is deliberately narrow: it is true only
    # when every candidate failure was a digest refusal.  A missing library, a
    # wrong architecture, an ABI rejection or a loader error is a broken build
    # and keeps hard-failing.
    try:
        from ama_cryptography._self_test import (
            integrity_failure_was_stale_binding as _integrity_was_stale_binding,
        )

        _integrity_stage_is_stale_binding = (
            any(_name == "integrity" and _ok is False for _name, _ok, _ in _results)
            and _integrity_was_stale_binding()
        )
    except Exception:  # pragma: no cover - _self_test is imported above
        _integrity_stage_is_stale_binding = False
    try:
        from ama_cryptography.pqc_backends import (
            native_backend_refused_on_digest as _refused_on_digest,
        )

        _native_stage_is_stale_digest = (
            any(_name == "native-backend" and _ok is False for _name, _ok, _ in _results)
            and _refused_on_digest()
        )
    except Exception:  # pragma: no cover - the import cannot fail in a built tree
        _native_stage_is_stale_digest = False

    # Every FAILED stage must be one of the two repairable ones. A run that
    # also broke a KAT is a broken build, and the presence of a stale digest
    # alongside it must not buy it an import.
    _repairable = {
        _name
        for _name, _ok, _ in _results
        if _ok is False
        and (
            (_name == "integrity" and _integrity_stage_is_stale_binding)
            or (_name == "native-backend" and _native_stage_is_stale_digest)
        )
    }
    _all_failures_repairable = bool(_repairable) and all(
        _name in _repairable for _name, _ok, _ in _results if _ok is False
    )

    if _os.environ.get(_diag_env, "").strip().lower() in _TRUE:
        _logging.getLogger(__name__).critical(
            "FIPS 140-3 POST FAILED and %s is set: completing the import for "
            "diagnosis only. The module is in the ERROR state and every "
            "cryptographic operation will be refused. Root cause: %s",
            _diag_env,
            _reason,
        )
    elif _all_failures_repairable and _process_is_the_signer():
        _logging.getLogger(__name__).critical(
            "FIPS 140-3 POST FAILED only in stage(s) a re-signing run repairs "
            "(%s) and this process IS the integrity signer running its "
            "writing subcommand: completing the import so the signing tooling "
            "can run. The module is in the ERROR state and "
            "every cryptographic operation through the public surface will be "
            "refused. Any native object mapped in this process was mapped "
            "under the signer's own load override and is digest-bound into "
            "the artefact this signing run produces; outside the signer "
            "identity, nothing unverified has been mapped. Root cause: %s",
            ", ".join(sorted(_repairable)),
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
