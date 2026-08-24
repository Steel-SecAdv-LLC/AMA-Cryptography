#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pytest Configuration and Shared Fixtures
=========================================

Centralized test fixtures for the AMA Cryptography test suite.
Provides reusable components for cryptographic testing.

This file consolidates fixtures from across the test suite to:
- Reduce code duplication
- Ensure consistent test setup
- Improve test maintainability
"""

from __future__ import annotations

import os
import platform
import secrets
import tempfile
from collections.abc import Callable, Generator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

# =============================================================================
# CI ENFORCEMENT: Crypto backend skip → failure in CI
# =============================================================================
# When AMA_CI_REQUIRE_BACKENDS=1 is set (by our ci.yml after building the
# C library), all cryptographic backends MUST be available. Tests that skip
# due to missing backends become hard failures. This env var is NOT set by
# other CI workflows that may not build the native library, so their
# legitimate skips are preserved.

_CI = os.environ.get("AMA_CI_REQUIRE_BACKENDS", "").lower() in ("true", "1", "yes")
_BACKEND_SKIP_REASONS = (
    "dilithium",
    "kyber",
    "sphincs",
    "backend",
    "native",
    "aes",
    "ed25519",
    "x25519",
    "argon2",
)


def _host_machine() -> str:
    return platform.machine().lower()


def _host_is_x86_64() -> bool:
    return _host_machine() in {"x86_64", "amd64"}


def _host_is_x86() -> bool:
    return _host_machine() in {"x86_64", "amd64", "i386", "i686", "x86"}


def _host_is_aarch64() -> bool:
    return _host_machine() in {"aarch64", "arm64"}


#: Instruction-set capabilities a test may declare with
#: ``@pytest.mark.requires_host_isa("<token>")``, each mapped to a predicate
#: that answers whether THIS host can provide it.
#:
#: The CI escalation below turns a backend-shaped skip into a hard failure
#: because a backend missing after a build is a defect.  A test whose subject
#: is an instruction-set extension is a different case: on an aarch64 runner
#: there is no x86 AES-NI to be missing, and "build the C library" — what the
#: escalation tells the operator to do — is not a remedy.  Three x86-only
#: parametrisations of
#: ``tests/test_aesni_is_not_gated_on_avx2.py::TestTheBackendAcrossBuildConfigurations``
#: failed every ubuntu-24.04-arm, windows-latest and macos-latest job that way:
#: the skip reason has to name AES-NI to be informative, and naming it is what
#: tripped ``_mentions_backend``.
#:
#: The exemption is deliberately NOT text-matched — "mentions x86" would let
#: any backend skip through by rewording.  A test must NAME a capability from
#: this table, and the hook then re-asks the host: on a host that HAS the
#: capability the skip is escalated exactly as before, so the marker cannot
#: hide a backend a build should have produced.  A token that is not in the
#: table is not an exemption either, so a typo fails closed.
HOST_ISA_PREDICATES: dict[str, Callable[[], bool]] = {
    "x86": _host_is_x86,
    "x86-64": _host_is_x86_64,
    "aarch64": _host_is_aarch64,
}


def host_isa_exempts(item: Any) -> bool:
    """Whether a capability this host does not have explains ``item``'s skip.

    Non-vacuous by construction: the predicate is evaluated against the real
    host every time, so this returns ``False`` — and the skip is escalated —
    on precisely the hosts where the capability exists and the skip would
    therefore be reporting a missing build artefact.
    """
    for marker in item.iter_markers("requires_host_isa"):
        for token in marker.args:
            predicate = HOST_ISA_PREDICATES.get(str(token))
            if predicate is not None and not predicate():
                return True
    return False


#: Every name ``pqc_backends._get_lib_names()`` can return, in the order that
#: function tries them — Windows first, because there CMake produces the
#: UNPREFIXED ``ama_cryptography.dll`` and ``_get_lib_names`` puts it ahead of
#: the ``lib``-prefixed spelling.
#:
#: Order is the whole point.  A caller that only asks "is a library here?" can
#: use any of these; a caller that MODIFIES the library — every
#: tamper-detection test in the suite — has to land on the file the loader will
#: actually open, or it tampers with a copy nothing reads and the gate it is
#: testing passes for the wrong reason.
#:
#: Two measured failures sit behind this list.  Three fixtures used to test for
#: the library with ``glob("libama_cryptography*")`` alone; on Windows that
#: matched nothing even when the DLL was present and loaded, so
#: `tests/test_native_integrity.py`, `tests/test_execution_integrity.py` and
#: the POST fixtures in `tests/test_post_failclosed.py` skipped their whole
#: integrity surface — 15 tests — on every Windows job, silently, while the
#: platform's own `import ama_cryptography` worked fine.  And
#: `tests/test_artefact_cache_poisoning.py` took ``sorted(glob(...))[0]``,
#: which on macOS is ``libama_cryptography.5.0.0.dylib`` (``.5`` sorts before
#: ``.d``) rather than the ``libama_cryptography.dylib`` the loader opens.
_NATIVE_LIB_NAMES = (
    "ama_cryptography.dll",
    "libama_cryptography.dll",
    "libama_cryptography.dylib",
    "libama_cryptography.so",
)

#: Versioned sonames — ``libama_cryptography.so.5.0.0``,
#: ``libama_cryptography.5.0.0.dylib``.  Consulted only after every name above
#: has missed, so a tree that holds both resolves to the loaded one.
_NATIVE_LIB_GLOB = "libama_cryptography*"


def native_library_path(directory: Path) -> Path | None:
    """The resolved native library in ``directory``, or ``None`` if absent.

    An unversioned name wins over a versioned soname: the versioned file is
    normally the real object and the bare name a symlink to it, and
    ``Path.resolve()`` collapses that anyway — but the bare name is what the
    loader opens, so it is what a modifying caller must be handed.
    """
    for name in _NATIVE_LIB_NAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate.resolve()
    matches = sorted(p for p in directory.glob(_NATIVE_LIB_GLOB) if p.is_file())
    return matches[-1].resolve() if matches else None


def native_library_present(directory: Path) -> bool:
    """Whether ``directory`` holds a built native library for this platform."""
    return native_library_path(directory) is not None


def _mentions_backend(reason: str) -> bool:
    """Whether a skip reason names a cryptographic backend."""
    return any(kw in reason.lower() for kw in _BACKEND_SKIP_REASONS)


def _is_backend_skip(marker: Any) -> bool:
    """Check if a skipif marker is about a missing crypto backend."""
    reason = ""
    if hasattr(marker, "kwargs"):
        reason = marker.kwargs.get("reason", "")
    if hasattr(marker, "args") and len(marker.args) > 1 and not reason:
        reason = str(marker.args[1])
    return _mentions_backend(reason)


def _reported_skip_reason(rep: Any) -> str:
    """The reason text pytest recorded for a skip, however it was raised.

    For a skip, ``rep.longrepr`` is the ``(path, lineno, message)`` triple, and
    the message is ``"Skipped: <reason>"``.  Reading it is the only way to see
    an *imperative* ``pytest.skip("...")`` — those raise at call time and leave
    no marker on the item, so marker inspection alone cannot find them.
    """
    longrepr = getattr(rep, "longrepr", None)
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        message = str(longrepr[2])
        _, _, tail = message.partition("Skipped: ")
        return tail or message
    return ""


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any) -> Any:
    """In CI, convert any backend-related skip into a hard failure.

    A test may carry several ``@pytest.mark.skipif`` decorators (for example
    ``TestAESGCMInterop`` has both ``@skip_no_native`` and ``@skip_no_pyca``).
    The skip we receive came from whichever marker's condition evaluated
    truthy at collection time; iterating ``item.iter_markers('skipif')``
    yields *all* of them regardless of which actually triggered, so we
    must re-check each marker's condition before treating it as the cause
    of the skip.  Without this scoping a test skipped for an unrelated
    reason (e.g. a broken PyCA install) would be incorrectly reported as
    a backend-missing failure because a sibling backend-related skipif
    happens to be attached to the same item.

    Marker inspection is not sufficient on its own.  An imperative
    ``pytest.skip("Kyber backend unavailable")`` — raised from a fixture or a
    test body, which is how several of the PQC KAT suites report a missing
    backend — attaches no marker to the item, so it passed straight through
    this hook and CI reported it as a skip.  That is the same
    escalation-shaped hole the ``skipif`` path exists to close, so the
    reason pytest actually recorded is checked too.

    One class of skip is exempt, and only one: a test that declares an
    instruction set the host does not have (``@pytest.mark.requires_host_isa``).
    "All cryptographic backends must be available in CI" is a claim about what
    a build should have produced; an x86 AES-NI kernel on an aarch64 runner is
    not one of those, and telling the operator to build the C library is not a
    remedy for it.  See :data:`HOST_ISA_PREDICATES` for why that exemption
    cannot be used to hide a real missing backend.
    """
    outcome = yield
    if not _CI:
        return
    rep = outcome.get_result()
    if not rep.skipped:
        return
    if host_isa_exempts(item):
        # The test declares an instruction set this host does not have, so no
        # build of this library could have produced the backend it names.  See
        # HOST_ISA_PREDICATES: on a host that DOES have it, this is False and
        # the escalation below runs unchanged.
        return

    def _fail(reason: str) -> None:
        rep.outcome = "failed"
        rep.longrepr = (
            f"CI FAILURE: {reason} — "
            "all cryptographic backends must be available in CI. "
            "The C library must be built before running tests."
        )

    # Interop oracle: a test marked requires_interop_oracle cross-checks an AMA
    # primitive against an external reference (PyCA cryptography / PyNaCl /
    # pycryptodome).  The require-backends lane installs all three, so a skip
    # here means that install broke and the ONLY independent-implementation
    # check of these primitives went silent — exactly the "a skip must not stand
    # in for coverage" hole this hook exists to close, and the one the nine
    # backend keywords never matched because these skips name the reference
    # library, not an AMA backend (audit M18).  Marker-based, not text-matched,
    # so it cannot be evaded by rewording the skip reason.
    if any(True for _ in item.iter_markers("requires_interop_oracle")):
        reported = _reported_skip_reason(rep)
        rep.outcome = "failed"
        rep.longrepr = (
            f"CI FAILURE: {reported or 'interop reference implementation unavailable'} — "
            "the cross-implementation validation oracle (PyCA cryptography / PyNaCl / "
            "pycryptodome) must be installed in the require-backends lane so this check "
            "runs. Install .[dev,legacy,benchmark] plus pycryptodome (audit M18)."
        )
        return

    for marker in item.iter_markers("skipif"):
        if not _is_backend_skip(marker):
            continue
        condition = marker.args[0] if marker.args else marker.kwargs.get("condition")
        if not condition:
            # The backend-related condition was false at evaluation time —
            # the backend is present, so this marker did not cause the skip.
            continue
        _fail(marker.kwargs.get("reason", "backend unavailable"))
        return

    reported = _reported_skip_reason(rep)
    if reported and _mentions_backend(reported):
        _fail(reported)


# =============================================================================
# TEMPORARY DIRECTORY FIXTURES
# =============================================================================


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_storage_path(temp_dir: Path) -> Path:
    """Provide a temporary path for key storage tests."""
    storage_path = temp_dir / "key_storage"
    storage_path.mkdir(parents=True, exist_ok=True)
    return storage_path


# =============================================================================
# KEY MANAGEMENT FIXTURES
# =============================================================================


@pytest.fixture
def master_seed() -> bytes:
    """Provide a deterministic master seed for reproducible HD key tests."""
    # Fixed seed for reproducible tests
    return bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
    )


@pytest.fixture
def random_seed() -> bytes:
    """Provide a random 64-byte seed for tests requiring entropy."""
    return secrets.token_bytes(64)


@pytest.fixture
def test_key_material() -> bytes:
    """Provide standard 32-byte key material for storage tests."""
    return b"test-key-material-32-bytes-long!"


@pytest.fixture
def test_password() -> str:
    """Provide a standard test password."""
    return "test-password-secure-123"  # nosec B105 -- test fixture password, not a production secret (CONF-001)


# =============================================================================
# HD KEY DERIVATION FIXTURES
# =============================================================================


@pytest.fixture
def hd_derivation(master_seed: bytes) -> Any:
    """Provide an HDKeyDerivation instance with deterministic seed."""
    from ama_cryptography.key_management import HDKeyDerivation

    return HDKeyDerivation(seed=master_seed)


# =============================================================================
# KEY ROTATION FIXTURES
# =============================================================================


@pytest.fixture
def rotation_manager() -> Any:
    """Provide a KeyRotationManager with default settings."""
    from ama_cryptography.key_management import KeyRotationManager

    return KeyRotationManager()


@pytest.fixture
def rotation_manager_short_period() -> Any:
    """Provide a KeyRotationManager with very short rotation period."""
    from ama_cryptography.key_management import KeyRotationManager

    return KeyRotationManager(rotation_period=timedelta(seconds=0))


@pytest.fixture
def rotation_manager_long_period() -> Any:
    """Provide a KeyRotationManager with long rotation period."""
    from ama_cryptography.key_management import KeyRotationManager

    return KeyRotationManager(rotation_period=timedelta(days=365))


# =============================================================================
# SECURE STORAGE FIXTURES
# =============================================================================


@pytest.fixture
def secure_storage(temp_storage_path: Path, test_password: str) -> Any:
    """Provide a SecureKeyStorage instance with password-derived key."""
    from ama_cryptography.key_management import SecureKeyStorage

    return SecureKeyStorage(temp_storage_path, master_password=test_password)


# =============================================================================
# CRYPTOGRAPHIC API FIXTURES
# =============================================================================


# =============================================================================
# PQC BACKEND FIXTURES
# =============================================================================


@pytest.fixture
def pqc_backend_info() -> Any:
    """Provide current PQC backend availability info."""
    from ama_cryptography.pqc_backends import get_pqc_backend_info

    return get_pqc_backend_info()


@pytest.fixture
def dilithium_available() -> Any:
    """Check if Dilithium is available."""
    from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE

    return DILITHIUM_AVAILABLE


@pytest.fixture
def kyber_available() -> Any:
    """Check if Kyber is available."""
    from ama_cryptography.pqc_backends import KYBER_AVAILABLE

    return KYBER_AVAILABLE


@pytest.fixture
def sphincs_available() -> Any:
    """Check if SPHINCS+ is available."""
    from ama_cryptography.pqc_backends import SPHINCS_AVAILABLE

    return SPHINCS_AVAILABLE


# =============================================================================
# EQUATION ENGINE FIXTURES
# =============================================================================


@pytest.fixture
def equation_engine() -> Any:
    """Provide an AmaEquationEngine instance."""
    from ama_cryptography.double_helix_engine import AmaEquationEngine

    return AmaEquationEngine()


@pytest.fixture
def initial_state() -> Any:
    """Provide an initial state vector for equation tests."""
    from ama_cryptography._numeric import array

    return array([1.0, 0.5, 0.25, 0.125, 0.0625])


# =============================================================================
# MONITOR FIXTURES
# =============================================================================


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================


def pytest_configure(config: Any) -> None:
    """Configure custom pytest markers and deferred warning filters."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "quantum: marks tests that require quantum-resistant libraries"
    )
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "security: marks security-related tests")
    config.addinivalue_line("markers", "performance: marks performance-related tests")

    # Register the SecurityWarning filter via the ini mechanism rather than
    # a direct ``warnings.filterwarnings()`` call.  Pytest wraps every test
    # in ``warnings.catch_warnings()`` and re-applies the configured ini
    # ``filterwarnings`` entries at the start of each test — a direct
    # ``warnings.filterwarnings()`` call here would be discarded on entry
    # to that context. Appending the filter here adds it to pytest's
    # ini-managed warning filters so it participates in that normal
    # per-test filter processing, without relying on a module-level
    # filter. (Pytest iterates the ini entries in order and prepends each
    # to the runtime filter stack via ``warnings.filterwarnings``; the
    # last ini entry therefore ends up at stack position 0, i.e. matched
    # before ``error`` — which is what we want for ``SecurityWarning``.)
    #
    # The filter is registered here (rather than in pyproject.toml) so that
    # pytest-cov has already enabled coverage instrumentation by the time
    # ``ama_cryptography.exceptions`` is imported below, which avoids the
    # 0 %-coverage measurement artefact caused by pytest importing the
    # module during initial filter-string parsing.
    from ama_cryptography.exceptions import SecurityWarning as _SecurityWarning

    config.addinivalue_line(
        "filterwarnings",
        f"default::{_SecurityWarning.__module__}.{_SecurityWarning.__qualname__}",
    )
