#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Regression coverage for ``tests/conftest.py::pytest_runtest_makereport``.

The CI-mode hook ``pytest_runtest_makereport`` converts any backend-related
``@pytest.mark.skipif`` skip into a hard failure when
``AMA_CI_REQUIRE_BACKENDS=1`` is set (so a CI job whose C library failed to
build is loudly broken rather than silently green via skipped tests).

A test may carry multiple ``@pytest.mark.skipif`` decorators; pytest iterates
all of them whether or not each one's condition triggered the skip.  Before
the fix that this module pins, the hook iterated every ``skipif`` marker
and triggered on the first whose **reason text** matched a backend keyword
("native", "aes", ...) without checking whether that specific marker's
**condition** was the cause of the skip.  Consequence:
``tests/test_aes_gcm_native.py::TestAESGCMInterop`` (which has both
``@skip_no_native`` and ``@skip_no_pyca``) was incorrectly reported as a
missing-backend failure in CI when PyCA was missing but the native backend
was present — failing every Python lane on PR #326 across Linux, macOS, and
Windows even though the native build itself was healthy.

The fix re-evaluates each backend-related marker's condition and only
escalates the skip to a failure when that condition was truthy.  These
tests pin that behavior so the regression cannot silently come back.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

import pytest

# Import the production helper rather than re-defining the keyword list — if
# the production list shrinks (e.g., a backend is removed from coverage) the
# tests below stay in lockstep automatically.
from tests.conftest import _is_backend_skip

# pytester is built into pytest but is opt-in; declare the plugin so the
# ``pytester`` fixture is resolvable.  Scoped to this module so the rest of
# the test suite is unaffected.
pytest_plugins = ["pytester"]


def _inner_pytest_args() -> tuple[str, ...]:
    """Arguments for the ``pytester`` subprocess runs below.

    ``--no-cov`` is a ``pytest-cov`` option, so passing it unconditionally made
    every subprocess run die with ``error: unrecognized arguments: --no-cov``
    and exit code 4 wherever ``pytest-cov`` is absent — which pytester then
    reports as ``ValueError: Pytest terminal summary report not found``, an
    error that says nothing about what these tests actually pin. ``pytest-cov``
    is in ``requirements-dev.txt`` but not in ``requirements.txt``, so a
    contributor running the suite against a plain install saw three failures
    unrelated to their change.

    It is still passed when the plugin *is* installed: a caller who exports
    coverage options in ``PYTEST_ADDOPTS`` would otherwise have the inner run
    inherit them and write a second, partial coverage file over the outer run's.
    """
    if importlib.util.find_spec("pytest_cov") is None:
        return ("-v", "-p", "no:cacheprovider")
    return ("-v", "--no-cov", "-p", "no:cacheprovider")


class _FakeMarker:
    """Minimal stand-in for ``pytest.Mark`` exposing the two attributes the
    hook reads (``args`` for positional condition, ``kwargs`` for ``reason``).
    """

    def __init__(self, condition: Any, reason: str) -> None:
        self.args: tuple[Any, ...] = (condition,)
        self.kwargs: dict[str, Any] = {"reason": reason}


def test_is_backend_skip_matches_native_reason() -> None:
    """A skipif with a backend keyword in the reason is recognised."""
    marker = _FakeMarker(True, "Native AES-256-GCM library not available")
    assert _is_backend_skip(marker) is True


def test_is_backend_skip_rejects_pyca_reason() -> None:
    """The PyCA reason text contains no backend keyword and must be ignored.

    This is the load-bearing assertion for the marker-scoping fix: if the
    classifier ever started matching "PyCA" the multi-skipif scoping logic
    would lose its discriminator and the original regression would resurface.
    """
    marker = _FakeMarker(True, "PyCA cryptography not available")
    assert _is_backend_skip(marker) is False
    marker2 = _FakeMarker(True, "PyCA cryptography not installed")
    assert _is_backend_skip(marker2) is False


def test_is_backend_skip_rejects_unrelated_reasons() -> None:
    """Reasons unrelated to backends (network gate, slow opt-in, etc.) are
    not classified as backend skips."""
    for reason in (
        "Requires network",
        "Live TSA integration test",
        "SoftHSM2 is not installed",
        "slow",
    ):
        marker = _FakeMarker(True, reason)
        assert _is_backend_skip(marker) is False, reason


@pytest.fixture
def isolated_conftest(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> pytest.Pytester:
    """Drop the real ``tests/conftest.py`` into a pytester sandbox so the
    test runs the exact production hook implementation.

    Using a real conftest copy (rather than re-implementing the hook
    inline) means any future drift in the production hook is caught by
    the assertion outcomes below — there's no shadow copy to forget to
    update.
    """
    # The copied conftest imports ``ama_cryptography`` at ``pytest_configure``
    # time.  In CI the package is pip-installed, so the pytester *subprocess*
    # can import it; run from a bare source checkout it cannot, and these tests
    # would fail with ModuleNotFoundError unrelated to what they pin.  Put the
    # repo root on PYTHONPATH so the subprocess resolves the in-tree package
    # either way.
    repo_root = Path(__file__).resolve().parent.parent
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv(
        "PYTHONPATH",
        str(repo_root) + (os.pathsep + existing if existing else ""),
    )
    conftest_src = (Path(__file__).parent / "conftest.py").read_text()
    pytester.makepyfile(conftest=conftest_src)
    return pytester


def test_dual_skipif_pyca_trigger_stays_a_skip_not_a_failure(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A test decorated with BOTH a backend ``skipif`` (condition False) AND
    a PyCA ``skipif`` (condition True) must remain a SKIP, never become a
    failure, even with ``AMA_CI_REQUIRE_BACKENDS=1`` set.  This is the exact
    shape of ``TestAESGCMInterop`` on which the original bug fired."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        # condition=False: the native backend IS present in this scenario,
        # so this marker would NOT have triggered the skip on its own.
        skip_native = pytest.mark.skipif(
            False,
            reason="Native AES-256-GCM library not available",
        )
        # condition=True: PyCA is missing, so THIS marker is what triggers
        # the actual skip.  Its reason text contains no backend keyword,
        # so the CI hook must not convert it to a failure.
        skip_pyca = pytest.mark.skipif(
            True,
            reason="PyCA cryptography not available",
        )

        @skip_native
        @skip_pyca
        class TestInterop:
            def test_pyca_only_skip_does_not_become_backend_failure(self):
                raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)


def test_backend_skipif_with_truthy_condition_does_become_failure(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hook's load-bearing purpose: when the backend really is missing
    (condition True) and ``AMA_CI_REQUIRE_BACKENDS=1``, the skip MUST be
    converted to a hard failure.  Pins the original intent so the scoping
    fix can't be over-corrected into silencing legitimate backend gaps."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        # condition=True: the native backend IS missing — exactly the
        # situation the CI hook exists to flag loudly.
        @pytest.mark.skipif(
            True,
            reason="Native AES-256-GCM library not available",
        )
        class TestBackendMissing:
            def test_should_have_been_a_loud_failure(self):
                raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    # A skipif-skip happens in the setup phase; when the hook flips
    # ``rep.outcome = "failed"`` that setup-phase outcome is reported by
    # pytest as an "error" (rather than a "failed") in the summary line —
    # the symptom we actually saw on PR #326 CI was "ERROR at setup of ...".
    # That distinction is what tells the operator the failure happened
    # before the test body ran, which is precisely what we want for a
    # missing-backend gate.
    result.assert_outcomes(errors=1, failed=0, skipped=0, passed=0)
    result.stdout.fnmatch_lines(["*CI FAILURE: Native AES-256-GCM library not available*"])


def test_backend_skipif_without_ci_env_stays_a_skip(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``AMA_CI_REQUIRE_BACKENDS=1``, a backend skip stays a skip
    — the hook only escalates in CI."""
    monkeypatch.delenv("AMA_CI_REQUIRE_BACKENDS", raising=False)
    isolated_conftest.makepyfile("""
        import pytest

        @pytest.mark.skipif(
            True,
            reason="Native AES-256-GCM library not available",
        )
        class TestBackendMissing:
            def test_should_skip_outside_ci(self):
                raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)


# ---------------------------------------------------------------------------
# Imperative skips
# ---------------------------------------------------------------------------
# The hook above reads ``item.iter_markers("skipif")``, which sees only
# *declarative* skips. An imperative ``pytest.skip("...")`` raised from a test
# body or a fixture attaches no marker, so it went straight through the hook
# and CI reported it as an ordinary skip — the same silently-green outcome the
# ``skipif`` path exists to prevent. Several PQC KAT suites report a missing
# backend exactly that way (``tests/test_pqc_kat.py`` lines 164, 177, 555), so
# the gap covered the backends most likely to be absent from a broken build.
#
# The hook now also reads the reason pytest recorded on the report itself,
# which is the only place an imperative skip's reason appears.


def test_imperative_backend_skip_in_a_test_body_becomes_a_failure(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``pytest.skip("Kyber backend unavailable")`` must not survive CI."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        def test_kyber_kat():
            pytest.skip("Kyber backend unavailable (build with -DAMA_USE_NATIVE_PQC=ON)")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    # Raised in the call phase, so it is reported as a failure rather than
    # the setup-phase "error" a skipif produces.
    result.assert_outcomes(failed=1, errors=0, skipped=0, passed=0)
    result.stdout.fnmatch_lines(["*CI FAILURE: Kyber backend unavailable*"])


def test_imperative_backend_skip_in_a_fixture_becomes_a_failure(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shape the SLH-DSA suites actually use: skip raised from a fixture."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        @pytest.fixture
        def sphincs_provider():
            pytest.skip("SPHINCS+ backend not available")

        def test_slhdsa_kat(sphincs_provider):
            raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(errors=1, failed=0, skipped=0, passed=0)
    result.stdout.fnmatch_lines(["*CI FAILURE: SPHINCS+ backend not available*"])


def test_imperative_non_backend_skip_stays_a_skip(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The five legitimate skips this suite still reports must be unaffected.

    Escalating on any imperative skip would turn every optional-dependency and
    network-gated test into a CI failure. These are the exact reason strings
    the suite emits today.
    """
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        def test_metadata():
            pytest.skip("package not pip-installed; metadata unavailable")

        def test_tsa():
            pytest.skip("Live TSA integration test — requires network and a TSA endpoint.")

        def test_hsm():
            pytest.skip("SoftHSM2 is not installed")

        def test_semgrep():
            pytest.skip("semgrep is not installed")

        def test_wycheproof():
            pytest.skip("network-dependent; set AMA_WYCHEPROOF_ONLINE=1 to check upstream bytes")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=5, failed=0, errors=0, passed=0)


def test_imperative_backend_skip_without_ci_env_stays_a_skip(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside CI an imperative backend skip is still just a skip."""
    monkeypatch.delenv("AMA_CI_REQUIRE_BACKENDS", raising=False)
    isolated_conftest.makepyfile("""
        import pytest

        def test_kyber_kat():
            pytest.skip("Kyber backend unavailable")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)


class TestNativeLibraryDetection:
    """The native-library probe must recognise the artefact on every platform.

    Three fixtures tested for a built library with
    ``glob("libama_cryptography*")``. On Windows CMake produces
    ``ama_cryptography.dll`` — ``pqc_backends._get_lib_names()`` lists it first
    for that platform — which the pattern never matches. So on every Windows
    job those fixtures reported "native library not built in this tree" and
    skipped the entire integrity surface (15 tests across
    ``test_native_integrity.py``, ``test_execution_integrity.py`` and
    ``test_post_failclosed.py``), while the same job's ``import
    ama_cryptography`` loaded that very DLL successfully.

    The skip was invisible for the usual reason: it read as a statement about
    the build, and nobody checks a skip that sounds true.
    """

    @pytest.mark.parametrize(
        "filename",
        [
            "libama_cryptography.so",  # Linux
            "libama_cryptography.so.4",  # Linux, versioned soname
            "libama_cryptography.dylib",  # macOS
            "ama_cryptography.dll",  # Windows, as CMake names it
            "libama_cryptography.dll",  # Windows, MinGW-style prefix
        ],
    )
    def test_every_platform_spelling_is_recognised(self, tmp_path: Path, filename: str) -> None:
        from tests.conftest import native_library_present

        (tmp_path / filename).write_bytes(b"\x7fELF")
        assert native_library_present(tmp_path), f"{filename} not recognised"

    def test_every_name_pqc_backends_looks_for_is_covered(self, tmp_path: Path) -> None:
        """Derived from the production list, so a new platform cannot drift.

        ``_get_lib_names`` is platform-conditional, so the names for the other
        two platforms are read out of its source rather than by calling it.
        """
        import re

        from tests.conftest import native_library_present

        repo_root = Path(__file__).resolve().parent.parent
        source = (repo_root / "ama_cryptography" / "pqc_backends.py").read_text(encoding="utf-8")
        body = source[source.index("def _get_lib_names()") :]
        body = body[: body.index("\ndef ")]
        names = set(re.findall(r'"(\w*ama_cryptography[.\w]*)"', body))
        assert len(names) >= 4, f"only found {names} — the extractor missed the candidate list"

        for name in sorted(names):
            probe = tmp_path / name.replace(".", "_")
            probe.mkdir()
            (probe / name).write_bytes(b"\x7fELF")
            assert native_library_present(probe), f"{name} is a real candidate but not recognised"

    def test_an_empty_tree_is_still_reported_as_missing(self, tmp_path: Path) -> None:
        """The probe must not become a tautology."""
        from tests.conftest import native_library_present

        assert not native_library_present(tmp_path)
        (tmp_path / "sha3_binding.cp311-win_amd64.pyd").write_bytes(b"MZ")
        assert not native_library_present(tmp_path), (
            "a Cython binding is not the native library; matching it would make "
            "the integrity fixtures run against a tree with no C library"
        )
