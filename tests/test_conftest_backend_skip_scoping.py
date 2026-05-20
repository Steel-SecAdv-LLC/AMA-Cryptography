#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
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
def isolated_conftest(pytester: pytest.Pytester) -> pytest.Pytester:
    """Drop the real ``tests/conftest.py`` into a pytester sandbox so the
    test runs the exact production hook implementation.

    Using a real conftest copy (rather than re-implementing the hook
    inline) means any future drift in the production hook is caught by
    the assertion outcomes below — there's no shadow copy to forget to
    update.
    """
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
    result = isolated_conftest.runpytest_subprocess("-v", "--no-cov", "-p", "no:cacheprovider")
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
    result = isolated_conftest.runpytest_subprocess("-v", "--no-cov", "-p", "no:cacheprovider")
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
    result = isolated_conftest.runpytest_subprocess("-v", "--no-cov", "-p", "no:cacheprovider")
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)
