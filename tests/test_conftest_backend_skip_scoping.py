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

import ast
import importlib.util
import os
from pathlib import Path
from typing import Any

import pytest

# Import the production helper rather than re-defining the keyword list — if
# the production list shrinks (e.g., a backend is removed from coverage) the
# tests below stay in lockstep automatically.
from tests import conftest
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
    # Built up and returned once, rather than two literal tuples of different
    # lengths: CodeQL reads those as a function returning tuples of differing
    # shape (py/mixed-tuple-returns) even though the annotation is the
    # homogeneous ``tuple[str, ...]``.  One return also makes the conditional
    # part obvious.
    args = ["-v"]
    if importlib.util.find_spec("pytest_cov") is not None:
        args.append("--no-cov")
    args += ["-p", "no:cacheprovider"]
    return tuple(args)


class _FakeMarker:
    """Minimal stand-in for ``pytest.Mark`` exposing the two attributes the
    hook reads (``args`` for positional condition, ``kwargs`` for ``reason``).
    """

    def __init__(self, condition: Any, reason: str) -> None:
        self.args: tuple[Any, ...] = (condition,)
        self.kwargs: dict[str, Any] = {"reason": reason}


class _FakeIsaMarker:
    """Minimal stand-in for a ``requires_host_isa`` ``pytest.Mark``."""

    def __init__(self, *tokens: str) -> None:
        self.args: tuple[str, ...] = tokens
        self.kwargs: dict[str, Any] = {}


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
    # Force the INNER pytest subprocess to speak UTF-8.  runpytest_subprocess
    # spawns pytest, captures its stdout/stderr as bytes, and decodes them as
    # UTF-8.  That inner run imports ama_cryptography, whose POST prints
    # diagnostics containing em dashes (e.g. "binding extensions PARTIALLY
    # covered ...").  On a windows-latest runner without PYTHONUTF8 the
    # subprocess emits those on a cp1252 stream, so the em dash is byte 0x97,
    # and pytester's UTF-8 decode raises "'utf-8' codec can't decode byte 0x97"
    # — failing all seven tests in this module on every windows-latest job in
    # ci.yml.  ci-build-test.yml sets PYTHONUTF8=1 at the step and so never saw
    # it.  ci.yml deliberately does NOT (its Run-pytest step verifies real
    # cp1252 console behaviour for tests/test_python_examples.py, which strips
    # these vars from its own children), so the guarantee has to be made HERE,
    # scoped to this fixture's inner subprocess only.  An earlier fix read the
    # conftest source with encoding="utf-8" — correct, but the failing bytes
    # are in the subprocess's runtime OUTPUT, not the source file, so it did
    # not resolve the failure.
    monkeypatch.setenv("PYTHONUTF8", "1")
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    # encoding="utf-8" on the source read stays load-bearing on its own: without
    # it Path.read_text() would use the outer process's locale codepage.
    conftest_src = (Path(__file__).parent / "conftest.py").read_text(encoding="utf-8")
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
# The one exemption: an instruction set the host does not have
# ---------------------------------------------------------------------------
# "All cryptographic backends must be available in CI" is a claim about what a
# build should have produced.  An x86 AES-NI kernel on an aarch64 runner is not
# one of those, and the escalation's remedy ("build the C library") is not a
# remedy for it.  Three x86-only parametrisations of
# tests/test_aesni_is_not_gated_on_avx2.py failed every ubuntu-24.04-arm,
# windows-latest and macos-latest job that way: the skip reason has to name
# AES-NI to be informative, and naming it is what matched _mentions_backend.
#
# The exemption is a declared capability re-checked against the real host, not
# a reason-text pattern.  These tests pin both halves — that it exempts, and
# that it cannot be used to hide a backend a build should have produced.


def _unsatisfied_isa_token() -> str:
    """A token from the production table this host does NOT satisfy.

    Derived rather than hardcoded: no host is both x86 and aarch64, so one
    always exists, and the test stays honest on whichever runner it lands on.
    """
    from tests.conftest import HOST_ISA_PREDICATES

    for token, predicate in HOST_ISA_PREDICATES.items():
        if not predicate():
            return token
    raise AssertionError(
        f"this host claims every instruction set in {sorted(HOST_ISA_PREDICATES)}, "
        "which cannot be true — the table has lost its discriminating power"
    )


def test_host_isa_exempts_only_when_the_host_lacks_the_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The predicate is re-asked, so the marker is not a blanket opt-out."""
    from tests import conftest as production

    monkeypatch.setitem(production.HOST_ISA_PREDICATES, "present", lambda: True)
    monkeypatch.setitem(production.HOST_ISA_PREDICATES, "absent", lambda: False)

    class _Item:
        def __init__(self, *tokens: str) -> None:
            self._tokens = tokens

        def iter_markers(self, name: str) -> list[Any]:
            assert name == "requires_host_isa"
            return [_FakeIsaMarker(token) for token in self._tokens]

    assert production.host_isa_exempts(_Item("absent")) is True
    assert production.host_isa_exempts(_Item("present")) is False
    assert production.host_isa_exempts(_Item()) is False
    # Fail closed: a token nobody registered is not an exemption, so a typo
    # escalates rather than silencing.
    assert production.host_isa_exempts(_Item("x86_65")) is False
    # One satisfied token does not cancel an unsatisfied one; the test cannot
    # run on this host either way.
    assert production.host_isa_exempts(_Item("present", "absent")) is True


def test_a_backend_skip_on_a_host_without_the_isa_stays_a_skip(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shape that broke every ARM, Windows and macOS job.

    Built with whichever token THIS host lacks, so the mechanism is exercised
    on every runner rather than only on the one the defect was found on.
    """
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile(f"""
        import pytest

        @pytest.mark.requires_host_isa({_unsatisfied_isa_token()!r})
        def test_aes_ni_gating():
            pytest.skip("AES-NI gating is an x86 property")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)


def test_a_backend_skip_on_a_host_that_does_have_the_isa_still_fails(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The half that keeps the exemption honest.

    The predicate is registered as satisfied inside the sandbox, so this runs
    identically on every runner — the point is that a satisfied capability
    changes nothing: a missing backend on a host that can host it is still a
    hard CI failure.
    """
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest
        import conftest

        conftest.HOST_ISA_PREDICATES["probe-isa"] = lambda: True

        @pytest.mark.requires_host_isa("probe-isa")
        def test_kyber_kat():
            pytest.skip("Kyber backend unavailable")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(failed=1, errors=0, skipped=0, passed=0)
    result.stdout.fnmatch_lines(["*CI FAILURE: Kyber backend unavailable*"])


def test_the_real_aesni_class_carries_the_marker_the_exemption_needs() -> None:
    """The one link the sandbox tests above cannot cover.

    They prove the hook exempts a marked item; this proves the item that
    actually skips on an aarch64 runner is marked, and marked with a token the
    production table knows.  ``pytest.mark`` on a class lands in
    ``cls.pytestmark``, and ``item.iter_markers`` walks function -> class ->
    module, so a marker here is a marker on every parametrisation of the three
    tests that failed.
    """
    from tests import test_aesni_is_not_gated_on_avx2 as aesni
    from tests.conftest import HOST_ISA_PREDICATES

    marks = [
        mark
        for mark in getattr(aesni.TestTheBackendAcrossBuildConfigurations, "pytestmark", [])
        if mark.name == "requires_host_isa"
    ]
    assert marks, (
        "TestTheBackendAcrossBuildConfigurations no longer declares "
        "requires_host_isa, so its x86-only skip is a hard CI failure again on "
        "every aarch64 runner"
    )
    tokens = [token for mark in marks for token in mark.args]
    assert tokens, "requires_host_isa was applied with no token, which exempts nothing"
    unknown = [token for token in tokens if token not in HOST_ISA_PREDICATES]
    assert not unknown, f"unregistered token(s) {unknown}; the exemption fails closed on those"


def test_an_unregistered_isa_token_is_not_an_exemption(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo must not silence a backend gap."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        @pytest.mark.requires_host_isa("x86_65")
        def test_sphincs_kat():
            pytest.skip("SPHINCS+ backend not available")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(failed=1, errors=0, skipped=0, passed=0)
    result.stdout.fnmatch_lines(["*CI FAILURE: SPHINCS+ backend not available*"])


def test_the_marker_is_registered_so_strict_markers_accepts_it(
    pytestconfig: pytest.Config,
) -> None:
    """``--strict-markers`` is on; an unregistered marker is a collection error.

    Asked of the running pytest rather than of ``pyproject.toml``: what matters
    is the marker pytest actually loaded, and reading the file would also drag
    ``tomllib`` — 3.11+ — into a tree whose floor is 3.10.
    """
    markers = pytestconfig.getini("markers")
    assert any(m.startswith("requires_host_isa(") for m in markers), markers


def test_every_registered_token_is_used_or_usable() -> None:
    """Non-vacuity: the table must hold callables that actually answer."""
    from tests.conftest import HOST_ISA_PREDICATES

    assert HOST_ISA_PREDICATES, "the table is empty; the marker can exempt nothing"
    answers = {token: predicate() for token, predicate in HOST_ISA_PREDICATES.items()}
    assert all(isinstance(v, bool) for v in answers.values()), answers
    assert any(answers.values()), (
        f"no registered instruction set matches this host ({answers}); the table "
        "cannot distinguish a capability the host has from one it does not"
    )


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


# ---------------------------------------------------------------------------
# Interop-oracle escalation (audit M18)
#
# The nine backend keywords never matched the cross-implementation tests, whose
# skip reasons name the REFERENCE library (PyCA cryptography / PyNaCl /
# pycryptodome), not an AMA backend.  A failed `.[dev,legacy,benchmark]` install
# in the require-backends lane muted every one of the only independent-oracle
# checks and the report stayed green.  The fix is a `requires_interop_oracle`
# marker the hook escalates, and a completeness guard so a new interop test
# cannot silently escape it.
# ---------------------------------------------------------------------------


def test_interop_marked_skip_becomes_a_failure_in_ci(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A skipped test carrying ``requires_interop_oracle`` must become a hard
    failure under ``AMA_CI_REQUIRE_BACKENDS=1`` — its reason names PyCA, not a
    backend, so the keyword net never caught it (M18)."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        @pytest.mark.requires_interop_oracle
        @pytest.mark.skipif(True, reason="PyCA cryptography not available")
        class TestInterop:
            def test_cross_check(self):
                raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(errors=1, failed=0, skipped=0, passed=0)
    result.stdout.fnmatch_lines(["*CI FAILURE: PyCA cryptography not available*"])


def test_interop_marked_skip_without_ci_env_stays_a_skip(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside the require-backends lane a missing oracle is a legitimate skip."""
    monkeypatch.delenv("AMA_CI_REQUIRE_BACKENDS", raising=False)
    isolated_conftest.makepyfile("""
        import pytest

        @pytest.mark.requires_interop_oracle
        @pytest.mark.skipif(True, reason="PyCA cryptography not available")
        class TestInterop:
            def test_cross_check(self):
                raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)


def test_an_unmarked_interop_skip_is_not_escalated(
    isolated_conftest: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The escalation is marker-gated, not prose-gated: a PyCA skip WITHOUT the
    marker stays a skip (this is why the completeness guard below matters — the
    marker, not the wording, is what escalates)."""
    monkeypatch.setenv("AMA_CI_REQUIRE_BACKENDS", "1")
    isolated_conftest.makepyfile("""
        import pytest

        @pytest.mark.skipif(True, reason="PyCA cryptography not available")
        class TestInterop:
            def test_cross_check(self):
                raise AssertionError("must not run")
        """)
    result = isolated_conftest.runpytest_subprocess(*_inner_pytest_args())
    result.assert_outcomes(skipped=1, failed=0, errors=0, passed=0)


#: Tokens that identify a skip reason as gating on an external reference
#: implementation rather than on an AMA backend.
_INTEROP_ORACLE_TOKENS = ("pyca", "cryptography not", "pynacl", "pycryptodome", "cross-validation")


def _reason_names_oracle(reason: str) -> bool:
    low = reason.lower()
    return any(tok in low for tok in _INTEROP_ORACLE_TOKENS)


def _skipif_reason(call: ast.Call) -> str | None:
    """The ``reason=`` string of a ``pytest.mark.skipif(...)`` call, or None."""
    func = call.func
    is_skipif = (isinstance(func, ast.Attribute) and func.attr == "skipif") or (
        isinstance(func, ast.Name) and func.id == "skipif"
    )
    if not is_skipif:
        return None
    for kw in call.keywords:
        if kw.arg == "reason" and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    # positional reason: skipif(condition, reason)
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        return str(call.args[1].value)
    return None


def _interop_helper_names(tree: ast.AST) -> set[str]:
    """Module-level names bound to a skipif whose reason names an oracle
    (``skip_no_pyca = pytest.mark.skipif(..., reason="PyCA ...")``)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            reason = _skipif_reason(node.value)
            if reason and _reason_names_oracle(reason):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
    return names


def _decorator_names(node: ast.AST) -> set[str]:
    """The simple/attribute names of a def/class's decorators, for helper and
    marker matching (``requires_interop_oracle``, ``skip_no_pyca``, …)."""
    names: set[str] = set()
    for dec in getattr(node, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _decorated_defs(
    tree: ast.AST,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]:
    out: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append(node)
    return out


def test_every_interop_reason_skip_in_the_tree_carries_the_marker() -> None:
    """Completeness guard (M18): any test whose skip gates on an interop oracle —
    inline reason OR a module-level skipif helper whose reason names one — must
    carry ``requires_interop_oracle``, so a new cross-implementation test cannot
    silently escape the escalation the way all of them did before this fix.

    Non-vacuous: the assertion below also fails if the scan finds NO interop
    skips at all, which would mean the pattern stopped matching."""
    tests_dir = Path(__file__).resolve().parent
    offenders: list[str] = []
    interop_sites = 0
    for path in sorted(tests_dir.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        helpers = _interop_helper_names(tree)
        for node in _decorated_defs(tree):
            dec_names = _decorator_names(node)
            inline_oracle = any(
                (_skipif_reason(dec) or "") and _reason_names_oracle(_skipif_reason(dec) or "")
                for dec in getattr(node, "decorator_list", [])
                if isinstance(dec, ast.Call)
            )
            via_helper = bool(dec_names & helpers)
            if inline_oracle or via_helper:
                interop_sites += 1
                if "requires_interop_oracle" not in dec_names:
                    offenders.append(f"{path.name}:{node.lineno}:{getattr(node, 'name', '?')}")
    assert interop_sites >= 6, f"expected the known interop skip sites, found {interop_sites}"
    assert not offenders, (
        "these tests gate on an interop oracle but lack @pytest.mark.requires_interop_oracle, "
        f"so a missing PyCA/PyNaCl/pycryptodome would mute them silently: {offenders}"
    )


def test_the_interop_marker_is_registered_so_strict_markers_accepts_it() -> None:
    """--strict-markers is in addopts; an unregistered marker would fail the
    whole suite. Pin that requires_interop_oracle is declared."""
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "requires_interop_oracle" in pyproject


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
            "libama_cryptography.so.5",  # Linux, versioned soname
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

    @pytest.mark.parametrize(
        "names,expected",
        [
            (
                ["libama_cryptography.5.0.0.dylib", "libama_cryptography.dylib"],
                "libama_cryptography.dylib",
            ),
            (
                [
                    "libama_cryptography.so",
                    "libama_cryptography.so.5",
                    "libama_cryptography.so.5.0.0",
                ],
                "libama_cryptography.so",
            ),
            (["ama_cryptography.dll", "libama_cryptography.dll"], "ama_cryptography.dll"),
        ],
        ids=["macos", "linux", "windows"],
    )
    def test_the_name_the_loader_opens_wins_over_a_versioned_sibling(
        self, tmp_path: Path, names: list[str], expected: str
    ) -> None:
        """A caller that MODIFIES the library has to land on the loaded file.

        ``sorted(glob("libama_cryptography*"))[0]`` does not: on macOS
        ``libama_cryptography.5.0.0.dylib`` sorts before
        ``libama_cryptography.dylib`` because ``.5`` precedes ``.d``, so the
        artefact-cache-poisoning test tampered with a copy nothing opens.  The
        pre-load digest check then compared an untampered file and passed, and
        the test's "refused before mapping" assertion failed on all five
        macos-latest jobs — for the one reason that would also let a real
        tampered library through.

        Run on every platform against constructed names, because the runner
        this suite happens to be on can only exercise one of the three.
        """
        from tests.conftest import native_library_path

        for name in names:
            (tmp_path / name).write_bytes(b"\x7fELF")
        resolved = native_library_path(tmp_path)
        assert resolved is not None and resolved.name == expected, resolved

    def test_the_candidate_order_matches_the_loader_branch_for_branch(self) -> None:
        """``_NATIVE_LIB_NAMES``'s order is the loader's, read from its source.

        The constructed-name test above pins the three orders that exist
        today; this one pins that they are still the LOADER's orders.
        ``_get_lib_names`` returns a different list per platform and the first
        name in each is the one the loader opens, so ``_NATIVE_LIB_NAMES`` must
        be a linear extension of every one of those lists — reorder
        ``_get_lib_names`` and a tamper-detection test starts modifying a file
        nothing reads, which is precisely the macOS defect this table was
        rewritten to fix, in a different guise.
        """
        import ast

        from tests.conftest import _NATIVE_LIB_NAMES

        repo_root = Path(__file__).resolve().parent.parent
        source = (repo_root / "ama_cryptography" / "pqc_backends.py").read_text(encoding="utf-8")
        function = next(
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.FunctionDef) and node.name == "_get_lib_names"
        )
        branches = [
            [ast.literal_eval(element) for element in node.value.elts]
            for node in ast.walk(function)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.List)
        ]
        assert len(branches) >= 3, f"expected one return per platform, found {branches}"

        for names in branches:
            for name in names:
                assert name in _NATIVE_LIB_NAMES, (
                    f"{name!r} is a name the loader tries and _NATIVE_LIB_NAMES "
                    "does not carry, so a tree holding only it reads as unbuilt"
                )
            positions = [_NATIVE_LIB_NAMES.index(name) for name in names]
            assert positions == sorted(positions), (
                f"the loader tries {names} in that order; _NATIVE_LIB_NAMES orders "
                f"them {sorted(names, key=_NATIVE_LIB_NAMES.index)}, so a tree "
                "holding more than one resolves to a file the loader does not open"
            )

    def test_an_empty_tree_is_still_reported_as_missing(self, tmp_path: Path) -> None:
        """The probe must not become a tautology."""
        from tests.conftest import native_library_present

        assert not native_library_present(tmp_path)
        (tmp_path / "sha3_binding.cp311-win_amd64.pyd").write_bytes(b"MZ")
        assert not native_library_present(tmp_path), (
            "a Cython binding is not the native library; matching it would make "
            "the integrity fixtures run against a tree with no C library"
        )


class TestEveryBackendSkipIsEscalatable:
    """A skip reason CI cannot escalate is a skip CI cannot see.

    ``AMA_CI_REQUIRE_BACKENDS=1`` turns backend-related skips into failures by
    matching the recorded reason against ``conftest._BACKEND_SKIP_REASONS``.
    That makes the wording of an imperative ``pytest.skip()`` a functional
    property of the test, not prose — and two reasons in
    ``tests/test_artefact_cache_poisoning.py`` matched no keyword:

        "no compiled binding extensions in this tree; ..."
        "could not sign the scratch tree: ..."

    That module is the only end-to-end coverage of the pre-import binding gate
    and the ``__pycache__`` poisoning attack, so a CI runner that failed to
    build the extensions, or failed to sign, skipped all of it and reported
    green.  Both now name what is actually missing, which is native.

    This pins the property for the module rather than the two strings, so a
    third skip added later is caught the same way.
    """

    #: The modules whose skips must all be escalatable.  Scoped rather than
    #: repo-wide on purpose: plenty of skips elsewhere are legitimately not
    #: about a backend (no network, no pwsh, no semgrep), and asserting over
    #: those would force keyword-stuffing, which is the opposite of the point.
    BACKEND_ONLY_MODULES = ("test_artefact_cache_poisoning.py",)

    @pytest.mark.parametrize("module_name", BACKEND_ONLY_MODULES)
    def test_every_literal_skip_reason_matches_a_backend_keyword(self, module_name: str) -> None:
        import ast

        source_path = Path(__file__).resolve().parent / module_name
        tree = ast.parse(source_path.read_text(encoding="utf-8"))

        unescalatable: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "skip"):
                continue
            if not (isinstance(func.value, ast.Name) and func.value.id == "pytest"):
                continue
            if not node.args:
                continue
            # Reasons are built from literals and f-strings; collect every
            # literal fragment, which is what conftest's keyword match sees.
            text = " ".join(
                part.value
                for part in ast.walk(node.args[0])
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if not any(keyword in text.lower() for keyword in conftest._BACKEND_SKIP_REASONS):
                unescalatable.append(f"line {node.lineno}: {text[:90]!r}")

        assert not unescalatable, (
            f"{module_name} has pytest.skip() reasons that AMA_CI_REQUIRE_BACKENDS "
            f"cannot escalate, so a CI runner missing the backend would skip this "
            f"coverage and report green: {unescalatable}. Name what is missing "
            f"using one of {sorted(conftest._BACKEND_SKIP_REASONS)}."
        )
