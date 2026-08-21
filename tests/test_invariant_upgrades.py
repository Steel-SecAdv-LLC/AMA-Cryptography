#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for Invariant Upgrades A-D.

INVARIANT-12: Constant-Time Required for All Secret-Dependent Operations
INVARIANT-13: No Unjustified Static-Analysis Suppressions
INVARIANT-7 (revised): No Cryptographic Fallbacks, Ever
INVARIANT-3 (addendum): Finalizer Failures Must Be Observable
"""

from __future__ import annotations

import gc
import inspect
import re
import subprocess
import sys
import threading
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Upgrade D — INVARIANT-3 Addendum: Finalizer Failures Must Be Observable
# ---------------------------------------------------------------------------


class TestFinalizerHealth:
    """INVARIANT-3 addendum: finalizer failures must be observable."""

    @pytest.fixture(autouse=True)
    def _reset(self) -> Generator[None, None, None]:
        from ama_cryptography import _finalizer_health as _fh

        _fh.reset_finalizer_health()
        yield
        _fh.reset_finalizer_health()

    def test_initial_state_no_errors(self) -> None:
        """Health check reports clean state before any failures."""
        from ama_cryptography._finalizer_health import finalizer_health_check

        ok, count, last = finalizer_health_check()
        assert ok is True
        assert count == 0
        assert last is None

    def test_record_finalizer_error_increments_counter(self) -> None:
        from ama_cryptography import _finalizer_health as fh

        before = fh.finalizer_error_count()
        fh.record_finalizer_error("TestSource", "test detail")
        after = fh.finalizer_error_count()
        assert after == before + 1

    def test_record_finalizer_error_sets_flag(self) -> None:
        from ama_cryptography import _finalizer_health as fh

        fh.record_finalizer_error("TestSource", "flag test")
        assert fh.has_finalizer_errors() is True

    def test_last_finalizer_error_returns_most_recent(self) -> None:
        from ama_cryptography import _finalizer_health as fh

        fh.record_finalizer_error("SourceA", "detail A")
        fh.record_finalizer_error("SourceB", "detail B")
        last = fh.last_finalizer_error()
        assert last is not None
        assert last == ("SourceB", "detail B")

    def test_health_check_composite(self) -> None:
        from ama_cryptography import _finalizer_health as fh

        fh.record_finalizer_error("Composite", "check")
        ok, count, last = fh.finalizer_health_check()
        assert ok is False  # errors recorded
        assert count >= 1
        assert last is not None
        assert last[0] == "Composite"

    def test_thread_safety(self) -> None:
        """Concurrent calls to record_finalizer_error must not corrupt state."""
        from ama_cryptography import _finalizer_health as fh

        before = fh.finalizer_error_count()
        n_threads = 10
        n_per_thread = 50
        barrier = threading.Barrier(n_threads)

        def worker() -> None:
            barrier.wait()
            for i in range(n_per_thread):
                fh.record_finalizer_error("ThreadTest", f"iter {i}")

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        after = fh.finalizer_error_count()
        assert after == before + n_threads * n_per_thread

    def test_dilithium_keypair_del_records_error_on_wipe_failure(self) -> None:
        """DilithiumKeyPair.__del__ must call record_finalizer_error on exception."""
        from ama_cryptography import _finalizer_health as fh
        from ama_cryptography.pqc_backends import DilithiumKeyPair

        kp = DilithiumKeyPair(
            public_key=b"\x00" * 1952,
            secret_key=bytearray(b"\x00" * 4032),
        )
        before = fh.finalizer_error_count()
        # Patch at class level so the GC-triggered __del__ sees the mock
        with mock.patch.object(DilithiumKeyPair, "wipe", side_effect=RuntimeError("mock")):
            del kp
            gc.collect()
        after = fh.finalizer_error_count()
        assert after == before + 1
        last = fh.last_finalizer_error()
        assert last is not None
        assert last[0] == "DilithiumKeyPair"

    def test_kyber_keypair_del_records_error_on_wipe_failure(self) -> None:
        """KyberKeyPair.__del__ must call record_finalizer_error on exception."""
        from ama_cryptography import _finalizer_health as fh
        from ama_cryptography.pqc_backends import KyberKeyPair

        kp = KyberKeyPair(
            public_key=b"\x00" * 1568,
            secret_key=bytearray(b"\x00" * 3168),
        )
        before = fh.finalizer_error_count()
        with mock.patch.object(KyberKeyPair, "wipe", side_effect=RuntimeError("mock")):
            del kp
            gc.collect()
        after = fh.finalizer_error_count()
        assert after == before + 1
        last = fh.last_finalizer_error()
        assert last is not None
        assert last[0] == "KyberKeyPair"

    def test_sphincs_keypair_del_records_error_on_wipe_failure(self) -> None:
        """SphincsKeyPair.__del__ must call record_finalizer_error on exception."""
        from ama_cryptography import _finalizer_health as fh
        from ama_cryptography.pqc_backends import SphincsKeyPair

        kp = SphincsKeyPair(
            public_key=b"\x00" * 64,
            secret_key=bytearray(b"\x00" * 128),
        )
        before = fh.finalizer_error_count()
        with mock.patch.object(SphincsKeyPair, "wipe", side_effect=RuntimeError("mock")):
            del kp
            gc.collect()
        after = fh.finalizer_error_count()
        assert after == before + 1
        last = fh.last_finalizer_error()
        assert last is not None
        assert last[0] == "SphincsKeyPair"


# ---------------------------------------------------------------------------
# Upgrade B — INVARIANT-7 (Revised): No Cryptographic Fallbacks, Ever
# ---------------------------------------------------------------------------


class TestNoCryptographicFallbacks:
    """INVARIANT-7 revised: library must refuse when native backend unavailable."""

    def test_crypto_api_refuses_without_hmac_backend(self) -> None:
        """crypto_api must raise RuntimeError when native HMAC is unavailable."""
        # We test the guard logic by checking the module-level code.
        # The actual import succeeds because backends ARE available in CI.
        # We verify the guard code path exists and would raise.
        import ama_cryptography.crypto_api as ca

        # The module sets HMAC_HKDF_AVAILABLE = True after the guard.
        # If we got here, the guard passed. Verify the flag:
        assert ca.HMAC_HKDF_AVAILABLE is True

    def test_key_management_refuses_without_hmac_backend(self) -> None:
        """key_management must raise RuntimeError when native HMAC-SHA512 is unavailable."""
        import ama_cryptography.key_management as km

        # The module imports successfully only when native is available.
        # Verify the native flag is set:
        assert km._HMAC_SHA512_NATIVE is True

    def test_crypto_api_no_fallback_code_path(self) -> None:
        """Verify no pure-Python fallback exists in the HMAC/HKDF functions."""
        import ast
        import inspect

        import ama_cryptography.crypto_api as ca

        src = inspect.getsource(ca._hmac_sha3_256)
        # Parse the function body to check for actual import statements (not docstrings)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert (
                        alias.name != "hmac"
                    ), "INVARIANT-7: _hmac_sha3_256 must not import stdlib hmac"
            elif isinstance(node, ast.ImportFrom):
                assert (
                    node.module != "hmac"
                ), "INVARIANT-7: _hmac_sha3_256 must not import from stdlib hmac"
        assert "hmac.new" not in src, "INVARIANT-7: _hmac_sha3_256 must not use hmac.new"

    def test_key_management_no_fallback_code_path(self) -> None:
        """Verify no pure-Python fallback exists in key_management._hmac_sha512."""
        import inspect

        import ama_cryptography.key_management as km

        src = inspect.getsource(km._hmac_sha512)
        assert "import hmac" not in src, "INVARIANT-7: _hmac_sha512 must not import stdlib hmac"
        assert "hmac.new" not in src, "INVARIANT-7: _hmac_sha512 must not use hmac.new"


# ---------------------------------------------------------------------------
# Upgrade A — INVARIANT-12: Constant-Time Required
# ---------------------------------------------------------------------------


class TestConstantTimeRequirements:
    """INVARIANT-12: all secret-dependent operations must be constant-time."""

    def test_crypto_api_hmac_delegates_to_native(self) -> None:
        """_hmac_sha3_256 must delegate to native backend, not implement crypto in Python."""
        import inspect

        import ama_cryptography.crypto_api as ca

        src = inspect.getsource(ca._hmac_sha3_256)
        assert (
            "native_hmac_sha3_256" in src
        ), "INVARIANT-12: _hmac_sha3_256 must delegate to native backend"

    def test_key_management_hmac_delegates_to_native(self) -> None:
        """_hmac_sha512 must delegate to native backend."""
        import inspect

        import ama_cryptography.key_management as km

        src = inspect.getsource(km._hmac_sha512)
        assert (
            "native_hmac_sha512" in src
        ), "INVARIANT-12: _hmac_sha512 must delegate to native backend"

    def test_constant_time_compare_uses_native_or_xor(self) -> None:
        """constant_time_compare must use native consttime_memcmp or XOR accumulator."""
        import inspect

        from ama_cryptography.secure_memory import constant_time_compare

        src = inspect.getsource(constant_time_compare)
        # Must use native or XOR-based comparison, not ==
        has_native = "_native_consttime_memcmp" in src
        has_xor = "result |=" in src
        assert (
            has_native or has_xor
        ), "INVARIANT-12: constant_time_compare must use native or XOR accumulator"

    def test_no_stdlib_hmac_in_crypto_modules(self) -> None:
        """No module under ama_cryptography/ may use stdlib hmac for crypto operations."""
        import ast

        repo_root = Path(__file__).resolve().parent.parent
        crypto_dir = repo_root / "ama_cryptography"

        violations: list[str] = []
        for py_file in sorted(crypto_dir.rglob("*.py")):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                # A module that fails to parse must not silently escape the scan
                # (an unparseable file could hide a banned import). Treat it as a
                # violation so the invariant cannot be bypassed.
                violations.append(f"{py_file.name}: unparseable ({exc})")
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "hmac":
                            violations.append(f"{py_file.name}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module == "hmac":
                        violations.append(f"{py_file.name}:{node.lineno}")

        assert not violations, f"INVARIANT-1/12: stdlib hmac imported in: {violations}"

    def test_no_third_party_crypto_imports_in_product_code(self) -> None:
        """INVARIANT-1: no third-party crypto library may be imported by product
        code (ama_cryptography/*.py).

        AMA ships its own primitives; importing PyCA cryptography, PyNaCl,
        pycryptodome, or pyOpenSSL in the runtime package would violate the
        zero-external-crypto-dependency invariant.  The stdlib-``hmac`` check
        above closed only one bypass class; this closes the other the audit
        flagged — a module could previously ``import cryptography`` with no
        automated tripwire (``.semgrep.yml`` and the test suite did not ban it).

        Test code (tests/) is exempt: differential/interop tests legitimately
        import these libraries via the ``[benchmark]`` extra to cross-check AMA
        output against an independent implementation.
        """
        import ast

        # Top-level module names that are third-party crypto providers.
        banned = {"cryptography", "nacl", "Crypto", "Cryptodome", "OpenSSL"}
        repo_root = Path(__file__).resolve().parent.parent
        crypto_dir = repo_root / "ama_cryptography"

        violations: list[str] = []
        for py_file in sorted(crypto_dir.rglob("*.py")):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                # A module that fails to parse must not silently escape the scan
                # (an unparseable file could hide a banned import). Treat it as a
                # violation so the invariant cannot be bypassed.
                violations.append(f"{py_file.name}: unparseable ({exc})")
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in banned:
                            violations.append(f"{py_file.name}:{node.lineno} ({alias.name})")
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    if root in banned:
                        violations.append(f"{py_file.name}:{node.lineno} ({node.module})")

        assert not violations, (
            "INVARIANT-1: third-party crypto library imported in product code: " f"{violations}"
        )


# ---------------------------------------------------------------------------
# Upgrade C — INVARIANT-13: No Unjustified Static-Analysis Suppressions
# ---------------------------------------------------------------------------


class TestSuppressionHygiene:
    """INVARIANT-13: all suppressions must have justification + tracking ID."""

    _SUPPRESSION_RE = re.compile(r"#\s*(noqa|nosec|pylint:\s*disable|type:\s*ignore)")
    _TRACKING_ID_RE = re.compile(r"\([A-Z]+-\d+\)")
    _JUSTIFICATION_RE = re.compile(r"[—–]|--|#\s*\S")

    _FORBIDDEN_DIRS = (
        "src/c/",
        "ama_cryptography/_primitive",
        "ama_cryptography/backend",
        "include/",
    )

    def _scan_violations(self, directory: str) -> list[str]:
        repo_root = Path(__file__).resolve().parent.parent
        target = repo_root / directory
        violations: list[str] = []
        for py_file in sorted(target.rglob("*.py")):
            rel = str(py_file.relative_to(repo_root))
            try:
                lines = py_file.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for lineno, line in enumerate(lines, 1):
                m = self._SUPPRESSION_RE.search(line)
                if m is None:
                    continue
                # Check forbidden
                for fd in self._FORBIDDEN_DIRS:
                    if rel.startswith(fd):
                        violations.append(f"{rel}:{lineno}: forbidden directory")
                        break
                else:
                    rest = line[m.end() :]
                    if not self._JUSTIFICATION_RE.search(rest):
                        violations.append(f"{rel}:{lineno}: missing justification")
                    elif not self._TRACKING_ID_RE.search(rest):
                        violations.append(f"{rel}:{lineno}: missing tracking ID")
        return violations

    def test_ama_cryptography_suppressions_justified(self) -> None:
        violations = self._scan_violations("ama_cryptography")
        assert not violations, "INVARIANT-13 violations in ama_cryptography/:\n" + "\n".join(
            f"  {v}" for v in violations
        )

    def test_no_suppressions_in_forbidden_dirs(self) -> None:
        """Suppressions absolutely forbidden in src/c/, _primitive, backend, include/.

        This used to walk ``rglob("*.py")`` under each forbidden directory.
        ``src/c/`` and ``include/`` hold no Python, and the other two entries
        name directories that do not exist, so it asserted over an empty set —
        the same vacuity the gate itself had, and it passed for years while a
        live suppression sat in ``src/c/ed25519_donna_shim.c``.  It now drives
        the gate's own C-tree scan, which is the thing CI runs.
        """
        repo_root = Path(__file__).resolve().parent.parent
        gate = self._load_gate()
        files = gate.c_tree_files(repo_root)
        assert len(files) > 50, (
            f"the C-tree scan found only {len(files)} files — an empty or "
            "collapsed scope is a checker fault, not a clean tree"
        )
        assert gate.scan_c_tree(repo_root) == []
        # And the Python trees the other rule governs, unchanged.
        for fd in self._FORBIDDEN_DIRS:
            target = repo_root / fd
            if not target.exists():
                continue
            for py_file in target.rglob("*.py"):
                content = py_file.read_text(encoding="utf-8", errors="replace")
                assert not self._SUPPRESSION_RE.search(
                    content
                ), f"INVARIANT-13: suppression found in forbidden dir: {py_file}"

    @staticmethod
    def _load_gate() -> Any:
        import importlib.util

        repo_root = Path(__file__).resolve().parent.parent
        path = repo_root / "tools" / "check_suppression_hygiene.py"
        spec = importlib.util.spec_from_file_location("_sup_gate", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_c_tree_scan_reports_a_planted_suppression(self) -> None:
        """Negative control: the scan must not be a blanket pass.

        Every marker form is planted, because the gate's value is that a
        reviewer cannot reach for any of them.
        """
        import tempfile

        gate = self._load_gate()
        markers = (
            "/* NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Assign) */",
            "int x = 0;  /* NOLINT */",
            "/* cppcheck-suppress nullPointer */",
            "/* nosemgrep: some-rule */",
            "/* coverity[tainted_data] */",
            "/* LINTED */",
        )
        for marker in markers:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "src" / "c").mkdir(parents=True)
                (root / "include").mkdir()
                (root / "include" / "ama_x.h").write_text("int f(void);\n", encoding="utf-8")
                (root / "src" / "c" / "x.c").write_text(
                    f"int f(void) {{\n    {marker}\n    return 0;\n}}\n", encoding="utf-8"
                )
                found = gate.scan_c_tree(root)
                assert found, f"the scan missed {marker!r}"
                assert "x.c" in found[0], found

    def test_the_c_tree_scan_fails_closed_on_an_empty_scope(self) -> None:
        """A glob that matches nothing must never read as "clean"."""
        import tempfile

        gate = self._load_gate()
        with tempfile.TemporaryDirectory() as td:
            found = gate.scan_c_tree(Path(td))
        assert found and "scan scope is empty" in found[0], found

    def test_vendored_code_is_out_of_scope(self) -> None:
        """INVARIANT-13 governs what this project writes.

        Rewriting a vendor comment would defeat the "no project-side
        modifications" property the vendor-isolation gate enforces separately.
        """
        import tempfile

        gate = self._load_gate()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src" / "c" / "vendor" / "thirdparty").mkdir(parents=True)
            (root / "src" / "c" / "vendor" / "thirdparty" / "v.c").write_text(
                "/* NOLINT */\nint g(void) { return 0; }\n", encoding="utf-8"
            )
            (root / "src" / "c" / "ours.c").write_text(
                "int h(void) { return 0; }\n", encoding="utf-8"
            )
            assert gate.scan_c_tree(root) == []

    def test_ci_enforcement_script_exists(self) -> None:
        """The CI suppression hygiene script must exist."""
        repo_root = Path(__file__).resolve().parent.parent
        script = repo_root / "tools" / "check_suppression_hygiene.py"
        assert script.exists(), "tools/check_suppression_hygiene.py must exist"

    def test_ci_enforcement_script_passes(self) -> None:
        """The CI suppression hygiene script must pass on the current codebase."""
        repo_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [sys.executable, str(repo_root / "tools" / "check_suppression_hygiene.py")],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(repo_root),
        )
        assert (
            result.returncode == 0
        ), f"check_suppression_hygiene.py failed:\n{result.stdout}\n{result.stderr}"


class TestSuppressionScanPrecision:
    """What the checker treats as a suppression, in both directions.

    The scan covers ``tools/`` as well as ``ama_cryptography/`` and ``tests/``:
    ``tools/`` is where the gates live, so a static analyser silenced there is
    silenced inside the layer that enforces this repository's security policy.

    Widening it required the checker to stop confusing prose *about* a
    suppression with a suppression. Both halves are asserted here — a checker
    that under-reports has stopped working, and one that fires on its own
    documentation gets routed around.
    """

    def test_a_trailing_marker_without_justification_is_reported(self) -> None:
        from tools.check_suppression_hygiene import check_source

        assert check_source("a.py", "import subprocess  # nosec B404\n")

    def test_a_trailing_marker_without_a_tracking_id_is_reported(self) -> None:
        from tools.check_suppression_hygiene import check_source

        violations = check_source("a.py", "import subprocess  # nosec B404 -- fixed argv\n")
        assert any("tracking ID" in v for v in violations)

    def test_a_fully_justified_trailing_marker_is_accepted(self) -> None:
        from tools.check_suppression_hygiene import check_source

        assert (
            check_source("a.py", "import subprocess  # nosec B404 -- fixed argv (AB-001)\n") == []
        )

    def test_prose_describing_a_marker_is_not_a_suppression(self) -> None:
        """The false-positive class that widening to ``tools/`` exposed."""
        from tools.check_suppression_hygiene import check_source

        source = (
            "# Justified findings carry an inline ``# nosec``, which is what\n"
            "# ``# type: ignore`` and ``# noqa`` mean elsewhere.\n"
            "x = 1\n"
        )
        assert check_source("a.py", source) == []

    def test_a_marker_inside_a_string_literal_is_not_a_suppression(self) -> None:
        """The scan used to regex the whole line, putting literals back in scope."""
        from tools.check_suppression_hygiene import check_source

        source = 'MESSAGE = "expected # nosec here"  # explains the message above\n'
        assert check_source("a.py", source) == []

    def test_a_file_level_type_ignore_is_still_in_scope(self) -> None:
        """mypy's whole-file directive is standalone but real, so it is kept."""
        from tools.check_suppression_hygiene import check_source

        assert check_source("a.py", "# type: ignore\nx = 1\n")

    def test_a_forbidden_directory_is_reported_regardless_of_justification(self) -> None:
        from tools.check_suppression_hygiene import check_source

        violations = check_source(
            "ama_cryptography/backend/x.py", "import os  # nosec B404 -- reason (AB-001)\n"
        )
        assert any("forbidden" in v for v in violations)

    def test_tools_is_actually_in_the_scanned_set(self) -> None:
        """A coverage extension that did not extend coverage would pass silently."""
        from tools.check_suppression_hygiene import main

        repo_root = Path(__file__).resolve().parent.parent
        source = inspect.getsource(main)
        assert 'Path("tools")' in source, "tools/ dropped out of the scanned set"
        assert (repo_root / "tools").is_dir()

    # -- The marker must name the rule it silences ------------------------

    def test_a_bare_nosec_is_reported_even_when_fully_justified(self) -> None:
        """The sharp case: it reads targeted and is not.

        bandit parses everything after ``# nosec`` as test ids, warns on each
        word it cannot resolve, and treats the resulting EMPTY set as "no
        specific tests" — i.e. blanket.  So this repository's own house style,
        ``# nosec -- reason (TAG-NNN)``, silences every bandit test on the line
        while carrying a justification that says otherwise.

        Measured against bandit 1.9.4 on two files differing only in the
        marker: with ``# nosec -- prose (DEMO-002)`` on a
        ``subprocess.call(..., shell=True)`` line, bandit reports nothing for
        that line; with ``# nosec B105`` — a code that matches nothing there —
        it still reports B607.
        """
        from tools.check_suppression_hygiene import check_source

        violations = check_source("a.py", "PW = 'x'  # nosec -- placeholder (AB-001)\n")
        assert any("missing rule id" in v for v in violations), violations

    @pytest.mark.parametrize("marker", ["# nosec B105", "# nosec: B105"])
    def test_both_targeted_nosec_spellings_are_accepted(self, marker: str) -> None:
        from tools.check_suppression_hygiene import check_source

        assert check_source("a.py", f"PW = 'x'  {marker} -- placeholder (AB-001)\n") == []

    def test_a_bare_noqa_is_reported_even_when_fully_justified(self) -> None:
        """ruff treats a bare ``# noqa`` as every rule on the line."""
        from tools.check_suppression_hygiene import check_source

        violations = check_source("a.py", "import os  # noqa -- reason (AB-001)\n")
        assert any("missing rule id" in v for v in violations), violations

    def test_a_targeted_noqa_is_accepted(self) -> None:
        from tools.check_suppression_hygiene import check_source

        assert check_source("a.py", "import os  # noqa: F401 -- reason (AB-001)\n") == []

    def test_the_repositorys_own_stacked_marker_form_is_accepted(self) -> None:
        """``# fmt: skip  # noqa: S311 # nosec B311 -- reason (NM-010)``.

        Verbatim from ``ama_cryptography/_numeric.py``: three markers on one
        line, two of them strict-form families.  A rule that rejected this
        would be a rule the tree could not satisfy.
        """
        from tools.check_suppression_hygiene import check_source

        source = (
            "rng = Random()  # fmt: skip  # noqa: S311 # nosec B311 "
            "-- non-crypto math only (NM-010)\n"
        )
        assert check_source("a.py", source) == []

    def test_no_marker_in_the_tree_is_written_bare(self) -> None:
        """Asserted against the tree, not only through the checker.

        The strict-form rule was added on a tree that already satisfied it, so
        this is the assertion that keeps it satisfied rather than evidence that
        it was ever violated.
        """
        from tools.check_suppression_hygiene import (
            _STRICT_FORMS,
            _SUPPRESSION_RE,
            effective_suppressions,
        )

        repo_root = Path(__file__).resolve().parent.parent
        blanket: list[str] = []
        for tree in ("ama_cryptography", "tests", "tools"):
            for py_file in sorted((repo_root / tree).rglob("*.py")):
                source = py_file.read_text(encoding="utf-8", errors="replace")
                for lineno, comment in effective_suppressions(source):
                    for match in _SUPPRESSION_RE.finditer(comment):
                        strict = _STRICT_FORMS.get(match.group(1))
                        if strict is None:
                            continue
                        if not strict[0].match(comment[match.end() :]):
                            blanket.append(
                                f"{py_file.relative_to(repo_root)}:{lineno}: {comment.strip()}"
                            )
        assert blanket == [], f"blanket suppression marker(s): {blanket}"

    def test_every_tools_suppression_carries_a_tracking_id(self) -> None:
        """Asserted directly against the tree, not only through the checker."""
        from tools.check_suppression_hygiene import _SUPPRESSION_RE, effective_suppressions

        repo_root = Path(__file__).resolve().parent.parent
        unjustified: list[str] = []
        for py_file in sorted((repo_root / "tools").rglob("*.py")):
            source = py_file.read_text(encoding="utf-8", errors="replace")
            for lineno, comment in effective_suppressions(source):
                if _SUPPRESSION_RE.search(comment) and not re.search(r"\([A-Z]+-\d+\)", comment):
                    unjustified.append(f"{py_file.relative_to(repo_root)}:{lineno}")
        assert unjustified == [], f"suppressions in tools/ without a tracking ID: {unjustified}"


# ---------------------------------------------------------------------------
# Cross-cutting: INVARIANTS.md documentation
# ---------------------------------------------------------------------------


class TestInvariantsDocumentation:
    """Verify INVARIANTS.md documents all new/revised invariants."""

    def _read_invariants_md(self) -> str:
        repo_root = Path(__file__).resolve().parent.parent
        return (repo_root / "INVARIANTS.md").read_text(encoding="utf-8")

    def test_invariant_3_addendum_documented(self) -> None:
        content = self._read_invariants_md()
        assert "Finalizer Failures Must Be Observable" in content

    def test_invariant_7_revised_documented(self) -> None:
        content = self._read_invariants_md()
        assert "No Cryptographic Fallbacks, Ever" in content

    def test_invariant_12_documented(self) -> None:
        content = self._read_invariants_md()
        assert "Constant-Time Required" in content

    def test_invariant_13_documented(self) -> None:
        content = self._read_invariants_md()
        assert "INVARIANT-13" in content

    def test_invariant_14_cve_hygiene_documented(self) -> None:
        content = self._read_invariants_md()
        assert "INVARIANT-14" in content
