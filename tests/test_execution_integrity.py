#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Execution integrity: the ``.pyc`` the interpreter runs vs the ``.py`` we signed
==============================================================================

The module-integrity digest signs the package's ``.py`` SOURCE.  CPython does
not execute source — it executes the bytecode in ``__pycache__/*.pyc``, and a
timestamp-based ``.pyc`` is honoured whenever its stored (mtime, size) match the
source, which an attacker with write access to the tree sets.  So the source
digest and its Ed25519 signature can all verify while poisoned bytecode runs.

The execution-integrity POST stage closes that: it recompiles each signed
``.py`` and refuses any cached ``.pyc`` whose bytecode is not a faithful compile
of it.  These tests pin both halves:

* the bytecode comparison is by executed surface (instructions + constants,
  recursively), so a ``.pyc`` built at a different path is not a false positive
  while a single altered instruction — even inside a nested function — is caught;
* a poisoned ``.pyc`` whose header still matches the pristine source (so the
  interpreter loads it and the source digest still verifies) fails POST and the
  import, end to end.

Run with:  pytest tests/test_execution_integrity.py -v
"""

from __future__ import annotations

import importlib.util
import marshal
import os
import py_compile
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from types import CodeType, ModuleType

import pytest

from ama_cryptography import _self_test as st
from tests.conftest import native_library_present

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

pytestmark = pytest.mark.fips

_PYC_HEADER_LEN = 16  # magic(4) + bit field(4) + (mtime,size | source hash)(8)


# ---------------------------------------------------------------------------
# 1. _code_matches — executed surface, not path or line info
# ---------------------------------------------------------------------------
class TestCodeMatches:
    def test_identical_source_matches(self) -> None:
        src = "def f(x):\n    return x + 1\n"
        assert st._code_matches(compile(src, "m.py", "exec"), compile(src, "m.py", "exec"))

    def test_filename_difference_is_not_a_mismatch(self) -> None:
        """A legitimate .pyc built at a different absolute path has a different
        co_filename and must NOT be flagged — otherwise every relocated install
        would fail POST."""
        src = "def f(x):\n    return x * 2\n"
        assert st._code_matches(
            compile(src, "/build/m.py", "exec"), compile(src, "/opt/m.py", "exec")
        )

    def test_changed_instruction_is_caught(self) -> None:
        a = compile("y = x + 1\n", "m.py", "exec")
        b = compile("y = x - 1\n", "m.py", "exec")
        assert not st._code_matches(a, b)

    def test_nested_function_body_change_is_caught(self) -> None:
        """The difference lives in a nested code object inside co_consts; the
        recursive descent is what catches it."""
        a = compile("def f(x):\n    return x + 1\n", "m.py", "exec")
        b = compile("def f(x):\n    return x + 2\n", "m.py", "exec")
        assert not st._code_matches(a, b)

    def test_constant_type_swap_is_caught(self) -> None:
        """``1 == 1.0`` and ``1 == True`` in Python, so a bare == would let an
        int constant be swapped for an equal-valued float/bool.  The type guard
        closes that."""
        a = compile("v = 1\n", "m.py", "exec")
        b = compile("v = 1.0\n", "m.py", "exec")
        assert not st._code_matches(a, b)


# ---------------------------------------------------------------------------
# 2. _verify_source_file_bytecode — one file's .pyc vs its source
# ---------------------------------------------------------------------------
def _make_module(tmp_path: Path, name: str, body: str) -> Path:
    py = tmp_path / f"{name}.py"
    py.write_text(textwrap.dedent(body), encoding="utf-8")
    return py


def _poison_pyc_body(pyc: Path, poisoned_code: CodeType) -> None:
    """Keep the 16-byte header (so it still looks up to date), swap the body."""
    header = pyc.read_bytes()[:_PYC_HEADER_LEN]
    pyc.write_bytes(header + marshal.dumps(poisoned_code))


class TestVerifySourceFileBytecode:
    def test_matching_pyc_verifies(self, tmp_path: Path) -> None:
        py = _make_module(tmp_path, "good", "A = 1\n\ndef f():\n    return A\n")
        py_compile.compile(str(py), doraise=True)
        status, error = st._verify_source_file_bytecode(py)
        assert (status, error) == ("verified", None)

    def test_poisoned_pyc_is_caught(self, tmp_path: Path) -> None:
        py = _make_module(
            tmp_path, "poison", "SECRET = 1\n\ndef check():\n    return SECRET == 1\n"
        )
        py_compile.compile(str(py), doraise=True)
        pyc = Path(importlib.util.cache_from_source(str(py)))
        # A different, still-valid code object with the SAME source on disk: the
        # source digest would still pass; only the bytecode check sees this.
        poisoned = compile("SECRET = 1\n\ndef check():\n    return True\n", str(py), "exec")
        _poison_pyc_body(pyc, poisoned)
        status, error = st._verify_source_file_bytecode(py)
        assert status == "verified"
        assert error is not None and "poisoned or stale" in error

    def test_no_cache_is_skipped(self, tmp_path: Path) -> None:
        py = _make_module(tmp_path, "nocache", "X = 2\n")
        # Deliberately do not compile: with no .pyc there is nothing to poison,
        # the interpreter would compile the signed source directly.
        assert st._verify_source_file_bytecode(py) == ("skipped", None)

    def test_foreign_interpreter_magic_is_skipped(self, tmp_path: Path) -> None:
        py = _make_module(tmp_path, "foreign", "X = 3\n")
        py_compile.compile(str(py), doraise=True)
        pyc = Path(importlib.util.cache_from_source(str(py)))
        blob = bytearray(pyc.read_bytes())
        blob[0] ^= 0xFF  # corrupt the magic → a different interpreter's cache
        pyc.write_bytes(bytes(blob))
        # The running interpreter would recompile from source, so this .pyc is
        # not what executes and is not ours to judge.
        assert st._verify_source_file_bytecode(py) == ("skipped", None)

    def test_corrupt_body_is_a_fault(self, tmp_path: Path) -> None:
        py = _make_module(tmp_path, "corrupt", "X = 4\n")
        py_compile.compile(str(py), doraise=True)
        pyc = Path(importlib.util.cache_from_source(str(py)))
        pyc.write_bytes(pyc.read_bytes()[:_PYC_HEADER_LEN] + b"\x00\x01not-marshal")
        status, error = st._verify_source_file_bytecode(py)
        assert status == "verified"
        assert error is not None and "unreadable" in error


# ---------------------------------------------------------------------------
# 3. _detect_module_substitution — a covered module served from elsewhere
# ---------------------------------------------------------------------------
def _fake_module(file_path: str | None) -> ModuleType:
    mod = ModuleType("ama_cryptography.fake")
    if file_path is not None:
        mod.__file__ = file_path
    return mod


class TestModuleSubstitution:
    def test_inside_package_is_ok(self) -> None:
        inside = _fake_module(str(PKG_DIR / "pqc_backends.py"))
        assert st._detect_module_substitution("ama_cryptography.fake", inside, PKG_DIR) is None

    def test_outside_package_is_flagged(self, tmp_path: Path) -> None:
        elsewhere = tmp_path / "pqc_backends.py"
        elsewhere.write_text("# impostor\n", encoding="utf-8")
        err = st._detect_module_substitution(
            "ama_cryptography.fake", _fake_module(str(elsewhere)), PKG_DIR
        )
        assert err is not None and "module substitution" in err

    def test_native_extension_is_ignored(self) -> None:
        so = _fake_module(str(PKG_DIR / "math_engine.cpython-311-x86_64-linux-gnu.so"))
        assert st._detect_module_substitution("ama_cryptography.math_engine", so, PKG_DIR) is None

    def test_no_file_is_ignored(self) -> None:
        assert (
            st._detect_module_substitution("ama_cryptography.fake", _fake_module(None), PKG_DIR)
            is None
        )


# ---------------------------------------------------------------------------
# 4. The real tree passes — and non-vacuously
# ---------------------------------------------------------------------------
class TestRealTree:
    def test_check_execution_integrity_passes(self) -> None:
        ok, verified, skipped, problems = st._check_execution_integrity()
        assert ok, problems
        # Non-vacuity: a check that skipped everything would also report ok=True
        # with zero problems.  The shipped tree is imported with bytecode
        # written, so most of its signed files must actually be bound.
        assert verified >= 20, (verified, skipped)


# ---------------------------------------------------------------------------
# 5. End to end: a poisoned .pyc fails POST and the import
# ---------------------------------------------------------------------------
def _run_python(code: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONPATH"] = str(cwd)
    env.pop("PYTHONDONTWRITEBYTECODE", None)  # we need .pyc files written
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def importable_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package that imports cleanly, with .pyc files written.

    Skips when the tree cannot be imported (no native library / no signed
    artefact) — the end-to-end path needs a POST that reaches the
    execution-integrity stage.
    """
    if not (PKG_DIR / "_integrity_signature.py").is_file():
        pytest.skip("no signed-integrity artefact in the source tree")
    if not native_library_present(PKG_DIR):
        pytest.skip("native library not built in this tree")

    root = tmp_path_factory.mktemp("exec_integrity")
    shutil.copytree(PKG_DIR, root / "ama_cryptography", symlinks=False)
    # Import once so the interpreter writes .pyc files into the copied tree.
    baseline = _run_python("import ama_cryptography; print('OK')", cwd=root)
    if baseline.returncode != 0 or "OK" not in baseline.stdout:
        pytest.skip(
            "copied tree does not import cleanly (native backend unavailable); "
            f"stdout={baseline.stdout!r} stderr={baseline.stderr[:400]!r}"
        )
    return root


class TestEndToEnd:
    def test_poisoned_pyc_fails_import(self, importable_tree: Path, tmp_path: Path) -> None:
        """Leave every .py pristine (so the signed digest still verifies) and
        drop a poisoned-but-valid .pyc whose header still matches its source.
        The interpreter loads it; the execution-integrity stage must still refuse."""
        # Work on a private copy (carrying the fixture's .pyc files) so poisoning
        # cannot leak into the shared baseline tree regardless of test order.
        root = tmp_path / "poisoned"
        shutil.copytree(
            importable_tree / "ama_cryptography", root / "ama_cryptography", symlinks=False
        )
        target = root / "ama_cryptography" / "exceptions.py"
        pyc = Path(importlib.util.cache_from_source(str(target)))
        assert pyc.is_file(), "baseline import did not cache exceptions.pyc"

        # Poison = the module's own source plus one harmless statement. The
        # bytecode differs (so the check must catch it) but the module still
        # imports and runs, so nothing crashes before POST reaches the stage —
        # proving the stage, not an incidental import error, is the gate.
        pristine = target.read_text(encoding="utf-8")
        poisoned_code = compile(
            pristine + "\n_EXEC_INTEGRITY_CANARY = 1\n", str(target), "exec", dont_inherit=True
        )
        header = pyc.read_bytes()[:_PYC_HEADER_LEN]
        pyc.write_bytes(header + marshal.dumps(poisoned_code))

        result = _run_python("import ama_cryptography", cwd=root)
        combined = (result.stdout + result.stderr).lower()
        assert result.returncode != 0, f"a poisoned .pyc imported cleanly:\n{combined}"
        assert "execution-integrity" in combined, combined
        assert "poisoned or stale" in combined, combined
        # The source digest itself must NOT be what tripped — the .py is pristine.
        assert "signed digest mismatch" not in combined, combined

    def test_baseline_tree_still_imports(self, importable_tree: Path) -> None:
        """Guards against the poison test passing only because the tree never
        imported: a fresh copy (untouched .pyc) must reach OPERATIONAL."""
        result = _run_python(
            """
            import ama_cryptography as a
            att = a.module_attestation()
            assert att["state"] == "OPERATIONAL", att
            rows = dict((n, d) for n, _p, d in a.module_self_test_results())
            assert "execution-integrity" in rows, rows
            print("OK")
            """,
            cwd=importable_tree,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout
