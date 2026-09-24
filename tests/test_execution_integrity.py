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

import importlib.machinery
import importlib.util
import marshal
import os
import py_compile
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from types import CodeType, FunctionType, ModuleType

import pytest

import ama_cryptography
from ama_cryptography import _self_test as st
from tests.conftest import native_library_present

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

pytestmark = pytest.mark.fips

_PYC_HEADER_LEN = 16  # magic(4) + bit field(4) + (mtime,size | source hash)(8)
_EXT_SUFFIX = importlib.machinery.EXTENSION_SUFFIXES[0]


#: Constant pairs that compare equal under ``==`` but are distinct constants
#: the interpreter executes differently.  Shared with
#: ``tests/test_verify_install_oob.py``, whose out-of-band copy of the
#: comparator must reject the same set.
EQUAL_BUT_DISTINCT_CONSTANTS: list[tuple[object, object]] = [
    ((1,), (True,)),
    ((1,), (1.0,)),
    (((1,),), ((True,),)),
    (frozenset({1, 2}), frozenset({True, 2})),
    (frozenset({1, 2}), frozenset({1.0, 2})),
    (0.0, -0.0),
    ((0.0,), (-0.0,)),
    (0j, complex(-0.0, 0.0)),
    (slice(1, 2, None), slice(True, 2, None)),
]

_PLACEHOLDER = "__placeholder__"


def code_with_constant(value: object) -> CodeType:
    """The code of ``def f(): return <value>``, ``value`` placed in ``co_consts``.

    Built by replacing one constant of a compiled template, which is what a
    poisoned ``.pyc`` does: identical instructions, one constant swapped.
    """
    module = compile(f"def f():\n    return {_PLACEHOLDER!r}\n", "m.py", "exec")
    template = next(c for c in module.co_consts if isinstance(c, CodeType))
    consts = tuple(value if c == _PLACEHOLDER else c for c in template.co_consts)
    assert consts != template.co_consts, "fixture: the placeholder was not a constant"
    return template.replace(co_consts=consts)


def call_code(code: CodeType) -> object:
    """Run a zero-argument function body built by :func:`code_with_constant`."""
    return FunctionType(code, {})()


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

    @pytest.mark.skipif(
        not hasattr((lambda: None).__code__, "co_exceptiontable"),
        reason="co_exceptiontable exists only on Python 3.11+; on 3.10 the same "
        "information is encoded as instructions inside co_code, which is already compared",
    )
    def test_rewritten_exception_table_is_caught(self) -> None:
        """A deleted ``except`` arm with byte-identical ``co_code``.

        From 3.11, exception handling is a side table mapping instruction
        ranges to handlers rather than ``SETUP_FINALLY``-style instructions.
        Blanking that table removes the handler WITHOUT touching one byte of
        ``co_code`` or one entry of ``co_consts`` — so before this was
        compared, a poisoned ``.pyc`` could delete any ``try``/``except`` in
        the package and pass execution integrity.  Applied to the
        ``except Exception`` arms that turn a failed KAT into a POST failure,
        the module would stay OPERATIONAL after a failed FIPS 140-3 §4.9.2
        conditional self-test.

        The assertions below prove the tamper is invisible to every other
        field, so the test fails if the ``co_exceptiontable`` comparison is
        removed rather than merely passing for some other reason.
        """
        src = (
            "def f(x):\n"
            "    try:\n"
            "        if x:\n"
            "            raise ValueError('boom')\n"
            "        return 'no-raise'\n"
            "    except ValueError:\n"
            "        return 'handled'\n"
        )
        fresh = next(c for c in compile(src, "m.py", "exec").co_consts if isinstance(c, CodeType))
        # getattr / kwargs-dict rather than direct access: mypy checks against
        # the 3.10 support floor, where neither the attribute nor the replace()
        # keyword exists.  The skipif above is the runtime guard.
        assert getattr(fresh, "co_exceptiontable", b""), "fixture: the handler makes a table"
        # co_exceptiontable is a 3.11+ only replace() keyword; the skipif above
        # is the runtime guard, and mypy checks against the 3.10 floor (EXI-001)
        blank_table: dict[str, bytes] = {"co_exceptiontable": b""}
        tampered = fresh.replace(**blank_table)  # type: ignore[arg-type]  # 3.10 floor (EXI-001)

        assert fresh.co_code == tampered.co_code, "the tamper must not touch co_code"
        assert fresh.co_consts == tampered.co_consts, "nor co_consts"
        assert not st._code_matches(fresh, tampered)

    def test_constant_type_swap_is_caught(self) -> None:
        """``1 == 1.0`` and ``1 == True`` in Python, so a bare == would let an
        int constant be swapped for an equal-valued float/bool.  The type guard
        closes that."""
        a = compile("v = 1\n", "m.py", "exec")
        b = compile("v = 1.0\n", "m.py", "exec")
        assert not st._code_matches(a, b)

    @pytest.mark.parametrize(
        ("original", "swapped"),
        EQUAL_BUT_DISTINCT_CONSTANTS,
        ids=[f"{o!r}->{s!r}" for o, s in EQUAL_BUT_DISTINCT_CONSTANTS],
    )
    def test_an_equal_but_distinct_constant_is_caught(
        self, original: object, swapped: object
    ) -> None:
        """A swap ``==`` cannot see, inside a container or on a signed zero.

        The guard was ``type(a) is not type(b) or a != b``: exact type for the
        outer value, then ``==``.  A tuple or frozenset passes the type check
        and ``==`` then equates ``1``/``1.0``/``True`` inside it; a float or
        complex passes the type check and ``==`` equates ``0.0`` and ``-0.0``.
        Measured on 3.11.15 before the fix: every pair here was accepted.

        The poisoned object is built the way a poisoned ``.pyc`` is -- same
        instructions, one constant replaced -- rather than by compiling a
        second source, because from 3.14 the compiler also emits the element
        as a separate top-level constant, which the outer type guard already
        caught and which would make this test pass for the wrong reason.
        """
        fresh = code_with_constant(original)
        poisoned = code_with_constant(swapped)

        # The fixture is a real hazard: invisible to ==, visible to the program.
        assert fresh.co_code == poisoned.co_code
        assert fresh.co_consts == poisoned.co_consts, "the swap must be invisible to =="
        assert repr(call_code(fresh)) != repr(call_code(poisoned)), "the swap must change behaviour"

        assert st._code_matches(fresh, code_with_constant(original)), "control: same constant"
        assert not st._code_matches(fresh, poisoned)

    def test_a_genuine_pyc_of_folded_constants_still_verifies(self, tmp_path: Path) -> None:
        """Non-vacuity, through the per-file path POST runs.

        A key that rejected every tuple, frozenset, slice or float would pass
        the test above and fail every install, so this compiles a module full
        of them with ``py_compile`` -- a genuine ``.pyc`` -- and verifies it.

        It also carries a constant-folded NaN.  ``nan != nan``, so under ``==``
        a faithful ``.pyc`` holding one was reported poisoned; ``1e999 -
        1e999`` folds to NaN on every supported interpreter (measured on
        3.10.20, 3.11.15, 3.12.3, 3.13.12 and 3.14.0rc2).  Keyed by its bit
        pattern it equals itself, as it does in the compiler's own constant
        de-duplication.
        """
        body = (
            "A = (1, 2.5, -0.0, b'x', None, ...)\n"
            "B = 1e999 - 1e999\n"
            "def f(x):\n"
            "    return x in {1, 2, 3} or x in ('a', 'b') or x == 1j or x[1:2]\n"
        )
        py = _make_module(tmp_path, "folded", body)
        fresh = compile(body, str(py), "exec")
        assert any(isinstance(c, float) and c != c for c in fresh.co_consts), "fixture: NaN"
        py_compile.compile(str(py), doraise=True)
        assert st._verify_source_file_bytecode(py) == ("verified", None)

    def test_a_poisoned_pyc_with_a_nested_swap_is_caught(self, tmp_path: Path) -> None:
        """End to end: ``(1,)`` swapped for ``(True,)`` in a loadable ``.pyc``.

        ``dont_inherit=True`` matters: without it ``compile()`` inherits this
        module's ``from __future__ import annotations`` flag, the poisoned
        object then differs in ``co_flags`` as well, and the test passes on
        the flag rather than on the constant.  The control write below proves
        the swap is the only difference.
        """
        py = _make_module(tmp_path, "nested", "A = (1,)\n")
        py_compile.compile(str(py), doraise=True)
        pyc = Path(importlib.util.cache_from_source(str(py)))
        fresh = compile("A = (1,)\n", str(py), "exec", dont_inherit=True)
        assert any(
            isinstance(c, tuple) and c == (1,) for c in fresh.co_consts
        ), "fixture: the tuple constant is present"

        _poison_pyc_body(pyc, fresh)
        assert st._verify_source_file_bytecode(py) == ("verified", None), "control"

        consts = tuple(
            (True,) if isinstance(c, tuple) and c == (1,) else c for c in fresh.co_consts
        )
        poisoned = fresh.replace(co_consts=consts)
        assert poisoned.co_consts == fresh.co_consts, "fixture: invisible to =="
        _poison_pyc_body(pyc, poisoned)
        status, error = st._verify_source_file_bytecode(py)
        assert status == "verified"
        assert error is not None and "poisoned or stale" in error

    def test_a_code_object_inside_a_container_never_matches(self) -> None:
        """Fail closed on a shape no faithful compile produces.

        The compiler never nests a code object in a tuple or frozenset
        constant, so ``_const_key`` keys one by identity rather than
        descending into it: two such tuples can only mismatch, even when the
        code objects are identical.
        """
        inner = compile("x = 1\n", "m.py", "exec")
        a = code_with_constant((inner,))
        b = code_with_constant((compile("x = 1\n", "m.py", "exec"),))
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

    def test_timestamp_stale_pyc_is_skipped(self, tmp_path: Path) -> None:
        """A (mtime,size)-invalid cache is recompiled by the interpreter.

        The same rule the wrong-magic case already applied: bytecode the
        running interpreter refuses to load is not what executes and is not
        ours to judge.  Judging it produced a false ``poisoned or stale .pyc``
        POST failure for the most ordinary state there is — edit a lazily
        imported module, re-sign, and the next import died on a cache that
        never ran, in a stage ``AMA_BUILD_PIPELINE=1`` does not repair.
        """
        py = _make_module(tmp_path, "stale_ts", "X = 5\n")
        py_compile.compile(str(py), doraise=True)
        # Change the size as well as the content: the header records the source
        # size alongside a whole-second mtime, so a same-size rewrite inside the
        # same second would still look current.
        py.write_text("X = 5\nY = 6\nZ = 7\n", encoding="utf-8")
        assert st._verify_source_file_bytecode(py) == ("skipped", None)

    def test_checked_hash_stale_pyc_is_skipped(self, tmp_path: Path) -> None:
        """PEP 552 checked-hash caches are validated by the interpreter too."""
        py = _make_module(tmp_path, "stale_hash", "X = 8\n")
        py_compile.compile(
            str(py), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH
        )
        py.write_text("X = 9\n", encoding="utf-8")
        assert st._verify_source_file_bytecode(py) == ("skipped", None)

    def test_unchecked_hash_pyc_is_still_judged(self, tmp_path: Path) -> None:
        """An UNCHECKED-hash cache is loaded blindly, so it must still be judged.

        This is the direction that matters for the attack: the interpreter does
        not validate the recorded hash, so a poisoned body executes.  Skipping
        every cache whose source moved on would have handed exactly this case a
        pass.
        """
        py = _make_module(tmp_path, "unchecked", "SECRET = 1\n\ndef check():\n    return True\n")
        py_compile.compile(
            str(py), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH
        )
        pyc = Path(importlib.util.cache_from_source(str(py)))
        poisoned = compile("SECRET = 1\n\ndef check():\n    return False\n", str(py), "exec")
        _poison_pyc_body(pyc, poisoned)
        status, error = st._verify_source_file_bytecode(py)
        assert status == "verified"
        assert error is not None and "poisoned or stale" in error

    def test_truncated_header_is_a_fault(self, tmp_path: Path) -> None:
        """A cache too short to carry a validation header is a fault, not a skip."""
        py = _make_module(tmp_path, "truncated", "X = 10\n")
        py_compile.compile(str(py), doraise=True)
        pyc = Path(importlib.util.cache_from_source(str(py)))
        pyc.write_bytes(pyc.read_bytes()[:10])
        status, error = st._verify_source_file_bytecode(py)
        assert status == "verified"
        assert error is not None and "truncated header" in error


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

    # A module's __file__ that is not a ``.py`` used to end the check.  Each of
    # these was returned as None before, while the import system was serving
    # the file in place of signed source.
    def test_sourceless_bytecode_is_flagged(self) -> None:
        pyc = _fake_module(str(PKG_DIR / "crypto_api" / "__init__.pyc"))
        err = st._detect_module_substitution("ama_cryptography.crypto_api", pyc, PKG_DIR)
        assert err is not None and "sourceless bytecode" in err

    def test_extension_package_init_is_flagged(self) -> None:
        ext = _fake_module(str(PKG_DIR / "crypto_api" / f"__init__{_EXT_SUFFIX}"))
        err = st._detect_module_substitution("ama_cryptography.crypto_api", ext, PKG_DIR)
        assert err is not None and "not a top-level binding" in err

    def test_extension_init_at_top_level_is_flagged(self) -> None:
        # Not in a subdirectory, so only the __init__ clause can reject it.
        ext = _fake_module(str(PKG_DIR / f"__init__{_EXT_SUFFIX}"))
        err = st._detect_module_substitution("ama_cryptography", ext, PKG_DIR)
        assert err is not None and "not a top-level binding" in err

    def test_extension_outside_package_is_flagged(self, tmp_path: Path) -> None:
        ext = _fake_module(str(tmp_path / f"sha3_binding{_EXT_SUFFIX}"))
        err = st._detect_module_substitution("ama_cryptography.sha3_binding", ext, PKG_DIR)
        assert err is not None and "module substitution" in err


# ---------------------------------------------------------------------------
# 3b. _find_import_shadowing — files the import system would load in place of
#     (or outside of) the signed source set
# ---------------------------------------------------------------------------
def _shadow_tree(tmp_path: Path) -> Path:
    """A scratch package laid out like the shipped one, which must scan clean."""
    pkg = tmp_path / "pkg"
    (pkg / "__pycache__").mkdir(parents=True)
    (pkg / "_post_kats").mkdir()
    for name in ("__init__.py", "crypto_api.py", "pqc_backends.py"):
        (pkg / name).write_text("X = 1\n", encoding="utf-8")
    (pkg / "sha3_binding.pyi").write_text("", encoding="utf-8")
    (pkg / f"sha3_binding{_EXT_SUFFIX}").write_bytes(b"ext")
    (pkg / "libama_cryptography.so").write_bytes(b"lib")
    (pkg / "libama_cryptography.so.5").write_bytes(b"lib")
    (pkg / "_post_kats" / "ml_kem_1024_kat.json").write_text("{}", encoding="utf-8")
    # A cache whose source is gone: PEP 3147 says the import system ignores it.
    (pkg / "__pycache__" / "gone.cpython-311.pyc").write_bytes(b"pyc")
    (pkg / "__pycache__" / "crypto_api.cpython-311.pyc").write_bytes(b"pyc")
    return pkg


def _scan(pkg: Path) -> list[str]:
    return ama_cryptography._find_import_shadowing(str(pkg))


class TestImportShadowingScan:
    def test_shipped_layout_is_clean(self, tmp_path: Path) -> None:
        assert _scan(_shadow_tree(tmp_path)) == []

    def test_namespace_directory_with_source_is_clean(self, tmp_path: Path) -> None:
        # No __init__: at most a namespace portion, which never shadows a
        # module file; any .py in it is inside the recursive signed digest.
        pkg = _shadow_tree(tmp_path)
        (pkg / "_post_kats" / "helper.py").write_text("Y = 2\n", encoding="utf-8")
        assert _scan(pkg) == []

    def test_sourceless_init_shadowing_a_module_is_refused(self, tmp_path: Path) -> None:
        """The reported attack, sourceless variant."""
        pkg = _shadow_tree(tmp_path)
        (pkg / "crypto_api").mkdir()
        (pkg / "crypto_api" / "__init__.pyc").write_bytes(b"pyc")
        faults = _scan(pkg)
        assert any("package directory shadows crypto_api.py" in f for f in faults), faults
        assert any("crypto_api/__init__.pyc: sourceless bytecode" in f for f in faults), faults

    def test_extension_init_shadowing_a_module_is_refused(self, tmp_path: Path) -> None:
        """The reported attack, extension variant."""
        pkg = _shadow_tree(tmp_path)
        (pkg / "pqc_backends").mkdir()
        (pkg / "pqc_backends" / f"__init__{_EXT_SUFFIX}").write_bytes(b"ext")
        faults = _scan(pkg)
        assert any("package directory shadows pqc_backends.py" in f for f in faults), faults
        assert any("below the package's top level" in f for f in faults), faults

    def test_source_package_shadowing_a_module_is_refused(self, tmp_path: Path) -> None:
        # Its __init__.py would change the digest, but only at POST — after a
        # shadowed _self_test or _module_state had already run in its place.
        pkg = _shadow_tree(tmp_path)
        (pkg / "crypto_api").mkdir()
        (pkg / "crypto_api" / "__init__.py").write_text("X = 2\n", encoding="utf-8")
        faults = _scan(pkg)
        assert faults == [
            "crypto_api/__init__.py: package directory shadows crypto_api.py — "
            "the import system resolves a package directory first"
        ]

    def test_extension_package_shadowing_a_binding_is_refused(self, tmp_path: Path) -> None:
        # ``from ama_cryptography.sha3_binding import ...`` (pqc_backends' probe)
        # would load the directory, not the signed top-level extension.
        pkg = _shadow_tree(tmp_path)
        (pkg / "sha3_binding").mkdir()
        (pkg / "sha3_binding" / f"__init__{_EXT_SUFFIX}").write_bytes(b"ext")
        faults = _scan(pkg)
        assert any(f"shadows sha3_binding{_EXT_SUFFIX}" in f for f in faults), faults

    def test_nested_extension_without_a_shadow_is_refused(self, tmp_path: Path) -> None:
        pkg = _shadow_tree(tmp_path)
        (pkg / "_post_kats" / f"evil{_EXT_SUFFIX}").write_bytes(b"ext")
        faults = _scan(pkg)
        assert faults == [
            f"_post_kats/evil{_EXT_SUFFIX}: extension module below the package's top "
            "level — outside the signed binding map"
        ]

    def test_top_level_sourceless_bytecode_is_refused(self, tmp_path: Path) -> None:
        # Shadows nothing (source beats bytecode), but serves any name with no
        # .py — an unbuilt binding, for one.
        pkg = _shadow_tree(tmp_path)
        (pkg / "hmac_binding.pyc").write_bytes(b"pyc")
        faults = _scan(pkg)
        assert faults == [
            "hmac_binding.pyc: sourceless bytecode outside __pycache__ — importable, "
            "and covered by no integrity layer"
        ]

    def test_extension_beside_source_of_the_same_name_is_refused(self, tmp_path: Path) -> None:
        pkg = _shadow_tree(tmp_path)
        (pkg / f"crypto_api{_EXT_SUFFIX}").write_bytes(b"ext")
        faults = _scan(pkg)
        assert faults == [
            f"crypto_api{_EXT_SUFFIX}: extension module shadows crypto_api.py — the "
            "import system loads the extension in its place"
        ]

    def test_symlinked_package_directory_is_refused(self, tmp_path: Path) -> None:
        pkg = _shadow_tree(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "__init__.py").write_text("X = 3\n", encoding="utf-8")
        try:
            os.symlink(outside, pkg / "extra", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"cannot create a directory symlink here: {exc}")
        faults = _scan(pkg)
        assert faults == [
            "extra/__init__.py: symlinked package directory — the signed digest "
            "does not walk directory symlinks"
        ]


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

    def test_real_tree_has_no_import_shadowing(self) -> None:
        assert _scan(PKG_DIR) == []

    def test_post_runs_the_shadowing_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pass 1 is wired into the stage, not only into ``__init__``."""
        monkeypatch.setattr(
            ama_cryptography, "_find_import_shadowing", lambda _pkg_dir: ["planted: canary"]
        )
        ok, _verified, _skipped, problems = st._check_execution_integrity()
        assert not ok
        assert "planted: canary" in problems


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


# ---------------------------------------------------------------------------
# 6. End to end: a planted package directory is refused before it can run
# ---------------------------------------------------------------------------
def _private_copy(importable_tree: Path, tmp_path: Path) -> Path:
    root = tmp_path / "planted"
    shutil.copytree(importable_tree / "ama_cryptography", root / "ama_cryptography", symlinks=False)
    return root


def _plant_sourceless_init(pkg: Path, name: str, marker: Path, scratch: Path) -> None:
    """``<name>/__init__.pyc``: the signed ``<name>.py`` plus a side effect.

    Faithful to the attack, so its only observable difference is the marker:
    ``__file__`` is pointed back at the signed ``.py`` (so the module's own
    path arithmetic and the loaded-module check both see the right path), and
    the body is the pristine module.  Compiled with ``py_compile``, exactly the
    recipe the finding gives; no ``.py`` is added to the package, so the signed
    digest does not move.
    """
    body = (pkg / f"{name}.py").read_text(encoding="utf-8")
    prelude = (
        f"__file__ = {str(pkg / f'{name}.py')!r}\n"
        "import pathlib as _planted_pathlib\n"
        f"_planted_pathlib.Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n"
    )
    future = "from __future__ import annotations\n"
    if future in body:
        body = body.replace(future, future + prelude, 1)
    else:
        body = prelude + body
    payload = scratch / f"planted_{name}.py"
    payload.write_text(body, encoding="utf-8")
    (pkg / name).mkdir()
    py_compile.compile(str(payload), cfile=str(pkg / name / "__init__.pyc"), doraise=True)


class TestImportShadowingEndToEnd:
    def test_sourceless_init_is_refused_before_it_runs(
        self, importable_tree: Path, tmp_path: Path
    ) -> None:
        """``_artefact_source`` is the first submodule the package imports (the
        binding gate reads the artefact through it), so a planted replacement
        would run before any check that follows.  Before the fix the import
        completed OPERATIONAL with the marker written."""
        root = _private_copy(importable_tree, tmp_path)
        marker = tmp_path / "planted_code_ran"
        _plant_sourceless_init(root / "ama_cryptography", "_artefact_source", marker, tmp_path)

        result = _run_python("import ama_cryptography", cwd=root)
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"a planted package directory imported:\n{combined}"
        assert not marker.exists(), "the planted module executed"
        assert "Refused BEFORE any submodule was imported" in combined, combined
        assert "package directory shadows _artefact_source.py" in combined, combined

    def test_extension_init_is_refused(self, importable_tree: Path, tmp_path: Path) -> None:
        """``crypto_api`` is imported lazily, so before the fix the package
        imported cleanly with ``crypto_api/__init__<suffix>`` waiting to be
        loaded on first use.  The file's content is irrelevant to the scan."""
        root = _private_copy(importable_tree, tmp_path)
        planted = root / "ama_cryptography" / "crypto_api"
        planted.mkdir()
        (planted / f"__init__{_EXT_SUFFIX}").write_bytes(b"\x7fELF planted")

        result = _run_python("import ama_cryptography", cwd=root)
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"a planted extension package imported:\n{combined}"
        assert "package directory shadows crypto_api.py" in combined, combined

    def test_reset_module_post_refuses_a_directory_planted_after_import(
        self, importable_tree: Path, tmp_path: Path
    ) -> None:
        """The POST pass, not only the pre-import gate: a tree changed after a
        clean import fails the execution-integrity stage on ``reset_module``."""
        root = _private_copy(importable_tree, tmp_path)
        result = _run_python(
            """
            import pathlib, py_compile
            import ama_cryptography as a
            assert a.module_attestation()["state"] == "OPERATIONAL"
            pkg = pathlib.Path(a.__file__).parent
            (pkg / "crypto_api").mkdir()
            src = pathlib.Path("planted_src.py")
            src.write_text("X = 1\\n", encoding="utf-8")
            planted = pkg / "crypto_api" / "__init__.pyc"
            py_compile.compile(str(src), cfile=str(planted), doraise=True)
            print("RESET", a.reset_module())
            rows = {n: (p, d) for n, p, d in a.module_self_test_results()}
            print("ROW", rows.get("execution-integrity"))
            """,
            cwd=root,
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert "RESET False" in result.stdout, combined
        assert "package directory shadows crypto_api.py" in result.stdout, combined
