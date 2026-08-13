#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
The ctypes ABI contract gate (INVARIANT-42, static half)
========================================================

Two directions.  The repository must pass its own gate — every assigned
ctypes signature agrees with the C header prototype for that symbol.  And the
gate must be able to *fail*: each defect class it exists to catch (an arity
change, a pointer/integer confusion, a misread return convention, a called
symbol with no declared signature, a signature for an undeclared symbol) is
demonstrated on synthetic input.  A gate whose rejection direction is never
exercised is a green light wired to nothing.
"""

from __future__ import annotations

import ast
import subprocess  # nosec B404 -- fixed-argv invocation of the repo's own tool (ABI-001)
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "tools"))
try:
    import check_ctypes_abi as gate  # type: ignore[import-not-found]  # loaded from tools/ via runtime sys.path insert; mypy cannot see it (ABI-002)
finally:
    sys.path.pop(0)


_HEADER = textwrap.dedent("""
    AMA_API int ama_two_args(const uint8_t* data, size_t len);
    AMA_API void ama_void_return(uint8_t* out);
    AMA_API int ama_uncalled(void);
    AMA_API ama_error_t ama_multiline(ama_algorithm_t alg,
                                      uint8_t *pk, size_t pk_len);
    """)


def _signatures_for(source: str, origin: str = "synthetic.py") -> Any:
    return gate.parse_python_signatures(ast.parse(textwrap.dedent(source)), origin)


class TestHeaderParser:
    def test_parses_prototypes_including_multiline(self) -> None:
        protos = gate.parse_header(_HEADER)
        assert protos["ama_two_args"].params == ("ptr", "int")
        assert protos["ama_two_args"].ret == "int"
        assert protos["ama_void_return"].ret == "void"
        assert protos["ama_uncalled"].params == ()
        assert protos["ama_multiline"].params == ("int", "ptr", "int")

    def test_comments_cannot_masquerade_as_prototypes(self) -> None:
        protos = gate.parse_header("/* AMA_API int ama_ghost(int a); */")
        assert "ama_ghost" not in protos


class TestRejectionDirections:
    def test_arity_drift_is_flagged(self) -> None:
        sigs, called, problems = _signatures_for("""
            lib.ama_two_args.argtypes = [ctypes.c_char_p]
            lib.ama_two_args.restype = ctypes.c_int
            """)
        assert problems == []
        found, checked = gate.check(gate.parse_header(_HEADER), [("synthetic.py", sigs, called)])
        assert checked == 1
        assert any("argtypes" in p and "ama_two_args" in p for p in found)

    def test_pointer_integer_confusion_is_flagged(self) -> None:
        sigs, called, _ = _signatures_for("""
            lib.ama_two_args.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            """)
        found, _ = gate.check(gate.parse_header(_HEADER), [("synthetic.py", sigs, called)])
        assert any("['ptr', 'ptr']" in p for p in found)

    def test_void_return_read_as_value_is_flagged(self) -> None:
        sigs, called, _ = _signatures_for("""
            lib.ama_void_return.argtypes = [ctypes.c_char_p]
            lib.ama_void_return.restype = ctypes.c_int
            """)
        found, _ = gate.check(gate.parse_header(_HEADER), [("synthetic.py", sigs, called)])
        assert any("restype" in p and "ama_void_return" in p for p in found)

    def test_called_but_unsigned_symbol_is_flagged(self) -> None:
        sigs, called, _ = _signatures_for("""
            def f(lib):
                return lib.ama_two_args(b"x", 1)
            """)
        assert "ama_two_args" in called and "ama_two_args" not in sigs
        found, _ = gate.check(gate.parse_header(_HEADER), [("synthetic.py", sigs, called)])
        assert any("CALLED but never assigned" in p for p in found)

    def test_signature_for_undeclared_symbol_is_flagged(self) -> None:
        sigs, called, _ = _signatures_for("""
            lib.ama_not_in_any_header.argtypes = [ctypes.c_int]
            """)
        found, _ = gate.check(gate.parse_header(_HEADER), [("synthetic.py", sigs, called)])
        assert any("no AMA_API prototype" in p for p in found)

    def test_matching_signatures_pass(self) -> None:
        sigs, called, problems = _signatures_for("""
            lib.ama_two_args.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            lib.ama_two_args.restype = ctypes.c_int
            lib.ama_void_return.argtypes = [ctypes.c_char_p]
            lib.ama_void_return.restype = None
            lib.ama_multiline.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
            lib.ama_multiline.restype = ctypes.c_int
            """)
        assert problems == []
        found, checked = gate.check(gate.parse_header(_HEADER), [("synthetic.py", sigs, called)])
        assert found == [] and checked == 3


class TestMainFailurePaths:
    """The gate's exit-code wiring, not just its predicates (review F10).

    ``check()`` producing a problem means nothing if ``main()`` does not turn
    it into a nonzero exit — that one line of plumbing is what CI actually
    consumes, so both failure exits are driven end to end here.
    """

    def _run_main(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        header: str,
        module_source: str,
    ) -> int:
        (tmp_path / "mod.py").write_text(textwrap.dedent(module_source), encoding="utf-8")
        header_file = tmp_path / "header.h"
        header_file.write_text(header, encoding="utf-8")
        monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(gate, "HEADER", header_file)
        monkeypatch.setattr(gate, "EXTRA_HEADERS", ())
        monkeypatch.setattr(gate, "MODULES", ("mod.py",))
        return int(gate.main([]))

    def test_a_mismatch_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        rc = self._run_main(
            monkeypatch,
            tmp_path,
            _HEADER,
            """
            lib.ama_two_args.argtypes = [ctypes.c_char_p]
            """,
        )
        assert rc == 1

    def test_an_unclassifiable_expression_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A parse problem must reach the exit code, not just a list."""
        rc = self._run_main(
            monkeypatch,
            tmp_path,
            _HEADER,
            """
            lib.ama_two_args.argtypes = make_argtypes()
            lib.ama_void_return.argtypes = [ctypes.c_char_p]
            """,
        )
        assert rc == 1

    def test_zero_checked_signatures_is_a_checker_bug_not_a_pass(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        rc = self._run_main(monkeypatch, tmp_path, _HEADER, "x = 1\n")
        assert rc == 2


class TestExtractionIdioms:
    def test_list_multiplication_and_getattr_loop(self) -> None:
        sigs, called, problems = _signatures_for("""
            lib.ama_two_args.argtypes = [ctypes.c_char_p] * 2
            for name in ("ama_void_return",):
                fn = getattr(lib, name)
                fn.argtypes = [ctypes.c_char_p]
                fn.restype = None
            """)
        assert problems == []
        assert sigs["ama_two_args"]["params"] == ("ptr", "ptr")
        assert sigs["ama_void_return"]["params"] == ("ptr",)
        assert sigs["ama_void_return"]["ret"] == "void"
        assert "ama_void_return" in called

    def test_alias_assignment_resolves(self) -> None:
        sigs, _, problems = _signatures_for("""
            lib.ama_two_args.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            lib.ama_multiline.argtypes = lib.ama_two_args.argtypes
            """)
        assert problems == []
        assert sigs["ama_multiline"]["params"] == ("ptr", "int")

    def test_unclassifiable_expression_is_a_problem_not_a_skip(self) -> None:
        _, _, problems = _signatures_for("""
            lib.ama_two_args.argtypes = make_argtypes()
            """)
        assert any("cannot classify" in p for p in problems)

    def test_local_binding_idiom_is_extracted_and_counted_as_called(self) -> None:
        """``fn = lib.ama_x`` then ``fn.argtypes = …`` / ``fn(...)`` (review F1).

        This idiom escaped the gate in BOTH directions — no signature and no
        call recorded — and its two live uses included the version
        handshake's own ctypes call, the one call in the package that runs
        against an unvalidated object.
        """
        sigs, called, problems = _signatures_for("""
            def probe(lib):
                fn = lib.ama_void_return
                fn.argtypes = [ctypes.c_char_p]
                fn.restype = None
                fn(b"x")
            """)
        assert problems == []
        assert sigs["ama_void_return"]["params"] == ("ptr",)
        assert sigs["ama_void_return"]["ret"] == "void"
        assert "ama_void_return" in called

    def test_binding_scope_does_not_leak_between_functions(self) -> None:
        """An ``fn`` in one function must not contaminate another's."""
        sigs, called, _ = _signatures_for("""
            def one(lib):
                fn = lib.ama_two_args
                fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

            def two(other):
                fn = other.unrelated
                fn(1)
            """)
        assert sigs["ama_two_args"]["params"] == ("ptr", "int")
        # Neither function CALLS an ama_ symbol (one only configures, two
        # calls a non-ama binding), so nothing may be recorded as called.
        assert called == set()


class TestThisRepository:
    def test_repository_passes_the_gate_and_it_is_not_vacuous(self) -> None:
        result = subprocess.run(  # nosec B603 -- fixed argv, repo tool, no shell (ABI-001)
            [sys.executable, str(REPO_ROOT / "tools" / "check_ctypes_abi.py")],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        # Vacuity guard, pinned TIGHT (review F11): the tree checks 126
        # signatures today, and the getattr-loop and local-binding idioms
        # contribute 13 of them — a loose floor (>= 100) would stay green
        # through the silent loss of every one of those.  Growing the native
        # surface legitimately raises this number; update it with the change
        # that does.
        assert "OK:" in result.stdout
        checked = int(result.stdout.split("OK:")[1].split()[0])
        assert checked >= 126, result.stdout

    def test_the_fragile_extraction_idioms_are_present_on_the_real_tree(self) -> None:
        """Sentinels for the idioms a refactor can silently defeat (F4/F11).

        Hoisting a loop's symbol tuple to a module constant, or renaming a
        local binding, would drop these from extraction with no error — the
        exact-symbol assertions here are the tripwire.
        """
        import ast as _ast

        src = (REPO_ROOT / "ama_cryptography" / "pqc_backends.py").read_text(encoding="utf-8")
        sigs, called, _ = gate.parse_python_signatures(
            _ast.parse(src), "ama_cryptography/pqc_backends.py"
        )
        for symbol in (
            # getattr-loop groups
            "ama_hkdf_sha256",
            "ama_hkdf_sha512",
            "ama_shake128",
            "ama_shake256",
            "ama_ml_kem_public_key_bytes",
            "ama_ml_dsa_signature_bytes",
            # the local-binding idiom (the version handshake's own call)
            "ama_version_number",
        ):
            assert symbol in sigs, f"{symbol} lost from extraction"
        assert "ama_version_number" in called

        src_sm = (REPO_ROOT / "ama_cryptography" / "secure_memory.py").read_text(encoding="utf-8")
        sigs_sm, called_sm, _ = gate.parse_python_signatures(
            _ast.parse(src_sm), "ama_cryptography/secure_memory.py"
        )
        assert "ama_secure_memzero" in sigs_sm
        assert "ama_secure_memzero" in called_sm
