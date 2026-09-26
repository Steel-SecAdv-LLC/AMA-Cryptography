# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every exported ``ama_*`` symbol is declared ``AMA_API`` in an installed header.

``cmake/ama_exports.map`` exports the ``ama_*`` wildcard.  Before this rule,
``tools/check_export_allowlist.py`` checked only the prefix and
``tools/check_public_api_docs.py`` only the declared-minus-exported direction,
so a non-static ``ama_zz_undeclared_internal`` added anywhere under ``src/c``
was exported and both gates passed.  ``check_exports`` now checks the reverse
direction too: exported minus declared-in-an-installed-header.

These drive ``check_exports`` with a substituted symbol table, so the rule is
pinned on every runner whatever library (if any) it built.  Each negative
control was mutation-checked: with the mechanism it names removed from the
gate, it fails.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_public_api_docs.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_public_api_docs_exports", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _failures(gate: ModuleType, repo: Path, exported: Iterable[str]) -> list[str]:
    symbols = frozenset(exported)
    report = gate.Report()
    with mock.patch.object(gate, "dynamic_symbols", lambda _library: symbols):
        gate.check_exports(report, repo, Path("libama_cryptography.so"))
    return list(report.failures)


def _clean(gate: ModuleType) -> set[str]:
    """Exactly the declared public ABI: what a correct library exports."""
    return set(gate.declared_public_symbols(REPO_ROOT)) | set(gate.MUST_BE_EXPORTED)


class TestTheDeclaredSetIsTheInstalledHeaders:
    def test_the_installed_headers_come_from_cmakelists(self, gate: ModuleType) -> None:
        installed = {
            path.relative_to(REPO_ROOT).as_posix()
            for path in gate.installed_public_headers(REPO_ROOT)
        }
        assert {"include/ama_cryptography.h", "include/ama_dispatch.h"} <= installed

    def test_the_second_installed_header_is_counted(self, gate: ModuleType) -> None:
        """``ama_dispatch_init`` is declared only in include/ama_dispatch.h."""
        assert "ama_dispatch_init" in gate.declared_public_symbols(REPO_ROOT)
        assert _failures(gate, REPO_ROOT, _clean(gate) | {"ama_dispatch_init"}) == []

    def test_a_cmakelists_without_public_header_fails_closed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        (tmp_path / "CMakeLists.txt").write_text("project(x C)\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="PUBLIC_HEADER"):
            gate.installed_public_headers(tmp_path)

    def test_an_installed_header_that_does_not_exist_fails_closed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        (tmp_path / "CMakeLists.txt").write_text(
            'set_target_properties(t PROPERTIES PUBLIC_HEADER "include/gone.h")\n',
            encoding="utf-8",
        )
        with pytest.raises(RuntimeError, match=r"include/gone\.h"):
            gate.installed_public_headers(tmp_path)

    def test_a_commented_out_prototype_is_not_a_declaration(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        (tmp_path / "include").mkdir()
        (tmp_path / "CMakeLists.txt").write_text(
            'set_target_properties(t PROPERTIES PUBLIC_HEADER "include/a.h")\n',
            encoding="utf-8",
        )
        (tmp_path / "include" / "a.h").write_text(
            "/* AMA_API int ama_ghost_block(void); */\n"
            "// AMA_API int ama_ghost_line(void);\n"
            "AMA_API int ama_real(void);\n",
            encoding="utf-8",
        )
        assert gate.declared_public_symbols(tmp_path) == frozenset({"ama_real"})

    def test_a_prototype_without_amaapi_is_not_a_declaration(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """The PE export table is generated from AMA_API declarations.

        A name an installed header declares without AMA_API is therefore on the
        ELF and Mach-O ABI and absent from the DLL -- one ABI per platform.
        """
        (tmp_path / "include").mkdir()
        (tmp_path / "CMakeLists.txt").write_text(
            'set_target_properties(t PROPERTIES PUBLIC_HEADER "include/a.h")\n',
            encoding="utf-8",
        )
        (tmp_path / "include" / "a.h").write_text(
            "int ama_plain(void);\nAMA_API int ama_real(void);\n", encoding="utf-8"
        )
        assert gate.declared_public_symbols(tmp_path) == frozenset({"ama_real"})

    def test_an_uninstalled_header_in_include_is_not_the_abi(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Location is not the criterion; being installed is."""
        (tmp_path / "include").mkdir()
        (tmp_path / "CMakeLists.txt").write_text(
            'set_target_properties(t PROPERTIES PUBLIC_HEADER "include/a.h")\n',
            encoding="utf-8",
        )
        (tmp_path / "include" / "a.h").write_text("AMA_API int ama_real(void);\n", encoding="utf-8")
        (tmp_path / "include" / "b.h").write_text(
            "AMA_API int ama_not_installed(void);\n", encoding="utf-8"
        )
        assert gate.declared_public_symbols(tmp_path) == frozenset({"ama_real"})


class TestTheReverseDirection:
    def test_the_declared_abi_passes(self, gate: ModuleType) -> None:
        """Positive control: a library exporting exactly the declared set is clean."""
        assert _failures(gate, REPO_ROOT, _clean(gate)) == []

    def test_an_undeclared_export_fails(self, gate: ModuleType) -> None:
        """The reported defect: a non-static helper under src/c becomes ABI."""
        failures = _failures(gate, REPO_ROOT, _clean(gate) | {"ama_zz_undeclared_internal"})
        assert len(failures) == 1, failures
        assert "ama_zz_undeclared_internal" in failures[0]
        assert "declared AMA_API in no installed public header" in failures[0]

    def test_amaapi_in_an_uninstalled_header_does_not_count(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """AMA_API in an uninstalled header, plus a mention in an installed
        header's COMMENT, is not a declaration: an out-of-tree consumer has no
        prototype for it.  (The real-tree case that motivated this,
        ``ama_sha256``, was fixed by declaring it in the public header.)"""
        (tmp_path / "include").mkdir()
        (tmp_path / "src").mkdir()
        (tmp_path / "CMakeLists.txt").write_text(
            'set_target_properties(t PROPERTIES PUBLIC_HEADER "include/a.h")\n',
            encoding="utf-8",
        )
        (tmp_path / "include" / "a.h").write_text(
            "/* see AMA_API void ama_helper(void); in src/h.h */\nAMA_API int ama_real(void);\n",
            encoding="utf-8",
        )
        (tmp_path / "src" / "h.h").write_text("AMA_API void ama_helper(void);\n", encoding="utf-8")
        assert gate.declared_public_symbols(tmp_path) == frozenset({"ama_real"})

    def test_the_real_trees_formerly_undeclared_exports_are_resolved(
        self, gate: ModuleType
    ) -> None:
        """``ama_sha256`` (bound by Python) is declared in an installed header;
        ``ama_has_avx2`` (declared only in the uninstalled include/ama_cpuid.h)
        is not, and is therefore reported if it is ever exported again."""
        declared = gate.declared_public_symbols(REPO_ROOT)
        assert "ama_sha256" in declared
        assert "ama_has_avx2" not in declared

    def test_a_compiler_clone_is_reported_once_not_twice(self, gate: ModuleType) -> None:
        failures = _failures(gate, REPO_ROOT, _clean(gate) | {"ama_hmac_sha256.part.0"})
        assert len(failures) == 1, failures
        assert "compiler-generated" in failures[0]


# ---------------------------------------------------------------------------
# tools/check_export_allowlist.py — the same ABI, enforced on the built object
# ---------------------------------------------------------------------------
#
# The allowlist gate checked the ``ama_`` PREFIX, and the version script
# exports the ``ama_*`` wildcard: the internal names ``cmake/ama_exports.map``
# localises, and any non-static helper added under ``src/c``, all carry the
# prefix.  So a version script that lost a ``local:`` entry — re-publishing an
# AES-GCM SIMD kernel that skips the entry point's length limits — passed that
# gate with "no offenders".  Its allowlist is now the declared ABI read above:
# ``AMA_API`` in an installed header, minus the localised names.  Each control
# drives it with a substituted symbol table, so the rule is pinned on every
# runner whatever library (if any) it built.

ALLOWLIST_PATH = REPO_ROOT / "tools" / "check_export_allowlist.py"


@pytest.fixture(scope="module")
def allowlist() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_export_allowlist", ALLOWLIST_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _main_over(
    allowlist: ModuleType, monkeypatch: pytest.MonkeyPatch, symbols: list[str], tmp_path: Path
) -> int:
    library = tmp_path / "libama_cryptography.so.5.0.0"
    library.write_bytes(b"\x7fELF")
    monkeypatch.setattr(allowlist, "_exported_symbols", lambda _lib: list(symbols))
    return int(allowlist.main([str(library)]))


def test_the_declared_abi_is_the_installed_headers_minus_the_localised(
    allowlist: ModuleType,
) -> None:
    public = allowlist._public_api_gate()
    declared = public.declared_public_symbols(REPO_ROOT)
    localised = public.localised_symbols(REPO_ROOT)
    allowed = allowlist.declared_abi(REPO_ROOT)
    assert allowed == declared - localised
    assert len(allowed) >= allowlist.MIN_AMA_EXPORTS, "the allowlist cannot clear the floor"


def test_exactly_the_declared_abi_passes(
    allowlist: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Positive control: the set a correct library exports, plus a linker marker."""
    symbols = [*sorted(allowlist.declared_abi(REPO_ROOT)), "_init"]
    assert _main_over(allowlist, monkeypatch, symbols, tmp_path) == 0


def test_an_undeclared_ama_export_fails(
    allowlist: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-static helper under src/c matches the ``ama_*`` wildcard.

    Measured before the fix: this set exited 0 — the prefix was the whole test.
    """
    symbols = [*sorted(allowlist.declared_abi(REPO_ROOT)), "ama_zz_undeclared_internal"]
    assert _main_over(allowlist, monkeypatch, symbols, tmp_path) == 1
    assert "ama_zz_undeclared_internal" in capsys.readouterr().err


def test_a_localised_internal_that_leaks_fails(
    allowlist: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A version script that lost a ``local:`` entry re-publishes the internal.

    Measured before the fix: this set exited 0.
    """
    localised = sorted(allowlist._public_api_gate().localised_symbols(REPO_ROOT))
    assert localised, "the version script localises nothing; this control has no subject"
    leaked = localised[0]
    symbols = [*sorted(allowlist.declared_abi(REPO_ROOT)), leaked]
    assert _main_over(allowlist, monkeypatch, symbols, tmp_path) == 1
    assert leaked in capsys.readouterr().err


def test_a_non_ama_export_still_fails(
    allowlist: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    symbols = [*sorted(allowlist.declared_abi(REPO_ROOT)), "ed25519_sign"]
    assert _main_over(allowlist, monkeypatch, symbols, tmp_path) == 1


def test_an_unreadable_declared_abi_is_inconclusive_not_a_pass(
    allowlist: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No declared set is not an empty allowlist and not a pass: exit 2."""
    monkeypatch.setattr(allowlist, "REPO", tmp_path)
    symbols = [f"ama_x{i}" for i in range(200)]
    assert _main_over(allowlist, monkeypatch, symbols, tmp_path) == 2


def test_the_offender_predicate(allowlist: ModuleType) -> None:
    allowed = frozenset({"ama_public"})
    symbols = ["ama_public", "ama_internal", "helper", "_fini", "ama_public.part.0"]
    assert allowlist.offending_symbols(symbols, allowed) == [
        "ama_internal",
        "ama_public.part.0",
        "helper",
    ]
