#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The built x86-64 library imports no libc copy routine (INVARIANT-6).

glibc selects EVEX forms of memcpy/memmove on every AVX-512 CPU. Those copy
through %ymm16-31, which a baseline x86-64 epilogue cannot clear, so a secret
the library moved that way is still in a register when the public call
returns (``AMA_API``'s ``zero_call_used_regs("all")`` reaches only
%xmm0-15). The next lazy-binding trampoline or signal frame then saves it onto
unscrubbed stack. Measured 2026-11-08, clang 18.1: ``ama_hkdf``,
``ama_hkdf_sha256``, ``ama_pbkdf2_hmac_sha512`` and ``ama_argon2id`` returned
with their output in %zmm16/%zmm17 (``tests/c/test_register_residue.c``).

The library therefore makes no such call:

* ``src/c/internal/ama_string_ops.h`` expands every source-level
  memcpy/memmove/memset inline.
* Clang's loop-idiom pass is off for these routines
  (``-fno-builtin-memcpy`` and friends, ``CMakeLists.txt``).
* Struct copies that clang would lower to a call are written as explicit
  copies.

This test holds the result where it can be read: the dynamic symbol table of
the shipped image.

memset is not on the list: a fill leaves only its constant fill byte in a
register, never a secret.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tests.conftest import native_library_path
from tools import check_vendor_isolation as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

_LIBRARY_DIRS = (
    Path("build") / "lib",
    Path("ama_cryptography"),
)

#: The libc routines that move caller bytes through vector registers.
COPY_ROUTINES = frozenset(
    {
        "memcpy",
        "memmove",
        "mempcpy",
        "bcopy",
        "__memcpy_chk",
        "__memmove_chk",
        "__mempcpy_chk",
    }
)

_EM_X86_64 = 62


def _built_library() -> Path | None:
    for relative in _LIBRARY_DIRS:
        directory = REPO_ROOT / relative
        if directory.is_dir():
            found = native_library_path(directory)
            if found is not None:
                return found
    return None


def _elf_machine(path: Path) -> int | None:
    head = path.read_bytes()[:20]
    if head[:4] != b"\x7fELF" or head[5] != 1:  # little-endian only
        return None
    machine: int = struct.unpack_from("<H", head, 18)[0]
    return machine


def _imported_copy_routines(path: Path) -> set[str]:
    info = gate.parse_binary(path)
    names = {sym.split("@", 1)[0] for sym in info.undefined_symbols}
    return names & COPY_ROUTINES


def test_the_x86_64_library_imports_no_libc_copy_routine() -> None:
    built = _built_library()
    if built is None:
        pytest.skip("native library not built in this tree")
    if _elf_machine(built) != _EM_X86_64:
        pytest.skip(f"{built.name} is not an x86-64 ELF image; glibc's EVEX routines are x86-64")
    imported = _imported_copy_routines(built)
    assert not imported, (
        f"{built} imports {sorted(imported)}: a secret copied by glibc's EVEX "
        "form is left in %ymm16-31, which the public epilogue cannot clear. "
        "Route the copy through src/c/internal/ama_string_ops.h (an explicit "
        "memcpy, not a struct assignment or a copy loop)."
    )


def test_the_check_sees_an_import(tmp_path: Path) -> None:
    """Non-vacuity: an ELF object that imports memcpy is reported."""
    import shutil
    import subprocess

    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler on PATH to build the control object")
    src = tmp_path / "control.c"
    src.write_text(
        "#include <string.h>\n"
        "void *control_copy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }\n",
        encoding="ascii",
    )
    so = tmp_path / "libcontrol.so"
    proc = subprocess.run(
        [cc, "-O2", "-shared", "-fPIC", "-fno-builtin", str(src), "-o", str(so)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or _elf_machine(so) is None:
        pytest.skip(f"the control object could not be built as ELF here: {proc.stderr[-300:]}")
    assert _imported_copy_routines(so) == {"memcpy"}


def test_the_analyzer_exception_is_confined_to_the_string_ops_header() -> None:
    """The one place the build treats clang's static analyzer differently.

    ``ama_string_ops.h`` steps aside under ``__clang_analyzer__``, because the
    analyzer cannot model REP MOVSB in inline assembly and would report every
    copied buffer as uninitialised. That is a tool limitation, so the
    exception is narrowed to the one file that demonstrates it (AGENTS.md
    section 5). This pins it there: no other C source may compile differently
    under analysis.
    """
    users = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for root in ("src/c", "include")
        for p in (REPO_ROOT / root).rglob("*")
        if p.suffix in (".c", ".h") and "__clang_analyzer__" in p.read_text(encoding="utf-8")
    )
    assert users == ["src/c/internal/ama_string_ops.h"], users
