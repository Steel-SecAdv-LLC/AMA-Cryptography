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
import sys
from pathlib import Path

import pytest

from tests.conftest import native_library_path
from tools import check_vendor_isolation as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Package-local first: ``pqc_backends._get_search_dirs()`` loads the copy in
#: the package before the build tree's, and a wheel ships only that one.  Both
#: are checked when both exist (Copilot review): passing on one image says
#: nothing about the other.
_LIBRARY_DIRS = (
    Path("ama_cryptography"),
    Path("build") / "lib",
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


def _built_libraries() -> list[Path]:
    """Every distinct library image this tree holds, the loaded one first."""
    images: list[Path] = []
    seen: set[Path] = set()
    for relative in _LIBRARY_DIRS:
        directory = REPO_ROOT / relative
        if directory.is_dir():
            found = native_library_path(directory)
            if found is not None and found.resolve() not in seen:
                seen.add(found.resolve())
                images.append(found)
    return images


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
    images = _built_libraries()
    if not images:
        pytest.skip("native library not built in this tree")
    elf = [image for image in images if _elf_machine(image) == _EM_X86_64]
    if not elf:
        pytest.skip(
            f"{images[0].name} is not an x86-64 ELF image; glibc's EVEX routines are x86-64"
        )
    offending = {str(image): sorted(_imported_copy_routines(image)) for image in elf}
    offending = {image: names for image, names in offending.items() if names}
    assert not offending, (
        f"{offending}: a secret copied by glibc's EVEX form is left in "
        "%ymm16-31, which the public epilogue cannot clear. Route the copy "
        "through src/c/internal/ama_string_ops.h (an explicit memcpy, not a "
        "struct assignment or a copy loop)."
    )


def test_every_image_in_the_tree_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both locations are read, the loaded one first, and a symlinked copy of
    the same image is read once."""
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    (tmp_path / "ama_cryptography").mkdir()
    (tmp_path / "build" / "lib").mkdir(parents=True)
    pkg = tmp_path / "ama_cryptography" / "libama_cryptography.so"
    built = tmp_path / "build" / "lib" / "libama_cryptography.so"
    pkg.write_bytes(b"package")
    built.write_bytes(b"build")
    assert _built_libraries() == [pkg, built]
    pkg.unlink()
    pkg.symlink_to(built)
    # native_library_path resolves links: the editable install's symlink and
    # the build output are one image, read once.
    assert _built_libraries() == [built.resolve()]


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
