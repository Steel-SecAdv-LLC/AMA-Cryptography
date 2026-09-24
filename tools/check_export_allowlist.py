#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — exported-symbol allowlist (audit B2)
======================================================

The companion to ``tools/check_vendor_isolation.py``.  That gate checks what the
built library pulls IN (no ``EVP_``, ``sodium_``, ``wc_``, ... symbols).  This
one checks what it sends OUT: the shared object must export ONLY AMA's own
``ama_*`` ABI.

Off-Windows ``AMA_API`` expands to nothing, so before ``cmake/ama_exports.map``
the linked ``.so`` exported all ~246 of its defined symbols -- at the time six
of them un-prefixed names from the since-removed vendored Ed25519 tree plus one
mutable data symbol.  A process that loaded AMA alongside a second copy of that
code could have had AMA's Ed25519 silently serviced by the other copy (ELF
flat-namespace interposition; a static consumer's symbols always win),
bypassing the canonical-R/S/y hardening -- and once ``.so.5`` publishes, every
exported name becomes an ABI promise.  CMakeLists.txt restricts the export set
with a version script; this gate is what keeps it restricted.

Any exported (defined, dynamic) symbol whose name does not begin with ``ama_``,
and is not one of the linker-generated ELF markers below, fails the gate.  A
non-vacuity floor rejects a stripped or wrong-path library that would otherwise
pass with "no offenders".

The ``ama_`` prefix is necessary, not sufficient.  The version script exports
the ``ama_*`` WILDCARD and then localises the internal names it would
otherwise publish (the AES-GCM SIMD kernels that skip the entry point's length
limits, the FIPS 204/205 internal interfaces), and any non-static helper added
under ``src/c`` matches the wildcard too.  A prefix test passes all of them.
So the allowlist is the declared ABI itself: every exported ``ama_*`` name must
be declared ``AMA_API`` in a header the build installs, and none may be one the
version script localises — both read by the same functions
``tools/check_public_api_docs.py`` uses, loaded from it, so the two gates
cannot disagree about what the ABI is.

Exit status:
  0  every exported symbol is the declared, non-localised ``ama_*`` ABI (or a
     linker marker) and the floor held.
  1  at least one exported symbol is outside that set.
  2  the check could not be made to mean anything (no library found, ``nm``
     unavailable, or the ama_* export count is below the non-vacuity floor).
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Optional, Sequence

REPO = Path(__file__).resolve().parent.parent

#: Linker/loader-generated symbols that are not part of any C ABI and may appear
#: in the dynamic symbol table on some toolchains even after a version script
#: localises everything else.  Never a public-API surface.  On GNU ld with
#: cmake/ama_exports.map none of these survive on this tree; the set exists so a
#: different conforming linker does not trip a false positive.
_ALLOWED_NON_AMA = frozenset(
    {
        "_init",
        "_fini",
        "_edata",
        "_end",
        "__bss_start",
        "__gmon_start__",
        "_IO_stdin_used",
        "__data_start",
    }
)

#: Non-vacuity floor.  The library defines ~240 ama_* symbols; require a large
#: fraction so a stripped, empty, or wrong-path object cannot pass by exporting
#: nothing.  Set well below the measured value to tolerate ABI growth/pruning.
MIN_AMA_EXPORTS = 150


def _find_library(explicit: Optional[Path]) -> Optional[Path]:
    if explicit is not None:
        return explicit if explicit.exists() else None
    repo = Path(__file__).resolve().parent.parent
    patterns = (
        "build/lib/libama_cryptography.so.*.*.*",
        "build/lib/libama_cryptography.so.*",
        "build*/lib/libama_cryptography.so.*",
        "build/lib/libama_cryptography.so",
    )
    for pat in patterns:
        hits = sorted(
            (p for p in repo.glob(pat) if p.is_file() and not p.is_symlink()),
            key=lambda p: len(p.name),
            reverse=True,  # prefer the fully-versioned real file over the .so link
        )
        if hits:
            return hits[0]
    return None


def _public_api_gate() -> ModuleType:
    """``tools/check_public_api_docs.py``, loaded by path (``tools/`` is not a package on ``sys.path`` when this runs as a script)."""
    path = Path(__file__).resolve().parent / "check_public_api_docs.py"
    spec = importlib.util.spec_from_file_location("_public_api_for_export_allowlist", path)
    if spec is None or spec.loader is None:  # pragma: no cover - unreachable on a real tree
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: its dataclasses resolve their own module.
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def declared_abi(repo: Optional[Path] = None) -> frozenset[str]:
    """The ``ama_*`` names the shared object may export.

    Declared ``AMA_API`` in an installed header, minus every name
    ``cmake/ama_exports.map`` localises.  Raises when either cannot be read —
    an empty allowlist would report every export as an offender, and a
    missing localised set would silently admit the internals.
    """
    root = REPO if repo is None else repo
    gate = _public_api_gate()
    declared: frozenset[str] = gate.declared_public_symbols(root)
    localised: frozenset[str] = gate.localised_symbols(root)
    if not declared or not localised:
        raise RuntimeError(
            "could not read the declared ABI (installed-header AMA_API "
            f"declarations: {len(declared)}, version-script local: names: "
            f"{len(localised)})"
        )
    return declared - localised


def offending_symbols(symbols: Sequence[str], allowed_ama: frozenset[str]) -> list[str]:
    """Exported names outside the ABI: non-``ama_`` (not a linker marker), or
    ``ama_*`` but not in ``allowed_ama``."""
    return sorted(
        name
        for name in symbols
        if name not in _ALLOWED_NON_AMA and (not name.startswith("ama_") or name not in allowed_ama)
    )


def _exported_symbols(lib: Path) -> list[str]:
    """Defined, dynamic symbol names via ``nm -D --defined-only``."""
    proc = subprocess.run(
        ["nm", "-D", "--defined-only", str(lib)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nm failed on {lib}: {proc.stderr.strip()}")
    symbols: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:  # address type name
            symbols.append(parts[-1])
    return symbols


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assert the shared library exports only the ama_* ABI (audit B2)."
    )
    parser.add_argument(
        "library",
        nargs="?",
        type=Path,
        default=None,
        help="path to libama_cryptography.so.* (auto-detected under build*/ if omitted)",
    )
    args = parser.parse_args(argv)

    lib = _find_library(args.library)
    if lib is None:
        print(
            "EXPORT ALLOWLIST INCONCLUSIVE — no libama_cryptography shared object found.\n"
            "Build it first: cmake -B build -DAMA_USE_NATIVE_PQC=ON && "
            "cmake --build build --target ama_cryptography_shared",
            file=sys.stderr,
        )
        return 2

    try:
        symbols = _exported_symbols(lib)
        allowed_ama = declared_abi()
    except (OSError, RuntimeError) as exc:
        print(f"EXPORT ALLOWLIST INCONCLUSIVE — {exc}", file=sys.stderr)
        return 2

    ama = [s for s in symbols if s.startswith("ama_")]
    offenders = offending_symbols(symbols, allowed_ama)

    print(f"Inspected {lib}")
    print(f"  exported (defined) symbols : {len(symbols)}")
    print(f"  ama_* ABI symbols          : {len(ama)}")
    print(f"  declared, non-localised ABI: {len(allowed_ama)}")
    print(f"  offenders                  : {len(offenders)}")

    if offenders:
        print(
            f"\nEXPORT ALLOWLIST FAILED — {len(offenders)} exported symbol(s) are not part of\n"
            "the declared ama_* ABI and are not linker-generated markers:",
            file=sys.stderr,
        )
        for symbol in offenders:
            why = (
                "not ama_*"
                if not symbol.startswith("ama_")
                else "ama_* but not declared AMA_API in an installed header, or localised"
            )
            print(f"  {symbol}  ({why})", file=sys.stderr)
        print(
            "\nThe shared library must export only AMA's own declared ama_* ABI (audit B2).\n"
            "Localise internal names via cmake/ama_exports.map; if a symbol is\n"
            "genuinely public, give it the ama_ prefix and an AMA_API declaration in\n"
            "an installed header.",
            file=sys.stderr,
        )
        return 1

    if len(ama) < MIN_AMA_EXPORTS:
        print(
            f"EXPORT ALLOWLIST INCONCLUSIVE — only {len(ama)} ama_* exports (< floor "
            f"{MIN_AMA_EXPORTS}); a stripped or wrong object would pass with no offenders.",
            file=sys.stderr,
        )
        return 2

    print(
        f"\nEXPORT ALLOWLIST PASSED — all {len(ama)} exported ama_* symbols are the "
        "declared, non-localised ABI."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
