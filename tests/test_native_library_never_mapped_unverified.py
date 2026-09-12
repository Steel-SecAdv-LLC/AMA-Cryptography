# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A native library that fails its digest check must never be MAPPED.

WHY THIS TEST EXISTS

``_find_native_library`` does not simply check a digest and then open a path.
It opens the candidate, hashes the bytes it holds open, and loads it through
``/proc/self/fd/N`` so that the bytes mapped are the bytes hashed — and on a
mismatch it refuses and returns ``None`` **without mapping**.  Its own refusal
message states the reason in as many words: *"refused before mapping ... a
shared object executes its constructors the moment it is mapped."*

That is the property, and it was defeated a few statements later by the
package's own import sequence.  Every Cython binding extension carries
``DT_NEEDED [libama_cryptography.so.5]`` and ``RUNPATH [$ORIGIN:...]``
(``readelf -dW``), and ``pqc_backends`` probed all five at module scope
unconditionally — including on the path where the native library had just been
rejected.  Importing ``ed25519_binding`` therefore made the dynamic loader map
the very object the digest check had refused, out of the package directory,
with no check of any kind, running its ELF constructors.

Measured before the fix, with one byte flipped in the in-package
``libama_cryptography.so.5.0.0``: the import raises ``CryptoModuleError`` as it
should, and ``/proc/self/maps`` nevertheless lists the tampered library.  An
attacker able to replace that file obtained code execution in the victim's
process *despite* the integrity check correctly detecting the tampering — which
is the entire purpose of a pre-load refusal.

The fix gates all five probes on ``_binding_imports_permitted()``, i.e. on the
native library having been verified and loaded.  Nothing is lost: a binding
cannot work without the library, because it is a hard ``DT_NEEDED``.

This test asserts the property end to end, in a subprocess against a tampered
copy of the package, and carries its own positive control so it cannot pass
because the probe stopped working.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "ama_cryptography"

#: Reads /proc/self/maps after attempting the import and reports both outcomes
#: on stdout as two machine-readable lines.
_PROBE = textwrap.dedent("""
    import sys

    def mapped():
        try:
            with open("/proc/self/maps", encoding="utf-8") as fh:
                return sorted({ln.split()[-1] for ln in fh if "libama_cryptography" in ln})
        except OSError:
            return []

    try:
        import ama_cryptography  # noqa: F401
        print("IMPORT=ok")
    except BaseException as exc:                      # noqa: BLE001
        print("IMPORT=refused:" + type(exc).__name__)
    print("MAPPED=" + ("yes" if mapped() else "no"))
    """)


def _bundled_library() -> Path | None:
    """The real native object inside the package, if this tree has one built."""
    for candidate in sorted(PACKAGE.glob("libama_cryptography.so.*")):
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def _binding_with_dt_needed() -> bool:
    """True when at least one built binding extension is present.

    Without one there is nothing to pull the library in behind the refusal, so
    the property under test is not exercised and a pass would mean nothing.
    """
    return any(PACKAGE.glob("*_binding*.so"))


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="needs /proc/self/maps to observe what the loader mapped",
)


@pytest.fixture(scope="module")
def package_copy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """An importable copy of the package, isolated from the repository.

    Copied rather than tampered in place: the real tree's object is mapped by
    every other test in this session, and flipping a byte under a live mapping
    segfaults the interpreter.
    """
    if _bundled_library() is None or not _binding_with_dt_needed():
        pytest.skip("no built native library and binding extensions in this tree")
    root = tmp_path_factory.mktemp("pkgcopy")
    shutil.copytree(PACKAGE, root / "ama_cryptography", symlinks=True)
    return root


def _run(root: Path) -> tuple[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root)
    env.pop("AMA_POST_DIAGNOSTIC_IMPORT", None)
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=str(root),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    out = proc.stdout
    imported = next((ln for ln in out.splitlines() if ln.startswith("IMPORT=")), "IMPORT=<none>")
    mapped = next((ln for ln in out.splitlines() if ln.startswith("MAPPED=")), "MAPPED=<none>")
    return imported, mapped


def test_positive_control_an_intact_copy_imports_and_maps(package_copy: Path) -> None:
    """The probe must be able to SEE a mapping, or the assertion below is empty.

    An untouched copy imports cleanly and the library is mapped — if this ever
    reports ``MAPPED=no``, the /proc parsing or the copy is broken and the real
    assertion proves nothing.
    """
    imported, mapped = _run(package_copy)
    assert imported == "IMPORT=ok", f"intact copy did not import: {imported}"
    assert mapped == "MAPPED=yes", "the probe cannot observe a mapping; it proves nothing"


def test_a_tampered_library_is_refused_without_ever_being_mapped(
    package_copy: Path, tmp_path: Path
) -> None:
    root = tmp_path / "tampered"
    shutil.copytree(package_copy, root, symlinks=True)

    lib = next(
        p
        for p in sorted((root / "ama_cryptography").glob("libama_cryptography.so.*"))
        if p.is_file() and not p.is_symlink()
    )
    blob = bytearray(lib.read_bytes())
    blob[len(blob) // 2] ^= 0x01  # deep in .text: digest changes, ELF stays loadable
    lib.write_bytes(bytes(blob))

    imported, mapped = _run(root)

    assert imported.startswith("IMPORT=refused"), (
        f"a tampered native library was accepted: {imported}. The digest check is the "
        f"only thing standing between a replaced .so and this process."
    )
    assert mapped == "MAPPED=no", (
        "the tampered library was MAPPED even though the digest check refused it. "
        "A shared object runs its ELF constructors the moment it is mapped, so an "
        "attacker who can replace that file has already executed code in this process "
        "— the refusal came too late to matter. This is what "
        "pqc_backends._binding_imports_permitted() prevents: the binding extensions "
        "carry DT_NEEDED on the library, so importing one maps it with no check at all."
    )
