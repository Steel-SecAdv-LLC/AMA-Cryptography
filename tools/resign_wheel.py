#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — post-repair wheel re-signer (Linux release pipeline).

Why this exists
---------------
The in-wheel Ed25519 integrity artefact
(``ama_cryptography/_integrity_signature.py``) is minted by ``setup.py``'s
post-build hook — BEFORE cibuildwheel's repair step runs.  On Linux the
DEFAULT ``auditwheel repair`` then rewrites the wheel.  Today auditwheel
grafts nothing into this project's wheels (INVARIANT-1: no external crypto
dependencies — the bindings resolve ``libama_cryptography`` in-package via
``$ORIGIN``, verified on the published v4.0.0 assets), so the signed bytes
and the shipped bytes coincide.  But that is a property of the *current*
auditwheel, not of the pipeline.  The 5.0.0 release dry run demonstrated the
failure mode on macOS: ``delocate-wheel`` rewrites each binding's Mach-O
load commands after signing, so every macOS wheel failed its own smoke test
with a digest MISMATCH on all five binding extensions.  macOS repair was
disabled as the workaround (``CIBW_REPAIR_WHEEL_COMMAND_MACOS: ""``); this
tool is the robust design for Linux, where the default repair is worth
keeping (manylinux retagging): re-sign each wheel AFTER repair, so the
artefact binds the post-repair — i.e. the shipped — bytes by construction,
whatever a future auditwheel decides to rewrite.

Wired in ``release.yml`` as::

    CIBW_REPAIR_WHEEL_COMMAND_LINUX:
        auditwheel repair -w {dest_dir} {wheel}
        && python {project}/tools/resign_wheel.py {dest_dir}

and validated per wheel by ``CIBW_TEST_COMMAND`` (``tools/wheel_smoke_test.py``
asserts every shipped binding extension matches its signed digest).

How it works
------------
For every ``*.whl`` in the repair ``{dest_dir}``:

1. Unpack it with :mod:`zipfile` into a temp directory.  Stdlib only, on
   purpose: ``CIBW_BEFORE_BUILD_LINUX`` installs cmake/cython/numpy and
   nothing installs the ``wheel`` CLI, so ``python -m wheel unpack/pack``
   is not guaranteed to exist in the environment that executes the repair
   command.  This tool therefore depends on nothing beyond the stdlib —
   the same rule the package itself lives by.
2. Delete the stale (pre-repair) integrity artefact, then run the signer as
   a subprocess against the unpacked tree::

       python -m ama_cryptography._build_sign \
           --package-dir <root>/ama_cryptography --bind-extensions

   with cwd and ``PYTHONPATH`` set to the unpacked root, so the package the
   signer imports IS the wheel's own tree: ``--package-dir`` supplies the
   ``.py``/binding digests, import-path discovery supplies the native
   digest, and ``pqc_backends._process_is_the_integrity_signer`` (which
   requires ``__main__.__spec__.name == "ama_cryptography._build_sign"``)
   resolves against the same tree.  Deleting the artefact first matters in
   exactly the scenario this tool exists for: if repair rewrote a binding,
   the pre-import gate (``__init__._refuse_tampered_bindings_before_import``)
   would refuse to initialise the package against the stale digests and the
   signer could never run.  With no artefact present nothing is signed, so
   nothing reads as tampering, and the ``.py`` digest is unaffected because
   ``_compute_package_digest`` excludes the artefact by design.
3. Guard against silent wrong signing: the signer's native digest comes
   from import-path discovery (``_find_native_library_path``), not from
   ``--package-dir`` — so a stray ``LD_LIBRARY_PATH`` entry or a
   ``/usr/local/lib`` install could hand it a library OUTSIDE the unpacked
   wheel.  The environment is pinned first (``AMA_CRYPTO_LIB_PATH`` pointed
   at the unpacked package directory, ``LD_LIBRARY_PATH``/
   ``DYLD_LIBRARY_PATH`` dropped), and then — authoritatively — the signed
   ``INTEGRITY_NATIVE_DIGEST_HEX`` is recomputed against the native library
   files actually inside the unpacked tree.  No match is a hard failure.
4. Repack over the original wheel in ``{dest_dir}``, preserving the
   original archive's exact entry inventory and per-entry metadata
   (permissions, timestamps, compression) and regenerating
   ``*.dist-info/RECORD`` — mandatory, because the artefact's bytes changed
   and an installer verifies every file against RECORD.  Repacking from the
   original inventory also means nothing the signer subprocess might drop
   into the tree (bytecode caches, scratch files) can ever ship.

Every failure exits nonzero with a one-line cause; a wheel is never
half-rewritten (the rebuild lands via ``os.replace`` of a completed temp
archive).

Exit status
-----------
``0`` when every wheel in ``{dest_dir}`` was re-signed and repacked;
``1`` on the first failure.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Sequence

#: The one package this pipeline builds.  A repaired wheel that does not
#: contain exactly one directory of this name is not a wheel this tool
#: understands, and signing the wrong tree is worse than failing.
PACKAGE_NAME = "ama_cryptography"

#: Filename prefixes of the vendored native library across the shipped
#: platforms — mirrors ``_build_sign._NATIVE_LIB_PREFIXES``.
NATIVE_LIB_PREFIXES: tuple[str, ...] = ("libama_cryptography", "ama_cryptography.dll")

#: The generated artefact this tool regenerates (and the digest-only legacy
#: artefact the signer refreshes alongside it).
ARTEFACT_NAME = "_integrity_signature.py"

#: ``INTEGRITY_NATIVE_DIGEST_HEX = "<64 hex>"`` in the generated artefact.
_NATIVE_DIGEST_RE = re.compile(r'^INTEGRITY_NATIVE_DIGEST_HEX = "([0-9a-f]{64})"$', re.M)

#: ``<dist>-<version>.dist-info/RECORD`` at the archive top level.
_RECORD_RE = re.compile(r"^[^/]+\.dist-info/RECORD$")


class ResignError(RuntimeError):
    """A condition under which shipping the wheel would be wrong.

    Raised for every failure mode this tool checks; ``main`` renders it as a
    one-line ``ERROR:`` and exit code 1, which fails the cibuildwheel repair
    step and therefore the release — the intended fail-closed behaviour.
    """


def _find_wheels(dest_dir: Path) -> list[Path]:
    """Every wheel the repair step left in ``dest_dir`` — at least one.

    cibuildwheel invokes the repair command once per built wheel with a
    fresh ``{dest_dir}``, so one wheel is the normal case; more than one is
    handled by re-signing each.  Zero means the ``auditwheel repair`` half
    of the command produced nothing, and silently succeeding here would let
    the build continue toward publishing nothing.
    """
    if not dest_dir.is_dir():
        raise ResignError(f"repair dest dir {dest_dir} does not exist or is not a directory")
    wheels = sorted(dest_dir.glob("*.whl"))
    if not wheels:
        raise ResignError(
            f"no *.whl found in {dest_dir} — auditwheel repair produced no wheel to re-sign"
        )
    return wheels


def _unpack(whl: Path, workdir: Path) -> tuple[Path, list[zipfile.ZipInfo]]:
    """Extract ``whl`` under ``workdir`` and return (root, original entries).

    The :class:`zipfile.ZipInfo` list is the authority for what the rebuilt
    archive will contain: exact names, order, permissions, timestamps and
    compression are all replayed from it by :func:`_repack`.
    """
    root = workdir / "unpacked"
    root.mkdir()
    with zipfile.ZipFile(whl) as archive:
        infos = archive.infolist()
        archive.extractall(root)
    return root, infos


def _locate_package_dir(root: Path) -> Path:
    """The single ``ama_cryptography/`` directory in the unpacked tree.

    Anything other than exactly one is a wheel this tool does not
    understand — signing an arbitrarily chosen tree would be the silent
    wrong-signing failure this tool exists to prevent.
    """
    candidates = sorted(path for path in root.rglob(PACKAGE_NAME) if path.is_dir())
    if len(candidates) != 1:
        listing = ", ".join(str(path.relative_to(root)) for path in candidates) or "none"
        raise ResignError(
            f"expected exactly one {PACKAGE_NAME}/ directory in the unpacked wheel, "
            f"found {len(candidates)} ({listing})"
        )
    return candidates[0]


def _native_library_candidates(pkg_dir: Path) -> list[Path]:
    """The vendored native-library files inside the unpacked package dir."""
    return sorted(
        path
        for path in pkg_dir.iterdir()
        if path.is_file() and path.name.startswith(NATIVE_LIB_PREFIXES)
    )


def _run_signer(root: Path, pkg_dir: Path) -> None:
    """Run the integrity signer against the unpacked wheel tree.

    The environment is pinned so every input the signer consumes comes from
    the unpacked wheel:

    * ``cwd`` and ``PYTHONPATH`` = the unpacked root, so
      ``import ama_cryptography`` resolves to the wheel's own tree (both
      precede site-packages, and ``python -m`` puts the cwd first);
    * ``AMA_CRYPTO_LIB_PATH`` = the unpacked package directory, so
      import-path native-library discovery starts (and, with the vendored
      library present, ends) inside the tree;
    * ``LD_LIBRARY_PATH``/``DYLD_LIBRARY_PATH`` dropped — the one documented
      way a candidate from outside the tree could outrank an in-tree one;
    * ``AMA_BUILD_PIPELINE=1`` — the signer's own gate (set by
      ``CIBW_ENVIRONMENT`` in the container already; pinned here so the
      tool does not depend on that);
    * ``PYTHONDONTWRITEBYTECODE=1`` — keeps ``__pycache__`` out of the tree
      (defence in depth: repack replays the original inventory anyway).

    The signing seed / trust anchor variables forwarded by
    ``CIBW_ENVIRONMENT_PASS_LINUX`` are inherited untouched, so the
    re-signed artefact carries the same anchoring the original did.
    """
    # The stale, pre-repair artefact must go before the signer process
    # imports the package: if repair rewrote a binding, the pre-import gate
    # would otherwise refuse the import against the stale digests — in
    # exactly the scenario this tool exists to handle.  With no artefact,
    # nothing is signed and nothing reads as tampering; the ``.py`` digest
    # is unchanged because it excludes the artefact by construction.
    (pkg_dir / ARTEFACT_NAME).unlink(missing_ok=True)
    # A fresh extraction has no bytecode cache; remove one anyway so a stale
    # compiled artefact can never shadow the deletion above.
    shutil.rmtree(pkg_dir / "__pycache__", ignore_errors=True)

    env = dict(os.environ)
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(root) if not previous else str(root) + os.pathsep + previous
    env["AMA_BUILD_PIPELINE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["AMA_CRYPTO_LIB_PATH"] = str(pkg_dir)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("DYLD_LIBRARY_PATH", None)

    command = [
        sys.executable,
        "-m",
        "ama_cryptography._build_sign",
        "--package-dir",
        str(pkg_dir),
        "--bind-extensions",
    ]
    completed = subprocess.run(command, cwd=root, env=env)
    if completed.returncode != 0:
        raise ResignError(
            f"integrity signer exited {completed.returncode} for {pkg_dir} — "
            "the post-repair wheel was NOT re-signed"
        )
    if not (pkg_dir / ARTEFACT_NAME).is_file():
        raise ResignError(
            f"signer exited 0 but wrote no {ARTEFACT_NAME} under {pkg_dir}; "
            "refusing to repack an unsigned tree"
        )


def _assert_native_digest_bound_in_root(pkg_dir: Path) -> Path:
    """Prove the signer bound a native library from INSIDE the unpacked tree.

    ``_build_sign`` takes the ``.py`` and binding digests from
    ``--package-dir`` but the NATIVE digest from import-path discovery, so
    this is the one input that could silently resolve outside the wheel.
    The check is post-hoc and byte-level rather than trusting the pinned
    environment: recompute SHA3-256 over every native-library file in the
    unpacked package dir and require the artefact's
    ``INTEGRITY_NATIVE_DIGEST_HEX`` to match one of them.  Returns the
    matching in-tree file.
    """
    artefact = pkg_dir / ARTEFACT_NAME
    match = _NATIVE_DIGEST_RE.search(artefact.read_text(encoding="utf-8"))
    if match is None:
        raise ResignError(f"{artefact} carries no parseable INTEGRITY_NATIVE_DIGEST_HEX")
    signed_digest = match.group(1)

    candidates = _native_library_candidates(pkg_dir)
    if not candidates:
        raise ResignError(
            f"no native library ({' / '.join(NATIVE_LIB_PREFIXES)}*) inside {pkg_dir} — "
            "the signer can only have bound a library from OUTSIDE the wheel"
        )
    for candidate in candidates:
        if hashlib.sha3_256(candidate.read_bytes()).hexdigest() == signed_digest:
            return candidate
    raise ResignError(
        "the signer bound a native library from OUTSIDE the unpacked wheel: "
        f"signed native digest {signed_digest} matches none of "
        f"{[candidate.name for candidate in candidates]} under {pkg_dir}. "
        "The artefact would attest to bytes the wheel does not ship."
    )


def _find_record_name(names: Sequence[str]) -> str:
    """The archive's single ``*.dist-info/RECORD`` entry."""
    records = [name for name in names if _RECORD_RE.match(name)]
    if len(records) != 1:
        raise ResignError(
            f"expected exactly one *.dist-info/RECORD in the wheel, found {records!r}"
        )
    return records[0]


def _tree_file(root: Path, name: str) -> Path:
    """``root/name``, refusing any archive name that escapes ``root``."""
    path = (root / name).resolve()
    if root.resolve() not in path.parents:
        raise ResignError(f"archive entry {name!r} escapes the unpacked root")
    return path


def _regenerate_record(root: Path, names: Sequence[str], record_name: str) -> bytes:
    """Rebuild RECORD from the (re-signed) tree — same shape ``wheel`` writes.

    ``path,sha256=<urlsafe-b64-no-padding>,size`` per file, CSV-quoted,
    CRLF-terminated (the csv module's default, matching the reference
    implementation), with RECORD's own row carrying empty hash and size.
    Mandatory: the artefact's bytes changed, and installers verify every
    file against RECORD at install time.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for name in names:
        if name.endswith("/"):
            continue
        if name == record_name:
            writer.writerow([name, "", ""])
            continue
        source = _tree_file(root, name)
        if not source.is_file():
            raise ResignError(
                f"{name} is in the original wheel but missing from the unpacked "
                "tree; refusing to repack an incomplete wheel"
            )
        data = source.read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        writer.writerow([name, f"sha256={digest.decode('ascii')}", str(len(data))])
    return buffer.getvalue().encode("utf-8")


def _repack(whl: Path, root: Path, infos: Sequence[zipfile.ZipInfo]) -> None:
    """Rebuild ``whl`` in place from the re-signed tree.

    The original entry list is the inventory: exactly those names ship,
    in the same order, with each entry's permissions (``external_attr`` —
    the extensions' exec bits live there), timestamp and compression method
    replayed from the source archive.  Bytes come from the tree, so the
    regenerated artefact lands and anything the signer subprocess created
    (bytecode caches) cannot.  A wheel carrying a detached RECORD signature
    is refused — regenerating RECORD would invalidate it silently.
    """
    names = [info.filename for info in infos]
    record_name = _find_record_name(names)
    for signature_file in (record_name + ".jws", record_name + ".p7s"):
        if signature_file in names:
            raise ResignError(
                f"wheel carries a detached RECORD signature ({signature_file}); "
                "regenerating RECORD would silently invalidate it"
            )
    record_bytes = _regenerate_record(root, names, record_name)

    replacement = whl.with_name(whl.name + ".resign-tmp")
    try:
        with zipfile.ZipFile(replacement, "w") as archive:
            for info in infos:
                clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                clone.external_attr = info.external_attr
                clone.compress_type = info.compress_type
                clone.create_system = info.create_system
                if info.is_dir():
                    data = b""
                elif info.filename == record_name:
                    data = record_bytes
                else:
                    source = _tree_file(root, info.filename)
                    if not source.is_file():
                        raise ResignError(
                            f"{info.filename} is in the original wheel but missing from "
                            "the unpacked tree; refusing to repack an incomplete wheel"
                        )
                    data = source.read_bytes()
                archive.writestr(clone, data)
        os.replace(replacement, whl)
    finally:
        replacement.unlink(missing_ok=True)


def resign_wheel(whl: Path) -> None:
    """Unpack, re-sign over the post-repair bytes, guard, and repack ``whl``."""
    with tempfile.TemporaryDirectory(prefix="ama-resign-") as tmp:
        root, infos = _unpack(whl, Path(tmp))
        pkg_dir = _locate_package_dir(root)
        artefact_arcname = (pkg_dir.relative_to(root) / ARTEFACT_NAME).as_posix()
        if artefact_arcname not in {info.filename for info in infos}:
            # Repack replays the original inventory, so an artefact the
            # build never shipped would be regenerated and then dropped.
            raise ResignError(
                f"wheel does not contain {artefact_arcname} — this wheel was never "
                "signed by the build, and re-signing cannot add the artefact"
            )
        _run_signer(root, pkg_dir)
        bound = _assert_native_digest_bound_in_root(pkg_dir)
        print(f"  native digest bound in-tree: {bound.relative_to(root).as_posix()}")
        _repack(whl, root, infos)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Re-sign every wheel in the cibuildwheel repair {dest_dir} over its "
            "POST-repair bytes, so the integrity artefact binds what ships."
        )
    )
    parser.add_argument(
        "dest_dir",
        type=Path,
        help="cibuildwheel repair {dest_dir} containing the repaired wheel(s)",
    )
    args = parser.parse_args(argv)

    try:
        for whl in _find_wheels(args.dest_dir):
            print(f"Re-signing post-repair wheel: {whl.name}")
            resign_wheel(whl)
            print(f"Re-signed over post-repair bytes: {whl.name}")
    except ResignError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "Refusing to ship: the integrity artefact must bind the exact bytes "
            "the wheel ships, and this wheel could not be re-signed to that state.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
