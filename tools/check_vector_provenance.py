#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — the published test vectors must still be the published bytes.

Why this exists
---------------
This repository's own pre-commit hooks used to rewrite its test vectors.
``trailing-whitespace`` and ``end-of-file-fixer`` ran unscoped, and a single
``pre-commit run --all-files`` modified 19 NIST/Ascon KAT files, the FIPS
140-3 power-on self-test KAT JSON, 94 binary fuzz seeds and 32 vendored
headers.  The KAT format spells an empty field as a key followed by a
trailing space, so ``PT = `` became ``PT =`` across ML-KEM (FIPS 203),
ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and Ascon.

The hooks are scoped now.  What made that incident worth a gate of its own is
that **nothing detected it**: measured on the rewritten tree, the corpus
generators' ``--check``, ``check_corpus_originality.py``,
``check_vendor_isolation.py`` and all 135 KAT tests still passed.  The
vectors had stopped matching what NIST published and every instrument in the
repository called the tree clean.

``wycheproof_vectors/`` was already protected this way — ``manifest.json``
pins a SHA-256 per file and ``refresh_wycheproof_corpus.py --offline``
verifies it.  Three trees had no equivalent.  This is that equivalent.

What it checks
--------------
For each protected root, every tracked file's SHA-256 against
:data:`MANIFEST_PATH`.  Three ways to fail, not one:

* a digest that does not match — the file was edited;
* a manifest entry with no file — a vector was deleted or renamed;
* a file with no manifest entry — a vector was added without being pinned,
  which is how a tree drifts out from under its own gate.

Why the digests are not the whole story
---------------------------------------
A manifest that lives in the same commit as the files it pins can be
regenerated to match corrupted files.  That is inherent, and pretending
otherwise would be the "gate that cannot fail" pattern this repository exists
to remove.  Two things narrow it:

* ``--update`` is explicit and never runs in CI, so a regeneration is a
  deliberate act that appears in the diff;
* ``tests/test_vector_provenance_gate.py`` pins the digests of a handful of
  ANCHOR files inline, in the test source, away from the manifest.  Rewriting
  the manifest alone leaves those assertions failing.

Exit status
-----------
0  every protected file matches its recorded digest
1  a file changed, went missing, or is unpinned
2  the gate could not read what it needs, or read too little to be believed
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "tests" / "kat" / "PROVENANCE.json"

#: Roots whose bytes are published elsewhere and must not drift, with what
#: each one is.  ``wycheproof_vectors`` is deliberately absent: it has its own
#: manifest and its own upstream re-fetch, and a second pin would be a second
#: thing to keep in step.
PROTECTED: dict[str, str] = {
    "tests/kat": "NIST and Ascon known-answer vectors, as published",
    "nist_vectors": "NIST reference vectors for the classical primitives",
    "ama_cryptography/_post_kats": "FIPS 140-3 power-on self-test vectors",
}

#: A clean report over a tree this gate could not really read means nothing.
#: Set below the real figures so a normal checkout never trips it, and far
#: enough above zero that an empty or partially-checked-out tree cannot pass.
MIN_FILES = 30


def _tracked_files(root: Path) -> list[Path]:
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.name != MANIFEST_PATH.name
    )


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build() -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for root in sorted(PROTECTED):
        directory = REPO_ROOT / root
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        for path in _tracked_files(directory):
            relative = path.relative_to(REPO_ROOT).as_posix()
            files[relative] = {"sha256": digest(path), "bytes": path.stat().st_size}
    return {
        "roots": PROTECTED,
        "files": files,
        "note": (
            "SHA-256 per file. Regenerate with "
            "`python tools/check_vector_provenance.py --update` only when a vector "
            "is deliberately added or a pin is deliberately advanced; a digest that "
            "changed on its own is a corrupted vector, not a stale manifest."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite the manifest from the current tree (never run in CI)",
    )
    args = parser.parse_args(argv)

    try:
        current = build()
    except FileNotFoundError as exc:
        print(f"FATAL: {exc} is missing; refusing to report a clean gate.", file=sys.stderr)
        return 2

    if len(current["files"]) < MIN_FILES:
        print(
            f"FATAL: found only {len(current['files'])} file(s) across {len(PROTECTED)} "
            f"protected root(s) (floor {MIN_FILES}). A clean report over a tree this "
            f"gate could not really read would mean nothing.",
            file=sys.stderr,
        )
        return 2

    if args.update:
        MANIFEST_PATH.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        total = sum(entry["bytes"] for entry in current["files"].values())
        print(
            f"wrote {MANIFEST_PATH.relative_to(REPO_ROOT)}: {len(current['files'])} file(s), {total:,} bytes"
        )
        return 0

    if not MANIFEST_PATH.is_file():
        print(
            f"FATAL: {MANIFEST_PATH.relative_to(REPO_ROOT)} is missing. Create it with "
            f"`python tools/check_vector_provenance.py --update`.",
            file=sys.stderr,
        )
        return 2
    recorded: dict[str, Any] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    pinned: dict[str, Any] = recorded.get("files", {})

    problems: list[str] = []
    for relative, entry in sorted(current["files"].items()):
        was = pinned.get(relative)
        if was is None:
            problems.append(
                f"{relative} is not pinned. A vector that is not in the manifest is "
                f"a vector this gate cannot notice being rewritten."
            )
        elif was.get("sha256") != entry["sha256"]:
            problems.append(
                f"{relative} CHANGED: recorded {was.get('sha256', '?')[:16]}..., "
                f"found {entry['sha256'][:16]}... ({was.get('bytes')} -> {entry['bytes']} bytes). "
                f"These bytes are published elsewhere; if this edit is deliberate, say so "
                f"and re-pin with --update."
            )
    for relative in sorted(set(pinned) - set(current["files"])):
        problems.append(f"{relative} is pinned but missing from the tree.")

    total = sum(entry["bytes"] for entry in current["files"].values())
    print(f"{'root':<34}{'files':>8}{'bytes':>14}")
    for root in sorted(PROTECTED):
        rows = [k for k in current["files"] if k.startswith(root + "/")]
        size = sum(current["files"][k]["bytes"] for k in rows)
        print(f"{root:<34}{len(rows):>8}{size:>14,}")
    print(f"{'total':<34}{len(current['files']):>8}{total:>14,}")

    if problems:
        print("\nVECTOR PROVENANCE CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: every published vector still matches its recorded digest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
