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
:data:`MANIFEST_PATH`.  Four ways to fail, not one:

* a digest that does not match — the file was edited;
* a manifest entry with no file — a vector was deleted or renamed;
* a file with no manifest entry — a vector was added without being pinned,
  which is how a tree drifts out from under its own gate;
* a tracked file whose suffix is not in :data:`VECTOR_SUFFIXES` and whose
  path is not in :data:`NON_VECTOR_ALLOWLIST` — a suffix filter alone would
  let a ``.hex`` or ``.bin`` vector live under a protected root, unpinned
  and unflagged, silently outside the gate.

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
1  a file changed, went missing, is unpinned, or is a stray — a tracked file
   under a protected root that is neither a pinned vector nor allowlisted
2  the gate could not read what it needs, or read too little to be believed
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from functools import lru_cache
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

#: The file forms that ARE published vectors.  The roots above are directories,
#: and `_tracked_files` used to hash everything in them: the manifest pinned
#: `nist_vectors/run_vectors.py` (54 KB of first-party Python, "Copyright (C)
#: 2025-2026 Steel Security Advisors LLC"), `nist_vectors/fetch_vectors.py`,
#: `nist_vectors/.gitignore` and four `README.md` files — seven entries out of
#: thirty-seven that no upstream publishes.
#:
#: That is not merely untidy.  The gate's whole claim is "these bytes are
#: published elsewhere and must not drift", and the same branch put those
#: Python files under black, ruff and `mypy --strict`: a formatter or a type
#: annotation would fail a gate whose message says the file no longer matches
#: what NIST published.  A gate whose failure names a cause the reader cannot
#: reproduce is one they learn to route around.
VECTOR_SUFFIXES: frozenset[str] = frozenset({".kat", ".rsp", ".json", ".txt", ".dat"})

#: The suffix filter's fail-closed companion.  A suffix filter alone has a
#: blind spot: a vector added under a protected root as `.hex`, `.bin` or
#: `.req` is neither pinned nor flagged — silently outside the gate.  So the
#: gate walks EVERY tracked file under the protected roots, and one that is
#: neither vector-suffixed (pinned above) nor named here, exactly, is a
#: failure.  This is the complete list of tracked non-vector housekeeping
#: under the roots: the first-party ACVP tooling, its ignore rules for the
#: files that tooling generates, and the README per vector family.  Adding a
#: housekeeping file is a deliberate act that appears here, in the diff.
NON_VECTOR_ALLOWLIST: frozenset[str] = frozenset(
    {
        "nist_vectors/.gitignore",
        "nist_vectors/fetch_vectors.py",
        "nist_vectors/run_vectors.py",
        "tests/kat/README.md",
        "tests/kat/ascon/README.md",
        "tests/kat/fips205/README.md",
        "tests/kat/keyformats/README.md",
    }
)

#: A clean report over a tree this gate could not really read means nothing.
#: Set below the real figures so a normal checkout never trips it, and far
#: enough above zero that an empty or partially-checked-out tree cannot pass.
#:
#: 30 when the sweep pinned every file under the protected roots; the tracked
#: published-vector count is now exactly 30, so the floor moves to 20 to keep
#: headroom.  20 is still an order of magnitude above what a partial checkout
#: produces.
MIN_FILES = 20


@lru_cache(maxsize=1)
def _git_tracked() -> frozenset[str]:
    """Every path `git ls-files` reports, repo-relative and POSIX-separated.

    This function is NAMED for git tracking and consulted neither git nor
    `.gitignore`: it was `root.rglob("*")`.  One protected root is
    `nist_vectors/`, whose own `.gitignore` enumerates twelve files the
    tooling deliberately GENERATES there — the ten ACVP JSONs
    `fetch_vectors.py` downloads, `results.json` from `run_vectors.py`, and
    `validation_summary.json` / `acvp_badge.json` from the ACVP workflow.  Any
    of them present made the gate report "<file> is not pinned. A vector that
    is not in the manifest is a vector this gate cannot notice being
    rewritten." and exit 1 — on a developer who had simply run the ACVP flow.

    Falls back to "everything on disk qualifies" when git is unavailable (a
    source tarball, a vendored copy), because refusing to run is worse than
    running over a tree whose ignore rules cannot be consulted.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return frozenset()
    return frozenset(name.decode("utf-8") for name in out.split(b"\0") if name)


def _all_tracked_files(root: Path) -> list[Path]:
    """Every tracked file under `root` (see `_git_tracked`), vector or not.

    The manifest itself and `__pycache__` are excluded; nothing else is.
    """
    tracked = _git_tracked()
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.name != MANIFEST_PATH.name
        and (not tracked or p.relative_to(REPO_ROOT).as_posix() in tracked)
    )


def _tracked_files(root: Path) -> list[Path]:
    """The tracked, PUBLISHED VECTOR files under `root`.

    Two filters, for two different failures: git tracking (see `_git_tracked`)
    and suffix (see VECTOR_SUFFIXES).
    """
    return [p for p in _all_tracked_files(root) if p.suffix.lower() in VECTOR_SUFFIXES]


def _stray_files(root: Path) -> list[Path]:
    """Tracked files under `root` that are neither vectors nor allowlisted.

    The complement of `_tracked_files` minus NON_VECTOR_ALLOWLIST: what the
    suffix filter cannot see and no one has vouched for.  Every entry is a
    gate failure — otherwise a vector added as `.hex` or `.bin` would sit
    under a protected root unpinned and unflagged.
    """
    return [
        p
        for p in _all_tracked_files(root)
        if p.suffix.lower() not in VECTOR_SUFFIXES
        and p.relative_to(REPO_ROOT).as_posix() not in NON_VECTOR_ALLOWLIST
    ]


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


# ---------------------------------------------------------------------------
# Upstream verification
# ---------------------------------------------------------------------------
#
# The digests in `files` prove the vendored bytes have not CHANGED since they
# were vendored.  They cannot prove those bytes were ever what upstream
# published: a corpus that never matched NIST verifies clean forever, and the
# ANCHOR digests in tests/test_vector_provenance_gate.py do not help, because
# they were computed from the same vendored bytes.
#
# `--verify-upstream` closes that for the vectors where it is possible, and is
# explicit about the ones where it is not.  Four buckets, and the coverage rule
# below requires every pinned file to be in exactly one:
#
#   verbatim           a byte-for-byte copy of an upstream file at an immutable
#                      ref.  Fetched and compared.
#   derived            a documented transformation of upstream that records the
#                      SHA-256 of each input in its own `source` block.  The
#                      transformation cannot be replayed from a fetch, but the
#                      INPUTS are fetched and compared, so the derivative cannot
#                      quietly change which upstream it claims to come from.
#   verified_elsewhere another tool already performs the upstream check, named
#                      per entry.  Listed so the rule stays total and nobody
#                      adds a second, drifting copy of the same check.
#   unverifiable       upstream exists but cannot be established by fetching —
#                      a generator that must be RUN, a prose transcription, a
#                      trim with no recorded source digest, a mutable ref.  The
#                      reason is recorded per file.
#
# A pinned file in none of the four is a failure, not a skip: that is how a new
# corpus gets added without anyone deciding how its provenance is established.

_UPSTREAM_BUCKETS = ("verbatim", "derived", "verified_elsewhere", "unverifiable")


def _fetch(url: str) -> bytes:
    # This module is run as a script (`python tools/check_vector_provenance.py`),
    # so the repository root is not on sys.path and `from tools import ...` fails
    # with ModuleNotFoundError. nist_vectors/fetch_vectors.py inserts the root for
    # the same reason; do the same rather than duplicating the retry policy, which
    # FETCH-003 requires every HTTPS fetch in this repository to share.
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from tools import http_fetch

    return http_fetch.fetch_bytes(url, user_agent="ama-cryptography-vector-provenance")


def verify_upstream() -> int:
    """Prove the vendored vectors are what upstream published, where possible."""
    if not MANIFEST_PATH.is_file():
        print(f"FATAL: {MANIFEST_PATH} is missing.", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    pinned = set(manifest.get("files", {}))
    if not pinned:
        print("FATAL: the manifest pins no files; nothing to verify.", file=sys.stderr)
        return 2

    buckets = {name: manifest.get(name, {}) for name in _UPSTREAM_BUCKETS}
    problems: list[str] = []

    # Coverage first: a file in no bucket, or in two, is a defect in the map.
    for relative in sorted(pinned):
        holding = [name for name in _UPSTREAM_BUCKETS if relative in buckets[name]]
        if not holding:
            problems.append(
                f"{relative} is pinned but appears in none of {', '.join(_UPSTREAM_BUCKETS)}. "
                f"Every vector must state how its provenance is established, even if "
                f"the answer is that it cannot be fetched."
            )
        elif len(holding) > 1:
            problems.append(f"{relative} appears in more than one bucket: {holding}.")
    for name in _UPSTREAM_BUCKETS:
        for relative in sorted(buckets[name]):
            if relative not in pinned:
                problems.append(f"{name} names {relative}, which the manifest does not pin.")

    verified = 0

    for relative, entry in sorted(buckets["verbatim"].items()):
        path = REPO_ROOT / relative
        if not path.is_file():
            problems.append(f"{relative}: pinned as verbatim but missing from the tree.")
            continue
        try:
            upstream = _fetch(entry["url"])
        except Exception as exc:
            problems.append(f"{relative}: could not fetch {entry['url']}: {exc}")
            continue
        local = path.read_bytes()
        if hashlib.sha256(upstream).hexdigest() != hashlib.sha256(local).hexdigest():
            problems.append(
                f"{relative}: does NOT match {entry['url']} "
                f"(upstream {hashlib.sha256(upstream).hexdigest()[:16]}, "
                f"vendored {hashlib.sha256(local).hexdigest()[:16]}). The vendored "
                f"vector is not what upstream published."
            )
        else:
            verified += 1
            print(f"  verbatim   OK  {relative}")

    for relative, entry in sorted(buckets["derived"].items()):
        path = REPO_ROOT / relative
        if not path.is_file():
            problems.append(f"{relative}: pinned as derived but missing from the tree.")
            continue
        try:
            block = json.loads(path.read_text(encoding="utf-8"))[entry["source_block"]]
        except Exception as exc:
            problems.append(
                f"{relative}: could not read its {entry['source_block']!r} block: {exc}"
            )
            continue
        for source in entry["sources"]:
            recorded = block.get(source["digest_field"])
            if not recorded:
                problems.append(
                    f"{relative}: its source block has no {source['digest_field']!r}, so "
                    f"there is nothing to compare {source['url']} against."
                )
                continue
            try:
                upstream = _fetch(source["url"])
            except Exception as exc:
                problems.append(f"{relative}: could not fetch {source['url']}: {exc}")
                continue
            actual = hashlib.sha256(upstream).hexdigest()
            if actual != recorded:
                problems.append(
                    f"{relative}: records {source['digest_field']} = {recorded[:16]}... "
                    f"for {source['url']}, but that file now hashes to {actual[:16]}.... "
                    f"The derivative names an upstream it did not come from."
                )
            else:
                verified += 1
                print(f"  derived    OK  {relative} <- {source['digest_field']}")

    for relative, entry in sorted(buckets["verified_elsewhere"].items()):
        print(f"  elsewhere  --  {relative} ({entry['by']})")
    for relative in sorted(buckets["unverifiable"]):
        print(f"  unfetchable--  {relative}")

    print(
        f"\n{verified} upstream comparison(s) made; "
        f"{len(buckets['verified_elsewhere'])} file(s) verified by another tool; "
        f"{len(buckets['unverifiable'])} file(s) recorded as not establishable by fetch."
    )

    if problems:
        print("\nUPSTREAM PROVENANCE CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    if verified == 0:
        print(
            "FATAL: no upstream comparison was actually performed. A run that "
            "fetched nothing must not report upstream provenance as established.",
            file=sys.stderr,
        )
        return 2

    print("OK: every fetchable vector still matches what upstream published.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite the manifest from the current tree (never run in CI)",
    )
    parser.add_argument(
        "--verify-upstream",
        action="store_true",
        help=(
            "fetch each vector's recorded upstream and prove the vendored bytes "
            "are what upstream published (needs network; the offline digest "
            "check proves only that they have not changed since vendoring)"
        ),
    )
    args = parser.parse_args(argv)

    if args.verify_upstream:
        return verify_upstream()

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
    for root in sorted(PROTECTED):
        for path in _stray_files(REPO_ROOT / root):
            relative = path.relative_to(REPO_ROOT).as_posix()
            problems.append(
                f"{relative} is under a protected root but is neither a pinned vector "
                f"nor in NON_VECTOR_ALLOWLIST. A suffix this gate does not recognize "
                f"is not an exemption; give the file a vector suffix and pin it with "
                f"--update, or allowlist it deliberately."
            )

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
