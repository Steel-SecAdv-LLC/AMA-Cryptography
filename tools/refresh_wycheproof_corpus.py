#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Verify or refresh the vendored Project Wycheproof corpus against upstream.

The gate in ``wycheproof_vectors/run_wycheproof.py`` runs **offline** against a
version-pinned, hash-checked corpus under ``wycheproof_vectors/vectors/`` whose
provenance is recorded in ``wycheproof_vectors/manifest.json``. This tool is the
other half of that contract: it re-derives that provenance from the upstream
`C2SP/wycheproof <https://github.com/C2SP/wycheproof>`_ repository so a human can
prove — or a CI job can assert — that the vendored bytes really are upstream's at
the recorded commit, and it regenerates the manifest when the pin is advanced.

Three modes:

``--verify`` (default)
    (1) *Offline integrity*: every vendored file's SHA-256 and vector count match
        the manifest, the manifest and the on-disk ``vectors/`` set agree in both
        directions, and the totals add up. This needs no network and is what the
        CI provenance test runs.
    (2) *Upstream provenance*: fetch each file from ``C2SP/wycheproof`` at the
        pinned commit and confirm the raw bytes are identical (same SHA-256) to
        what is vendored. Skipped when ``--offline`` is given.
    Exits non-zero if anything disagrees.

``--offline``
    Run only the offline integrity half of ``--verify``. Air-gap friendly; this
    is the exact check ``tests/test_wycheproof_corpus_provenance.py`` drives.

``--refresh``
    Fetch every manifest-listed file from upstream at ``--commit`` (default: the
    currently pinned commit), write the raw bytes back byte-for-byte, and
    regenerate ``manifest.json`` (per-file SHA-256, vector count, group count,
    byte length, algorithm, schema; the aggregate ``totalVectors``; and the
    ``upstream`` pin). Prints a diff of what moved and reminds you to re-review
    ``README.md`` and the runner's policy counts, which are deliberately *not*
    auto-edited.

Network notes: outbound HTTPS honours ``HTTPS_PROXY``/``HTTP_PROXY`` and the
standard ``SSL_CERT_FILE``/``SSL_CERT_DIR`` environment variables (via
``ssl.create_default_context``), so it works both on a normal CI runner and
behind a TLS-terminating proxy without code changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "wycheproof_vectors"
MANIFEST_PATH = VECTORS_DIR / "manifest.json"
FILES_SUBDIR = "vectors"

_HTTP_TIMEOUT = 60
_USER_AGENT = "AMA-Crypto-Wycheproof-Refresh/1.0"


# ---------------------------------------------------------------------------
# Manifest + file helpers
# ---------------------------------------------------------------------------
def load_manifest() -> dict[str, Any]:
    """Load and minimally validate manifest.json."""
    manifest: dict[str, Any] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for key in ("files", "totalVectors", "upstream"):
        if key not in manifest:
            raise ValueError(f"manifest.json is missing the required {key!r} key")
    for key in ("commit", "repository", "path"):
        if key not in manifest["upstream"]:
            raise ValueError(f"manifest.json upstream is missing the required {key!r} key")
    return manifest


def derive_file_meta(raw: bytes) -> dict[str, Any]:
    """Re-derive a manifest file entry from raw JSON bytes.

    SHA-256 and byte length are taken over the *raw* bytes (the vendored file is
    kept byte-identical to upstream, so these stay checkable); the counts come
    from parsing. ``numberOfTests`` is upstream's own declared count and
    ``actualTests`` is the count actually present — they match for every current
    file, and the runner enforces ``actualTests``.
    """
    data = json.loads(raw)
    groups = data["testGroups"]
    actual = sum(len(g["tests"]) for g in groups)
    return {
        "actualTests": actual,
        "algorithm": data["algorithm"],
        "bytes": len(raw),
        "numberOfTests": data.get("numberOfTests", actual),
        "schema": data["schema"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "testGroups": len(groups),
    }


def upstream_url(manifest: dict[str, Any], filename: str, commit: str) -> str:
    """Raw upstream URL for one vendored file at a given commit."""
    repo = manifest["upstream"]["repository"].removeprefix("https://github.com/").strip("/")
    path = manifest["upstream"]["path"].strip("/")
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{path}/{filename}"


def fetch_bytes(url: str) -> bytes:
    """Download raw bytes over HTTPS, honouring proxy + CA env vars.

    The scheme is checked rather than assumed.  ``urllib`` also opens ``file:``
    and ``ftp:``, so a URL reaching here from a manifest — the manifest being
    the thing this tool exists to *re-derive*, not a trusted input — could
    otherwise read a local path and have its contents vendored as "upstream".
    An https-only guard is what makes the S310 suppression below a statement of
    fact instead of a promise.
    """
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-HTTPS corpus URL: {url!r}")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(  # noqa: S310 -- https enforced directly above (WYC-001)
        url, headers={"User-Agent": _USER_AGENT}
    )
    # The suppression anchors on the physical line ruff reports, which for a
    # wrapped call is the one carrying the callee — not the closing `as resp:`.
    with urllib.request.urlopen(  # noqa: S310 -- https enforced directly above (WYC-001)
        req, timeout=_HTTP_TIMEOUT, context=ctx
    ) as resp:
        return bytes(resp.read())


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
def verify_offline(manifest: dict[str, Any]) -> list[str]:
    """Offline integrity: vendored files match the manifest, bidirectionally."""
    problems: list[str] = []
    listed = set(manifest["files"])
    present = {p.name for p in (VECTORS_DIR / FILES_SUBDIR).glob("*.json")}

    for extra in sorted(present - listed):
        problems.append(
            f"{extra}: present under {FILES_SUBDIR}/ but absent from manifest.json "
            "— an unlisted corpus file is never run and would go uncovered"
        )

    running_total = 0
    for name, meta in sorted(manifest["files"].items()):
        path = VECTORS_DIR / FILES_SUBDIR / name
        if not path.is_file():
            problems.append(f"{name}: listed in manifest but missing on disk")
            continue
        derived = derive_file_meta(path.read_bytes())
        running_total += derived["actualTests"]
        for field in ("sha256", "actualTests", "testGroups", "bytes"):
            if derived[field] != meta.get(field):
                problems.append(
                    f"{name}: {field} {derived[field]!r} on disk != manifest {meta.get(field)!r}"
                )

    if running_total != manifest["totalVectors"]:
        problems.append(
            f"totalVectors: {running_total} vectors on disk != manifest "
            f"{manifest['totalVectors']}"
        )
    return problems


def verify_upstream(manifest: dict[str, Any], commit: str) -> list[str]:
    """Provenance: vendored bytes are identical to upstream at ``commit``."""
    problems: list[str] = []
    for name, meta in sorted(manifest["files"].items()):
        url = upstream_url(manifest, name, commit)
        try:
            raw = fetch_bytes(url)
        except Exception as exc:
            problems.append(f"{name}: could not fetch upstream ({type(exc).__name__}: {exc})")
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if digest != meta["sha256"]:
            problems.append(
                f"{name}: upstream SHA-256 {digest} at {commit[:12]} != manifest "
                f"{meta['sha256']} — the vendored copy is not upstream's bytes"
            )
        else:
            print(f"  ok  {name}: {digest[:16]}… matches upstream @ {commit[:12]}")
    return problems


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------
def refresh(manifest: dict[str, Any], commit: str) -> int:
    """Re-vendor every manifest file from upstream at ``commit`` and rewrite it."""
    new_files: dict[str, Any] = {}
    changed: list[str] = []
    total = 0
    for name in sorted(manifest["files"]):
        url = upstream_url(manifest, name, commit)
        print(f"  fetching {url}")
        raw = fetch_bytes(url)
        meta = derive_file_meta(raw)
        old = manifest["files"].get(name, {})
        (VECTORS_DIR / FILES_SUBDIR / name).write_bytes(raw)
        new_files[name] = meta
        total += meta["actualTests"]
        if old.get("sha256") != meta["sha256"]:
            changed.append(
                f"    {name}: sha256 {str(old.get('sha256'))[:12]}… -> {meta['sha256'][:12]}…, "
                f"vectors {old.get('actualTests')} -> {meta['actualTests']}"
            )

    new_manifest = {
        "files": new_files,
        "totalVectors": total,
        "upstream": {
            **manifest["upstream"],
            "commit": commit,
            "retrieved": date.today().isoformat(),
        },
    }
    MANIFEST_PATH.write_text(
        json.dumps(new_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="",
    )

    print(f"\nRewrote {len(new_files)} files; totalVectors = {total}; commit pinned to {commit}.")
    if changed:
        print("Changed files:")
        print("\n".join(changed))
    else:
        print("No byte changes (corpus already matched upstream at this commit).")
    print(
        "\nReview by hand (deliberately NOT auto-edited):\n"
        "  - wycheproof_vectors/README.md (commit, retrieved date, per-file counts)\n"
        "  - wycheproof_vectors/run_wycheproof.py policy `expected` counts if the\n"
        "    vector set changed (out-of-scope / acceptable / divergence buckets)\n"
        "Then run: python tools/refresh_wycheproof_corpus.py --verify"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--verify",
        action="store_true",
        help="verify vendored corpus against the manifest and upstream (default)",
    )
    mode.add_argument(
        "--refresh",
        action="store_true",
        help="re-vendor from upstream at --commit and regenerate manifest.json",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="verify only the offline manifest<->disk integrity (no network)",
    )
    parser.add_argument(
        "--commit",
        default=None,
        help="upstream commit SHA (default: the commit pinned in manifest.json)",
    )
    args = parser.parse_args(argv)

    manifest = load_manifest()
    commit = args.commit or manifest["upstream"]["commit"]

    if args.refresh:
        if args.offline:
            parser.error("--refresh cannot be combined with --offline (it needs the network)")
        return refresh(manifest, commit)

    print("Offline integrity (vendored corpus vs manifest.json):")
    problems = verify_offline(manifest)
    if not problems:
        print(
            f"  ok  {len(manifest['files'])} files, {manifest['totalVectors']} vectors, digests + counts match"
        )

    if not args.offline:
        print(f"\nUpstream provenance (vs C2SP/wycheproof @ {commit[:12]}):")
        problems += verify_upstream(manifest, commit)

    if problems:
        print(f"\nCORPUS PROBLEMS ({len(problems)}):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nFAIL: vendored Wycheproof corpus did not verify.", file=sys.stderr)
        return 1

    print("\nOK: vendored Wycheproof corpus is intact and matches upstream provenance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
