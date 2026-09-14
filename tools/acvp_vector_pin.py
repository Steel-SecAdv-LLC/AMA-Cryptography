#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The ACVP projections nist_vectors/ fetches must be the bytes the attestation names.

Why this exists
---------------
``fetch_vectors.py`` downloads ten ``internalProjection.json`` files from
``usnistgov/ACVP-Server``, ``run_vectors.py`` validates the library against
them, and ``docs/compliance/acvp_attestation.json`` publishes the result. The
download was pinned to a release tag, ``v1.1.0.42``, and to nothing else:

* A tag names a snapshot; it does not fix its bytes. A tag is a movable ref,
  and the fetch goes through a CDN. Whatever arrived under that name was
  validated against and published as the attested corpus.
* A file already on disk was skipped and used as found. An edited, truncated
  or wrong-ref local copy validated without a word.
* The fetcher re-serialised what it received, so even a reader who thought to
  compare the on-disk bytes with upstream could not have matched them.

So the attestation could say ``v1.1.0.42`` while the harness ran against bytes
nobody had identified. This module fixes the bytes, not just the name. It lives under tools/ rather than
nist_vectors/ because INVARIANT-36 keeps every digest implementation out of the
vector generators' directory: a generator transcribes published values and computes
nothing, and this module is a checker, not a generator.
``docs/compliance/acvp_vector_digests.json`` records the SHA-256 and length of
every projection at the attested ref, next to the attestation whose numbers
depend on them. The fetcher verifies before it writes and refuses a local file
that does not match; the harness verifies before it reads; the workflow runs
``--check`` between the two steps and cross-checks the manifest's ref against
the attestation's. Each refusal is independent of the others.

Three records now have to agree, and ``tests/test_acvp_vector_digests_gate.py``
holds them to it: this manifest, the digest ``tests/kat/PROVENANCE.json`` pins
for the vendored copy of the SLH-DSA projection, and the two upstream digests
recorded inside ``tests/kat/fips203/acvp/ml_kem_acvp_v1.1.0.42.json``. A tag
re-cut upstream, a corrupted transfer or a hand-edited manifest breaks that
agreement somewhere it can be seen.

Advancing the pin is a deliberate act: ``python3 nist_vectors/fetch_vectors.py
--refresh-manifest`` with ``ACVP_REF`` set to the new tag rewrites this
manifest and the fetched files together, and refuses to run under GitHub
Actions. A digest that changed on its own is not a stale manifest; it is a tag
that no longer serves the bytes it served when the attestation was generated.

Exit status of ``--check``
--------------------------
0  every pinned projection is on disk and matches its digest and length
1  a projection is missing or differs
2  the manifest itself cannot be read or is malformed
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "nist_vectors"
MANIFEST_PATH = REPO_ROOT / "docs" / "compliance" / "acvp_vector_digests.json"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: Refs that name whatever upstream has at the moment rather than a snapshot.
#: A pin to one of these is not a pin, so the manifest refuses to carry it.
MUTABLE_REF_SEGMENTS: tuple[str, ...] = ("/master/", "/main/", "/HEAD/")

MANIFEST_NOTE = (
    "SHA-256 and byte length of every ACVP-Server internalProjection.json that "
    "nist_vectors/fetch_vectors.py downloads, taken at the immutable upstream ref "
    "below. The ref names a snapshot; these digests fix its bytes. fetch_vectors.py "
    "refuses to write a download that does not match and refuses to trust a local "
    "file that does not match; run_vectors.py refuses to validate against one; "
    ".github/workflows/acvp_validation.yml checks every file between the two steps "
    "and cross-checks this ref against docs/compliance/acvp_attestation.json. "
    "Regenerate ONLY with `python3 nist_vectors/fetch_vectors.py --refresh-manifest` "
    "(with ACVP_REF set) when the pin is deliberately advanced, in the same commit "
    "as the attestation refresh. A digest that changed on its own is not a stale "
    "manifest: it means the tag no longer serves the bytes the attestation was "
    "generated against."
)


class AcvpVectorIntegrityError(RuntimeError):
    """A projection is not the pinned bytes, or the pin itself cannot be used."""


@dataclass(frozen=True)
class Entry:
    """One pinned projection: the file name under ``nist_vectors/`` and its bytes."""

    name: str
    algo_dir: str
    sha256: str
    size: int

    @property
    def url_path(self) -> str:
        return f"{self.algo_dir}/{PROJECTION_FILENAME}"


@dataclass(frozen=True)
class Manifest:
    acvp_ref: str
    base_url: str
    entries: dict[str, Entry]

    def url_for(self, entry: Entry) -> str:
        return projection_url(self.base_url, entry.algo_dir)


#: The one file the pin covers in each ACVP-Server algorithm directory.
PROJECTION_FILENAME = "internalProjection.json"


def base_url_for_ref(ref: str) -> str:
    """The raw-content root of ``gen-val/json-files`` at ``ref``."""
    return f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{ref}/gen-val/json-files"


def projection_url(base_url: str, algo_dir: str, filename: str = PROJECTION_FILENAME) -> str:
    """The URL of ``filename`` in ``algo_dir`` under ``base_url``.

    The ONE place that path is spelled.  ``Manifest.url_for`` (what the pin
    describes) and ``nist_vectors/fetch_vectors.py`` (what is actually
    downloaded) both come here, so the two cannot drift into naming different
    files — the fetcher used to rebuild the same string inline.
    """
    return f"{base_url}/{algo_dir}/{filename}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> tuple[str, int]:
    """SHA-256 and length of ``path``, streamed so the 30 MB projection is not slurped."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def load_manifest(path: Path | None = None) -> Manifest:
    """Read and validate the manifest. Anything malformed is an error, never a default.

    ``MANIFEST_PATH`` is read at call time, not bound as a default at definition
    time, so a test that points the module at a scratch manifest points every
    caller at it — a definition-time default silently kept writing the real one.
    """
    if path is None:
        path = MANIFEST_PATH
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AcvpVectorIntegrityError(
            f"{_rel(path)} is missing: the ACVP projections are not pinned, so nothing "
            f"can say whether a fetched file is the attested one"
        ) from None
    except (OSError, ValueError) as exc:
        raise AcvpVectorIntegrityError(f"{_rel(path)} could not be read: {exc}") from exc

    if not isinstance(raw, dict):
        raise AcvpVectorIntegrityError(f"{_rel(path)}: top level is not an object")

    ref = raw.get("acvp_ref")
    if not isinstance(ref, str) or not ref or ref != ref.strip():
        raise AcvpVectorIntegrityError(f"{_rel(path)}: acvp_ref must be a non-blank string")
    base_url = raw.get("base_url")
    if base_url != base_url_for_ref(ref):
        raise AcvpVectorIntegrityError(
            f"{_rel(path)}: base_url must be {base_url_for_ref(ref)!r} for acvp_ref "
            f"{ref!r}, not {base_url!r}"
        )
    for segment in MUTABLE_REF_SEGMENTS:
        if segment in f"/{ref}/":
            raise AcvpVectorIntegrityError(
                f"{_rel(path)}: acvp_ref {ref!r} is a moving ref; a digest taken from it "
                f"pins nothing"
            )

    files = raw.get("files")
    if not isinstance(files, dict) or not files:
        raise AcvpVectorIntegrityError(f"{_rel(path)}: 'files' must be a non-empty object")

    entries: dict[str, Entry] = {}
    for name, item in files.items():
        if not isinstance(name, str) or not name.endswith(".json") or "/" in name:
            raise AcvpVectorIntegrityError(f"{_rel(path)}: {name!r} is not a projection file name")
        if not isinstance(item, dict):
            raise AcvpVectorIntegrityError(f"{_rel(path)}: {name}: entry is not an object")
        algo_dir = item.get("algo_dir")
        digest = item.get("sha256")
        size = item.get("bytes")
        if not isinstance(algo_dir, str) or not algo_dir or "/" in algo_dir:
            raise AcvpVectorIntegrityError(
                f"{_rel(path)}: {name}: algo_dir is not a directory name"
            )
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise AcvpVectorIntegrityError(
                f"{_rel(path)}: {name}: sha256 is not 64 lowercase hex digits"
            )
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise AcvpVectorIntegrityError(f"{_rel(path)}: {name}: bytes is not a positive integer")
        entries[name] = Entry(name=name, algo_dir=algo_dir, sha256=digest, size=size)

    return Manifest(acvp_ref=ref, base_url=base_url, entries=entries)


def verify_bytes(entry: Entry, data: bytes, *, origin: str) -> None:
    """Refuse ``data`` unless it is exactly the pinned projection."""
    actual = sha256_hex(data)
    if len(data) != entry.size or actual != entry.sha256:
        raise AcvpVectorIntegrityError(
            f"{entry.name}: {origin} is not the pinned projection: pinned sha256 "
            f"{entry.sha256[:16]}... ({entry.size} bytes), got {actual[:16]}... "
            f"({len(data)} bytes). The pin is the attested corpus; the bytes are not."
        )


def verify_file(entry: Entry, path: Path) -> None:
    """Refuse the file at ``path`` unless it is exactly the pinned projection."""
    if not path.is_file():
        raise AcvpVectorIntegrityError(
            f"{entry.name}: not present at {_rel(path)}; run nist_vectors/fetch_vectors.py"
        )
    actual, size = digest_file(path)
    if size != entry.size or actual != entry.sha256:
        raise AcvpVectorIntegrityError(
            f"{entry.name}: the file at {_rel(path)} is not the pinned projection: pinned "
            f"sha256 {entry.sha256[:16]}... ({entry.size} bytes), on disk {actual[:16]}... "
            f"({size} bytes). Delete it and re-run nist_vectors/fetch_vectors.py, or "
            f"advance the pin deliberately with --refresh-manifest."
        )


def check_ref(manifest: Manifest, resolved_ref: str) -> None:
    """The digests are only meaningful at the ref they were taken from."""
    if manifest.acvp_ref != resolved_ref:
        raise AcvpVectorIntegrityError(
            f"ACVP_REF resolves to {resolved_ref!r} but {MANIFEST_PATH.name} pins "
            f"{manifest.acvp_ref!r}. Either unset ACVP_REF, or advance the pin "
            f"deliberately with `python3 nist_vectors/fetch_vectors.py --refresh-manifest`."
        )


def write_manifest(manifest: Manifest, path: Path | None = None) -> None:
    if path is None:
        path = MANIFEST_PATH
    payload: dict[str, Any] = {
        "note": MANIFEST_NOTE,
        "acvp_ref": manifest.acvp_ref,
        "base_url": manifest.base_url,
        "files": {
            name: {"algo_dir": e.algo_dir, "bytes": e.size, "sha256": e.sha256}
            for name, e in sorted(manifest.entries.items())
        },
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check_tree(vectors_dir: Path, manifest: Manifest) -> list[str]:
    """Every pinned projection must be present under ``vectors_dir`` and match."""
    problems: list[str] = []
    for name, entry in sorted(manifest.entries.items()):
        try:
            verify_file(entry, vectors_dir / name)
        except AcvpVectorIntegrityError as exc:
            problems.append(str(exc))
        else:
            print(f"  OK  {name:32s} {entry.size:>10d} bytes  sha256 {entry.sha256[:16]}...")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the fetched ACVP projections against their pinned digests."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify every pinned projection under --vectors-dir (the default action)",
    )
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--vectors-dir", type=Path, default=VECTORS_DIR)
    args = parser.parse_args([] if argv is None else argv)

    manifest_path: Path = MANIFEST_PATH if args.manifest is None else args.manifest
    try:
        manifest = load_manifest(manifest_path)
    except AcvpVectorIntegrityError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    print(f"ACVP projections pinned at {manifest.acvp_ref} ({len(manifest.entries)} files):")
    problems = check_tree(args.vectors_dir, manifest)
    if problems:
        print("\nACVP VECTOR DIGEST CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"OK: all {len(manifest.entries)} ACVP projections match "
        f"{_rel(manifest_path)} at {manifest.acvp_ref}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
