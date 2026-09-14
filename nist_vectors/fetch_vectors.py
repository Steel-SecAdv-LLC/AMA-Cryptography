#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Fetch NIST ACVP test vectors from the ACVP-Server repository.

Vector sourcing rules:
- SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, HMAC-SHA-256,
  ML-KEM-1024, ML-DSA-65, SLH-DSA-SHA2-256f:
    Pull internalProjection.json from ACVP-Server gen-val json-files, and
    accept each ONLY if it is byte-for-byte the projection pinned by SHA-256
    in docs/compliance/acvp_vector_digests.json (see tools/acvp_vector_pin.py
    for why a tag alone pins nothing).  The bytes are written verbatim.
- SHA-256: FIPS 180-4 Section B.1 reference vectors (hardcoded).
- AES-256-GCM: SP 800-38D Appendix B TC13-TC16 (hardcoded).

``--refresh-manifest`` advances the pin: with ``ACVP_REF`` set to the new tag
it fetches every projection, rewrites the manifest from what arrived, and
refuses to run under GitHub Actions, because moving the pin is a reviewed
change and never a side effect of a CI run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

VECTORS_DIR = Path(__file__).parent


# The upstream ACVP-Server ref. Defaults to the immutable release tag
# `v1.1.0.42` — the exact upstream snapshot the 1,215-vector attestation
# in docs/compliance/acvp_attestation.json was generated against (815 AFT
# + 400 SHA-3 MCT; the MCT vectors live in the same v1.1.0.42 JSON
# projections and were brought under AMA coverage on the 2.1.5 line via
# run_vectors.py::_run_sha3_mct / _run_shake_mct). Pinning a tag (not a
# branch) guarantees that a local run without ACVP_REF set reproduces
# the same bytes the CI workflow and the published attestation
# reference. Override with `export ACVP_REF=<tag-or-sha>` (or `master`
# if deliberately testing against upstream tip). The resolved ref is
# returned by `_acvp_ref()` and recorded in validation_summary.json by
# .github/workflows/acvp_validation.yml; that workflow also cross-checks
# the ref against docs/compliance/acvp_attestation.json::acvp_ref so the
# attestation artifact and the CI run cannot silently drift apart.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools import acvp_vector_pin as acvp_manifest  # noqa: E402 -- path insert above (ACVP-001)
from tools import http_fetch  # noqa: E402 -- repo-root path insert above (FETCH-003)

DEFAULT_ACVP_REF = "v1.1.0.42"


def _acvp_ref() -> str:
    return os.environ.get("ACVP_REF", DEFAULT_ACVP_REF).strip() or DEFAULT_ACVP_REF


ACVP_BASE = acvp_manifest.base_url_for_ref(_acvp_ref())

# Algorithm directory names on ACVP-Server (actual paths verified)
# Each entry: output_filename -> ACVP-Server directory name
ACVP_FETCH_LIST: list[tuple[str, str]] = [
    ("SHA3-256-2.0.json", "SHA3-256-2.0"),
    ("SHA3-512-2.0.json", "SHA3-512-2.0"),
    ("SHAKE-128-1.0.json", "SHAKE-128-1.0"),
    ("SHAKE-256-1.0.json", "SHAKE-256-1.0"),
    ("HMAC-SHA2-256-2.0.json", "HMAC-SHA2-256-2.0"),
    ("ML-KEM-keyGen-FIPS203.json", "ML-KEM-keyGen-FIPS203"),
    ("ML-KEM-encapDecap-FIPS203.json", "ML-KEM-encapDecap-FIPS203"),
    ("ML-DSA-keyGen-FIPS204.json", "ML-DSA-keyGen-FIPS204"),
    ("ML-DSA-sigVer-FIPS204.json", "ML-DSA-sigVer-FIPS204"),
    ("SLH-DSA-sigVer-FIPS205.json", "SLH-DSA-sigVer-FIPS205"),
]


def fetch_acvp_file(algo_dir: str, filename: str) -> bytes:
    """Download one file from the ACVP-Server tree and return its bytes verbatim.

    Ten of these are issued back to back and raw.githubusercontent.com answers a
    burst by resetting some of it, so the transport is bounded and retried by
    tools/http_fetch.py — the same policy the Wycheproof corpus fetch uses, and
    the same module, because two copies of a retry policy is how the second site
    goes unfixed.

    The bytes are returned as received, neither parsed nor re-serialised: the
    digest pin in docs/compliance/acvp_vector_digests.json is over what upstream
    publishes, and what reaches disk must be that, byte for byte.  (The fetcher
    used to `json.dumps(json.loads(...), indent=2)` on the way through, which
    left nothing on disk that could ever have been compared with upstream.)
    """
    url = f"{ACVP_BASE}/{algo_dir}/{filename}"
    print(f"  Fetching {url}")
    return http_fetch.fetch_bytes(url, user_agent="AMA-Crypto-Vectors/1.0")


def _load_manifest() -> acvp_manifest.Manifest:
    return acvp_manifest.load_manifest()


def fetch_acvp_vectors() -> list[str]:
    """Fetch every projection in ACVP_FETCH_LIST, each verified against its pin.

    Returns the algorithms that could not be acquired AS PINNED.  It returns them
    rather than swallowing them: this function used to print `[ERROR]` and
    continue, and `main()` returned 0 unconditionally, so a fetch that acquired
    NOTHING reported success.  The failure then surfaced two steps later as
    `nist_vectors/results.json missing — harness crashed`, which names the wrong
    component and sends the reader to the wrong file.  A step whose whole job is
    to acquire the vectors must fail when it has not acquired them.

    "Acquired" now means acquired and verified.  Every file is checked against
    docs/compliance/acvp_vector_digests.json before it is written, and a file
    already on disk is checked rather than trusted: one that matches is kept
    without a fetch, one that does not is re-fetched and replaced only by bytes
    that match.  A download that does not match is never written and counts as a
    failure, so a corrupted transfer, a re-cut tag or an edited local copy all
    fail this step by name instead of being validated against and published.
    """
    failures: list[str] = []
    try:
        manifest = _load_manifest()
        acvp_manifest.check_ref(manifest, _acvp_ref())
    except acvp_manifest.AcvpVectorIntegrityError as exc:
        print(f"  [ERROR] {exc}", file=sys.stderr)
        return [algo_dir for _, algo_dir in ACVP_FETCH_LIST]

    for out_name, algo_dir in ACVP_FETCH_LIST:
        out_path = VECTORS_DIR / out_name
        entry = manifest.entries.get(out_name)
        if entry is None:
            print(
                f"  [ERROR] {out_name} is not pinned in {acvp_manifest.MANIFEST_PATH.name}; "
                f"refusing to fetch an unpinned projection",
                file=sys.stderr,
            )
            failures.append(algo_dir)
            continue
        if entry.algo_dir != algo_dir:
            print(
                f"  [ERROR] {out_name}: the fetch list names {algo_dir!r} but the pin "
                f"was taken from {entry.algo_dir!r}",
                file=sys.stderr,
            )
            failures.append(algo_dir)
            continue

        if out_path.exists():
            try:
                acvp_manifest.verify_file(entry, out_path)
            except acvp_manifest.AcvpVectorIntegrityError as exc:
                print(f"  [STALE] {exc}")
                print(f"          re-fetching {out_name}; replaced only by bytes that verify")
            else:
                print(f"  [OK] {out_name} already present, digest verified")
                continue

        print(f"Fetching {algo_dir} vectors...")
        try:
            data = fetch_acvp_file(algo_dir, "internalProjection.json")
            acvp_manifest.verify_bytes(entry, data, origin=f"the download of {entry.url_path}")
            # A digest match on bytes that are not JSON would mean the pin itself
            # was taken from something that is not a projection.  Parse to prove
            # the pin is usable; write what arrived, not the parse.
            json.loads(data)
            out_path.write_bytes(data)
            print(
                f"  -> Saved {out_name} ({len(data)} bytes, "
                f"sha256 {entry.sha256[:16]}... verified)"
            )
        except Exception as e:
            print(f"  [ERROR] Failed to acquire {algo_dir} as pinned: {e}", file=sys.stderr)
            failures.append(algo_dir)
    return failures


def refresh_manifest() -> int:
    """Re-pin docs/compliance/acvp_vector_digests.json to what ACVP_REF serves now.

    A deliberate act, run by a person advancing the pin, in the same commit as
    the attestation refresh.  It refuses to run under GitHub Actions: the pin
    exists so that CI checks bytes against a reviewed record, and a CI run that
    could rewrite that record would be checking bytes against themselves.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(
            "refusing to refresh the manifest under GitHub Actions: advancing the pin "
            "is a reviewed change, not a CI side effect",
            file=sys.stderr,
        )
        return 1

    ref = _acvp_ref()
    try:
        previous: dict[str, acvp_manifest.Entry] = _load_manifest().entries
    except acvp_manifest.AcvpVectorIntegrityError as exc:
        print(f"  (no usable previous manifest: {exc})")
        previous = {}

    entries: dict[str, acvp_manifest.Entry] = {}
    for out_name, algo_dir in ACVP_FETCH_LIST:
        data = fetch_acvp_file(algo_dir, "internalProjection.json")
        json.loads(data)
        entry = acvp_manifest.Entry(
            name=out_name,
            algo_dir=algo_dir,
            sha256=acvp_manifest.sha256_hex(data),
            size=len(data),
        )
        (VECTORS_DIR / out_name).write_bytes(data)
        entries[out_name] = entry
        before = previous.get(out_name)
        if before is None:
            print(f"  NEW      {out_name}: {entry.sha256[:16]}... ({entry.size} bytes)")
        elif before.sha256 != entry.sha256 or before.size != entry.size:
            print(
                f"  CHANGED  {out_name}: {before.sha256[:16]}... ({before.size} bytes) -> "
                f"{entry.sha256[:16]}... ({entry.size} bytes)"
            )
        else:
            print(f"  same     {out_name}")

    manifest = acvp_manifest.Manifest(
        acvp_ref=ref, base_url=acvp_manifest.base_url_for_ref(ref), entries=entries
    )
    acvp_manifest.write_manifest(manifest)
    print(
        f"\nWrote {acvp_manifest.MANIFEST_PATH.name} pinned at "
        f"{ref}. If this moved the pin, the attestation refresh procedure in "
        f".github/workflows/acvp_validation.yml applies: the attestation JSON, the "
        f"workflow default, DEFAULT_ACVP_REF here and the manifest advance together."
    )
    return 0


def create_sha256_vectors() -> None:
    """Create SHA-256 test vectors from FIPS 180-4 Section B.1."""
    out_path = VECTORS_DIR / "SHA-256-FIPS180-4.json"
    if out_path.exists():
        print("  [SKIP] SHA-256-FIPS180-4.json already exists")
        return

    # Every digest below is TRANSCRIBED from the publication named in
    # ``source``, not computed here.
    #
    # They used to be ``hashlib.sha256(...).hexdigest()`` calls evaluated at
    # generation time.  On any libcrypto-linked CPython — every manylinux wheel
    # and every mainstream distribution Python, as
    # ``tools/check_stdlib_hash_boundary.py``'s own docstring states —
    # ``hashlib.sha256`` IS OpenSSL, so regenerating this file replaced the
    # NIST vectors with OpenSSL's output wearing a NIST label, and
    # ``nist_vectors/run_vectors.py`` then validated AMA's SHA-256 against
    # them.  That is a differential test against another implementation
    # presented as conformance to a specification, and it is the exact pattern
    # ``tools/check_corpus_originality.py`` exists to forbid: "AMA is checked
    # against specifications and its own reference encoder, not against another
    # implementation."  It is also the vendor boundary INVARIANT-1 draws —
    # OpenSSL may be a benchmark comparator and never a source of truth.
    #
    # The committed values were already correct; what was wrong was where the
    # next regeneration would have got them.
    vectors = {
        "source": "FIPS 180-4 Section B.1",
        "url": "https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
        "algorithm": "SHA-256",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "tests": [
                    {
                        "tcId": 1,
                        "msg": "616263",
                        # Transcribed from FIPS 180-4 Appendix B.1, not
                        # computed.  See the note above the dict.
                        "md": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                        "note": 'Input: "abc" (FIPS 180-4 Appendix B.1)',
                    },
                    {
                        "tcId": 2,
                        "msg": (
                            "6162636462636465636465666465666765666768"
                            "666768696768696a68696a6b696a6b6c6a6b6c6d"
                            "6b6c6d6e6c6d6e6f6d6e6f706e6f7071"
                        ),
                        # FIPS 180-4 Appendix B.2.
                        "md": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                        "note": "Input: 448-bit message (FIPS 180-4 Appendix B.2)",
                    },
                    {
                        "tcId": 3,
                        "msg": "",
                        # SHA-256 of the empty string.  Not in Appendix B
                        # (which starts at "abc"), so it is cited to its own
                        # source: NIST CAVP SHA-256 ShortMsg, Len = 0.
                        "md": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "note": "Input: empty string (NIST CAVP SHAVS ShortMsg, Len=0)",
                    },
                ],
            }
        ],
    }
    out_path.write_text(json.dumps(vectors, indent=2))
    print("  -> Saved SHA-256-FIPS180-4.json")


def create_aes256gcm_vectors() -> None:
    """Create AES-256-GCM vectors from SP 800-38D Appendix B (TC13-TC16).

    These are the McGrew & Viega test cases with 256-bit keys.
    Source: https://csrc.nist.gov/pubs/sp/800/38/d/final
    """
    out_path = VECTORS_DIR / "AES-256-GCM-SP800-38D.json"
    if out_path.exists():
        print("  [SKIP] AES-256-GCM-SP800-38D.json already exists")
        return

    vectors = {
        "source": "NIST SP 800-38D Appendix B (McGrew & Viega)",
        "url": "https://csrc.nist.gov/pubs/sp/800/38/d/final",
        "algorithm": "AES-256-GCM",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "keyLen": 256,
                "tests": [
                    {
                        "tcId": 13,
                        "key": "00000000000000000000000000000000"
                        "00000000000000000000000000000000",
                        "iv": "000000000000000000000000",
                        "pt": "",
                        "aad": "",
                        "ct": "",
                        "tag": "530f8afbc74536b9a963b4f1c4cb738b",
                    },
                    {
                        "tcId": 14,
                        "key": "00000000000000000000000000000000"
                        "00000000000000000000000000000000",
                        "iv": "000000000000000000000000",
                        "pt": "00000000000000000000000000000000",
                        "aad": "",
                        "ct": "cea7403d4d606b6e074ec5d3baf39d18",
                        "tag": "d0d1c8a799996bf0265b98b5d48ab919",
                    },
                    {
                        "tcId": 15,
                        "key": "feffe9928665731c6d6a8f9467308308"
                        "feffe9928665731c6d6a8f9467308308",
                        "iv": "cafebabefacedbaddecaf888",
                        "pt": "d9313225f88406e5a55909c5aff5269a"
                        "86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525"
                        "b16aedf5aa0de657ba637b391aafd255",
                        "aad": "",
                        "ct": "522dc1f099567d07f47f37a32a84427d"
                        "643a8cdcbfe5c0c97598a2bd2555d1aa"
                        "8cb08e48590dbb3da7b08b1056828838"
                        "c5f61e6393ba7a0abcc9f662898015ad",
                        "tag": "b094dac5d93471bdec1a502270e3cc6c",
                    },
                    {
                        "tcId": 16,
                        "key": "feffe9928665731c6d6a8f9467308308"
                        "feffe9928665731c6d6a8f9467308308",
                        "iv": "cafebabefacedbaddecaf888",
                        "pt": "d9313225f88406e5a55909c5aff5269a"
                        "86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525"
                        "b16aedf5aa0de657ba637b39",
                        "aad": "feedfacedeadbeeffeedfacedeadbeef" "abaddad2",
                        "ct": "522dc1f099567d07f47f37a32a84427d"
                        "643a8cdcbfe5c0c97598a2bd2555d1aa"
                        "8cb08e48590dbb3da7b08b1056828838"
                        "c5f61e6393ba7a0abcc9f662",
                        "tag": "76fc6ece0f4e1768cddf8853bb2d551b",
                    },
                ],
            }
        ],
    }
    out_path.write_text(json.dumps(vectors, indent=2))
    print("  -> Saved AES-256-GCM-SP800-38D.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify the NIST ACVP vectors.")
    parser.add_argument(
        "--refresh-manifest",
        action="store_true",
        help=(
            "advance the digest pin to whatever ACVP_REF serves now (deliberate; "
            "refused under GitHub Actions)"
        ),
    )
    args = parser.parse_args([] if argv is None else argv)
    if args.refresh_manifest:
        return refresh_manifest()

    print("=== NIST Vector Fetching ===\n")

    print("1. Fetching ACVP-Server vectors (verified against the digest pin)...")
    failures = fetch_acvp_vectors()

    print("\n2. Creating SHA-256 (FIPS 180-4) vectors...")
    create_sha256_vectors()

    print("\n3. Creating AES-256-GCM (SP 800-38D) vectors...")
    create_aes256gcm_vectors()

    if failures:
        print(
            f"\n=== FAILED === could not acquire {len(failures)} algorithm(s) as pinned: "
            f"{', '.join(failures)}",
            file=sys.stderr,
        )
        print(
            "Refusing to report success with vectors missing: the validation "
            "step would fail on the absent file and blame the harness.",
            file=sys.stderr,
        )
        return 1

    print("\n=== Done ===")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
