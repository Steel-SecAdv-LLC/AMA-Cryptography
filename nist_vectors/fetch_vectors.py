#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Fetch NIST ACVP test vectors from the ACVP-Server repository.

Vector sourcing rules:
- SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, HMAC-SHA-256,
  ML-KEM-1024, ML-DSA-65, SLH-DSA-SHA2-256f:
    Pull internalProjection.json from ACVP-Server gen-val json-files.
- SHA-256: FIPS 180-4 Section B.1 reference vectors (hardcoded).
- AES-256-GCM: SP 800-38D Appendix B TC13-TC16 (hardcoded).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, cast

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

from tools import http_fetch  # noqa: E402 -- repo-root path insert above (FETCH-003)

DEFAULT_ACVP_REF = "v1.1.0.42"


def _acvp_ref() -> str:
    return os.environ.get("ACVP_REF", DEFAULT_ACVP_REF).strip() or DEFAULT_ACVP_REF


ACVP_BASE = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/" f"{_acvp_ref()}/gen-val/json-files"
)

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


def fetch_acvp_file(algo_dir: str, filename: str) -> dict[str, Any]:
    """Download a JSON file from the ACVP-Server repository.

    Ten of these are issued back to back and raw.githubusercontent.com answers a
    burst by resetting some of it, so the transport is bounded and retried by
    tools/http_fetch.py — the same policy the Wycheproof corpus fetch uses, and
    the same module, because two copies of a retry policy is how the second site
    goes unfixed.
    """
    url = f"{ACVP_BASE}/{algo_dir}/{filename}"
    print(f"  Fetching {url}")
    data = http_fetch.fetch_bytes(url, user_agent="AMA-Crypto-Vectors/1.0")
    return cast(dict[str, Any], json.loads(data))


def fetch_acvp_vectors() -> list[str]:
    """Fetch all ACVP internalProjection.json files.

    Returns the algorithms that could not be fetched.  It returns them rather
    than swallowing them: this function used to print `[ERROR]` and continue,
    and `main()` returned 0 unconditionally, so a fetch that acquired NOTHING
    reported success.  The failure then surfaced two steps later as
    `nist_vectors/results.json missing — harness crashed`, which names the wrong
    component and sends the reader to the wrong file.  A step whose whole job is
    to acquire the vectors must fail when it has not acquired them.
    """
    failures: list[str] = []
    for out_name, algo_dir in ACVP_FETCH_LIST:
        out_path = VECTORS_DIR / out_name
        if out_path.exists():
            print(f"  [SKIP] {out_name} already exists")
            continue
        print(f"Fetching {algo_dir} vectors...")
        try:
            data = fetch_acvp_file(algo_dir, "internalProjection.json")
            out_path.write_text(json.dumps(data, indent=2))
            print(f"  -> Saved {out_name}")
        except Exception as e:
            print(f"  [ERROR] Failed to fetch {algo_dir}: {e}")
            failures.append(algo_dir)
    return failures


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


def main() -> int:
    print("=== NIST Vector Fetching ===\n")

    print("1. Fetching ACVP-Server vectors...")
    failures = fetch_acvp_vectors()

    print("\n2. Creating SHA-256 (FIPS 180-4) vectors...")
    create_sha256_vectors()

    print("\n3. Creating AES-256-GCM (SP 800-38D) vectors...")
    create_aes256gcm_vectors()

    if failures:
        print(
            f"\n=== FAILED === could not fetch {len(failures)} algorithm(s): "
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
    sys.exit(main())
