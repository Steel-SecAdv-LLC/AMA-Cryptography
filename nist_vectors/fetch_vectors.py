#!/usr/bin/env python3
"""Fetch NIST ACVP test vectors from the ACVP-Server repository.

Vector sourcing rules:
- SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, HMAC-SHA-256,
  ML-KEM-1024, ML-DSA-65, SLH-DSA-SHA2-256f:
    Pull internalProjection.json from ACVP-Server gen-val json-files.
- SHA-256: FIPS 180-4 Section B.1 reference vectors (hardcoded).
- AES-256-GCM: SP 800-38D Appendix B TC13-TC16 (hardcoded).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any, cast

VECTORS_DIR = Path(__file__).parent


# The upstream ACVP-Server ref. Defaults to the immutable release tag
# `v1.1.0.42` — the exact upstream snapshot the 1,215-vector attestation
# in docs/compliance/acvp_attestation.json was generated against (815 AFT
# + 400 SHA-3 MCT; the MCT vectors live in the same v1.1.0.42 JSON
# projections and were brought under AMA coverage in v2.1.6 via
# run_vectors.py::_run_sha3_mct / _run_shake_mct). Pinning a tag (not a
# branch) guarantees that a local run without ACVP_REF set reproduces
# the same bytes the CI workflow and the published attestation
# reference. Override with `export ACVP_REF=<tag-or-sha>` (or `master`
# if deliberately testing against upstream tip). The resolved ref is
# returned by `_acvp_ref()` and recorded in validation_summary.json by
# .github/workflows/acvp_validation.yml; that workflow also cross-checks
# the ref against docs/compliance/acvp_attestation.json::acvp_ref so the
# attestation artifact and the CI run cannot silently drift apart.
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
    """Download a JSON file from the ACVP-Server repository."""
    url = f"{ACVP_BASE}/{algo_dir}/{filename}"
    print(f"  Fetching {url}")
    req = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "AMA-Crypto-Vectors/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        data = resp.read()
    return cast(dict[str, Any], json.loads(data))


def fetch_acvp_vectors() -> None:
    """Fetch all ACVP internalProjection.json files."""
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


def create_sha256_vectors() -> None:
    """Create SHA-256 test vectors from FIPS 180-4 Section B.1."""
    out_path = VECTORS_DIR / "SHA-256-FIPS180-4.json"
    if out_path.exists():
        print("  [SKIP] SHA-256-FIPS180-4.json already exists")
        return

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
                        "md": hashlib.sha256(b"abc").hexdigest(),
                        "note": 'Input: "abc"',
                    },
                    {
                        "tcId": 2,
                        "msg": (
                            "6162636462636465636465666465666765666768"
                            "666768696768696a68696a6b696a6b6c6a6b6c6d"
                            "6b6c6d6e6c6d6e6f6d6e6f706e6f7071"
                        ),
                        "md": hashlib.sha256(
                            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                        ).hexdigest(),
                        "note": "Input: 448-bit message",
                    },
                    {
                        "tcId": 3,
                        "msg": "",
                        "md": hashlib.sha256(b"").hexdigest(),
                        "note": "Input: empty string",
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
    fetch_acvp_vectors()

    print("\n2. Creating SHA-256 (FIPS 180-4) vectors...")
    create_sha256_vectors()

    print("\n3. Creating AES-256-GCM (SP 800-38D) vectors...")
    create_aes256gcm_vectors()

    print("\n=== Done ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
