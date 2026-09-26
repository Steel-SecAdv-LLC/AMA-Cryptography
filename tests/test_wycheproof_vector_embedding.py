# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The Wycheproof vector embedded in ``tests/c/test_chacha20poly1305.c`` is
the JSON's, byte for byte, and the JSON is the one the manifest records.

The per-slot KAT sweep (INVARIANT-45) counts ``test_chacha20poly1305`` as a
published-vector KAT for the ``chacha20-avx2x8`` cell.  Its only published
vector was RFC 8439's 114-byte message, and ``chacha20_xor`` hands only whole
512-byte chunks to the 8-way kernel, so under that pin the published answer
never entered the kernel the cell is named for (measured: the first entry into
``ama_chacha20_block_x8_avx2`` came from the equivalence sweep, not the KAT).
Wycheproof tcId 90 — 513 bytes, ``result: valid`` — is embedded so a published
ciphertext and tag pass through the kernel; this test is what stops the
embedded copy from drifting away from the corpus it cites.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
C_TEST = REPO_ROOT / "tests" / "c" / "test_chacha20poly1305.c"
VECTORS = REPO_ROOT / "wycheproof_vectors" / "vectors" / "chacha20_poly1305_test.json"
MANIFEST = REPO_ROOT / "wycheproof_vectors" / "manifest.json"
TC_ID = 90


def _embedded_arrays() -> dict[str, bytes]:
    """The five ``static const uint8_t NAME[N] = { ... };`` arrays of the
    Wycheproof function, parsed from the C source."""
    source = C_TEST.read_text(encoding="utf-8")
    start = source.index("static void test_wycheproof_tc90_long_message(void)")
    end = source.index("static void test_scalar_vs_dispatched_sweep(void)")
    body = source[start:end]
    arrays: dict[str, bytes] = {}
    for match in re.finditer(r"static const uint8_t (\w+)\[(\d+)\] = \{(.*?)\};", body, re.DOTALL):
        name, declared, initialiser = match.group(1), int(match.group(2)), match.group(3)
        data = bytes(int(tok, 16) for tok in re.findall(r"0x([0-9a-fA-F]{2})", initialiser))
        assert len(data) == declared, f"{name}: {len(data)} bytes in a [{declared}] array"
        arrays[name] = data
    return arrays


def test_the_json_file_is_the_one_the_manifest_records() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    recorded = manifest["files"]["chacha20_poly1305_test.json"]["sha256"]
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == recorded


def test_the_embedded_vector_is_tcid_90_byte_for_byte() -> None:
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(t for g in doc["testGroups"] for t in g["tests"] if t["tcId"] == TC_ID)
    assert case["result"] == "valid"
    assert case["aad"] == ""
    embedded = _embedded_arrays()
    assert set(embedded) == {"key", "nonce", "msg", "expected_ct", "expected_tag"}
    assert embedded["key"] == bytes.fromhex(case["key"])
    assert embedded["nonce"] == bytes.fromhex(case["iv"])
    assert embedded["msg"] == bytes.fromhex(case["msg"])
    assert embedded["expected_ct"] == bytes.fromhex(case["ct"])
    assert embedded["expected_tag"] == bytes.fromhex(case["tag"])


def test_the_message_is_long_enough_to_reach_the_eight_way_kernel() -> None:
    """512 bytes is the chunk the dispatcher hands to chacha20_block_x8; the
    513th byte takes the scalar tail, so both paths carry a published answer."""
    assert len(_embedded_arrays()["msg"]) == 513


def test_the_kat_calls_the_vector_before_the_equivalence_sweep() -> None:
    source = C_TEST.read_text(encoding="utf-8")
    main_body = source[source.index("int main(void)") :]
    assert main_body.index("test_wycheproof_tc90_long_message();") < main_body.index(
        "test_scalar_vs_dispatched_sweep();"
    )
