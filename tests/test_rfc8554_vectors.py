# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
RFC 8554 Appendix F — the HSS/LMS answer key, vendored and checked.

**AMA does not implement HSS/LMS.** This module asserts nothing about AMA's
behaviour, and there is no scaffolding here pretending otherwise.

What it does assert is that the *reference* for that work is real. PR #378 says
"RFC 8554's Appendix F test cases have been extracted and verified to parse to
the expected 60-byte public keys and 2644/3860-byte signatures, so the answer
key for the first half of that work is ready whenever it is authorised". That
extraction existed nowhere in the repository — the sentence described work that
had been done and not committed, which is the same shape of claim as a
documented test count nobody checks.

So the vectors are now vendored, through the same ``--specs`` provenance path as
every other corpus (``tools/build_keyformat_corpus.py``), subject to the same
``--verify`` and ``--verify-upstream`` gates, and structurally validated here.
When LMS is implemented, the answer key is already in the tree and already
proven to be the RFC's.

Deliberately *only* what RFC 8554 publishes. SP 800-208's approved parameter
sets and its §6.2 derivation are not here: the published PDF did not yield
reliable text, and guessing an approved parameter set is exactly the speculative
standards work this repository refuses. That exclusion is unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "kat" / "keyformats" / "rfc8554_hss_lms.json"

DATA: dict[str, Any] = json.loads(CORPUS.read_text())
RECORDS: list[dict[str, Any]] = DATA["records"]


def _record(case: int, kind: str) -> dict[str, Any]:
    return next(r for r in RECORDS if r["case"] == case and r["kind"] == kind)


def test_the_corpus_carries_both_published_test_cases() -> None:
    """RFC 8554 Appendix F publishes two complete cases, each with a public key,
    a message and a signature. A partial extraction would look usable."""
    assert len(RECORDS) == 6, [f"{r['case']}/{r['kind']}" for r in RECORDS]
    for case in (1, 2):
        for kind in ("public_key", "message", "signature"):
            assert _record(case, kind)["hex"], f"case {case} {kind} is empty"


def test_the_source_is_the_rfc() -> None:
    assert "rfc-editor.org/rfc/rfc8554" in DATA["source"]["url"]
    assert DATA["source"]["revision"] == "RFC 8554, April 2019"


@pytest.mark.parametrize("case", [1, 2])
def test_the_public_key_has_the_size_the_structure_implies(case: int) -> None:
    """An HSS public key is ``u32 levels || LMS public key``, and an LMS public
    key is ``u32 type || u32 otstype || I[16] || K[32]``.

    Derived from the structure rather than copied from a claim: 4 + 4 + 4 + 16
    + 32 = 60. Both published cases use a two-level tree; the parameter sets
    differ between them and are read back separately below.
    """
    record = _record(case, "public_key")
    assert record["bytes"] == 4 + 4 + 4 + 16 + 32 == 60


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        # Case 1: HSS with Nspk = 1 over LM_SHA256_M32_H5 / LMOTS_SHA256_N32_W8.
        #   LMOTS sig = u32 type + C[32] + y[34][32]        = 4 + 32 + 1088 = 1124
        #   LMS sig   = u32 q + LMOTS sig + u32 type + path[5][32]
        #                                                    = 4 + 1124 + 4 + 160 = 1292
        #   LMS pub   = u32 type + u32 otstype + I[16] + K[32]              = 56
        #   HSS sig   = u32 Nspk + sig[0] + pub[1] + sig[1]
        #                                          = 4 + 1292 + 56 + 1292 = 2644
        (1, 2644),
        # Case 2: top-level LM_SHA256_M32_H10 / LMOTS_SHA256_N32_W4, second
        # level LM_SHA256_M32_H5 / LMOTS_SHA256_N32_W8.
        #   LMOTS sig (w=4, p=67) = 4 + 32 + 67*32                = 2180
        #   sig[0] (h=10)         = 4 + 2180 + 4 + 320            = 2508
        #   pub[1]                                                =   56
        #   sig[1] (h=5, w=8)     = as case 1                     = 1292
        #   HSS sig               = 4 + 2508 + 56 + 1292          = 3860
        (2, 3860),
    ],
)
def test_the_signature_has_the_size_its_parameter_sets_imply(
    case: int, expected: int
) -> None:
    """The size is re-derived above from the parameter sets, not asserted from
    the extraction. That distinction caught a real extractor bug: the block for
    case 1's signature originally ran on into "Test Case 2 Private Key" and
    picked up two SEED/I pairs — 96 extra octets, producing a 2740-octet
    "signature" that decoded to nothing and looked entirely plausible.
    """
    assert _record(case, "signature")["bytes"] == expected


@pytest.mark.parametrize("record", RECORDS,
                         ids=[f"case{r['case']}-{r['kind']}" for r in RECORDS])
def test_every_value_is_well_formed_hexadecimal(record: dict[str, Any]) -> None:
    value = record["hex"]
    assert len(value) % 2 == 0, "an odd-length hex string cannot be octets"
    decoded = bytes.fromhex(value)          # raises on any non-hex character
    assert len(decoded) == record["bytes"], "the recorded length disagrees with the value"


def test_the_messages_are_the_texts_the_rfc_prints() -> None:
    """Appendix F prints an ASCII gutter beside the message octets, so the
    plaintext is recoverable and is a free check on the extraction: if the
    gutter had been concatenated into the value, this would be gibberish.
    """
    first = bytes.fromhex(_record(1, "message")["hex"]).decode("ascii")
    assert first.startswith("The powers not delegated to the United States")
    second = bytes.fromhex(_record(2, "message")["hex"]).decode("ascii")
    assert second.startswith("The enumeration in the Constitution, of certain rights")


def test_the_first_signature_declares_one_signed_public_key() -> None:
    """A structural spot-check on the assembled bytes, independent of the sizes.

    RFC 8554 §6.4: an HSS signature begins with ``u32 Nspk``. Case 1 prints
    ``Nspk 00000001``, so the first four octets must be exactly that — which
    they can only be if the concatenation started in the right place.
    """
    signature = bytes.fromhex(_record(1, "signature")["hex"])
    assert int.from_bytes(signature[:4], "big") == 1
    # …and the LMS signature that follows opens with q = 5, as the RFC prints.
    assert int.from_bytes(signature[4:8], "big") == 5


@pytest.mark.parametrize(
    ("case", "lms_type", "lmots_type"),
    [
        # RFC 8554 §4.1 / §5.1 registry values, as each case prints them.
        # Case 1: LM_SHA256_M32_H5 (5) with LMOTS_SHA256_N32_W8 (4).
        (1, 5, 4),
        # Case 2's top-level tree is taller and its Winternitz parameter
        # smaller: LM_SHA256_M32_H10 (6) with LMOTS_SHA256_N32_W4 (3). That is
        # why its signature is 3860 octets rather than 2644 — see the size
        # derivation above — and asserting 5/4 for both cases would have been
        # a transcription rather than a reading.
        (2, 6, 3),
    ],
)
def test_the_public_keys_declare_the_parameter_sets_the_rfc_names(
    case: int, lms_type: int, lmots_type: int
) -> None:
    """Registry values read back out of the assembled key.

    Reading the fields proves the offsets are right, not merely the total
    length — a concatenation that started one field late would still be 60
    octets.
    """
    key = bytes.fromhex(_record(case, "public_key")["hex"])
    assert int.from_bytes(key[0:4], "big") == 2, "levels"
    assert int.from_bytes(key[4:8], "big") == lms_type
    assert int.from_bytes(key[8:12], "big") == lmots_type


def test_nothing_here_claims_ama_implements_lms() -> None:
    """The point of the module, stated as a test so it cannot drift.

    Vendoring an answer key is not implementing the algorithm. If HSS/LMS is
    ever added, this assertion is what forces the claim to be updated
    deliberately rather than by the corpus quietly acquiring a meaning it did
    not have.
    """
    import ama_cryptography

    for attribute in dir(ama_cryptography):
        assert "lms" not in attribute.lower(), attribute
        assert "xmss" not in attribute.lower(), attribute
