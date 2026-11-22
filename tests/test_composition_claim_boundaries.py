# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""docs/DESIGN_NOTES.md section 5 states the composed constructions' claims
in one place; the code facts it cites are pinned here.

Section 5 is prose about code: the hybrid signature's domain string and
framing, the combiner's transcript, the posture ladders and confirmation
semantics, and where the package's keys come from.  Each was wrong somewhere
in the tree before it was written (CRYPTOGRAPHY.md showed the v1 hybrid and an
unprefixed combiner; section 3.2 said every layer key was HKDF-derived;
section 2.2 said pending actions required acknowledgement).  These tests fail
if the code moves away from what section 5 says, or section 5 from the code.
"""

from __future__ import annotations

import ast
import re
import struct
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
NOTES = REPO_ROOT / "docs" / "DESIGN_NOTES.md"
HEADER = REPO_ROOT / "include" / "ama_cryptography.h"


def _section5() -> str:
    text = NOTES.read_text(encoding="utf-8")
    start = text.index("## 5. Claim Boundaries")
    return text[start : text.index("\n## ", start + 10)]


def test_section_5_is_the_single_place_and_is_referenced() -> None:
    body = _section5()
    for sub in ("### 5.1", "### 5.2", "### 5.3", "### 5.4"):
        assert sub in body
    # Every subsection states where its claim stops.
    assert body.count("**Stops at.**") == 4
    for doc in ("SECURITY.md", "CRYPTOGRAPHY.md"):
        assert "DESIGN_NOTES.md" in (REPO_ROOT / doc).read_text(encoding="utf-8")


def test_the_hybrid_signature_domain_is_one_string() -> None:
    from ama_cryptography.crypto_api import HYBRID_SIG_DOMAIN, hybrid_classical_input

    c_domain = re.search(
        r'#define AMA_HYBRID_SIG_DOMAIN "([^"]+)"', HEADER.read_text(encoding="utf-8")
    )
    assert c_domain is not None
    assert HYBRID_SIG_DOMAIN.decode("ascii") == c_domain.group(1)
    assert f'`D = "{c_domain.group(1)}"`' in _section5()
    # 0x00 || len(D) || D || M, the framing section 5.1 states.
    assert hybrid_classical_input(b"M") == b"\x00" + bytes([len(HYBRID_SIG_DOMAIN)]) + (
        HYBRID_SIG_DOMAIN + b"M"
    )


def test_the_c_hybrid_verifier_evaluates_both_halves() -> None:
    source = (REPO_ROOT / "src" / "c" / "ama_core.c").read_text(encoding="utf-8")
    body = source[source.index("static ama_error_t hybrid_verify(") :]
    body = body[: body.index("\n}\n")]
    classical = body.index("rc_classical = ama_ed25519_verify(")
    pqc = body.index("rc_pqc = ama_dilithium_verify_ctx(")
    verdict = body.index("rc_classical == AMA_SUCCESS && rc_pqc == AMA_SUCCESS")
    assert classical < pqc < verdict, "both halves are computed before the AND"


def test_the_combiner_transcript_is_the_one_section_5_2_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ama_cryptography import hybrid_combiner

    captured: dict[str, Any] = {}

    def _capture(self: Any, salt: bytes, ikm: Any, info: bytes, okm_len: int) -> bytearray:
        captured.update(salt=salt, ikm=bytes(ikm), info=info, okm_len=okm_len)
        return bytearray(okm_len)

    monkeypatch.setattr(hybrid_combiner.HybridCombiner, "_hkdf_native", _capture)
    monkeypatch.setattr(hybrid_combiner, "check_crypto_permitted", lambda: None)
    combiner = hybrid_combiner.HybridCombiner()
    combiner._has_native = True
    k1, k2, c1, c2, pk1, pk2 = b"\x01" * 32, b"\x02" * 32, b"c1", b"c22", b"p1", b"pk2"
    combiner.combine(k1, k2, c1, c2, pk1, pk2)

    def i32(n: int) -> bytes:
        return struct.pack(">I", n)

    assert captured["salt"] == i32(2) + c1 + i32(3) + c2
    assert captured["ikm"] == k1 + k2
    assert captured["info"] == b"ama-hybrid-kem-v2" + b"\x02" + i32(2) + pk1 + i32(3) + pk2
    assert captured["okm_len"] == 32
    assert hybrid_combiner._HYBRID_LABEL == b"ama-hybrid-kem-v2"
    assert '"ama-hybrid-kem-v2" || 0x02' in _section5()


def test_the_kem_provider_always_binds_both_public_keys() -> None:
    """Section 5.2: public-key binding exists only when the caller passes them,
    and HybridKEMProvider always does."""
    tree = ast.parse((REPO_ROOT / "ama_cryptography" / "crypto_api.py").read_text(encoding="utf-8"))
    provider = next(
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "HybridKEMProvider"
    )
    calls = [
        n
        for n in ast.walk(provider)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "combine"
    ]
    assert len(calls) == 2, "one combine() in encapsulate, one in decapsulate"
    for call in calls:
        assert {kw.arg for kw in call.keywords} >= {"classical_pk", "pqc_pk"}


def test_the_posture_ladders_and_veto_window_are_as_stated() -> None:
    import inspect

    from ama_cryptography.adaptive_posture import CryptoPostureController

    ladders = CryptoPostureController.ALGORITHM_FAMILIES
    assert ladders["signature"] == {
        "ED25519": 0,
        "ML_DSA_65": 1,
        "SPHINCS_256F": 2,
        "HYBRID_SIG": 3,
    }
    assert ladders["kem"] == {"KYBER_1024": 0, "HYBRID_KEM": 1}
    body = _section5()
    assert "`ED25519 (0) < ML_DSA_65 (1) < SPHINCS_256F (2) < HYBRID_SIG (3)`" in body
    assert "`KYBER_1024 (0) < HYBRID_KEM (1)`" in body
    grace = inspect.signature(CryptoPostureController.__init__).parameters["grace_period"]
    assert grace.default == 300.0
    assert "default 300 s" in NOTES.read_text(encoding="utf-8")
    source = inspect.getsource(CryptoPostureController._process_expired_pending_actions)
    assert "Auto-executing pending action" in source, "an unanswered action executes"


def test_the_package_hmac_key_is_drawn_not_derived() -> None:
    """Section 3.2 / 5.4: the HMAC key comes from the CSPRNG and travels in
    the package; only the Layer-4 keys are HKDF-derived."""
    source = (REPO_ROOT / "ama_cryptography" / "crypto_api.py").read_text(encoding="utf-8")
    start = source.index("def create_crypto_package(")
    body = source[start : source.index("\ndef ", start + 10)]
    assert re.search(r"hmac_key = held\(secure_token_bytearray\(32\)\)", body)
    assert "hmac_key=hmac_key" in body
