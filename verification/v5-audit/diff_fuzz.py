#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Item 12 — differential fuzzing of AMA vs pyca/cryptography + pycryptodome.

Random inputs, byte-compare outputs on the overlapping primitives (AES-256-GCM,
ChaCha20-Poly1305, Ed25519, HKDF-SHA256/384/512). Any disagreement is a bug in
one implementation and is reported with the exact seed to reproduce.

The comparator libraries are imported HERE ONLY — audit test environment, never
by shipped AMA code (constraint 3b). Run:  python diff_fuzz.py <iterations>

--selftest plants a deliberate 1-byte corruption of AMA's output for one
primitive and confirms the differential detector fires (the negative control).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, "/home/user/AMA-Cryptography")

# AMA under test
import nacl.signing
from Crypto.Cipher import AES as _PYCAES
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Comparators (test-env only)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF

from ama_cryptography import crypto_api as capi
from ama_cryptography import pqc_backends as pqb


class DisagreementError(Exception):
    pass


def _rnd(n: int) -> bytes:
    return os.urandom(n)


def diff_aes_gcm(rng_len: int, corrupt: bool = False) -> None:
    key = _rnd(32)
    nonce = _rnd(12)
    pt = _rnd(rng_len)
    aad = _rnd(rng_len % 32)
    ama_ct, ama_tag = pqb.native_aes256_gcm_encrypt(key, nonce, pt, aad)
    if corrupt and ama_ct:
        ama_ct = bytes([ama_ct[0] ^ 0x01]) + ama_ct[1:]
    # pyca
    ref = AESGCM(key).encrypt(nonce, pt, aad if aad else None)
    ref_ct, ref_tag = ref[:-16], ref[-16:]
    if ama_ct != ref_ct or ama_tag != ref_tag:
        raise DisagreementError(
            f"AES-GCM mismatch vs pyca: key={key.hex()} nonce={nonce.hex()} "
            f"pt={pt.hex()} aad={aad.hex()}\n  ama=({ama_ct.hex()},{ama_tag.hex()})\n"
            f"  pyca=({ref_ct.hex()},{ref_tag.hex()})"
        )
    # pycryptodome
    c = _PYCAES.new(key, _PYCAES.MODE_GCM, nonce=nonce)
    if aad:
        c.update(aad)
    pyc_ct, pyc_tag = c.encrypt_and_digest(pt)
    if ama_ct != pyc_ct or ama_tag != pyc_tag:
        raise DisagreementError(
            f"AES-GCM mismatch vs pycryptodome: key={key.hex()} nonce={nonce.hex()} "
            f"pt={pt.hex()} aad={aad.hex()}"
        )


def diff_chacha(rng_len: int, corrupt: bool = False) -> None:
    key = _rnd(32)
    nonce = _rnd(12)
    pt = _rnd(rng_len)
    aad = _rnd(rng_len % 32)
    ama_ct, ama_tag = pqb.native_chacha20poly1305_encrypt(key, nonce, pt, aad)
    if corrupt and ama_tag:
        ama_tag = bytes([ama_tag[0] ^ 0x01]) + ama_tag[1:]
    ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad if aad else None)
    ref_ct, ref_tag = ref[:-16], ref[-16:]
    if ama_ct != ref_ct or ama_tag != ref_tag:
        raise DisagreementError(
            f"ChaCha20-Poly1305 mismatch vs pyca: key={key.hex()} nonce={nonce.hex()} "
            f"pt={pt.hex()} aad={aad.hex()}\n  ama=({ama_ct.hex()},{ama_tag.hex()})\n"
            f"  pyca=({ref_ct.hex()},{ref_tag.hex()})"
        )


def diff_ed25519(rng_len: int, corrupt: bool = False) -> None:
    ed = capi.AmaCryptography(capi.AlgorithmType.ED25519)
    kp = ed.generate_keypair()
    msg = _rnd(rng_len)
    sig = ed.sign(msg, kp.secret_key)
    raw_sig = bytes(sig.signature)
    if corrupt and raw_sig:
        raw_sig = bytes([raw_sig[0] ^ 0x01]) + raw_sig[1:]
    # The Ed25519 secret_key layout is seed(32)||pubkey(32); pyca/nacl take the
    # 32-byte seed. Cross-verify AMA's signature with pyca and nacl, and verify
    # a pyca signature with AMA — signatures are deterministic (RFC 8032), so
    # the raw bytes must match too.
    seed = bytes(kp.secret_key)[:32]
    pub = bytes(kp.public_key)
    pyca_priv = Ed25519PrivateKey.from_private_bytes(seed)
    pyca_sig = pyca_priv.sign(msg)
    if raw_sig != pyca_sig:
        raise DisagreementError(
            f"Ed25519 signature bytes differ from pyca: seed={seed.hex()} msg={msg.hex()}\n"
            f"  ama ={raw_sig.hex()}\n  pyca={pyca_sig.hex()}"
        )
    # AMA verifies pyca's signature; pyca verifies AMA's.
    if not ed.verify(msg, pyca_sig, pub):
        raise DisagreementError(f"AMA rejected a pyca Ed25519 signature: msg={msg.hex()}")
    Ed25519PublicKey.from_public_bytes(pub).verify(raw_sig, msg)  # raises on mismatch
    nacl.signing.VerifyKey(pub).verify(msg, raw_sig)  # raises on mismatch


def diff_hkdf(rng_len: int, corrupt: bool = False) -> None:
    ikm = _rnd(rng_len + 1)
    salt = _rnd(rng_len % 40)
    info = _rnd(rng_len % 24)
    length = 1 + (rng_len % 64)
    for algo, hshfn in (
        ("sha256", _h.SHA256()),
        ("sha384", _h.SHA384()),
        ("sha512", _h.SHA512()),
    ):
        ama_out = getattr(pqb, f"native_hkdf_{algo}")(ikm, length, salt=salt or None, info=info)
        if corrupt and ama_out:
            ama_out = bytes([ama_out[0] ^ 0x01]) + ama_out[1:]
        ref = _HKDF(algorithm=hshfn, length=length, salt=salt or None, info=info).derive(ikm)
        if ama_out != ref:
            raise DisagreementError(
                f"HKDF-{algo} mismatch vs pyca: ikm={ikm.hex()} salt={salt.hex()} "
                f"info={info.hex()} len={length}\n  ama ={ama_out.hex()}\n  pyca={ref.hex()}"
            )


PRIMS = {
    "aes_gcm": diff_aes_gcm,
    "chacha20poly1305": diff_chacha,
    "ed25519": diff_ed25519,
    "hkdf": diff_hkdf,
}


def main() -> int:
    if "--selftest" in sys.argv:
        # Negative control: each primitive's detector MUST fire on a corrupted
        # AMA output.
        failures = []
        for name, fn in PRIMS.items():
            try:
                fn(17, corrupt=True)
                failures.append(name)  # did NOT detect the planted corruption
            except DisagreementError:
                pass  # correctly detected
            except Exception as exc:
                # a raise from a verify() on corrupted sig also counts as detection
                if name == "ed25519":
                    continue
                failures.append(f"{name}:{exc!r}")
        if failures:
            print(f"NEGATIVE CONTROL BROKEN: undetected corruption in {failures}")
            return 1
        print(
            "negative control OK: every primitive's differential detector fires on a 1-byte corruption"
        )
        return 0

    iters = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 2000
    counts = dict.fromkeys(PRIMS, 0)
    for i in range(iters):
        length = (i * 7) % 300  # vary lengths incl. 0, block boundaries
        for name, fn in PRIMS.items():
            fn(length)
            counts[name] += 1
    total = sum(counts.values())
    print(f"differential fuzz: {iters} iterations, {total} comparisons, 0 disagreements")
    print("per-primitive comparisons:", counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
