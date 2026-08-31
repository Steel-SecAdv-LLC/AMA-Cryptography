#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Item 7: refleak/RSS/fd soak over the public Python API.

Runs every curated public-API operation in a loop for --minutes wall time,
sampling VmRSS and open-fd count every --sample-every iterations.

Mechanical verdict (exit 0 iff all hold):
  1. every op ran at least once per iteration with no unexpected exception
     (ops that are impossible in this environment are declared, with reason,
     in NOT_COVERED and reported);
  2. fd count at end == fd count at warmup boundary;
  3. least-squares RSS slope over the samples after warmup < 10240 bytes/min.

--negative-control seeds a deliberate 256 KiB/iteration leak; the harness
MUST then FAIL threshold 3 (exit nonzero) for its clean run to count.
--preflight runs exactly one iteration and reports per-op status.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from collections.abc import Callable

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

NOT_COVERED: dict[str, str] = {}
LEAK_HOARD: list[bytes] = []


def rss_bytes() -> int:
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("VmRSS not found")


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def build_ops() -> dict[str, Callable[[], None]]:
    import ama_cryptography as ama
    from ama_cryptography import adaptive_posture as ap
    from ama_cryptography import agent_binding as ab
    from ama_cryptography import ascon as ascon
    from ama_cryptography import crypto_api as capi
    from ama_cryptography import equations as eq
    from ama_cryptography import hybrid_combiner as hc
    from ama_cryptography import integrity as integ
    from ama_cryptography import key_formats as kf
    from ama_cryptography import key_management as km
    from ama_cryptography import monitoring as mon
    from ama_cryptography import pqc_backends as pqb
    from ama_cryptography import rfc3161_timestamp as ts
    from ama_cryptography import secure_memory as sm
    from ama_cryptography import session as sess

    ops: dict[str, Callable[[], None]] = {}
    msg = b"refleak soak message"

    ed = capi.AmaCryptography(capi.AlgorithmType.ED25519)

    def op_ed25519_roundtrip() -> None:
        kp = ed.generate_keypair()
        sig = ed.sign(msg, kp.secret_key)
        if not ed.verify(msg, sig, kp.public_key):
            raise RuntimeError("ed25519 verify returned False")

    ops["crypto_api.ed25519_keygen_sign_verify"] = op_ed25519_roundtrip

    if capi.DILITHIUM_AVAILABLE:
        mldsa = capi.AmaCryptography(capi.AlgorithmType.ML_DSA_65)

        def op_mldsa_roundtrip() -> None:
            kp = mldsa.generate_keypair()
            sig = mldsa.sign(msg, kp.secret_key)
            if not mldsa.verify(msg, sig, kp.public_key):
                raise RuntimeError("ML-DSA verify returned False")

        ops["crypto_api.mldsa_keygen_sign_verify"] = op_mldsa_roundtrip
    else:
        NOT_COVERED["crypto_api.mldsa"] = "DILITHIUM_AVAILABLE is False"

    if capi.KYBER_AVAILABLE:
        kem = capi.AmaCryptography(capi.AlgorithmType.KYBER_1024)

        def op_kem_roundtrip() -> None:
            kp = kem.generate_keypair()
            enc = kem.encapsulate(kp.public_key)
            ss = kem.decapsulate(enc.ciphertext, kp.secret_key)
            if ss != enc.shared_secret:
                raise RuntimeError("ML-KEM shared secret mismatch")

        ops["crypto_api.mlkem_encaps_decaps"] = op_kem_roundtrip
    else:
        NOT_COVERED["crypto_api.mlkem"] = "KYBER_AVAILABLE is False"

    def op_hash_ct() -> None:
        h = ed.hash_message(msg)
        if not ed.constant_time_compare(h, h):
            raise RuntimeError("constant_time_compare(h, h) is False")

    ops["crypto_api.hash_and_ct_compare"] = op_hash_ct

    def op_package() -> None:
        pkg = capi.create_crypto_package(msg)
        pk = pkg.keypairs["HYBRID_SIG"].public_key
        res = capi.verify_crypto_package(msg, pkg, expected_public_key=pk)
        if not all(res.values()):
            raise RuntimeError(f"package verify verdict not all-true: {res}")

    ops["package.create_verify"] = op_package

    def op_batch_verify() -> None:
        entries: list[tuple[bytes, bytes, bytes]] = []
        for _ in range(5):
            kp = ed.generate_keypair()
            sig = ed.sign(msg, kp.secret_key)
            entries.append((msg, bytes(sig.signature), bytes(kp.public_key)))
        if not all(ama.batch_verify_ed25519(entries)):
            raise RuntimeError("batch_verify_ed25519 rejected a valid entry")

    ops["batch_verify_ed25519"] = op_batch_verify

    def op_ascon() -> None:
        k = ascon.generate_key()
        n = ascon.generate_nonce()
        ct, tag = ascon.aead128_encrypt(k, n, msg, b"ad")
        if ascon.aead128_decrypt(k, n, ct, tag, b"ad") != msg:
            raise RuntimeError("ascon roundtrip mismatch")
        ascon.hash256(msg)

    if ascon.ASCON_AVAILABLE:
        ops["ascon.aead_hash"] = op_ascon
    else:
        NOT_COVERED["ascon"] = "ASCON_AVAILABLE is False"

    def op_keyformats() -> None:
        kp = ed.generate_keypair()
        priv = kf.PrivateKey("Ed25519", bytes(kp.secret_key), kp.public_key)
        jwk = kf.private_key_to_jwk(priv)
        kf.jwk_to_private_key(jwk)
        kf.jwk_thumbprint(kf.public_key_to_jwk(priv.public()))
        cose = kf.private_key_to_cose(priv)
        kf.cose_to_private_key(cose)
        pem = kf.encode_pem(priv.to_pkcs8(), "PRIVATE KEY")
        _label, der = kf.decode_pem(pem, expected_label="PRIVATE KEY")
        kf.load_pkcs8(der)
        kf.load_spki(priv.public().to_spki())

    ops["key_formats.jwk_cose_pem_roundtrips"] = op_keyformats

    def op_secure_memory() -> None:
        with sm.secure_buffer(64) as buf:
            buf[:4] = b"AAAA"
        b = bytearray(sm.secure_random_bytes(32))
        sm.secure_memzero(b)
        if not sm.constant_time_compare(b"x" * 16, b"x" * 16):
            raise RuntimeError("secure_memory constant_time_compare is False")
        ama.secure_token_bytes(32)

    ops["secure_memory.buffer_memzero_random"] = op_secure_memory

    def op_agent_binding() -> None:
        binding = ab.AgentBinding(
            os.urandom(ab.AGENT_INSTANCE_ID_BYTES),
            lifetime=ab.AgentLifetime.EPHEMERAL,
            capabilities=ab.AgentCapability.DATA_SIGN,
        )
        binding.encode()
        binding.check()
        binding.derive_key(os.urandom(32), 32, info=b"soak")
        if not binding.is_permitted():
            raise RuntimeError("agent binding not permitted")

    ops["agent_binding.encode_check_derive"] = op_agent_binding

    def op_adaptive_posture() -> None:
        ctl = ap.CryptoPostureController()
        ctl.evaluate_and_respond()
        ctl.get_posture_summary()

    ops["adaptive_posture.controller"] = op_adaptive_posture

    def op_session() -> None:
        store = sess.SessionStore()
        s = store.create(ttl_seconds=60)
        store.get(s.session_id)
        store.close(s.session_id)

    ops["session.store_create_close"] = op_session

    # One monitor for the whole soak (real code constructs a monitor once and
    # reuses it), on an ISOLATED persist path so the soak never touches the
    # host-global ~/.ama_cryptography/nonce_tracker.dat.  check_nonce is fed a
    # BOUNDED rolling pool of nonces: the NonceTracker's _seen ledger grows
    # monotonically with DISTINCT nonces BY DESIGN (evicting a seen nonce would
    # fail-open on reuse detection — a documented, security-required property,
    # not a leak), so an unbounded distinct-nonce feed would drive intended
    # growth and mask real leaks.  A bounded pool exercises the fresh-record
    # and reuse-detected branches while keeping memory flat, which is what this
    # soak must measure.
    _mon_tmpdir = tempfile.mkdtemp(prefix="ama-soak-nonce-")
    _soak_monitor = mon.AmaCryptographyMonitor(
        nonce_persist_path=os.path.join(_mon_tmpdir, "nonce_tracker.dat")
    )
    _nonce_pool = [os.urandom(12) for _ in range(256)]
    _nonce_state = {"i": 0}

    def op_monitoring() -> None:
        i = _nonce_state["i"]
        _nonce_state["i"] = i + 1
        _soak_monitor.record_operation_event("sign", key_fingerprint=os.urandom(16))
        # Rolling bounded pool: mostly fresh early, then all reuse — both
        # branches exercised, ledger capped at pool size.
        try:
            _soak_monitor.check_nonce(b"soak-key-id", _nonce_pool[i % len(_nonce_pool)])
        except Exception as exc:
            _ = exc
        _soak_monitor.get_security_report()

    ops["monitoring.create_record_report"] = op_monitoring

    def op_kms() -> None:
        hd = km.HDKeyDerivation(seed=os.urandom(64))
        hd.derive_key(44, 0, 0, 0)
        mgr = km.KeyRotationManager()
        mgr.register_key("soak-a", "signing")
        mgr.register_key("soak-b", "signing")
        mgr.initiate_rotation("soak-a", "soak-b")
        mgr.complete_rotation("soak-a")
        mgr.get_active_key()

    ops["key_management.hd_and_rotation"] = op_kms

    def op_pqc_backends() -> None:
        pqb.native_hkdf(os.urandom(32), length=64, salt=b"s", info=b"i")
        pqb.hmac_sha3_256(os.urandom(32), msg)

    ops["pqc_backends.hkdf_hmac"] = op_pqc_backends

    def op_equations() -> None:
        eq.golden_ratio_convergence_proof(10)
        ama.verify_mathematical_foundations()

    ops["equations.proofs"] = op_equations

    def op_rfc3161_offline() -> None:
        ts.build_timestamp_request(os.urandom(32))

    ops["rfc3161.build_request_offline"] = op_rfc3161_offline

    def op_hybrid() -> None:
        comb = hc.HybridCombiner()
        comb.combine(os.urandom(32), os.urandom(32), os.urandom(32), os.urandom(32))

    ops["hybrid_combiner.combine"] = op_hybrid

    def op_integrity() -> None:
        ok, reason = integ.verify_module_integrity()  # type: ignore[attr-defined]  # public helper not in integrity.__all__, resolved at runtime (VAUDIT-002)
        if not ok:
            raise RuntimeError(f"module integrity: {reason}")

    ops["integrity.verify_module"] = op_integrity

    def op_module_state() -> None:
        ama.module_status()
        ama.module_attestation()
        ama.module_self_test_results()
        ama.check_operational()
        ama.post_duration_ms()

    ops["module_state.status_attestation"] = op_module_state

    return ops


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=float, default=65.0)
    parser.add_argument("--sample-every", type=int, default=5)
    parser.add_argument(
        "--warmup-iters",
        type=int,
        default=12000,
        help="run every op this many times before sampling begins, to saturate "
        "the bounded (maxlen=10000) monitor deques so the measured window is "
        "past their legitimate fill ramp",
    )
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--negative-control", action="store_true")
    parser.add_argument(
        "--ops", default="", help="comma-separated substrings; keep only matching ops (bisection)"
    )
    args = parser.parse_args()

    ops = build_ops()
    if args.ops:
        keys = [k for k in ops if any(sub in k for sub in args.ops.split(","))]
        ops = {k: ops[k] for k in keys}
    print(f"ops: {len(ops)} {sorted(ops)}; NOT_COVERED: {NOT_COVERED}")

    if args.preflight:
        failures = []
        for name, fn in ops.items():
            try:
                fn()
                print(f"OK   {name}")
            except Exception as exc:
                failures.append((name, repr(exc)))
                print(f"FAIL {name}: {exc!r}")
        return 1 if failures else 0

    op_errors: list[str] = []

    # Warmup: saturate bounded structures (maxlen=10000 deques) before we
    # start measuring, so the sampled window reflects steady state, not the
    # legitimate one-time fill ramp.  Negative-control mode skips warmup so
    # the seeded leak is visible from iteration 1.
    warmup = 0 if args.negative_control else args.warmup_iters
    for w in range(warmup):
        for name, fn in ops.items():
            try:
                fn()
            except Exception as exc:  # recorded, fails the run
                op_errors.append(f"warmup{w} {name}: {exc!r}")
        if len(op_errors) > 20:
            break
    if warmup:
        print(f"warmup complete: {warmup} iters, {len(op_errors)} op errors", flush=True)

    deadline = time.monotonic() + args.minutes * 60
    samples: list[tuple[float, int, int]] = []  # (minute, rss, fds)
    it = 0
    t_start = time.monotonic()
    while time.monotonic() < deadline:
        it += 1
        for name, fn in ops.items():
            try:
                fn()
            except Exception as exc:
                op_errors.append(f"iter{it} {name}: {exc!r}")
                if len(op_errors) > 20:
                    break
        if args.negative_control:
            LEAK_HOARD.append(os.urandom(256 * 1024))
        if it % args.sample_every == 0:
            minute = (time.monotonic() - t_start) / 60
            samples.append((minute, rss_bytes(), fd_count()))
            print(
                f"iter={it} t={minute:.1f}min rss={samples[-1][1]//1024}KiB fds={samples[-1][2]}",
                flush=True,
            )
        if len(op_errors) > 20:
            break

    # Verdict.  Structures were pre-saturated in warmup (except in
    # negative-control mode, where we still drop the first quarter so the
    # seeded leak's slope is measured on a settled baseline), so the measured
    # window is steady state — use all of it, minus a short settle.
    warm_idx = max(1, len(samples) // 8) if not args.negative_control else max(1, len(samples) // 4)
    warm = samples[warm_idx:]
    ok = True
    if op_errors:
        print(f"OP ERRORS ({len(op_errors)}):")
        for e in op_errors[:20]:
            print("  ", e)
        ok = False
    if len(warm) < 4:
        print("insufficient samples")
        ok = False
    else:
        fd_delta = warm[-1][2] - warm[0][2]
        xs = [s[0] for s in warm]
        ys = [s[1] for s in warm]
        n = len(xs)
        mx = sum(xs) / n
        my = sum(ys) / n
        denom = sum((x - mx) ** 2 for x in xs) or 1e-9
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom  # bytes/min
        print(
            f"iterations={it} samples={len(samples)} fd_delta={fd_delta} "
            f"rss_slope={slope:.0f} B/min (threshold < 10240)"
        )
        if fd_delta != 0:
            print("FD COUNT NOT FLAT")
            ok = False
        if slope >= 10240:
            print("RSS SLOPE OVER THRESHOLD")
            ok = False
    print("REFLEAK SOAK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
