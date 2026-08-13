#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Generate and verify the FIPS 140-3 POST Known Answer Test vectors
=================================================================

The power-on self-test needs a genuine *Known Answer Test* for every approved
algorithm: a fixed input with exactly one correct output, so an implementation
that is self-consistent but wrong is caught.  A keygen/encaps/decaps or
sign/verify **roundtrip** is not that — it proves the implementation agrees
with itself, which a mistyped parameter set, a shared NTT bug, or an
always-accept verifier all satisfy.

This tool extracts one authentic record per algorithm from the version-pinned
NIST ACVP vectors already vendored under ``tests/kat/`` (see
``tests/kat/README.md`` for provenance), **verifies the built native library
reproduces the known answer**, and writes the pinned vector into
``ama_cryptography/_post_kats/`` where ``_self_test`` loads it at import.  The
extracted records are integrity-covered: ``_compute_module_digest`` hashes the
``_post_kats/`` directory, so a swapped vector fails POST.

Algorithms and what is pinned:

* **ML-KEM-1024** — deterministic keygen ``(d, z) -> (pk, sk)`` *and*
  deterministic decapsulation ``(ct, sk) -> ss``.  Both are functions with one
  correct output.
* **ML-DSA-65** — deterministic keygen ``seed -> (pk, sk)`` *and* verification
  ``(pk, msg, ctx, sig) -> valid``.
* **SLH-DSA-SHA2-256f** — verification ``(pk, msg, ctx, sig) -> valid``.
  Signing at this parameter set is too slow for the POST budget; verify-only is
  the FIPS 140-3 §4.9.1 KAT, mirroring the existing SLH-DSA-SHAKE-128s vector.

Usage::

    python tools/build_post_kats.py           # regenerate the pinned vectors
    python tools/build_post_kats.py --check    # verify pinned == vendored (CI gate)

``--check`` re-extracts from the vendored sources and asserts the pinned files
match byte-for-byte, so the POST vectors cannot silently drift from their NIST
provenance.  It does NOT require the native library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
KAT_DIR = REPO_ROOT / "tests" / "kat"
OUT_DIR = REPO_ROOT / "ama_cryptography" / "_post_kats"


def _parse_flat_kat(path: Path) -> list[dict[str, str]]:
    """Parse the repo's ``key = hexvalue`` record format (blank-line separated)."""
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


def _source_fingerprint(path: Path, record_id: str, fields: dict[str, str]) -> str:
    """SHA3-256 over the source path, record id, and extracted fields.

    Lets ``--check`` confirm the pinned vector was extracted from exactly this
    vendored record, so a change to either side is caught.
    """
    hasher = hashlib.sha3_256()
    # as_posix() so the fingerprint is identical on every platform — str() of a
    # WindowsPath renders backslashes, which would make --check reject vectors
    # pinned on a POSIX machine (and vice versa) for a purely cosmetic reason.
    hasher.update(path.relative_to(REPO_ROOT).as_posix().encode("utf-8"))
    hasher.update(record_id.encode("utf-8"))
    for key in sorted(fields):
        hasher.update(key.encode("utf-8"))
        hasher.update(fields[key].encode("utf-8"))
    return hasher.hexdigest()


def _build_ml_kem_1024() -> dict[str, Any]:
    src = KAT_DIR / "fips203" / "ml_kem_1024.kat"
    rec = _parse_flat_kat(src)[0]
    fields = {k: rec[k] for k in ("d", "z", "pk", "sk", "ct", "ss")}
    return {
        "algorithm": "ML-KEM-1024",
        "kind": "keygen+decaps",
        "parameter_set": 1024,
        "provenance": {
            "source": src.relative_to(REPO_ROOT).as_posix(),
            "upstream": "NIST ACVP-Server ML-KEM-keyGen/encapDecap-FIPS203 v1.1.0.42",
            "record": 0,
            "fingerprint": _source_fingerprint(src, "record[0]", fields),
        },
        "d_hex": rec["d"],
        "z_hex": rec["z"],
        "pk_hex": rec["pk"],
        "sk_hex": rec["sk"],
        "ct_hex": rec["ct"],
        "ss_hex": rec["ss"],
    }


def _build_ml_dsa_65() -> dict[str, Any]:
    src = KAT_DIR / "fips204" / "ml_dsa_65.kat"
    rec = _parse_flat_kat(src)[0]
    fields = {k: rec[k] for k in ("seed", "pkey", "skey", "msg", "ctx", "sig")}
    return {
        "algorithm": "ML-DSA-65",
        "kind": "keygen+verify",
        "parameter_set": 65,
        "provenance": {
            "source": src.relative_to(REPO_ROOT).as_posix(),
            "upstream": "NIST ACVP-Server ML-DSA-keyGen/sigGen-FIPS204 v1.1.0.42",
            "record": 0,
            "fingerprint": _source_fingerprint(src, "record[0]", fields),
        },
        "seed_hex": rec["seed"],
        "pk_hex": rec["pkey"],
        "sk_hex": rec["skey"],
        "msg_hex": rec["msg"],
        "ctx_hex": rec["ctx"],
        "sig_hex": rec["sig"],
    }


def _build_slh_dsa_sha2_256f() -> dict[str, Any]:
    src = KAT_DIR / "fips205" / "SLH-DSA-sigVer-FIPS205.json"
    payload = json.loads(src.read_text(encoding="utf-8"))
    for group in payload["testGroups"]:
        if group.get("parameterSet") != "SLH-DSA-SHA2-256f":
            continue
        for test in group["tests"]:
            if test.get("testPassed") is True:
                fields = {
                    "pk": test["pk"],
                    "message": test["message"],
                    "context": test.get("context", ""),
                    "signature": test["signature"],
                }
                return {
                    "algorithm": "SLH-DSA-SHA2-256f",
                    "kind": "verify",
                    "parameter_set": "SHA2-256f",
                    "provenance": {
                        "source": src.relative_to(REPO_ROOT).as_posix(),
                        "upstream": "NIST ACVP-Server SLH-DSA-sigVer-FIPS205 v1.1.0.42",
                        "tgId": group["tgId"],
                        "tcId": test["tcId"],
                        "fingerprint": _source_fingerprint(
                            src, f"tgId={group['tgId']},tcId={test['tcId']}", fields
                        ),
                    },
                    "tcId": test["tcId"],
                    "pk_hex": test["pk"],
                    "message_hex": test["message"],
                    "context_hex": test.get("context", ""),
                    "signature_hex": test["signature"],
                }
    raise RuntimeError("no passing SLH-DSA-SHA2-256f sigVer record found in the vendored vector")


_BUILDERS = {
    "ml_kem_1024_kat.json": _build_ml_kem_1024,
    "ml_dsa_65_kat.json": _build_ml_dsa_65,
    "slh_dsa_sha2_256f_kat.json": _build_slh_dsa_sha2_256f,
}


def _verify_against_native(name: str, payload: dict[str, Any]) -> None:
    """Confirm the built native library reproduces each pinned known answer.

    Skipped by ``--check`` (which is source-only); run during generation so a
    vector is never pinned unless the shipped implementation actually produces
    it.
    """
    import os

    os.environ.setdefault("AMA_POST_DIAGNOSTIC_IMPORT", "1")
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import ama_cryptography.pqc_backends as pb

    # Explicit raises rather than asserts: this is verification logic, and
    # ``python -O`` strips asserts.  A vector must never be pinned unless the
    # shipped implementation actually reproduces it.
    def _require(condition: bool, message: str) -> None:
        if not condition:
            raise RuntimeError(f"{name}: {message}")

    if payload["algorithm"] == "ML-KEM-1024":
        pk, sk = pb.native_ml_kem_keypair_from_seed(
            1024, bytes.fromhex(payload["d_hex"]), bytes.fromhex(payload["z_hex"])
        )
        _require(pk.hex() == payload["pk_hex"], "ML-KEM keygen pk mismatch")
        _require(sk.hex() == payload["sk_hex"], "ML-KEM keygen sk mismatch")
        ss = pb.native_ml_kem_decapsulate(
            1024, bytes.fromhex(payload["ct_hex"]), bytes.fromhex(payload["sk_hex"])
        )
        _require(ss.hex() == payload["ss_hex"], "ML-KEM decaps ss mismatch")
    elif payload["algorithm"] == "ML-DSA-65":
        pk, sk = pb.native_ml_dsa_keypair_from_seed(65, bytes.fromhex(payload["seed_hex"]))
        _require(pk.hex() == payload["pk_hex"], "ML-DSA keygen pk mismatch")
        _require(sk.hex() == payload["sk_hex"], "ML-DSA keygen sk mismatch")
        ok = pb.native_ml_dsa_verify(
            65,
            bytes.fromhex(payload["msg_hex"]),
            bytes.fromhex(payload["sig_hex"]),
            bytes.fromhex(payload["pk_hex"]),
            ctx=bytes.fromhex(payload["ctx_hex"]),
        )
        _require(ok, "ML-DSA verify rejected a valid signature")
    elif payload["algorithm"] == "SLH-DSA-SHA2-256f":
        ok = pb.slhdsa_verify(
            bytes.fromhex(payload["message_hex"]),
            bytes.fromhex(payload["signature_hex"]),
            bytes.fromhex(payload["pk_hex"]),
            bytes.fromhex(payload["context_hex"]),
            param_set="SHA2-256f",
        )
        _require(ok, "SLH-DSA-SHA2-256f verify rejected a valid signature")
    else:  # pragma: no cover - defensive
        raise RuntimeError(f"no native verification wired for {payload['algorithm']}")


def _serialise(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def generate(verify: bool = True) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in _BUILDERS.items():
        payload = builder()
        if verify:
            _verify_against_native(name, payload)
        # newline="\n" keeps the pinned vector LF on Windows too; --check and
        # the module-digest computation both read these bytes.
        (OUT_DIR / name).write_text(_serialise(payload), encoding="utf-8", newline="\n")
        print(f"wrote {OUT_DIR.joinpath(name).relative_to(REPO_ROOT)} ({payload['algorithm']})")
    return 0


def check() -> int:
    problems: list[str] = []
    for name, builder in _BUILDERS.items():
        pinned_path = OUT_DIR / name
        if not pinned_path.is_file():
            problems.append(f"{name}: pinned vector missing — run tools/build_post_kats.py")
            continue
        expected = _serialise(builder())
        actual = pinned_path.read_text(encoding="utf-8")
        if expected != actual:
            problems.append(
                f"{name}: pinned vector does not match the vendored NIST source. "
                "Re-run tools/build_post_kats.py, or investigate the drift."
            )
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        return 1
    print(f"OK: {len(_BUILDERS)} POST KAT vectors match their vendored NIST sources.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/verify FIPS POST KAT vectors")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify pinned vectors match the vendored sources (no native library needed)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="when generating, skip the native-library reproduction check",
    )
    args = parser.parse_args()
    if args.check:
        return check()
    return generate(verify=not args.no_verify)


if __name__ == "__main__":
    sys.exit(main())
