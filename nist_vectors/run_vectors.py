#!/usr/bin/env python3
"""Run NIST ACVP test vectors against the AMA Cryptography native C library.

Rules:
- AFT and MCT vectors for the SHA-3 family (SHA3-256, SHA3-512, SHAKE-128,
  SHAKE-256). LDT/VOT are still skipped (LDT requires multi-gigabyte inputs;
  VOT is superseded by AFT coverage of the output length range).
- Non-byte-aligned inputs (bitLength % 8 != 0) are skipped.
- ML-KEM-1024 only (512/768 not implemented).
- ML-KEM EncapDecap: decapsulation only (AMA doesn't expose randomness m).
- ML-DSA-65 SigVer: external/pure interface (TG 3) only.
- SLH-DSA-SHA2-256f SigVer: external/pure interface (TG 5) only.
- Uses existing Python ctypes FFI to libama_cryptography.so.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

VECTORS_DIR = Path(__file__).parent
REPO_ROOT = VECTORS_DIR.parent
LIB_DIR = REPO_ROOT / "build" / "lib"


# The upstream ACVP-Server ref whose `gen-val/json-files` tree the
# per-algorithm `source_url` fields below point at. Must track the same
# normalization as `nist_vectors/fetch_vectors.py::_acvp_ref()` so the
# URLs a reader sees in `results.json` / `validation_summary.json`
# resolve to the exact bytes the harness actually ran against. The
# attestation cross-check in `.github/workflows/acvp_validation.yml`
# enforces that this ref matches `acvp_attestation.json::acvp_ref`.
_DEFAULT_ACVP_REF = "v1.1.0.42"


def _acvp_ref() -> str:
    return os.environ.get("ACVP_REF", _DEFAULT_ACVP_REF).strip() or _DEFAULT_ACVP_REF


ACVP_BASE_URL = f"https://github.com/usnistgov/ACVP-Server/tree/{_acvp_ref()}/gen-val/json-files"


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
@dataclass
class AlgorithmResult:
    algorithm: str
    standard: str
    source_url: str
    vectors_tested: int = 0
    vectors_skipped: int = 0
    skip_reasons: list[str] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)
    mct_skipped: int = 0
    notes: str = ""


RESULTS: list[AlgorithmResult] = []


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------
def load_library() -> ctypes.CDLL:
    """Load the AMA Cryptography shared library."""
    lib_names = ["libama_cryptography.so", "libama_cryptography.so.2"]
    for name in lib_names:
        path = LIB_DIR / name
        if path.is_file():
            lib = ctypes.CDLL(str(path))
            _setup_ctypes(lib)
            return lib
    raise RuntimeError(f"Cannot find library in {LIB_DIR}")


def _setup_ctypes(lib: ctypes.CDLL) -> None:
    """Configure all ctypes signatures."""
    c_char_p = ctypes.c_char_p
    c_size_t = ctypes.c_size_t
    c_int = ctypes.c_int

    # SHA3-256
    lib.ama_sha3_256.argtypes = [c_char_p, c_size_t, c_char_p]
    lib.ama_sha3_256.restype = c_int

    # SHA3-512
    lib.ama_sha3_512.argtypes = [c_char_p, c_size_t, c_char_p]
    lib.ama_sha3_512.restype = c_int

    # SHAKE-128 (one-shot)
    lib.ama_shake128.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t]
    lib.ama_shake128.restype = c_int

    # SHAKE-256 (one-shot)
    lib.ama_shake256.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t]
    lib.ama_shake256.restype = c_int

    # SHA-256
    lib.ama_sha256.argtypes = [c_char_p, c_char_p, c_size_t]
    lib.ama_sha256.restype = None

    # HMAC-SHA-256
    lib.ama_hmac_sha256.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p]
    lib.ama_hmac_sha256.restype = None

    # AES-256-GCM encrypt
    lib.ama_aes256_gcm_encrypt.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    lib.ama_aes256_gcm_encrypt.restype = c_int

    # ML-KEM-1024 deterministic keygen
    lib.ama_kyber_keypair_from_seed.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
    lib.ama_kyber_keypair_from_seed.restype = c_int

    # ML-KEM-1024 decapsulate
    lib.ama_kyber_decapsulate.argtypes = [
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
    ]
    lib.ama_kyber_decapsulate.restype = c_int

    # ML-DSA-65 deterministic keygen
    lib.ama_dilithium_keypair_from_seed.argtypes = [c_char_p, c_char_p, c_char_p]
    lib.ama_dilithium_keypair_from_seed.restype = c_int

    # ML-DSA-65 verify
    lib.ama_dilithium_verify.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p]
    lib.ama_dilithium_verify.restype = c_int

    # ML-DSA-65 verify with context (FIPS 204 external/pure)
    lib.ama_dilithium_verify_ctx.argtypes = [
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
    ]
    lib.ama_dilithium_verify_ctx.restype = c_int

    # SPHINCS+-256f verify
    lib.ama_sphincs_verify.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p]
    lib.ama_sphincs_verify.restype = c_int

    # SPHINCS+-256f verify with context (FIPS 205 external/pure)
    lib.ama_sphincs_verify_ctx.argtypes = [
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
    ]
    lib.ama_sphincs_verify_ctx.restype = c_int


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------
def _load_vector_file(path: Path) -> dict[str, Any] | None:
    """Load a vector JSON file, returning None if it does not exist."""
    if not path.is_file():
        return None
    return cast(dict[str, Any], json.loads(path.read_text()))


def _sha3_mct_iterate(
    lib: ctypes.CDLL,
    sha3_fn_name: str,
    digest_size: int,
    seed: bytes,
) -> list[bytes]:
    """Run the ACVP SHA-3 Monte Carlo Test algorithm.

    Per https://pages.nist.gov/ACVP/draft-celi-acvp-sha3.html Section 6.2.1:

        Seed = provided seed
        for j = 0..99:                       # outer = 100 result blocks
            MD[0] = Seed
            for i = 1..1000:                 # inner = 1000 hashes
                MD[i] = SHA3(MD[i-1])
            resultsArray[j].md = MD[1000]
            Seed = MD[1000]

    Uses the one-shot ama_sha3_256 / ama_sha3_512 entry points — each inner
    iteration is a complete hash of the previous digest, so the streaming
    incremental API is not required here (it is required for variants that
    accumulate state across iterations, but the FIPS-202 MCT spec does not).
    Returns the 100 outer-iteration digests.
    """
    fn = getattr(lib, sha3_fn_name)
    out_buf = ctypes.create_string_buffer(digest_size)
    md_prev = seed
    results: list[bytes] = []
    for _j in range(100):
        for _i in range(1000):
            fn(md_prev, ctypes.c_size_t(len(md_prev)), out_buf)
            md_prev = out_buf.raw[:digest_size]
        results.append(md_prev)
    return results


def _run_sha3_mct(
    lib: ctypes.CDLL,
    res: AlgorithmResult,
    tg: dict[str, Any],
    sha3_fn_name: str,
    digest_size: int,
) -> None:
    """Score an MCT test group for SHA3-256 or SHA3-512 against AMA's one-shot
    hash API and mutate ``res`` in place. On Seed-length mismatches the group
    is skipped rather than failed — the ACVP server encodes seeds in ``msg``
    at full digest length.

    Each MCT tcId expands to 100 vectors (one per `resultsArray` entry), so
    when a tcId is skipped the counter is incremented by the size of the
    results array (or a 100 fallback if the group is malformed) rather than
    by 1 — otherwise ``vectors_tested + vectors_skipped`` does not equal the
    algorithm's true vector count in the summary table.
    """
    for tc in tg["tests"]:
        msg_hex = tc.get("msg", "")
        results = tc.get("resultsArray") or []
        # Every correctly-formed MCT tcId has 100 results; fall back to 100
        # if resultsArray is absent entirely so the skip counter still
        # reflects the "one tcId = 100 vectors" accounting used for passes.
        expected_count = len(results) if results else 100

        if not msg_hex or not results:
            res.vectors_skipped += expected_count
            res.skip_reasons.append(
                f"MCT tcId {tc['tcId']}: missing msg or resultsArray "
                f"({expected_count} vectors skipped)"
            )
            continue
        seed = bytes.fromhex(msg_hex)
        if len(seed) != digest_size:
            res.vectors_skipped += expected_count
            res.skip_reasons.append(
                f"MCT tcId {tc['tcId']}: seed length {len(seed)} != digest size "
                f"{digest_size} ({expected_count} vectors skipped)"
            )
            continue

        try:
            actual_digests = _sha3_mct_iterate(lib, sha3_fn_name, digest_size, seed)
        except Exception as exc:  # pragma: no cover - defensive
            # Count all 100 iterations as failed, not just 1, so the pass +
            # fail + skip totals add up.
            res.fail_count += expected_count
            res.failures.append(
                {
                    "tcId": str(tc["tcId"]),
                    "expected": f"100 x {digest_size}-byte digests",
                    "actual": f"exception: {exc}",
                    "note": "SHA-3 MCT execution failed",
                }
            )
            continue

        # ACVP returns a per-iteration pass/fail view: one tcId contributes
        # 100 vectors, each of which must match. Track them independently so
        # the summary accurately reflects MCT coverage.
        for idx, expected in enumerate(results):
            expected_hex = expected["md"].lower()
            actual_hex = actual_digests[idx].hex()
            res.vectors_tested += 1
            if actual_hex == expected_hex:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": f"{tc['tcId']}/MCT-j={idx}",
                        "expected": expected_hex,
                        "actual": actual_hex,
                        "note": "SHA-3 MCT digest mismatch",
                    }
                )


def test_sha3_256(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="SHA3-256",
        standard="FIPS 202",
        source_url=(f"{ACVP_BASE_URL}/SHA3-256-2.0"),
    )
    path = VECTORS_DIR / "SHA3-256-2.0.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        test_type = tg["testType"]
        if test_type == "MCT":
            _run_sha3_mct(lib, res, tg, "ama_sha3_256", 32)
            continue
        if test_type != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {test_type} vectors")
            continue
        for tc in tg["tests"]:
            bit_len = tc.get("len", 0)
            if bit_len % 8 != 0:
                res.vectors_skipped += 1
                res.skip_reasons.append(f"tcId {tc['tcId']}: non-byte-aligned (bitLen={bit_len})")
                continue
            msg = bytes.fromhex(tc["msg"]) if tc["msg"] else b""
            expected = tc["md"].lower()
            out = ctypes.create_string_buffer(32)
            lib.ama_sha3_256(msg, ctypes.c_size_t(len(msg)), out)
            actual = out.raw.hex()
            res.vectors_tested += 1
            if actual == expected:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected,
                        "actual": actual,
                        "note": "Hash mismatch",
                    }
                )
    return res


def test_sha3_512(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="SHA3-512",
        standard="FIPS 202",
        source_url=(f"{ACVP_BASE_URL}/SHA3-512-2.0"),
    )
    path = VECTORS_DIR / "SHA3-512-2.0.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        test_type = tg["testType"]
        if test_type == "MCT":
            _run_sha3_mct(lib, res, tg, "ama_sha3_512", 64)
            continue
        if test_type != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {test_type} vectors")
            continue
        for tc in tg["tests"]:
            bit_len = tc.get("len", 0)
            if bit_len % 8 != 0:
                res.vectors_skipped += 1
                res.skip_reasons.append(f"tcId {tc['tcId']}: non-byte-aligned (bitLen={bit_len})")
                continue
            msg = bytes.fromhex(tc["msg"]) if tc["msg"] else b""
            expected = tc["md"].lower()
            out = ctypes.create_string_buffer(64)
            lib.ama_sha3_512(msg, ctypes.c_size_t(len(msg)), out)
            actual = out.raw.hex()
            res.vectors_tested += 1
            if actual == expected:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected,
                        "actual": actual,
                        "note": "Hash mismatch",
                    }
                )
    return res


def _shake_mct_iterate(
    lib: ctypes.CDLL,
    shake_fn_name: str,
    seed: bytes,
    min_out_bits: int,
    max_out_bits: int,
) -> list[tuple[bytes, int]]:
    """Run the ACVP SHAKE Monte Carlo Test.

    Per https://pages.nist.gov/ACVP/draft-celi-acvp-sha3.html Section 6.2.2:

        Range  = (maxOutLen - minOutLen) / 8 + 1        # in bytes
        outLen = maxOutLen / 8                          # in bytes
        Msg[0] = Seed                                   # always 128 bits
        for j = 0..99:
            for i = 1..1000:
                # left-most 128 bits, zero-pad if shorter
                Msg[i] = Output[i-1][0:16] padded/truncated to 16 bytes
                Output[i] = SHAKE(Msg[i], outLen bytes)
                # rightmost 16 bits of Output[i] as big-endian unsigned int
                rightmost = int.from_bytes(Output[i][-2:], 'big')
                outLen = minOutLen/8 + (rightmost % Range)
            resultsArray[j] = (Output[1000], outLen_for_that_iter)

    Implementation notes:

    * The ctypes output buffer is allocated **once** at ``max_out`` bytes
      and re-used for all 100,000 inner SHAKE calls. A naive version
      allocates a fresh ``ctypes.create_string_buffer(out_len)`` on every
      inner iteration — that is 100,000 Python/C heap roundtrips per
      tcId and dominates CI runtime.
    * On each squeeze, only the first ``out_len`` bytes of the shared
      buffer are live; anything beyond that belongs to the previous
      iteration and is ignored (and overwritten on the next call).

    Returns the 100 (digest, outLen_bytes) pairs.
    """
    fn = getattr(lib, shake_fn_name)
    # Group-level skip in _run_shake_mct already guards against non-byte-aligned
    # output ranges. This is a defensive check against programmer error rather
    # than a runtime guard against malformed input — use ValueError rather than
    # assert so the message survives `python -O`.
    if min_out_bits % 8 != 0 or max_out_bits % 8 != 0:
        raise ValueError(
            f"SHAKE MCT output range must be byte-aligned: "
            f"min={min_out_bits}b, max={max_out_bits}b"
        )
    min_out = min_out_bits // 8
    max_out = max_out_bits // 8
    rng = max_out - min_out + 1

    msg = bytes(seed)  # caller trims/pads to 16 bytes
    if len(msg) < 16:
        msg = msg + bytes(16 - len(msg))
    else:
        msg = msg[:16]

    # Single reusable ctypes buffer, sized for the worst case. SHAKE writes
    # exactly `out_len` bytes on each call (see ama_shake128/256), so the
    # stale bytes past index out_len from the previous iteration are
    # harmless — we slice `raw[:out_len]` before using the digest.
    out_buf = ctypes.create_string_buffer(max_out)
    out_len = max_out
    results: list[tuple[bytes, int]] = []
    for _j in range(100):
        for _i in range(1000):
            fn(msg, ctypes.c_size_t(len(msg)), out_buf, ctypes.c_size_t(out_len))
            digest = out_buf.raw[:out_len]

            # Build next message: left-most 16 bytes (zero-pad if short)
            if out_len >= 16:
                msg = digest[:16]
            else:
                msg = digest + bytes(16 - out_len)

            # Update out_len from rightmost 16 bits of digest
            if out_len >= 2:
                rightmost = int.from_bytes(digest[-2:], "big")
            elif out_len == 1:
                rightmost = digest[-1]
            else:
                rightmost = 0
            out_len = min_out + (rightmost % rng)

        results.append((digest, out_len))
    return results


def _run_shake_mct(
    lib: ctypes.CDLL,
    res: AlgorithmResult,
    tg: dict[str, Any],
    shake_fn_name: str,
) -> None:
    """Score a SHAKE MCT test group. The ACVP group specifies ``minOutLen``
    and ``maxOutLen`` in bits; both must be byte-aligned (they always are in
    the upstream vector files). Vectors inside the group each contain a
    ``msg`` seed and a ``resultsArray`` of 100 entries.

    Skip counters mirror the SHA-3 MCT variant: a skipped tcId increments
    ``vectors_skipped`` by the size of its ``resultsArray`` (or 100 when
    absent) rather than by 1, so the per-algorithm totals line up with
    the tested+skipped accounting in the summary table.
    """
    min_out_bits = int(tg.get("minOutLen", 0))
    max_out_bits = int(tg.get("maxOutLen", 0))
    if min_out_bits == 0 or max_out_bits == 0 or min_out_bits % 8 != 0 or max_out_bits % 8 != 0:
        # Group-level skip: count 100 per tcId (the per-vector expansion)
        skipped = 0
        for _tc in tg.get("tests", []):
            skipped += len(_tc.get("resultsArray") or []) or 100
        res.vectors_skipped += skipped
        res.skip_reasons.append(
            f"MCT TG {tg['tgId']}: non-byte-aligned output-len range "
            f"[{min_out_bits}, {max_out_bits}] bits ({skipped} vectors skipped)"
        )
        return

    for tc in tg["tests"]:
        msg_hex = tc.get("msg", "")
        results = tc.get("resultsArray") or []
        expected_count = len(results) if results else 100

        if not msg_hex or not results:
            res.vectors_skipped += expected_count
            res.skip_reasons.append(
                f"MCT tcId {tc['tcId']}: missing msg or resultsArray "
                f"({expected_count} vectors skipped)"
            )
            continue
        seed = bytes.fromhex(msg_hex)

        try:
            actual = _shake_mct_iterate(lib, shake_fn_name, seed, min_out_bits, max_out_bits)
        except Exception as exc:  # pragma: no cover
            # Count every vector under this tcId as failed so the summary
            # totals stay consistent.
            res.fail_count += expected_count
            res.failures.append(
                {
                    "tcId": str(tc["tcId"]),
                    "expected": "100 x (md, outLen)",
                    "actual": f"exception: {exc}",
                    "note": "SHAKE MCT execution failed",
                }
            )
            continue

        for idx, expected in enumerate(results):
            expected_md = expected["md"].lower()
            expected_outlen = int(expected.get("outLen", 0))
            actual_md, actual_outlen_bytes = actual[idx]
            actual_md_hex = actual_md.hex()
            res.vectors_tested += 1
            if actual_md_hex == expected_md and actual_outlen_bytes * 8 == expected_outlen:
                res.pass_count += 1
            else:
                res.fail_count += 1
                note = "SHAKE MCT mismatch"
                if actual_outlen_bytes * 8 != expected_outlen:
                    note += f" (outLen {actual_outlen_bytes*8} vs {expected_outlen})"
                res.failures.append(
                    {
                        "tcId": f"{tc['tcId']}/MCT-j={idx}",
                        "expected": (
                            expected_md[:64] + "..." if len(expected_md) > 64 else expected_md
                        ),
                        "actual": (
                            actual_md_hex[:64] + "..." if len(actual_md_hex) > 64 else actual_md_hex
                        ),
                        "note": note,
                    }
                )


def test_shake128(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="SHAKE-128",
        standard="FIPS 202",
        source_url=(f"{ACVP_BASE_URL}/SHAKE-128-1.0"),
    )
    path = VECTORS_DIR / "SHAKE-128-1.0.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        test_type = tg["testType"]
        if test_type == "MCT":
            _run_shake_mct(lib, res, tg, "ama_shake128")
            continue
        if test_type != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {test_type} vectors")
            continue
        for tc in tg["tests"]:
            bit_len = tc.get("len", 0)
            out_len_bits = tc.get("outLen", 0)
            if bit_len % 8 != 0:
                res.vectors_skipped += 1
                res.skip_reasons.append(
                    f"tcId {tc['tcId']}: non-byte-aligned input (bitLen={bit_len})"
                )
                continue
            if out_len_bits % 8 != 0:
                res.vectors_skipped += 1
                res.skip_reasons.append(
                    f"tcId {tc['tcId']}: non-byte-aligned output (outLen={out_len_bits})"
                )
                continue
            msg = bytes.fromhex(tc["msg"]) if tc["msg"] else b""
            out_len = out_len_bits // 8
            expected = tc["md"].lower()
            out = ctypes.create_string_buffer(out_len)
            lib.ama_shake128(msg, ctypes.c_size_t(len(msg)), out, ctypes.c_size_t(out_len))
            actual = out.raw.hex()
            res.vectors_tested += 1
            if actual == expected:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected[:64] + "..." if len(expected) > 64 else expected,
                        "actual": actual[:64] + "..." if len(actual) > 64 else actual,
                        "note": "XOF output mismatch",
                    }
                )
    return res


def test_shake256(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="SHAKE-256",
        standard="FIPS 202",
        source_url=(f"{ACVP_BASE_URL}/SHAKE-256-1.0"),
    )
    path = VECTORS_DIR / "SHAKE-256-1.0.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        test_type = tg["testType"]
        if test_type == "MCT":
            _run_shake_mct(lib, res, tg, "ama_shake256")
            continue
        if test_type != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {test_type} vectors")
            continue
        for tc in tg["tests"]:
            bit_len = tc.get("len", 0)
            out_len_bits = tc.get("outLen", 0)
            if bit_len % 8 != 0:
                res.vectors_skipped += 1
                res.skip_reasons.append(
                    f"tcId {tc['tcId']}: non-byte-aligned input (bitLen={bit_len})"
                )
                continue
            if out_len_bits % 8 != 0:
                res.vectors_skipped += 1
                res.skip_reasons.append(
                    f"tcId {tc['tcId']}: non-byte-aligned output (outLen={out_len_bits})"
                )
                continue
            msg = bytes.fromhex(tc["msg"]) if tc["msg"] else b""
            out_len = out_len_bits // 8
            expected = tc["md"].lower()
            out = ctypes.create_string_buffer(out_len)
            lib.ama_shake256(msg, ctypes.c_size_t(len(msg)), out, ctypes.c_size_t(out_len))
            actual = out.raw.hex()
            res.vectors_tested += 1
            if actual == expected:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected[:64] + "..." if len(expected) > 64 else expected,
                        "actual": actual[:64] + "..." if len(actual) > 64 else actual,
                        "note": "XOF output mismatch",
                    }
                )
    return res


def test_hmac_sha256(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="HMAC-SHA-256",
        standard="FIPS 198-1",
        source_url=(f"{ACVP_BASE_URL}/HMAC-SHA2-256-2.0"),
    )
    path = VECTORS_DIR / "HMAC-SHA2-256-2.0.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["testType"] != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            continue
        for tc in tg["tests"]:
            key = bytes.fromhex(tc["key"])
            msg = bytes.fromhex(tc["msg"]) if tc["msg"] else b""
            mac_len = tc["macLen"] // 8
            expected = tc["mac"].lower()[: mac_len * 2]
            out = ctypes.create_string_buffer(32)
            lib.ama_hmac_sha256(
                key,
                ctypes.c_size_t(len(key)),
                msg,
                ctypes.c_size_t(len(msg)),
                out,
            )
            actual = out.raw[:mac_len].hex()
            res.vectors_tested += 1
            if actual == expected:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected,
                        "actual": actual,
                        "note": "HMAC output mismatch",
                    }
                )
    return res


def test_sha256(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="SHA-256",
        standard="FIPS 180-4",
        source_url="https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
    )
    path = VECTORS_DIR / "SHA-256-FIPS180-4.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["testType"] != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {tg['testType']} vectors")
            continue
        for tc in tg["tests"]:
            msg = bytes.fromhex(tc["msg"]) if tc["msg"] else b""
            expected = tc["md"].lower()
            out = ctypes.create_string_buffer(32)
            lib.ama_sha256(out, msg, ctypes.c_size_t(len(msg)))
            actual = out.raw.hex()
            res.vectors_tested += 1
            if actual == expected:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected,
                        "actual": actual,
                        "note": "Hash mismatch",
                    }
                )
    return res


def test_aes256gcm(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="AES-256-GCM",
        standard="NIST SP 800-38D",
        source_url="https://csrc.nist.gov/pubs/sp/800/38/d/final",
    )
    path = VECTORS_DIR / "AES-256-GCM-SP800-38D.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["testType"] != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {tg['testType']} vectors")
            continue
        for tc in tg["tests"]:
            key = bytes.fromhex(tc["key"])
            iv = bytes.fromhex(tc["iv"])
            pt = bytes.fromhex(tc["pt"]) if tc["pt"] else b""
            aad = bytes.fromhex(tc["aad"]) if tc["aad"] else b""
            expected_ct = tc["ct"].lower()
            expected_tag = tc["tag"].lower()

            ct_buf = ctypes.create_string_buffer(max(len(pt), 1))
            tag_buf = ctypes.create_string_buffer(16)

            rc = lib.ama_aes256_gcm_encrypt(
                key,
                iv,
                pt if pt else None,
                ctypes.c_size_t(len(pt)),
                aad if aad else None,
                ctypes.c_size_t(len(aad)),
                ct_buf,
                tag_buf,
            )
            res.vectors_tested += 1
            actual_ct = ct_buf.raw[: len(pt)].hex()
            actual_tag = tag_buf.raw.hex()
            if rc != 0:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"ct={expected_ct} tag={expected_tag}",
                        "actual": f"error code {rc}",
                        "note": "AES-GCM encrypt returned error",
                    }
                )
            elif actual_ct == expected_ct and actual_tag == expected_tag:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"ct={expected_ct} tag={expected_tag}",
                        "actual": f"ct={actual_ct} tag={actual_tag}",
                        "note": "Ciphertext or tag mismatch",
                    }
                )
    return res


def test_ml_kem_keygen(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="ML-KEM-1024 KeyGen",
        standard="FIPS 203",
        source_url=(f"{ACVP_BASE_URL}/ML-KEM-keyGen-FIPS203"),
    )
    path = VECTORS_DIR / "ML-KEM-keyGen-FIPS203.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["testType"] != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            continue
        if tg.get("parameterSet") != "ML-KEM-1024":
            count = len(tg.get("tests", []))
            res.vectors_skipped += count
            res.skip_reasons.append(
                f"TG {tg['tgId']}: skipped {count} vectors "
                f"(param={tg.get('parameterSet')}, only ML-KEM-1024 tested)"
            )
            continue
        for tc in tg["tests"]:
            d_seed = bytes.fromhex(tc["d"])
            z_seed = bytes.fromhex(tc["z"])
            expected_ek = tc["ek"].lower()
            expected_dk = tc["dk"].lower()

            pk_buf = ctypes.create_string_buffer(1568)
            sk_buf = ctypes.create_string_buffer(3168)

            rc = lib.ama_kyber_keypair_from_seed(d_seed, z_seed, pk_buf, sk_buf)
            res.vectors_tested += 1
            if rc != 0:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"ek={expected_ek[:32]}...",
                        "actual": f"error code {rc}",
                        "note": "Deterministic keygen returned error",
                    }
                )
                continue
            actual_ek = pk_buf.raw.hex()
            actual_dk = sk_buf.raw.hex()
            if actual_ek == expected_ek and actual_dk == expected_dk:
                res.pass_count += 1
            else:
                mismatch = "ek mismatch" if actual_ek != expected_ek else "dk mismatch"
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"ek={expected_ek[:32]}... dk={expected_dk[:32]}...",
                        "actual": f"ek={actual_ek[:32]}... dk={actual_dk[:32]}...",
                        "note": mismatch,
                    }
                )
    return res


def test_ml_kem_decap(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="ML-KEM-1024 EncapDecap",
        standard="FIPS 203",
        source_url=(f"{ACVP_BASE_URL}/ML-KEM-encapDecap-FIPS203"),
        notes="Decapsulation only; deterministic encapsulation not tested "
        "(AMA does not expose randomness parameter m).",
    )
    path = VECTORS_DIR / "ML-KEM-encapDecap-FIPS203.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["testType"] != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            res.skip_reasons.append(f"TG {tg['tgId']}: skipped {count} {tg['testType']} vectors")
            continue
        if tg.get("parameterSet") != "ML-KEM-1024":
            count = len(tg.get("tests", []))
            res.vectors_skipped += count
            res.skip_reasons.append(
                f"TG {tg['tgId']}: skipped {count} vectors "
                f"(param={tg.get('parameterSet')}, only ML-KEM-1024 tested)"
            )
            continue
        for tc in tg["tests"]:
            dk = bytes.fromhex(tc["dk"])
            c = bytes.fromhex(tc["c"])
            expected_k = tc["k"].lower()

            ss_buf = ctypes.create_string_buffer(32)
            rc = lib.ama_kyber_decapsulate(
                c,
                ctypes.c_size_t(len(c)),
                dk,
                ctypes.c_size_t(len(dk)),
                ss_buf,
                ctypes.c_size_t(32),
            )
            res.vectors_tested += 1
            if rc != 0:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected_k,
                        "actual": f"error code {rc}",
                        "note": "Decapsulation returned error",
                    }
                )
                continue
            actual_k = ss_buf.raw.hex()
            if actual_k == expected_k:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": expected_k,
                        "actual": actual_k,
                        "note": "Shared secret mismatch after decapsulation",
                    }
                )
    return res


def test_ml_dsa_keygen(lib: ctypes.CDLL) -> AlgorithmResult:
    res = AlgorithmResult(
        algorithm="ML-DSA-65 KeyGen",
        standard="FIPS 204",
        source_url=(f"{ACVP_BASE_URL}/ML-DSA-keyGen-FIPS204"),
    )
    path = VECTORS_DIR / "ML-DSA-keyGen-FIPS204.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["testType"] != "AFT":
            count = len(tg.get("tests", []))
            res.mct_skipped += count
            continue
        if tg.get("parameterSet") != "ML-DSA-65":
            count = len(tg.get("tests", []))
            res.vectors_skipped += count
            res.skip_reasons.append(
                f"TG {tg['tgId']}: skipped {count} vectors "
                f"(param={tg.get('parameterSet')}, only ML-DSA-65 tested)"
            )
            continue
        for tc in tg["tests"]:
            seed = bytes.fromhex(tc["seed"])
            expected_pk = tc["pk"].lower()
            expected_sk = tc["sk"].lower()

            pk_buf = ctypes.create_string_buffer(1952)
            sk_buf = ctypes.create_string_buffer(4032)

            rc = lib.ama_dilithium_keypair_from_seed(seed, pk_buf, sk_buf)
            res.vectors_tested += 1
            if rc != 0:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"pk={expected_pk[:32]}...",
                        "actual": f"error code {rc}",
                        "note": "Deterministic keygen returned error",
                    }
                )
                continue
            actual_pk = pk_buf.raw.hex()
            actual_sk = sk_buf.raw.hex()
            if actual_pk == expected_pk and actual_sk == expected_sk:
                res.pass_count += 1
            else:
                mismatch = "pk mismatch" if actual_pk != expected_pk else "sk mismatch"
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"pk={expected_pk[:32]}... sk={expected_sk[:32]}...",
                        "actual": f"pk={actual_pk[:32]}... sk={actual_sk[:32]}...",
                        "note": mismatch,
                    }
                )
    return res


def test_ml_dsa_sigver(lib: ctypes.CDLL) -> AlgorithmResult:
    """ML-DSA-65 SigVer — external/pure interface (TG 3)."""
    res = AlgorithmResult(
        algorithm="ML-DSA-65 SigVer",
        standard="FIPS 204",
        source_url=(f"{ACVP_BASE_URL}/ML-DSA-sigVer-FIPS204"),
        notes="External/pure interface (TG 3) only. Uses ama_dilithium_verify_ctx "
        "which applies FIPS 204 domain-separation wrapper.",
    )
    path = VECTORS_DIR / "ML-DSA-sigVer-FIPS204.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["tgId"] != 3:
            count = len(tg.get("tests", []))
            res.vectors_skipped += count
            res.skip_reasons.append(
                f"TG {tg['tgId']}: skipped {count} vectors "
                f"(only TG 3 external/pure interface tested)"
            )
            continue
        for tc in tg["tests"]:
            pk = bytes.fromhex(tc["pk"])
            message = bytes.fromhex(tc["message"])
            signature = bytes.fromhex(tc["signature"])
            context_hex = tc.get("context", "")
            ctx = bytes.fromhex(context_hex) if context_hex else b""
            expected_pass = tc["testPassed"]

            rc = lib.ama_dilithium_verify_ctx(
                message,
                ctypes.c_size_t(len(message)),
                ctx,
                ctypes.c_size_t(len(ctx)),
                signature,
                ctypes.c_size_t(len(signature)),
                pk,
            )
            # AMA_SUCCESS = 0, AMA_ERROR_VERIFY_FAILED = -4
            actual_pass = rc == 0
            res.vectors_tested += 1
            if actual_pass == expected_pass:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"testPassed={expected_pass}",
                        "actual": f"testPassed={actual_pass} (rc={rc})",
                        "note": (f"SigVer verdict mismatch. context_len=" f"{len(ctx)}."),
                    }
                )
    return res


def test_slh_dsa_sigver(lib: ctypes.CDLL) -> AlgorithmResult:
    """SLH-DSA-SHA2-256f SigVer — external/pure interface (TG 5)."""
    res = AlgorithmResult(
        algorithm="SLH-DSA-SHA2-256f SigVer",
        standard="FIPS 205",
        source_url=(f"{ACVP_BASE_URL}/SLH-DSA-sigVer-FIPS205"),
        notes="External/pure interface (TG 5) only. Uses ama_sphincs_verify_ctx "
        "which applies FIPS 205 domain-separation wrapper.",
    )
    path = VECTORS_DIR / "SLH-DSA-sigVer-FIPS205.json"
    data = _load_vector_file(path)
    if data is None:
        res.notes = f"Vector file {path.name} not found; run fetch_vectors.py"
        return res
    for tg in data["testGroups"]:
        if tg["tgId"] != 5:
            count = len(tg.get("tests", []))
            res.vectors_skipped += count
            res.skip_reasons.append(
                f"TG {tg['tgId']}: skipped {count} vectors "
                f"(only TG 5 SLH-DSA-SHA2-256f external/pure tested)"
            )
            continue
        for tc in tg["tests"]:
            pk = bytes.fromhex(tc["pk"])
            message = bytes.fromhex(tc["message"])
            signature = bytes.fromhex(tc["signature"])
            context_hex = tc.get("context", "")
            ctx = bytes.fromhex(context_hex) if context_hex else b""
            expected_pass = tc["testPassed"]

            rc = lib.ama_sphincs_verify_ctx(
                message,
                ctypes.c_size_t(len(message)),
                ctx,
                ctypes.c_size_t(len(ctx)),
                signature,
                ctypes.c_size_t(len(signature)),
                pk,
            )
            actual_pass = rc == 0
            res.vectors_tested += 1
            if actual_pass == expected_pass:
                res.pass_count += 1
            else:
                res.fail_count += 1
                res.failures.append(
                    {
                        "tcId": str(tc["tcId"]),
                        "expected": f"testPassed={expected_pass}",
                        "actual": f"testPassed={actual_pass} (rc={rc})",
                        "note": (f"SigVer verdict mismatch. context_len=" f"{len(ctx)}."),
                    }
                )
    return res


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    print("=" * 70)
    print("NIST ACVP Vector Validation — AMA Cryptography")
    print("=" * 70)

    print("\nLoading native library...")
    lib = load_library()
    print(f"  Loaded from {LIB_DIR}")

    env_info = {
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "arch": platform.machine(),
    }
    print(f"  OS: {env_info['os']}")
    print(f"  Python: {env_info['python']}")
    print(f"  Arch: {env_info['arch']}")

    tests = [
        ("SHA3-256", test_sha3_256),
        ("SHA3-512", test_sha3_512),
        ("SHAKE-128", test_shake128),
        ("SHAKE-256", test_shake256),
        ("HMAC-SHA-256", test_hmac_sha256),
        ("SHA-256", test_sha256),
        ("AES-256-GCM", test_aes256gcm),
        ("ML-KEM-1024 KeyGen", test_ml_kem_keygen),
        ("ML-KEM-1024 EncapDecap", test_ml_kem_decap),
        ("ML-DSA-65 KeyGen", test_ml_dsa_keygen),
        ("ML-DSA-65 SigVer", test_ml_dsa_sigver),
        ("SLH-DSA-SHA2-256f SigVer", test_slh_dsa_sigver),
    ]

    start_time = time.time()

    for name, test_fn in tests:
        print(f"\n--- {name} ---")
        try:
            result = test_fn(lib)
            RESULTS.append(result)
            status = "PASS" if result.fail_count == 0 else "FAIL"
            print(
                f"  Tested: {result.vectors_tested}  "
                f"Pass: {result.pass_count}  "
                f"Fail: {result.fail_count}  "
                f"Skipped: {result.vectors_skipped}  "
                f"MCT/other skipped: {result.mct_skipped}  "
                f"[{status}]"
            )
            if result.failures:
                for f in result.failures[:5]:
                    print(f"    FAIL tcId={f['tcId']}: {f['note']}")
                    print(f"      expected: {f['expected']}")
                    print(f"      actual:   {f['actual']}")
                if len(result.failures) > 5:
                    print(f"    ... and {len(result.failures) - 5} more failures")
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback

            traceback.print_exc()

    elapsed = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"Total time: {elapsed:.1f}s")

    # Summary
    total_tested = sum(r.vectors_tested for r in RESULTS)
    total_pass = sum(r.pass_count for r in RESULTS)
    total_fail = sum(r.fail_count for r in RESULTS)
    total_skip = sum(r.vectors_skipped for r in RESULTS)
    print(f"Total vectors tested: {total_tested}")
    print(f"Total pass: {total_pass}")
    print(f"Total fail: {total_fail}")
    print(f"Total skipped: {total_skip}")

    # Write results.json
    algo_list: list[dict[str, object]] = []
    for r in RESULTS:
        algo_entry: dict[str, object] = {
            "algorithm": r.algorithm,
            "standard": r.standard,
            "source_url": r.source_url,
            "vectors_tested": r.vectors_tested,
            "vectors_skipped": r.vectors_skipped,
            "skip_reasons": r.skip_reasons,
            "pass_count": r.pass_count,
            "fail_count": r.fail_count,
            "mct_skipped": r.mct_skipped,
        }
        if r.notes:
            algo_entry["notes"] = r.notes
        if r.failures:
            algo_entry["failures"] = r.failures
        algo_list.append(algo_entry)

    results_json: dict[str, object] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": env_info,
        "library": "libama_cryptography.so (native C, no liboqs/PQClean)",
        "summary": {
            "total_tested": total_tested,
            "total_pass": total_pass,
            "total_fail": total_fail,
            "total_skipped": total_skip,
        },
        "algorithms": algo_list,
    }

    out_path = VECTORS_DIR / "results.json"
    out_path.write_text(json.dumps(results_json, indent=2))
    print(f"\nResults written to {out_path}")

    return 1 if total_fail > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
