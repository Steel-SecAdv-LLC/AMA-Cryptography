#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Secret residue in process memory (INVARIANT-6), measured rather than argued
===========================================================================

INVARIANT-6 asks that secret material be held where it can be zeroed.  Code
review can check that a function returns a ``bytearray``; it cannot check that
nothing else -- a cache, module state, a container, an exception, a stray
``bytes`` -- still holds the secret after the caller has wiped what it was
given.  This tool checks exactly that, by looking.

For each operation in :data:`OPERATIONS`, in a fresh interpreter:

1. run it and take the secret it returns (a ``bytearray``);
2. split the secret into two random XOR shares, then zero the secret and drop
   every container the operation returned;
3. rebuild the secret from its shares into ONE ``bytearray`` (the needle),
   whose address is known;
4. read every readable mapping of the process through ``/proc/self/mem`` and
   count occurrences of the needle anywhere but at the needle itself.

The shares are not the secret, so holding them plants no copy; the needle is
the one copy the measurement makes, and it is excluded by address.  The scan
reads into a single reused buffer that is zeroed after every chunk, so the
instrument does not leave copies of what it has seen either.

What it measures, and what it does not
--------------------------------------
* **Live copies -- measured.**  A copy that is still referenced (retained in
  module state, a cache, a container, a traceback) is found every time.  The
  positive control: with the continuous-RNG test patched to keep the raw
  sample instead of its digest (the defect the digest form fixed), a 32-byte
  draw leaves one copy; shipped, none (2026-10-08).
* **Freed memory -- not reliably.**  A freed ``bytes`` copy of a 32-byte
  secret was NOT found in the control run: pymalloc returns a freed block to
  the next allocation of its size class, and the measurement itself allocates
  in that class before it scans.  So a zero here says no copy is *reachable*;
  it does not say none was ever *made*.  That half is held by construction
  (``_take_secret``, ``_borrow`` and the ``bytearray`` contracts) and by code
  review, not by this instrument.
* Linux only (``/proc/self/mem``).

This is a measurement instrument producing an inventory, not a gate with an
exemption list (AGENTS.md section 10).  ``tests/test_secret_residue.py`` runs
it over the operations whose zero is a pinned property.

Exit status: 0 measured (whatever the counts), 2 the measurement could not
run here.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent

_MAP_RE = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S{4}) \S+ \S+ \S+\s*(.*)$")
_UNREADABLE = frozenset({"[vvar]", "[vsyscall]", "[vvar_vclock]"})
_CHUNK = 1 << 22


def _regions() -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    with open("/proc/self/maps", encoding="ascii") as maps:
        for line in maps:
            match = _MAP_RE.match(line.rstrip("\n"))
            if match is None:
                continue
            lo, hi = int(match[1], 16), int(match[2], 16)
            perms, name = match[3], match[4]
            if perms[0] == "r" and name not in _UNREADABLE:
                out.append((lo, hi, name or "[anon]"))
    return out


def _address(buf: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


def scan(needle: bytearray) -> list[tuple[int, str]]:
    """Every address holding ``needle`` except the needle itself."""
    width = len(needle)
    work = bytearray(_CHUNK + width)
    work_lo = _address(work)
    work_hi = work_lo + len(work)
    skip = _address(needle)
    view = memoryview(work)
    hits: list[tuple[int, str]] = []
    fd = os.open("/proc/self/mem", os.O_RDONLY)
    try:
        for lo, hi, name in _regions():
            pos = lo
            while pos < hi:
                want = min(len(work), hi - pos)
                try:
                    got = os.preadv(fd, [view[:want]], pos)
                except OSError:
                    break
                start = 0
                while True:
                    k = work.find(needle, start, got)
                    if k < 0:
                        break
                    addr = pos + k
                    if addr != skip and not work_lo <= addr < work_hi:
                        hits.append((addr, name))
                    start = k + 1
                ctypes.memset(work_lo, 0, len(work))
                if got <= width:
                    break
                pos += got - width + 1
    finally:
        os.close(fd)
        ctypes.memset(work_lo, 0, len(work))
    return hits


def measure(operation: Callable[[], bytearray]) -> list[tuple[int, str]]:
    """Run ``operation``, wipe its secret, and return the copies left behind."""
    secret = operation()
    if not isinstance(secret, bytearray):
        raise TypeError(f"the operation returned {type(secret).__name__}, not a bytearray")
    n = len(secret)
    # The mask comes from the OS directly, NOT the library's CSPRNG: a draw
    # through the library runs the continuous health test, which replaces the
    # state that test keeps -- the instrument would rewrite the very memory
    # it is about to inspect (measured: it made the retained-copy control
    # read 0 or 1 at random).  The mask is not secret.
    share_a = bytearray(os.urandom(n))
    share_b = bytearray(n)
    for i in range(n):
        share_b[i] = secret[i] ^ share_a[i]
    memoryview(secret)[:] = bytes(n)
    del secret
    gc.collect()
    needle = bytearray(n)
    for i in range(n):
        needle[i] = share_a[i] ^ share_b[i]
    try:
        return scan(needle)
    finally:
        memoryview(needle)[:] = bytes(n)


# ---------------------------------------------------------------------------
# The inventory.  Each entry returns a bytearray holding a secret the library
# produced, having dropped every other object the operation handed back.
# ---------------------------------------------------------------------------


def _kyber_decapsulate() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    kp = pb.generate_kyber_keypair()
    ct = pb.kyber_encapsulate(kp.public_key).ciphertext
    return pb.kyber_decapsulate(ct, kp.secret_key)


def _ml_kem_decapsulate() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    pk, sk = pb.native_ml_kem_keypair(768)
    ct, ss = pb.native_ml_kem_encapsulate(768, pk)
    memoryview(ss)[:] = bytes(len(ss))
    return pb.native_ml_kem_decapsulate(768, ct, sk)


def _x25519_exchange() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    _, ours = pb.native_x25519_keypair()
    theirs, _ = pb.native_x25519_keypair()
    return pb.native_x25519_key_exchange(ours, theirs)


def _nistp_ecdh() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    _, ours = pb.native_nistp_keypair("P-256")
    theirs, _ = pb.native_nistp_keypair("P-256")
    return pb.native_nistp_ecdh("P-256", ours, theirs)


def _hkdf_sha3_cython() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    return pb.native_hkdf(bytes(range(32)), 32, salt=b"s", info=b"residue")


def _hkdf_sha256() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    return pb.native_hkdf_sha256(bytes(range(32)), 32, salt=b"s", info=b"residue")


def _pbkdf2_sha512() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    return pb.native_pbkdf2_hmac_sha512(b"correct horse", b"mnemonic", 2, 64)


def _argon2id() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    return pb.native_argon2id(b"correct horse", b"saltsaltsalt", t_cost=1, m_cost=64, parallelism=1)


def _hd_derive_path() -> bytearray:
    from ama_cryptography.key_management import HDKeyDerivation

    key, chain = HDKeyDerivation().derive_path("m/44'/0'/0'/0/7")
    memoryview(chain)[:] = bytes(len(chain))
    return key


def _secure_token_bytearray() -> bytearray:
    from ama_cryptography._module_state import secure_token_bytearray

    return secure_token_bytearray(32)


def _ed25519_keypair() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    secret: bytearray = pb.native_ed25519_keypair()[1]
    return secret


def _hybrid_kem_decapsulate() -> bytearray:
    from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

    kem = AmaCryptography(algorithm=AlgorithmType.HYBRID_KEM)
    kp = kem.generate_keypair()
    ct = kem.encapsulate(kp.public_key).ciphertext
    return kem.decapsulate(ct, kp.secret_key)


def _frost_dealt_share() -> bytearray:
    import ama_cryptography.pqc_backends as pb

    _, shares = pb.frost_keygen_trusted_dealer(2, 3)
    for share in shares[1:]:
        memoryview(share)[:] = bytes(len(share))
    return bytearray(memoryview(shares[0])[:32])


OPERATIONS: dict[str, Callable[[], bytearray]] = {
    "kyber_decapsulate": _kyber_decapsulate,
    "native_ml_kem_decapsulate": _ml_kem_decapsulate,
    "native_x25519_key_exchange": _x25519_exchange,
    "native_nistp_ecdh": _nistp_ecdh,
    "native_hkdf (Cython path)": _hkdf_sha3_cython,
    "native_hkdf_sha256": _hkdf_sha256,
    "native_pbkdf2_hmac_sha512": _pbkdf2_sha512,
    "native_argon2id": _argon2id,
    "HDKeyDerivation.derive_path": _hd_derive_path,
    "secure_token_bytearray": _secure_token_bytearray,
    "native_ed25519_keypair": _ed25519_keypair,
    "hybrid KEM decapsulate": _hybrid_kem_decapsulate,
    "frost_keygen_trusted_dealer share": _frost_dealt_share,
}


def _measure_in_child(name: str) -> dict[str, object]:
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--child", name],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=600,
        check=False,
    )
    if proc.returncode != 0:
        return {"operation": name, "error": (proc.stderr or proc.stdout).strip()[-2000:]}
    result: dict[str, object] = json.loads(proc.stdout.strip().splitlines()[-1])
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 2)[1])
    parser.add_argument("--child", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Emit the inventory as JSON.")
    parser.add_argument(
        "operations", nargs="*", help="Operations to measure (default: the whole inventory)."
    )
    args = parser.parse_args(argv)

    if not os.path.exists("/proc/self/mem"):
        print("measure_secret_residue: needs /proc/self/mem (Linux)", file=sys.stderr)
        return 2

    if args.child:
        hits = measure(OPERATIONS[args.child])
        print(
            json.dumps(
                {
                    "operation": args.child,
                    "copies": len(hits),
                    "regions": sorted({n for _, n in hits}),
                }
            )
        )
        return 0

    names = args.operations or list(OPERATIONS)
    unknown = [n for n in names if n not in OPERATIONS]
    if unknown:
        parser.error(f"unknown operation(s): {unknown}")
    results = [_measure_in_child(name) for name in names]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            if "error" in row:
                print(f"  {row['operation']:<38} ERROR {row['error']}")
            else:
                print(f"  {row['operation']:<38} {row['copies']} live copies  {row['regions']}")
    return 2 if any("error" in row for row in results) else 0


if __name__ == "__main__":
    sys.exit(main())
