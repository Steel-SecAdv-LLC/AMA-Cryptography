#!/usr/bin/env python3
"""
Minimal PQC sanity check for Ava Guardian ♱.

This script asserts PQC backend availability and exercises a hybrid
sign/verify path. It exits non-zero on failure so it can be used in CI
or local smoke testing.
"""

from ava_guardian.crypto_api import AlgorithmType, AvaGuardianCrypto
from ava_guardian.exceptions import PQCUnavailableError
from ava_guardian.pqc_backends import PQCStatus, get_pqc_backend_info, get_pqc_status


def main() -> None:
    status = get_pqc_status()
    info = get_pqc_backend_info()

    if status != PQCStatus.AVAILABLE:
        raise SystemExit(
            "PQC unavailable: install liboqs-python and ensure it loads correctly."
        )

    if info.get("dilithium_backend") != "liboqs":
        raise SystemExit(
            "PQC backend is not liboqs. Install liboqs-python for constant-time support."
        )

    crypto = AvaGuardianCrypto(algorithm=AlgorithmType.HYBRID_SIG)
    try:
        keypair = crypto.generate_keypair()
        signature = crypto.sign(b"sanity-check", keypair.secret_key)
        valid = crypto.verify(b"sanity-check", signature.signature, keypair.public_key)
    except (PQCUnavailableError, RuntimeError, ValueError, OSError) as exc:
        raise SystemExit(f"PQC sanity check failed: {exc}")

    if not valid:
        raise SystemExit("PQC sanity check failed: signature verification returned False.")

    print("PQC sanity check passed: liboqs backend available and hybrid sign/verify succeeded.")


if __name__ == "__main__":
    main()
