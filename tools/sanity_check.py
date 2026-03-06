#!/usr/bin/env python3
"""
Minimal PQC sanity check for AMA Cryptography ♱.

This script asserts PQC backend availability and exercises a hybrid
sign/verify path. It exits non-zero on failure so it can be used in CI
or local smoke testing.
"""

from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography
from ama_cryptography.exceptions import PQCUnavailableError
from ama_cryptography.pqc_backends import PQCStatus, get_pqc_backend_info, get_pqc_status


def main() -> None:
    status = get_pqc_status()
    info = get_pqc_backend_info()

    if status != PQCStatus.AVAILABLE:
        raise SystemExit(
            "PQC unavailable: build native C library with "
            "cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )

    backend = info.get("dilithium_backend")
    if backend is None:
        raise SystemExit(
            "PQC backend unavailable. Build native C library."
        )
    if backend != "native":
        raise SystemExit(
            f"PQC backend is '{backend}'. Expected 'native'."
        )

    crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
    try:
        keypair = crypto.generate_keypair()
        signature = crypto.sign(b"sanity-check", keypair.secret_key)
        valid = crypto.verify(b"sanity-check", signature.signature, keypair.public_key)
    except PQCUnavailableError as exc:
        raise SystemExit(f"PQC sanity check failed: {exc}")

    if not valid:
        raise SystemExit("PQC sanity check failed: signature verification returned False.")

    print("PQC sanity check passed: native backend available and hybrid sign/verify succeeded.")


if __name__ == "__main__":
    main()
