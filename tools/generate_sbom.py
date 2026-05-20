#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0

"""Generate the AMA Cryptography C-library CycloneDX SBOM from a single
source of truth.

INVARIANT-11 declares the SBOM as the release gate.  Before this script
existed, ``.github/workflows/security.yml`` shipped the C-library
components as a hardcoded heredoc with ``"version": "3.0.0"`` baked in,
even when ``pyproject.toml`` had bumped to 3.1.0.  Drift on day one.

This generator reads the package version from ``pyproject.toml`` once
and renders every C-library component pinned to that version.  CI then
asserts via ``--check`` that the rendered output matches a committed
copy at ``docs/compliance/sbom-c-library.json``.  Any version-bump PR
that forgets to regenerate the SBOM fails CI before the artefact can
ship to PyPI.

Exit codes:
    0  generated (or, with --check, the on-disk copy matches)
    1  drift detected with --check, OR a structural error

Usage:
    Regenerate:           python tools/generate_sbom.py
    CI assertion:         python tools/generate_sbom.py --check
    Explicit output path: python tools/generate_sbom.py --output PATH
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO / "docs" / "compliance" / "sbom-c-library.json"


# ---------------------------------------------------------------------------
# C-library component manifest
#
# Each row is (component_name, description) — the version field is driven
# entirely by pyproject.toml at render time so a release bump cannot
# leave a stale `"version": "X.Y.Z"` baked into the artefact.
#
# Keep this list in sync with the C sources under src/c/ that publish a
# named library component to the SBOM consumer.  The eleven entries
# below were inherited unchanged from the previous hardcoded heredoc
# in security.yml; the only PR-level edits to this list should land
# alongside a new C primitive (or the removal of one), and that PR
# must also update the dependency graph in
# ``docs/compliance/CSRC_ALIGN_REPORT.md``.  Order is alphabetical so
# a diff between two SBOM revisions is easy to read.
# ---------------------------------------------------------------------------
C_COMPONENTS: list[tuple[str, str]] = [
    ("ama_aes_gcm", "AES-256-GCM AEAD (NIST SP 800-38D)"),
    ("ama_argon2", "Argon2id password hashing (RFC 9106)"),
    ("ama_chacha20poly1305", "ChaCha20-Poly1305 AEAD (RFC 8439)"),
    ("ama_dilithium", "ML-DSA-65 post-quantum signatures (NIST FIPS 204)"),
    ("ama_ed25519", "Ed25519 digital signatures (RFC 8032)"),
    ("ama_hkdf", "HKDF-SHA3-256 key derivation (RFC 5869)"),
    ("ama_kyber", "Kyber-1024 ML-KEM (NIST FIPS 203)"),
    ("ama_secp256k1", "secp256k1 elliptic curve operations"),
    ("ama_sha3", "SHA3-256/512, SHAKE128/256 (NIST FIPS 202)"),
    ("ama_sphincs", "SPHINCS+-256f SLH-DSA (NIST FIPS 205)"),
    ("ama_x25519", "X25519 ECDH key exchange (RFC 7748)"),
]


def read_package_version() -> str:
    """Read the project version from pyproject.toml.

    Hand-rolled TOML parsing (no `tomllib` dependency on the Python 3.9
    end of the matrix).  The pattern anchors ``^version = "X.Y.Z"`` at
    line start so the ``project.version`` field is the only thing that
    can match — a ``dependencies = [...]`` block that happened to
    contain a quoted version string can't.
    """
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    if match is None:
        raise SystemExit(
            "ERROR: tools/generate_sbom.py: could not locate "
            '`version = "..."` in pyproject.toml [project] block'
        )
    return match.group(1)


def render_sbom(version: str) -> dict:
    """Render the C-library SBOM as a CycloneDX 1.5 JSON document.

    The ``serialNumber`` is a deterministic UUID5 derived from the
    version so two SBOM regenerations against the same input produce
    byte-identical output.  This is what makes the CI ``--check`` mode
    able to compare with a committed artefact without managing a
    rolling cache of random UUIDs.
    """
    deterministic_namespace = uuid.UUID("c1c7d2bc-1c1f-4e29-9b5a-c3a7e1f4b8d2")
    serial_uuid = uuid.uuid5(deterministic_namespace, f"ama-cryptography-c-library@{version}")

    components = []
    for name, description in C_COMPONENTS:
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "description": description,
                "scope": "required",
                "purl": f"pkg:generic/{name}@{version}",
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "ama-cryptography",
                "version": version,
                "description": "Quantum-resistant cryptographic protection system",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "supplier": {"name": "Steel Security Advisors LLC"},
            }
        },
        "components": components,
        "dependencies": [],
    }


def serialize(doc: dict) -> str:
    """Render the SBOM with stable formatting so the CI --check is byte-exact."""
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output path (default: {DEFAULT_OUTPUT.relative_to(REPO)})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Render the SBOM in memory and compare it to the existing "
            "file on disk; exit 1 on drift.  Used by CI to assert that "
            "pyproject.toml's version matches the committed SBOM."
        ),
    )
    args = parser.parse_args()

    version = read_package_version()
    doc = render_sbom(version)
    rendered = serialize(doc)

    if args.check:
        if not args.output.exists():
            print(
                f"ERROR: --check expected an existing SBOM at {args.output} "
                f"(rendered from pyproject.toml version={version!r}); "
                "rerun tools/generate_sbom.py and commit the result.",
                file=sys.stderr,
            )
            return 1
        existing = args.output.read_text(encoding="utf-8")
        if existing != rendered:
            print(
                f"ERROR: SBOM drift detected at {args.output}.\n"
                f"Package version (pyproject.toml): {version!r}\n"
                "Rerun: python tools/generate_sbom.py\n"
                "Commit the regenerated artefact.\n",
                file=sys.stderr,
            )
            return 1
        print(f"OK: SBOM matches pyproject.toml version {version!r}")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {args.output} (version={version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
