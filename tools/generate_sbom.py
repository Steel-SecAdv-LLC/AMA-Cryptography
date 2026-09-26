#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
# named library component to the SBOM consumer: every top-level TU whose
# capability is exposed through the public API (include/ama_cryptography.h)
# is a component; TUs that only support those capabilities belong in
# INTERNAL_SUPPORT below.  The split is enforced — render_sbom() refuses
# to run if a top-level src/c/*.c file is in neither set, so a new
# primitive cannot land without an SBOM decision (the eleven-entry list
# inherited from the old security.yml heredoc silently missed every
# primitive added after it: Ascon, FROST, agent binding, HSS/LMS, the
# NIST prime curves — closed out in the 3.5.0 release).  A PR that edits
# this list must also update the standards-alignment table in
# ``docs/compliance/CSRC_ALIGN_REPORT.md``.  Order is alphabetical so
# a diff between two SBOM revisions is easy to read.
# ---------------------------------------------------------------------------
C_COMPONENTS: list[tuple[str, str]] = [
    ("ama_aes_gcm", "AES-256-GCM AEAD (NIST SP 800-38D)"),
    ("ama_agent_binding", "Agent-instance key/signature binding (INVARIANT-30)"),
    ("ama_argon2", "Argon2id password hashing (RFC 9106)"),
    ("ama_ascon", "Ascon-AEAD128 AEAD and Ascon-Hash256 (NIST SP 800-232)"),
    ("ama_chacha20poly1305", "ChaCha20-Poly1305 AEAD (RFC 8439)"),
    ("ama_dilithium", "ML-DSA-44/-65/-87 post-quantum signatures (NIST FIPS 204)"),
    ("ama_ed25519", "Ed25519 digital signatures (RFC 8032)"),
    ("ama_frost", "FROST threshold Ed25519 signatures (RFC 9591-style)"),
    ("ama_hkdf", "HKDF-SHA3-256 key derivation (RFC 5869)"),
    ("ama_kyber", "ML-KEM-512/-768/-1024 key encapsulation (NIST FIPS 203)"),
    ("ama_lms", "HSS/LMS hash-based signature verification (RFC 8554)"),
    ("ama_nistp", "ECDSA and ECDH over NIST P-256/P-384/P-521 (FIPS 186-5; RFC 6979 nonces)"),
    ("ama_pbkdf2", "PBKDF2-HMAC-SHA256/512 key derivation (NIST SP 800-132)"),
    ("ama_secp256k1", "secp256k1 elliptic curve operations"),
    ("ama_sha3", "SHA3-256/384/512, SHAKE128/256 (NIST FIPS 202)"),
    ("ama_sha512", "SHA-512/SHA-384 one-shot hashing (NIST FIPS 180-4)"),
    ("ama_slhdsa", "SLH-DSA-SHA2-256f + SHAKE-128s (NIST FIPS 205); legacy ama_sphincs_* API"),
    ("ama_x25519", "X25519 ECDH key exchange (RFC 7748)"),
]

# Top-level src/c TUs that implement or support the components above but
# publish no capability of their own through include/ama_cryptography.h.
# Every top-level src/c/*.c stem must appear in exactly one of the two
# sets; render_sbom() enforces the partition.
INTERNAL_SUPPORT: frozenset[str] = frozenset(
    {
        "ama_aes_bitsliced",  # constant-time AES backend of ama_aes_gcm
        "ama_consttime",  # constant-time comparison/select helpers
        "ama_core",  # library init / self-test plumbing
        "ama_cpuid",  # CPU feature detection for dispatch
        "ama_hmac_sha256",  # internal HMAC used by LMS / NIST-P paths
        "ama_hmac_sha384",  # internal HMAC used by RFC 6979 (P-384)
        "ama_platform_rand",  # OS CSPRNG shim
        "ama_secure_memory",  # zeroization / locked-memory helpers
        "ama_sha256",  # internal SHA-256 backing LMS / NIST-P / HMAC
        "ama_sha256_ni",  # SHA-NI accelerated SHA-256 backend
    }
)


# ---------------------------------------------------------------------------
# Adapted third-party source (CycloneDX pedigree)
#
# NOTICE lists source that is compiled into the library and ADAPTED from a
# third-party implementation under that implementation's licence.  Until
# this registry existed the SBOM recorded none of it: ama_ed25519 was
# rendered as an in-house Apache-2.0 component while NOTICE carried an MIT
# attribution for the safegcd inversion it compiles in, and the README and
# the INVARIANT-1 addendum told a licence reviewer there was no third-party
# code at all.  A downstream redistributor reading the SBOM or those pages
# would have shipped binaries without the MIT notice NOTICE says applies.
#
# The registry is checked three ways, so it cannot drift from the tree:
#   * every src/c or include/ file whose comments say "see NOTICE" must be
#     registered here (a new adaptation cannot land unrecorded);
#   * every registered file must exist and still say "see NOTICE";
#   * NOTICE must name every registered file and its licence, and the
#     component it is attributed to must be a C_COMPONENTS entry.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdaptedSource:
    """One compiled-in file adapted from a third-party implementation."""

    component: str  # the C_COMPONENTS entry that compiles it in
    licence: str  # SPDX identifier of the upstream licence
    upstream_name: str
    upstream_supplier: str
    upstream_purl: str
    upstream_file: str  # the upstream file its structure follows
    what: str  # one line: what was adapted


ADAPTED_SOURCES: dict[str, AdaptedSource] = {
    "src/c/internal/ama_fe25519_safegcd.h": AdaptedSource(
        component="ama_ed25519",
        licence="MIT",
        upstream_name="secp256k1",
        upstream_supplier="The Bitcoin Core developers",
        upstream_purl="pkg:github/bitcoin-core/secp256k1",
        upstream_file="src/modinv64_impl.h",
        what=(
            "Constant-time inversion modulo 2^255 - 19 (Bernstein-Yang safegcd, "
            "batched 62-bit divsteps); its structure follows libsecp256k1's "
            "modinv64 reference implementation."
        ),
    ),
}

#: A comment that points the reader at NOTICE for this file's licence.  Comment
#: leaders (``*``, ``//``) and line breaks between the words are tolerated, as
#: in the safegcd header's "MIT licence — see\n * NOTICE".
_SEE_NOTICE = re.compile(r"\bsee(?:[\s*/]|\\)+NOTICE\b")


def _cites_notice(text: str) -> bool:
    return bool(_SEE_NOTICE.search(text))


def check_adapted_sources(repo: Path = REPO) -> list[str]:
    """Problems with the adapted-source registry; empty when it holds."""
    problems: list[str] = []
    citing: set[str] = set()
    for root in ("src/c", "include"):
        base = repo / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".c", ".h", ".S", ".s", ".asm") or not path.is_file():
                continue
            if _cites_notice(path.read_text(encoding="utf-8", errors="replace")):
                citing.add(path.relative_to(repo).as_posix())
    for name in sorted(citing - set(ADAPTED_SOURCES)):
        problems.append(
            f"{name} cites NOTICE for its licence but is not in ADAPTED_SOURCES, so "
            "the SBOM carries no pedigree or licence for it"
        )
    notice_path = repo / "NOTICE"
    notice = notice_path.read_text(encoding="utf-8") if notice_path.is_file() else ""
    components = {name for name, _ in C_COMPONENTS}
    for name, adapted in sorted(ADAPTED_SOURCES.items()):
        if name not in citing:
            problems.append(
                f"ADAPTED_SOURCES lists {name}, which does not exist or no longer cites "
                "NOTICE; remove the entry or restore the attribution"
            )
        if name not in notice:
            problems.append(f"NOTICE does not name {name}")
        if not re.search(rf"\b{re.escape(adapted.licence)}\b", notice):
            problems.append(f"NOTICE does not state the {adapted.licence} licence for {name}")
        if adapted.component not in components:
            problems.append(
                f"ADAPTED_SOURCES attributes {name} to {adapted.component!r}, which is "
                "not a C_COMPONENTS entry"
            )
    return problems


def _component_record(name: str, description: str, version: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "description": description,
        "scope": "required",
        "purl": f"pkg:generic/{name}@{version}",
    }
    adapted = {path: a for path, a in sorted(ADAPTED_SOURCES.items()) if a.component == name}
    if adapted:
        licences = sorted({"Apache-2.0", *(a.licence for a in adapted.values())})
        record["licenses"] = [{"expression": " AND ".join(licences)}]
        record["pedigree"] = {
            "ancestors": [
                {
                    "type": "library",
                    "name": a.upstream_name,
                    "supplier": {"name": a.upstream_supplier},
                    "purl": a.upstream_purl,
                    "licenses": [{"license": {"id": a.licence}}],
                    "description": f"{a.upstream_file}: the reference {path} adapts",
                }
                for path, a in adapted.items()
            ],
            "notes": " ".join(
                f"{path} is adapted source ({a.licence}, attributed in NOTICE): {a.what}"
                for path, a in adapted.items()
            ),
        }
    return record


def check_component_completeness() -> None:
    """Fail closed if src/c grows a TU the SBOM has not classified.

    Scans top-level ``src/c/*.c`` (subdirectories — dispatch/, SIMD
    kernels, x86/ — are implementation detail of the top-level TUs)
    and requires every stem to be either a named component or an entry
    in INTERNAL_SUPPORT.  Runs in both generate and --check mode, so CI
    rejects a new primitive whose SBOM classification was forgotten —
    the failure mode that let Ascon, FROST, agent binding, HSS/LMS and
    the NIST prime curves ship unlisted between 3.4.0 and 3.5.0.
    """
    # The manifest comment says "Order is alphabetical so a diff between two
    # SBOM revisions is easy to read", and `render_sbom()` emits the list in
    # list order without sorting.  Nothing checked it, and the list was not
    # sorted: `ama_pbkdf2` sat after `ama_secp256k1`, and the committed
    # docs/compliance/sbom-c-library.json carried the same misordering.  A
    # documented convention nothing enforces is a convention that drifts.
    ordered = [name for name, _ in C_COMPONENTS]
    if ordered != sorted(ordered):
        first = next((a, b) for a, b in zip(ordered, sorted(ordered), strict=True) if a != b)
        raise SystemExit(
            "ERROR: tools/generate_sbom.py: C_COMPONENTS is not in alphabetical "
            f"order, which the manifest comment promises. First difference: "
            f"{first[0]!r} where {first[1]!r} was expected."
        )

    component_names = {name for name, _ in C_COMPONENTS}
    overlap = component_names & INTERNAL_SUPPORT
    if overlap:
        raise SystemExit(
            "ERROR: tools/generate_sbom.py: listed as both component and "
            f"internal support: {sorted(overlap)}"
        )
    on_disk = {p.stem for p in (REPO / "src" / "c").glob("*.c")}
    unclassified = on_disk - component_names - INTERNAL_SUPPORT
    missing = (component_names | INTERNAL_SUPPORT) - on_disk
    problems = []
    if unclassified:
        problems.append(
            f"src/c TU(s) with no SBOM classification: {sorted(unclassified)} "
            "— add each to C_COMPONENTS (public capability) or "
            "INTERNAL_SUPPORT (supporting TU) in tools/generate_sbom.py"
        )
    if missing:
        problems.append(
            f"SBOM entries with no src/c TU on disk: {sorted(missing)} "
            "— remove them or restore the source file"
        )
    if problems:
        raise SystemExit("ERROR: tools/generate_sbom.py: " + "; ".join(problems))


def read_package_version() -> str:
    """Read the project version from pyproject.toml.

    Hand-rolled TOML parsing (no `tomllib` dependency on the Python 3.10
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


def render_sbom(version: str) -> dict[str, Any]:
    """Render the C-library SBOM as a CycloneDX 1.5 JSON document.

    The ``serialNumber`` is a deterministic UUID5 derived from the
    version so two SBOM regenerations against the same input produce
    byte-identical output.  This is what makes the CI ``--check`` mode
    able to compare with a committed artefact without managing a
    rolling cache of random UUIDs.
    """
    check_component_completeness()
    adapted_problems = check_adapted_sources()
    if adapted_problems:
        raise SystemExit("ERROR: tools/generate_sbom.py: " + "; ".join(adapted_problems))

    deterministic_namespace = uuid.UUID("c1c7d2bc-1c1f-4e29-9b5a-c3a7e1f4b8d2")
    serial_uuid = uuid.uuid5(deterministic_namespace, f"ama-cryptography-c-library@{version}")

    components = [
        _component_record(name, description, version) for name, description in C_COMPONENTS
    ]

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


def serialize(doc: dict[str, Any]) -> str:
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
