#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-1 Addendum: every shipping primitive maps to a registry entry.

CSRC_STANDARDS.md opens with an exhaustiveness claim::

    This document maps every cryptographic primitive implemented in AMA
    Cryptography to its governing standard, parameter set, and authoritative
    source URL. Only algorithms with shipping code are listed — no aspirational
    entries.

and INVARIANTS.md makes it binding: "All cryptographic primitives implemented in
this library **must** map to a non-deprecated entry in CSRC_STANDARDS.md. Adding
any new algorithm requires updating CSRC_STANDARDS.md ... **before**
implementation is permitted."

Nothing checked it.  Run against CSRC_STANDARDS.md as it stood before this pass,
this gate reports **18** violations: NIST P-256/P-384/P-521 ECDSA and ECDH
(FIPS 186-5 and SP 800-56A rev. 3 both uncited), LMS and HSS verification
(SP 800-208), ML-KEM-512, ML-KEM-768, ML-DSA-44, ML-DSA-87, SLH-DSA-SHAKE-128s,
HMAC-SHA-384, HMAC-SHA-512 and HMAC-SHA3-256 — all shipping code, in a document
whose first paragraph says it lists all of it.  The same branch had added five
other rows, so the rule was known and still not met, which is what a rule with
no gate looks like.

The last three of those are the reason for the parameter-set level described
below: a family-level check saw ``ama_hmac_*`` cite FIPS 198-1 through the
HMAC-SHA-256 row and reported the family covered, while three further HMAC
constructions shipped with no row at all.

HOW IT WORKS
============

Two levels, because a family-level check alone is too coarse to see what the
audit actually found.

**Families.** DISCOVERED from ``include/ama_cryptography.h``: every ``AMA_API``
prototype contributes its ``ama_<family>_...`` prefix.  Each family must appear
in :data:`FAMILY_REGISTRY_TOKENS` — a family the mapping does not know fails,
which is exactly the "update CSRC_STANDARDS.md before implementation" rule
expressed as a check — and each mapped token must be findable somewhere in
CSRC_STANDARDS.md's tables.

**Parameter sets.** A family-level token is satisfied by ONE row, so
``ama_ml_dsa_*`` mapping to "ML-DSA-65" said nothing about ML-DSA-44 and
ML-DSA-87, and ``ama_hmac_*`` mapping to "FIPS 198-1" said nothing about
HMAC-SHA-384 — three of the entries the audit found missing, invisible to the
coarse check.  So the parameter sets are discovered too: from the enumerators
of the header's parameter-set enums (``AMA_ML_DSA_*``, ``AMA_ML_KEM_*``,
``AMA_SLHDSA_*``, ``AMA_NIST_CURVE_*``) and from the ``ama_hmac_<hash>``
prototypes, each of which must map to a token in :data:`PARAM_SET_TOKENS` and
appear in the **Algorithm column** of a registry row.

The Algorithm column, not the whole row, because the whole row is too
permissive here: "PBKDF2 with HMAC-SHA-512 PRF" in the parameter-set cell of
the PBKDF2 row would otherwise satisfy a check for a shipping HMAC-SHA-512
primitive that has no row of its own.

Both mappings are hand-written because the registry key ("ML-KEM-1024") and the
symbol prefix (``ama_kyber_``) are different names for the same thing and no
derivation connects them.  What they are NOT is a hand-maintained list of what
ships: that half is discovered at both levels, so neither a new family nor a
new parameter set can be quietly omitted from the registry or from this file.

Exit codes
----------
* 0 — every discovered family and parameter set maps to a registry entry.
* 1 — a family or parameter set is unmapped, or a mapped token is absent from
  the registry, or the scan found nothing (fail-closed).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

HEADER = "include/ama_cryptography.h"
REGISTRY = "CSRC_STANDARDS.md"

#: ``AMA_API <return type> ama_<family>_<rest>(`` — the shipped C surface.
_PROTOTYPE_RE = re.compile(r"^AMA_API\s+[A-Za-z_][\w \t*]*\bama_(?P<symbol>[a-z0-9_]+)\s*\(", re.M)

#: Family prefix -> the string(s) that must appear in CSRC_STANDARDS.md.
#:
#: A tuple means the family spans more than one governing publication and each
#: must be present: ``ama_nistp_*`` implements ECDSA (FIPS 186-5) *and* ECDH
#: (SP 800-56A rev. 3), and a registry that cites only the first describes half
#: the family.
#:
#: ``None`` means the family is deliberately not a registry entry, with the
#: reason in the comment beside it.  Those are support surfaces, not
#: primitives; a primitive can never be ``None``.
FAMILY_REGISTRY_TOKENS: dict[str, str | tuple[str, ...] | None] = {
    "sha3": "FIPS 202",
    "shake128": "SHAKE128",
    "shake256": "SHAKE256",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "hmac": "FIPS 198-1",
    "pbkdf2": "NIST SP 800-132",
    "hkdf": "RFC 5869",
    "argon2id": "RFC 9106",
    "aes256": "NIST SP 800-38D",
    "aes": "NIST SP 800-38D",
    "chacha20poly1305": "RFC 8439",
    "ascon": "NIST SP 800-232",
    "kyber": "ML-KEM-1024",
    "ml": "ML-KEM-512",  # ama_ml_kem_* / ama_ml_dsa_* parameter-set API
    "kem": "ML-KEM-768",
    "dilithium": "ML-DSA-65",
    "sphincs": "SLH-DSA-SHA2-256f",
    "slhdsa": "SLH-DSA-SHAKE-128s",
    "lms": "NIST SP 800-208",
    "hss": "NIST SP 800-208",
    "ed25519": "RFC 8032",
    "x25519": "RFC 7748",
    "secp256k1": "SEC 2 v2",
    "nistp": ("FIPS 186-5", "NIST SP 800-56A"),  # ECDSA and ECDH, two publications
    "frost": "RFC 9591",
    # Support surfaces: no algorithm of their own.
    "version": None,  # library version accessors
    "secure": None,  # secure_memory / secure_zero helpers
    "consttime": None,  # constant-time comparison primitives
    "agent": None,  # agent-binding envelope over the primitives above
    "context": None,  # AmaContext lifecycle
    "integrity": None,  # build-time integrity accessors
    "keypair": None,  # generic keypair helper over the families above
    "sign": None,  # generic dispatch wrapper
    "verify": None,  # generic dispatch wrapper
}

#: Enumerators of the header's parameter-set enums.  These are what makes the
#: check granular: the family ``ama_ml_dsa_*`` is one prefix, but it ships three
#: parameter sets and the registry claims to list every one.
_PARAM_ENUM_RE = re.compile(
    r"^\s*(?P<name>AMA_(?:ML_DSA|ML_KEM|SLHDSA|NIST_CURVE)_[A-Z0-9_]+)\s*=", re.M
)

#: ``AMA_API ... ama_hmac_<hash>(`` — HMAC is the one family whose variants are
#: distinguished by SYMBOL rather than by an enum, so it is discovered here.
_HMAC_PROTOTYPE_RE = re.compile(
    r"^AMA_API\s+[A-Za-z_][\w \t*]*\bama_hmac_(?P<hash>[a-z0-9_]+)\s*\(", re.M
)

#: Discovered parameter-set identifier -> the string that must appear in the
#: **Algorithm column** of a CSRC_STANDARDS.md row.  Same discipline as
#: :data:`FAMILY_REGISTRY_TOKENS`: what ships is discovered, only the naming is
#: written down, and an identifier this mapping does not know is a failure.
PARAM_SET_TOKENS: dict[str, str] = {
    "AMA_ML_DSA_44": "ML-DSA-44",
    "AMA_ML_DSA_65": "ML-DSA-65",
    "AMA_ML_DSA_87": "ML-DSA-87",
    "AMA_ML_KEM_512": "ML-KEM-512",
    "AMA_ML_KEM_768": "ML-KEM-768",
    "AMA_ML_KEM_1024": "ML-KEM-1024",
    # FIPS 205 names the instantiation "SLH-DSA-SHA2-256f-simple"; the registry
    # row and the rest of the tree use the parameter-set name without the
    # instantiation suffix, which is the string a reader looks for.
    "AMA_SLHDSA_SHA2_256F": "SLH-DSA-SHA2-256f",
    "AMA_SLHDSA_SHAKE_128S": "SLH-DSA-SHAKE-128s",
    "AMA_NIST_CURVE_P256": "P-256",
    "AMA_NIST_CURVE_P384": "P-384",
    "AMA_NIST_CURVE_P521": "P-521",
    # HMAC variants, keyed by the symbol suffix rather than an enumerator.
    "ama_hmac_sha384": "HMAC-SHA-384",
    "ama_hmac_sha512": "HMAC-SHA-512",
    "ama_hmac_sha3_256": "HMAC-SHA3-256",
}

#: A registry with fewer rows than this has broken, not shrunk.
MIN_REGISTRY_ROWS = 30

#: Fewer families than this means the header scan has broken.
MIN_FAMILIES = 20

#: Fewer parameter sets than this means the enum scan has broken.  Eleven
#: enumerators plus three HMAC prototypes ship today.
MIN_PARAM_SETS = 12


def discovered_families(header: Path) -> set[str]:
    """Every ``ama_<family>_`` prefix that carries an ``AMA_API`` prototype."""
    text = header.read_text(encoding="utf-8")
    return {match.group("symbol").split("_", 1)[0] for match in _PROTOTYPE_RE.finditer(text)}


def discovered_parameter_sets(header: Path) -> set[str]:
    """Every shipping parameter set, by the identifier that declares it.

    Two sources, because the header declares them two ways: the enumerators of
    the parameter-set enums (``AMA_ML_KEM_512`` and friends) and the
    ``ama_hmac_<hash>`` prototypes, HMAC being the family whose variants are
    separate symbols rather than one symbol taking an enum.
    """
    text = header.read_text(encoding="utf-8")
    found = {match.group("name") for match in _PARAM_ENUM_RE.finditer(text)}
    found |= {f"ama_hmac_{match.group('hash')}" for match in _HMAC_PROTOTYPE_RE.finditer(text)}
    return found


def registry_rows(registry: Path) -> list[str]:
    """Every table row of CSRC_STANDARDS.md's algorithm tables."""
    return [
        line
        for line in registry.read_text(encoding="utf-8").splitlines()
        if line.startswith("| ") and not line.startswith("| ---") and "|---" not in line
    ]


def registry_algorithm_cells(rows: list[str]) -> list[str]:
    """The first cell of each row — the Algorithm column.

    The parameter-set check reads this rather than the whole row.  A row's
    later cells describe the entry ("PBKDF2 with HMAC-SHA-512 PRF"), and
    matching against them would let one algorithm's prose stand in for another
    algorithm's missing row.
    """
    cells = []
    for row in rows:
        parts = row.split("|")
        cells.append(parts[1].strip() if len(parts) > 1 else "")
    return cells


def audit(root: Path = REPO) -> list[str]:
    problems: list[str] = []
    header = root / HEADER
    registry = root / REGISTRY
    if not header.is_file() or not registry.is_file():
        return [f"{HEADER} or {REGISTRY} is missing; the scan has no scope"]

    families = discovered_families(header)
    if len(families) < MIN_FAMILIES:
        return [
            f"discovered only {len(families)} primitive families in {HEADER} "
            f"(expected at least {MIN_FAMILIES}) — a collapsed scan, not a clean tree"
        ]

    param_sets = discovered_parameter_sets(header)
    if len(param_sets) < MIN_PARAM_SETS:
        return [
            f"discovered only {len(param_sets)} parameter sets in {HEADER} "
            f"(expected at least {MIN_PARAM_SETS}) — a collapsed scan, not a clean tree"
        ]

    rows = registry_rows(registry)
    if len(rows) < MIN_REGISTRY_ROWS:
        return [
            f"{REGISTRY} has only {len(rows)} table row(s) (expected at least "
            f"{MIN_REGISTRY_ROWS}) — refusing to check against a registry that "
            f"looks truncated"
        ]
    joined = "\n".join(rows)
    algorithm_cells = registry_algorithm_cells(rows)

    for family in sorted(families):
        if family not in FAMILY_REGISTRY_TOKENS:
            problems.append(
                f"{HEADER}: family 'ama_{family}_*' has shipping AMA_API prototypes "
                f"but no entry in FAMILY_REGISTRY_TOKENS. INVARIANT-1's Algorithm "
                f"Registry addendum requires {REGISTRY} to be updated BEFORE the "
                f"implementation lands; add the row there and the mapping here."
            )
            continue
        mapped = FAMILY_REGISTRY_TOKENS[family]
        if mapped is None:
            continue
        tokens = (mapped,) if isinstance(mapped, str) else mapped
        for token in tokens:
            if token not in joined:
                problems.append(
                    f"{REGISTRY}: no row mentions {token!r}, which family "
                    f"'ama_{family}_*' maps to. The document's own first paragraph "
                    f"says it lists every implemented primitive."
                )

    for identifier in sorted(param_sets):
        if identifier not in PARAM_SET_TOKENS:
            problems.append(
                f"{HEADER}: parameter set {identifier!r} ships but has no entry in "
                f"PARAM_SET_TOKENS. INVARIANT-1's Algorithm Registry addendum "
                f"requires {REGISTRY} to be updated BEFORE the implementation "
                f"lands; add the row there and the mapping here."
            )
            continue
        token = PARAM_SET_TOKENS[identifier]
        if not any(token in cell for cell in algorithm_cells):
            problems.append(
                f"{REGISTRY}: no row's Algorithm column names {token!r}, the "
                f"parameter set {identifier} ships. A family-level citation is "
                f"not enough: the document says it maps every primitive to its "
                f"parameter set."
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(REPO))
    args = parser.parse_args(argv)
    root = Path(args.root)

    problems = audit(root)
    if problems:
        print(
            "INVARIANT-1 Addendum violation — the algorithm registry is incomplete:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    families = discovered_families(root / HEADER)
    param_sets = discovered_parameter_sets(root / HEADER)
    mapped = sum(1 for f in families if FAMILY_REGISTRY_TOKENS.get(f) is not None)
    print(
        f"OK: {len(families)} primitive families in {HEADER}; {mapped} map to a "
        f"{REGISTRY} entry and {len(families) - mapped} are declared support "
        f"surfaces. {len(param_sets)} parameter sets each map to a named row."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
