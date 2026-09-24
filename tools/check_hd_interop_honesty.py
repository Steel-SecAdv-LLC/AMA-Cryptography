#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-16 for the HD key-derivation claim: BIP32-style, not BIP32-compatible.

The fact this gate protects
---------------------------
``ama_cryptography/key_management.py`` derives its master key with

    HMAC-SHA512(key=b"AMA Cryptography Master Key", msg=seed)

where BIP32 specifies ``b"Bitcoin seed"``.  The CHILD key derivation follows
BIP32's formulae exactly, but every key in the tree descends from a different
root, so — in the source file's own words — *no BIP32 test vector can pass
here and no BIP32 wallet or library derives the same keys from the same seed*.

"Compatible" and "compliant" are therefore false.  "Style" is true.  The
distinction is not pedantry: a reader who believes the former will hand this
library a seed phrase and expect their wallet's addresses back.

Why a gate and not just a correction
------------------------------------
This defect has already been found and corrected once.  ``CHANGELOG.md``
records it as **KM-HD-001**:

    `HDKeyDerivation` was documented "BIP32-compliant" while its master key
    uses the HMAC key `"AMA Cryptography Master Key"` where BIP32 specifies
    `"Bitcoin seed"`, so no BIP32 wallet derives these keys.

That correction shipped with no gate behind it, and six sites across
``wiki/`` , ``CRYPTOGRAPHY.md`` and ``CSRC_STANDARDS.md`` still carried the
false claim afterwards.  A correction without a gate is a correction that
comes back.

What fails
----------
Any documentation file claiming BIP32 compatibility, compliance,
interoperability or conformance — and, separately, any row of
``CSRC_STANDARDS.md``'s conformance table that names BIP-32 in its Standard
column.

The second rule exists because the first does not catch it.  That row read

    | secp256k1 | SEC 2 v2 / BIP-32 | ... | Used for BIP-32 HD key derivation |

which contains no "compatible" and no "compliant", yet asserts conformance
more strongly than either: it is a standards-conformance table, and the
Standard column is the claim.  Prose rules do not catch structured claims.

``CHANGELOG.md`` and the development journals under ``docs/changelog/`` are
exempt: they are the historical record (``tools/_repo.py``'s
``is_historical_record``), and KM-HD-001's own entry necessarily quotes the
wording it retired.

Exit status
-----------
0  no false compatibility claim
1  at least one file claims BIP32 compatibility
2  the check could not run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Documentation trees to scan.
SCAN_ROOTS: tuple[str, ...] = ("", "wiki", "docs")

SCAN_SUFFIXES: frozenset[str] = frozenset({".md", ".rst", ".txt"})


def _is_historical_record(relative: str) -> bool:
    """CHANGELOG.md and ``docs/changelog/``: history, including KM-HD-001's wording.

    Excluding the historical record is what lets the gate be strict everywhere
    else.  Which files that is has one definition, in ``tools/_repo.py``.
    """
    root = str(Path(__file__).resolve().parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    from tools._repo import is_historical_record

    return is_historical_record(relative)


EXCLUDED_DIRS: frozenset[str] = frozenset(
    {".git", "build", "dist", "node_modules", "__pycache__", ".venv", "venv"}
)

#: Each pattern is a claim of INTEROPERABILITY, which is the false part.
#: "BIP32-style", "BIP32's formulae", "BIP32-standard HMAC-SHA-512" and
#: "BIP32 path" are all accurate and must keep passing.
BANNED: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"BIP[- ]?32[- ]?compatible", re.IGNORECASE),
        'BIP32 "compatible" — the master key uses a different HMAC key, so no '
        "BIP32 wallet derives these keys. Say BIP32-style.",
    ),
    (
        re.compile(r"BIP[- ]?32[- ]?complian(?:t|ce)", re.IGNORECASE),
        'BIP32 "compliance" — the derived tree does not match BIP32. ' "Say BIP32-style.",
    ),
    (
        re.compile(r"BIP[- ]?32[- ]?interoperab", re.IGNORECASE),
        "BIP32 interoperability is exactly what this implementation does NOT " "have.",
    ),
    (
        re.compile(r"conforms?\s+to\s+BIP[- ]?32", re.IGNORECASE),
        "conformance to BIP32 is not claimable: the master derivation differs.",
    ),
)

#: A line that states the NEGATIVE is the correct wording and must not be
#: flagged when it quotes the banned phrase in order to deny it.
NEGATION_CUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bnot\b[^.]{0,80}(compatible|compliant|interoperab)", re.IGNORECASE),
    re.compile(r"(compatible|compliant|interoperab)[^.]{0,40}\bnot\b", re.IGNORECASE),
    re.compile(r"\bwas documented\b", re.IGNORECASE),
    re.compile(r"\bdeliberately\b", re.IGNORECASE),
    re.compile(r"\bno longer\b", re.IGNORECASE),
)


#: The conformance table whose Standard column IS the claim.
STANDARDS_TABLE = "CSRC_STANDARDS.md"

#: A markdown table row: | algorithm | standard | params | notes |
_TABLE_ROW = re.compile(r"^\s*\|(?P<algorithm>[^|]+)\|(?P<standard>[^|]+)\|")

_BIP32_TOKEN = re.compile(r"BIP[- ]?32", re.IGNORECASE)


def find_standards_table_claims(repo: Path = REPO) -> list[tuple[str, int, str, str]]:
    """Rows of the conformance table that name BIP-32 as a standard met."""
    path = repo / STANDARDS_TABLE
    if not path.is_file():
        return []
    findings: list[tuple[str, int, str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = _TABLE_ROW.match(line)
        if not match:
            continue
        if _BIP32_TOKEN.search(match.group("standard")):
            findings.append(
                (
                    STANDARDS_TABLE,
                    number,
                    line.strip(),
                    "BIP-32 appears in the Standard column of a conformance "
                    "table. The master derivation does not follow BIP-32, so "
                    "this row claims conformance the implementation does not "
                    "have. Name the standard it does meet (SEC 2 v2) and "
                    "describe the BIP-32 relationship in the notes column.",
                )
            )
    return findings


def _is_negated(line: str) -> bool:
    return any(cue.search(line) for cue in NEGATION_CUES)


def scanned_files(repo: Path = REPO) -> list[Path]:
    seen: set[Path] = set()
    for root in SCAN_ROOTS:
        base = repo / root if root else repo
        if not base.is_dir():
            continue
        candidates = base.rglob("*") if root else base.glob("*")
        for path in candidates:
            if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
                continue
            if any(part in EXCLUDED_DIRS for part in path.relative_to(repo).parts):
                continue
            if _is_historical_record(path.relative_to(repo).as_posix()):
                continue
            seen.add(path)
    return sorted(seen)


def find_claims(repo: Path = REPO) -> list[tuple[str, int, str, str]]:
    """Every false BIP32 compatibility claim: (file, line number, text, why)."""
    findings: list[tuple[str, int, str, str]] = []
    for path in scanned_files(repo):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if _is_negated(line):
                continue
            for pattern, why in BANNED:
                if pattern.search(line):
                    findings.append((path.relative_to(repo).as_posix(), number, line.strip(), why))
                    break
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    args = parser.parse_args(argv)

    if not (args.repo / "ama_cryptography" / "key_management.py").is_file():
        print(
            f"FATAL: {args.repo} does not look like the repository root.",
            file=sys.stderr,
        )
        return 2

    files = scanned_files(args.repo)
    if not files:
        print("FATAL: no documentation files were scanned.", file=sys.stderr)
        return 2

    findings = find_claims(args.repo) + find_standards_table_claims(args.repo)
    if findings:
        print(
            f"HD INTEROPERABILITY HONESTY CHECK FAILED — {len(findings)} " f"false claim(s):",
            file=sys.stderr,
        )
        for relative, number, line, why in findings:
            print(f"  {relative}:{number}", file=sys.stderr)
            print(f"      {line[:140]}", file=sys.stderr)
            print(f"      -> {why}", file=sys.stderr)
        print(
            "\nThe child KDF follows BIP32; the MASTER key does not. "
            "ama_cryptography/key_management.py states it plainly: no BIP32 "
            "test vector passes here and no BIP32 wallet derives the same keys "
            "from the same seed. This was already corrected once as KM-HD-001 "
            "and came back because nothing gated it.",
            file=sys.stderr,
        )
        return 1

    print(f"OK    {len(files)} documentation file(s); no false BIP32 compatibility claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
