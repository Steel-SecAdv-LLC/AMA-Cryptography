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

What is scanned
---------------
Every ``.md`` / ``.rst`` / ``.txt`` file git tracks, at any depth, and the
docstrings, string literals and comments of every Python source under
``ama_cryptography/``.

The scan used to be ``.md``/``.rst``/``.txt`` in three places — the root
(non-recursively), ``wiki/`` and ``docs/`` — so it never read a Python file
at all.  KM-HD-001's wording lived in exactly such a file: the
``HDKeyDerivation`` docstrings in ``ama_cryptography/key_management.py``
("Hierarchical Deterministic Key Derivation (BIP32-compliant)", "Child Key
Derivation (Private) - BIP32 Compliant"), which Sphinx autodoc publishes.
Restoring either one passed this gate.  A README under ``examples/`` or
``benchmarks/`` was not read either.

Each line is also judged joined to the next, so a phrase a wrap splits
("... is BIP32" / "compatible ...") is still one phrase; matching one
physical line at a time never saw it.

A denial is not a claim
-----------------------
A line that states the NEGATIVE is the correct wording, so a match is
exempt when — and only when — the negation governs THAT phrase: a negator at
most two words before it (``is not BIP32-compatible``, ``no longer BIP32
compliant``, ``non-BIP32-compatible``, ``without BIP32 compatibility``), a
predicate straight after it (``"BIP32-compatible" is false``), or a quotation
of retired wording (``was documented "BIP32-compliant"``).

The exemption used to be any negation cue ANYWHERE on the line —
``compatible[^.]{0,40}not``, ``deliberately``, ``no longer``,
``was documented`` — so "HDKeyDerivation is BIP32-compatible, so you do not
need a separate wallet library" and "Deliberately BIP32-compliant for wallet
migration" both passed: the false claim, exempted by a word that denied
something else.

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
import io
import re
import subprocess
import sys
import tokenize
from pathlib import Path
from typing import Callable, Iterable

REPO = Path(__file__).resolve().parent.parent

#: Documentation suffixes, scanned at any depth.
SCAN_SUFFIXES: frozenset[str] = frozenset({".md", ".rst", ".txt"})

#: Python sources whose docstrings, string literals and comments are scanned:
#: the shipped package, whose docstrings Sphinx autodoc publishes and whose
#: messages a caller reads.
PY_SCAN_ROOTS: tuple[str, ...] = ("ama_cryptography",)
PY_SUFFIXES: frozenset[str] = frozenset({".py", ".pyi"})


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
#: "BIP32 path" are all accurate and must keep passing.  Each match runs to the
#: end of its word, so the text after it is what follows the whole phrase.
BANNED: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        # "compatibility" too: the noun claims exactly what the adjective does,
        # and ``compatible`` alone let "Full BIP32 compatibility" through.
        re.compile(r"BIP[- ]?32[- ]?compatib(?:le|ility)\b", re.IGNORECASE),
        'BIP32 "compatible" — the master key uses a different HMAC key, so no '
        "BIP32 wallet derives these keys. Say BIP32-style.",
    ),
    (
        re.compile(r"BIP[- ]?32[- ]?complian(?:t|ce)\b", re.IGNORECASE),
        'BIP32 "compliance" — the derived tree does not match BIP32. ' "Say BIP32-style.",
    ),
    (
        re.compile(r"BIP[- ]?32[- ]?interoperab\w*", re.IGNORECASE),
        "BIP32 interoperability is exactly what this implementation does NOT " "have.",
    ),
    (
        re.compile(r"conforms?\s+to\s+BIP[- ]?32\b", re.IGNORECASE),
        "conformance to BIP32 is not claimable: the master derivation differs.",
    ),
)

#: A negator that governs the phrase: at most two words before it, optionally
#: with an opening quote.  ``not only`` / ``not just`` / ``not merely`` /
#: ``not simply`` introduce the claim rather than deny it.
_NEGATED_BEFORE = re.compile(
    r"(?:\b(?:(?:can)?not(?![\s-]+(?:only|just|merely|simply)\b)|never|no|non|neither|nor|without"
    r"|lacks?|lacking)|n['\u2019]t)(?:[\s-]+[\w'\u2019]+){0,2}[\s-]+[\"\u201c'`]?$",
    re.IGNORECASE,
)

#: A predicate straight after the phrase that denies it:
#: ``"BIP32-compatible" is false``.
_NEGATED_AFTER = re.compile(
    r"^[\"\u201d'`]?\s+(?:is|are|was|were)\s+(?:not|false|untrue|wrong|incorrect)\b",
    re.IGNORECASE,
)

#: A quotation of wording that has been retired: ``was documented "BIP32-compliant"``.
_RETIRED_QUOTE = re.compile(
    r"\b(?:was|were|had\s+been|previously|formerly)\s+(?:documented|described|called"
    r"|label(?:l)?ed|advertised|claimed)(?:\s+as)?\s+[\"\u201c'`]$",
    re.IGNORECASE,
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


def _is_denied(line: str, match: re.Match[str]) -> bool:
    """Whether the negation on ``line`` governs THIS occurrence of the phrase."""
    before, after = line[: match.start()], line[match.end() :]
    return bool(
        _NEGATED_BEFORE.search(before)
        or _NEGATED_AFTER.match(after)
        or _RETIRED_QUOTE.search(before)
    )


def claim_in(line: str, spanning: int | None = None) -> str | None:
    """The reason ``line`` is a false claim, or ``None``.

    Every occurrence of every banned phrase is judged on its own, so a denial
    of one phrase cannot exempt a claim of another on the same line.  With
    ``spanning``, only an occurrence that straddles that offset is judged (the
    seam of two joined lines, see :func:`claims_in`).
    """
    for pattern, why in BANNED:
        for match in pattern.finditer(line):
            if spanning is not None and not match.start() < spanning < match.end():
                continue
            if not _is_denied(line, match):
                return why
    return None


def claims_in(numbered: Iterable[tuple[int, str]]) -> list[tuple[int, str, str]]:
    """``(line number, text, why)`` for every claim in consecutive lines.

    Prose wraps.  "is BIP32" at the end of one line and "compatible" at the
    start of the next is the same claim, and matching line by line never saw
    it.  Each line is therefore also judged joined to the next one (a
    hyphenated break re-joined without the space), counting only an occurrence
    that crosses the seam, reported at the first line.
    """
    lines = list(numbered)
    found: list[tuple[int, str, str]] = []
    for index, (number, line) in enumerate(lines):
        why = claim_in(line)
        if why is None and index + 1 < len(lines) and lines[index + 1][0] == number + 1:
            head = line.rstrip()
            tail = lines[index + 1][1].lstrip()
            joined = head + tail if head.endswith("-") else f"{head} {tail}"
            why = claim_in(joined, spanning=len(head))
            if why is not None:
                line = joined
        if why is not None:
            found.append((number, line.strip(), why))
    return found


def _candidate_files(repo: Path) -> list[str]:
    """Every file to consider, relative to ``repo``: what git tracks when
    ``repo`` is a work-tree top, otherwise a walk of the tree."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        top = None
    if (
        top is not None
        and top.returncode == 0
        and Path(top.stdout.strip()).resolve() == (repo.resolve())
    ):
        root = str(Path(__file__).resolve().parent.parent)
        if root not in sys.path:
            sys.path.insert(0, root)
        from tools._repo import tracked_names

        return tracked_names(repo)
    return [path.relative_to(repo).as_posix() for path in repo.rglob("*") if path.is_file()]


def _selected(repo: Path, keep: Callable[[str, str], bool]) -> list[Path]:
    seen: set[Path] = set()
    for relative in _candidate_files(repo):
        parts = relative.split("/")
        if any(part in EXCLUDED_DIRS for part in parts):
            continue
        if _is_historical_record(relative):
            continue
        if keep(relative, Path(relative).suffix.lower()):
            seen.add(repo / relative)
    return sorted(seen)


def scanned_files(repo: Path = REPO) -> list[Path]:
    """Documentation files, at any depth."""
    return _selected(repo, lambda _relative, suffix: suffix in SCAN_SUFFIXES)


def scanned_sources(repo: Path = REPO) -> list[Path]:
    """Python sources under :data:`PY_SCAN_ROOTS`."""
    return _selected(
        repo,
        lambda relative, suffix: suffix in PY_SUFFIXES
        and relative.split("/", 1)[0] in PY_SCAN_ROOTS,
    )


#: Token types that carry prose in a Python source.  ``FSTRING_MIDDLE`` exists
#: from Python 3.12, where an f-string is no longer one STRING token.
_FSTRING_MIDDLE: int | None = getattr(tokenize, "FSTRING_MIDDLE", None)
_PROSE_TOKENS: frozenset[int] = frozenset(
    {tokenize.STRING, tokenize.COMMENT}
    | ({_FSTRING_MIDDLE} if _FSTRING_MIDDLE is not None else set())
)


def python_prose(text: str) -> list[tuple[int, str]]:
    """``(line number, text)`` for each physical line of every docstring,
    string literal and comment in a Python source.

    Code is left out: an identifier is not a claim.  A source that does not
    tokenize is read whole rather than skipped.
    """
    lines: list[tuple[int, str]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type in _PROSE_TOKENS:
                for offset, line in enumerate(token.string.splitlines()):
                    lines.append((token.start[0] + offset, line))
    except (tokenize.TokenError, SyntaxError):
        return list(enumerate(text.splitlines(), start=1))
    return lines


def find_claims(repo: Path = REPO) -> list[tuple[str, int, str, str]]:
    """Every false BIP32 compatibility claim: (file, line number, text, why)."""
    findings: list[tuple[str, int, str, str]] = []
    sources: list[tuple[Path, bool]] = [(path, False) for path in scanned_files(repo)]
    sources += [(path, True) for path in scanned_sources(repo)]
    for path, is_python in sources:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        numbered = python_prose(text) if is_python else enumerate(text.splitlines(), start=1)
        relative = path.relative_to(repo).as_posix()
        findings += [(relative, number, line, why) for number, line, why in claims_in(numbered)]
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

    try:
        files = scanned_files(args.repo)
        sources = scanned_sources(args.repo)
        findings = find_claims(args.repo) + find_standards_table_claims(args.repo)
    except RuntimeError as exc:  # tools._repo.TrackedFilesError: git could not enumerate
        print(f"FATAL: could not enumerate the files to scan: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("FATAL: no documentation files were scanned.", file=sys.stderr)
        return 2

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

    print(
        f"OK    {len(files)} documentation file(s) and {len(sources)} package source(s); "
        "no false BIP32 compatibility claim"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
