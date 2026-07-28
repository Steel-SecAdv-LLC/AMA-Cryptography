#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Checkout Byte-Identity Verifier
==================================================

Verifies the property several of this repository's gates silently assume:
**the bytes on disk are the bytes that were committed, on every platform.**

Why this exists
---------------
A surprising amount of this repository is measured by octet rather than by
meaning.  ``wycheproof_vectors/manifest.json`` pins a SHA-256 per corpus file.
``tools/build_keyformat_corpus.py --verify`` re-derives record counts and
structural sizes.  The reproducible-build gate compares artefact digests.  And
``NoteArtifactDetector`` — whose calibration ``tests/test_agentic_abuse_detectors.py``
re-derives on every run — samples a fixed 8 KiB head-and-tail window of each
tracked file, so for any file larger than that window, *which text is scored
depends on the byte offsets of everything before it*.

Git's default configuration on Windows (``core.autocrlf=true``) rewrites LF to
CRLF as it writes the working tree.  The checkout then no longer matches the
blob: digests change, and an 8 KiB window over a 38 KiB document slides by one
octet per preceding line, so it covers different prose than it does on Linux.

That is not a hypothetical.  It failed all ten Windows CI jobs on this branch:
``IMPLEMENTATION_GUIDE.md`` scored 1.50 on Linux and 1.25 on Windows purely
because 1,343 line terminators had grown a byte each, and the calibration test
that asserts 1.50 admits exactly one more benign file than 1.75 could not hold.
Nothing about the detector, the document or the threshold was wrong.  The two
platforms were reading different files.

The fix is ``* -text`` in ``.gitattributes``, which disables both the clean and
the smudge filter so the working tree *is* the committed blob everywhere.  This
checker exists because that fix has two failure modes, and both are silent:

``the mechanism can be removed``
    A later edit that narrows or drops the blanket rule restores the platform
    divergence, and nothing would notice until a Windows job failed for a
    reason with no obvious connection to the change.

``the content can drift``
    With conversion disabled, git no longer normalises on commit either.  A
    contributor whose editor writes CRLF now commits CRLF *verbatim*, which
    skews the same byte-sensitive gates on every platform at once — a strictly
    worse outcome than the one being fixed, and permanent rather than
    per-checkout.

So both are checked: the effective attribute is resolved through git's own
matcher (not by grepping ``.gitattributes``, which a comment would satisfy),
and the *index* is inspected rather than the working tree, because what is
committed is the thing that must be clean.  A CRLF blob that a correctly
configured checkout happens to render as LF is still a defect.

What is checked
---------------
``index cleanliness``
    No tracked text blob may contain CRLF or mixed terminators.  Files git
    classifies as binary (``-text``) are exempt: two fuzzer seed corpora
    legitimately carry ``\\r\\n`` as opaque input data, and a seed corpus that
    had to avoid an octet would be a worse corpus.

``conversion disabled``
    Every tracked text file must resolve to an unset ``text`` attribute, i.e.
    no EOL translation in either direction.  Checked per path via
    ``git check-attr``, so a rule that matches most of the tree but misses a
    subdirectory is reported rather than assumed away.

Both directions are pinned by ``tests/test_line_endings_gate.py``: the parser
is exercised against synthetic ``crlf``/``mixed`` records, so the gate's
ability to *reject* is demonstrated without committing a defective file.

Usage
-----
::

    python tools/check_line_endings.py              # scan tracked files
    python tools/check_line_endings.py --paths a b  # scan specific paths

Exits 0 when the checkout is byte-identical on every platform, 1 otherwise.
"""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 -- fixed-argv git invocations only, never a shell (EOL-002)
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

#: ``git ls-files --eol`` index classifications that mean "this blob carries a
#: line terminator that is not LF".  ``none`` is a file with no terminator at
#: all (empty, or a single unterminated line) and is clean by definition;
#: ``-text`` is git's binary classification and is exempt by design.
_DIRTY_EOL = frozenset({"crlf", "mixed", "cr"})

#: Classifications that exempt a path from the ``text`` attribute check.  A
#: binary blob is not subject to EOL translation whatever the attribute says.
_BINARY_EOL = frozenset({"-text"})


@dataclass(frozen=True)
class Violation:
    """A tracked path whose bytes are not stable across platforms."""

    path: str
    reason: str

    def render(self) -> str:
        return f"{self.path}: {self.reason}"


@dataclass(frozen=True)
class EolRecord:
    """One parsed line of ``git ls-files --eol``."""

    index_eol: str
    worktree_eol: str
    attrs: str
    path: str


def parse_eol_output(text: str) -> list[EolRecord]:
    """Parse ``git ls-files --eol`` output into records.

    The format is ``i/<eol> w/<eol> attr/<attrs><TAB><path>``, with the three
    fields blank-padded to fixed columns.  The path is split on the tab rather
    than on whitespace so that a path containing spaces survives; the fields
    before it never contain one.
    """
    records: list[EolRecord] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields, sep, path = line.partition("\t")
        if not sep:
            continue
        parts = fields.split()
        if len(parts) < 3:
            continue
        index_eol, worktree_eol, attrs = parts[0], parts[1], parts[2]
        records.append(
            EolRecord(
                index_eol=index_eol.removeprefix("i/"),
                worktree_eol=worktree_eol.removeprefix("w/"),
                attrs=attrs.removeprefix("attr/"),
                path=path,
            )
        )
    return records


def check_records(records: Sequence[EolRecord]) -> list[Violation]:
    """Return violations for already-parsed ``git ls-files --eol`` records.

    Separated from the subprocess call so the rejection direction can be
    exercised against synthetic input: this repository has no CRLF blob to
    point the gate at, and committing one to prove the gate works would defeat
    the gate.
    """
    violations: list[Violation] = []
    for record in records:
        if record.index_eol in _BINARY_EOL:
            continue
        if record.index_eol in _DIRTY_EOL:
            violations.append(
                Violation(
                    record.path,
                    (
                        f"committed blob has {record.index_eol.upper()} line endings; "
                        "byte-sensitive gates (corpus digests, the 8 KiB detector "
                        "sample window) read the blob verbatim, so this shifts them "
                        "on every platform — commit LF"
                    ),
                )
            )
    return violations


def check_attributes(
    attrs_by_path: dict[str, str], records: Sequence[EolRecord]
) -> list[Violation]:
    """Return violations for paths whose ``text`` attribute is not unset.

    ``attrs_by_path`` maps a path to git's resolved value of the ``text``
    attribute: ``unset`` is what ``-text`` produces and the only accepted
    value.  ``set``, ``auto`` and ``unspecified`` all leave at least one
    platform performing EOL translation.
    """
    binary_paths = {r.path for r in records if r.index_eol in _BINARY_EOL}
    violations: list[Violation] = []
    for path, value in sorted(attrs_by_path.items()):
        if path in binary_paths or value == "unset":
            continue
        violations.append(
            Violation(
                path,
                (
                    f'git resolves the "text" attribute to {value!r} rather than unset, '
                    "so a checkout with core.autocrlf=true rewrites this file and stops "
                    "matching the committed blob — restore the `* -text` rule in "
                    ".gitattributes"
                ),
            )
        )
    return violations


def _git(repo_root: Path, args: Sequence[str], stdin: Optional[str] = None) -> str:
    """Run a fixed-argv git command in ``repo_root`` and return stdout."""
    try:
        return subprocess.run(  # nosec B603 -- fixed argv, no shell, trusted git binary (EOL-003)
            ["git", *args],
            cwd=str(repo_root),
            input=stdin,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: unable to query git ({' '.join(args)}): {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _resolve_text_attribute(repo_root: Path, paths: Sequence[str]) -> dict[str, str]:
    """Resolve the ``text`` attribute for ``paths`` via git's own matcher.

    Uses ``--stdin -z`` so the query is one process regardless of tree size and
    so paths containing a newline cannot desynchronise the parse.  The output
    is a flat NUL-separated stream of ``path, attribute, value`` triples.
    """
    if not paths:
        return {}
    out = _git(
        repo_root,
        ["check-attr", "--stdin", "-z", "text"],
        stdin="\0".join(paths) + "\0",
    )
    fields = out.split("\0")
    resolved: dict[str, str] = {}
    for i in range(0, len(fields) - 2, 3):
        resolved[fields[i]] = fields[i + 2]
    return resolved


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the checkout is byte-identical to the index on every platform."
    )
    parser.add_argument("--paths", nargs="*", help="explicit paths to scan")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent

    ls_args = ["ls-files", "--eol"]
    if args.paths:
        ls_args += ["--", *args.paths]
    records = parse_eol_output(_git(repo_root, ls_args))

    if not records:
        print(
            "ERROR: git reported no tracked files — the gate would pass vacuously",
            file=sys.stderr,
        )
        return 2

    violations = check_records(records)
    violations += check_attributes(
        _resolve_text_attribute(repo_root, [r.path for r in records]),
        records,
    )

    if violations:
        print("Checkout byte-identity check FAILED\n", file=sys.stderr)
        for violation in sorted(violations, key=lambda v: (v.path, v.reason)):
            print(f"  {violation.render()}", file=sys.stderr)
        print(
            f"\n{len(violations)} violation(s) across {len(records)} tracked file(s).",
            file=sys.stderr,
        )
        return 1

    binary = sum(1 for r in records if r.index_eol in _BINARY_EOL)
    print(
        f"Checkout byte-identity OK: {len(records) - binary} text file(s) LF-terminated "
        f"with EOL conversion disabled, {binary} binary file(s) exempt."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
