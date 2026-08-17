#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Frozen Compiler-Warning Allowlist
====================================================

Fails the build if any compiler warning appears outside a short, explicitly
justified allowlist.  This is the enforcement half of the "Strict Compiler
Warnings" jobs in ``.github/workflows/static-analysis.yml``; the jobs produce
the logs, this script decides.

Why this is a script and not three copies of a shell pipeline
-------------------------------------------------------------
The allowlist used to live inline in one workflow step as a chain of
``grep -v``.  That had two consequences, and the second is the reason this
file exists.

``the allowlist could not be reused``
    The step ran in exactly one configuration — x86-64, one compiler at a
    time, **no** ``CMAKE_BUILD_TYPE`` — and its conclusion ("no warnings
    outside ``src/c/vendor/`` beyond the two documented extension classes")
    was reported as a property of the repository.  It was a property of that
    configuration.  Two whole classes of diagnostic were unreachable from it:

    *optimizer-dependent warnings*
        ``-Wmaybe-uninitialized``, ``-Wstringop-truncation``,
        ``-Wstringop-overflow``, ``-Wrestrict`` and everything
        ``_FORTIFY_SOURCE`` derives are computed from dataflow the optimizer
        builds.  At ``-O0`` GCC emits none of them.  Measured on the commit
        that introduced this script: the tree compiled at ``-O0`` produced
        zero warnings outside the allowlist, and the same tree compiled
        ``Release`` produced seven ``-Wstringop-truncation`` in
        ``benchmarks/benchmark_c_raw.c`` — plus, with LTO on (the
        configuration ``make c`` and the release wheels use), a
        ``'pk_k' may be used uninitialized`` for a keypair call whose return
        value was discarded.

    *architecture-dependent warnings*
        ``src/c/neon/**`` and ``src/c/sve2/**`` compile to a placeholder
        typedef on x86-64.  On AArch64 they compiled 36
        ``-Wmissing-prototypes`` — a class the same job makes **fatal** with
        ``-Werror=missing-prototypes`` — because the kernels' prototypes were
        hand-transcribed at each consumer instead of living in a header.  A
        gate that is ``-Werror`` on a class the build carries 36 instances of
        is not enforcing that class; it is not looking at it.

``a gate whose input vanished passed``
    ``grep`` exits 2 with "No such file or directory", which ``|| true``
    flattened into the same empty result as "no warnings found".  That is
    handled here by refusing to run against a missing or empty log.

Both configurations and both architectures now feed this one allowlist.

What is allowed, and why
------------------------
``src/c/vendor/**``
    INVARIANT-1 keeps vendored sources byte-for-byte unmodified, so their
    diagnostics are not ours to fix.

``fe51.h`` / ``fe64.h`` — ``ISO C does not support '__int128' types``
    ``-Wpedantic`` under GCC.  The 128-bit limbs are what the field
    arithmetic is built on; there is no ISO C spelling of them.

``x86/ama_nistp_mont_mulx.c`` — ``string literal of length``
    ``-Woverlength-strings`` under clang.  One atomic ``asm()`` block:
    splitting the Montgomery kernel into several ``asm`` statements would
    forfeit the register-state guarantees the kernel depends on, and the
    warning measures the concatenated literal anyway.

Tightening (a class driven to zero) means deleting its entry below.
Loosening requires editing this file in review — which is the point.

Usage
-----
::

    python3 tools/check_compiler_warnings.py build-warnings.log [more.log ...]

Exit codes
----------
``0``
    Every warning in every log matched the allowlist.
``1``
    A warning outside the allowlist was found, or a log was missing/empty.
``2``
    Usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, NamedTuple, Sequence

#: Lines that are compiler diagnostics.  ``warning:`` is the GCC/clang
#: spelling; MSVC uses ``warning Cxxxx:`` which this also matches.
_WARNING_RE = re.compile(r"\bwarning[ :]")

#: GCC quotes identifiers with U+2018/U+2019 under a UTF-8 locale and with
#: ASCII apostrophes otherwise.  ``.{1,3}`` spans either spelling: one ASCII
#: byte, or the three UTF-8 bytes of the curly quote.  A bracket class would
#: not work — a C-locale reader splits a multibyte quote into single bytes.
_QUOTE = r".{1,3}"


class Exemption(NamedTuple):
    """One allowlist entry: a name, a matcher, and the reason it exists."""

    name: str
    pattern: re.Pattern[str]
    reason: str


EXEMPTIONS: tuple[Exemption, ...] = (
    Exemption(
        name="vendored-source",
        pattern=re.compile(r"[/\\]src[/\\]c[/\\]vendor[/\\]"),
        reason=(
            "INVARIANT-1 keeps vendored sources byte-for-byte unmodified, so "
            "their diagnostics are not ours to fix."
        ),
    ),
    Exemption(
        name="int128-extension",
        pattern=re.compile(
            r"fe(51|64)\.h:[0-9:]+\s*warning:\s*ISO C does not support "
            rf"{_QUOTE}__int128{_QUOTE} types"
        ),
        reason=(
            "-Wpedantic under GCC.  The 128-bit limbs are what the X25519 / "
            "Ed25519 field arithmetic is built on; ISO C has no spelling for "
            "them."
        ),
    ),
    Exemption(
        name="overlength-asm-literal",
        pattern=re.compile(r"ama_nistp_mont_mulx\.c:[0-9:]+\s*warning:\s*string literal of length"),
        reason=(
            "-Woverlength-strings under clang.  One atomic asm() block; "
            "splitting the Montgomery kernel would forfeit the register-state "
            "guarantees it depends on."
        ),
    ),
)


class Finding(NamedTuple):
    log: Path
    line_no: int
    text: str


def classify(line: str) -> str | None:
    """Return the name of the exemption covering ``line``, or ``None``."""
    for exemption in EXEMPTIONS:
        if exemption.pattern.search(line):
            return exemption.name
    return None


def scan(log_path: Path) -> tuple[list[Finding], dict[str, int]]:
    """Scan one build log.

    Returns the warnings that matched no exemption, and a per-exemption count
    of the ones that did.  The counts are reported even on success: an
    exemption that stops matching is a class that has been driven to zero,
    and the right response is to delete its entry rather than to leave a dead
    pattern behind.
    """
    findings: list[Finding] = []
    allowed: dict[str, int] = {e.name: 0 for e in EXEMPTIONS}

    # errors="replace": a build log can carry any bytes a source file's
    # diagnostics quote back, and this gate must never fail on decoding
    # rather than on content.
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.rstrip("\n")
            if not _WARNING_RE.search(line):
                continue
            covered = classify(line)
            if covered is None:
                findings.append(Finding(log_path, line_no, line.strip()))
            else:
                allowed[covered] += 1
    return findings, allowed


def check(log_paths: Sequence[Path]) -> int:
    findings: list[Finding] = []
    allowed_total: dict[str, int] = {e.name: 0 for e in EXEMPTIONS}
    missing = False

    for log_path in log_paths:
        # Fail closed on a vanished or empty log.  grep's "No such file"
        # flattened into "no warnings found" is precisely the shape this
        # repository's gate audit exists to remove: a control that reports OK
        # having examined nothing.
        if not log_path.is_file():
            print(
                f"ERROR: build log {log_path} does not exist — the build "
                f"step produced no log, so no warning was examined.",
                file=sys.stderr,
            )
            missing = True
            continue
        if log_path.stat().st_size == 0:
            print(
                f"ERROR: build log {log_path} is empty — no warning was " f"examined.",
                file=sys.stderr,
            )
            missing = True
            continue

        log_findings, allowed = scan(log_path)
        findings.extend(log_findings)
        for name, count in allowed.items():
            allowed_total[name] += count

    if missing:
        print("Refusing to pass: at least one build log was missing or empty.", file=sys.stderr)
        return 1

    if findings:
        print("Compiler warnings outside the frozen allowlist:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding.log}:{finding.line_no}: {finding.text}", file=sys.stderr)
        print(f"\n{len(findings)} warning(s) outside the allowlist.", file=sys.stderr)
        print(
            "Fix them at source.  Adding an entry to EXEMPTIONS in "
            "tools/check_compiler_warnings.py requires a reason that "
            "survives review.",
            file=sys.stderr,
        )
        return 1

    print("OK: no compiler warnings outside the frozen allowlist.")
    for name, count in allowed_total.items():
        print(f"  allowlisted [{name}]: {count}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail on any compiler warning outside the frozen allowlist."
    )
    parser.add_argument(
        "logs",
        nargs="+",
        type=Path,
        help="build log(s) to scan; every one must exist and be non-empty",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    return check(args.logs)


if __name__ == "__main__":
    sys.exit(main())
