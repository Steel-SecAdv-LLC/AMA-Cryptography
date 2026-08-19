#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — dudect class-staging gate

A dudect lane compares two input classes, and the two classes must differ in
the property under test and in NOTHING ELSE.  Handing the timed call one of
two per-class buffers breaks that: the classes then differ in the input's
ADDRESS as well as its value, and a load's timing legitimately depends on its
address — which cache line it falls in, whether it spans two, which set it
maps to.

Why that needs a gate rather than a comment
-------------------------------------------
Unlike scheduler noise, an address bias is FIXED for a given binary on a given
host.  It therefore reproduces in every round with the same sign, which is
precisely the shape the multi-round majority rule and the direction rule in
``tests/c/dudect/dudect_rounds.h`` are unable to tell apart from a leak.  No
threshold and no number of rounds separates them; only the experiment's design
does.

The size of the effect is measured, not asserted.  With the
Ascon-AEAD128-encrypt lane's own cipher call and *identical key data in both
classes* — so the true effect is exactly zero — placing class 0's key across
two cache lines while class 1's sits inside one drives the cropped statistic
to |t| = 13.5..30.9, over threshold in 10 of 10 runs, all one sign.  Staged
through a single buffer the same measurement reports 0 of 10.

This became reachable when the harnesses adopted percentile cropping, which
resolves the BULK of the timing distribution: for that lane the cropped bulk
has a standard deviation near 4 ns over ~22,000 samples per class, so the
standard error is about 0.04 ns and the threshold is crossed by a systematic
difference of roughly 0.2 ns — under half a cycle at 2.1 GHz.

The rule
--------
A lane must not bind a class-selected pointer for the timed call directly.  It
must copy the selected class's input into ONE shared, cache-line-aligned
buffer (``dudect_stage()``) and hand the timed call that buffer.

Two forms satisfy the rule:

``dudect_stage(buf, class_idx ? A : B, sizeof buf)``
    the general case, used by every keyed and message lane.

a single reused probe rewritten class-symmetrically
    used by the tag-compare lanes, where both end bytes are stored
    unconditionally every iteration and only the stored VALUE is
    class-dependent.  These lanes contain no class-selected pointer at all, so
    they trivially satisfy the check.

The gate also requires every staging buffer to be declared ``_Alignas(64)``:
an unaligned staging buffer can straddle a cache line, which reintroduces the
very asymmetry the staging removes — just for both classes at once, which
inflates the noise floor instead of biasing the mean.

Why a gate and not review
-------------------------
This discipline was already discovered once, in the AES-GCM tag-compare lane,
which carries a comment describing this exact failure mode and the fix for it.
It was not propagated to the other lanes, and the Ascon-AEAD128-encrypt lane
subsequently went red in CI for the reason that comment describes.  A property
that has already regressed once is a property that needs enforcement.

Exit status
-----------
0  every dudect lane stages its class input
1  at least one lane binds a class-selected pointer, or a staging buffer is
   not cache-line aligned
2  a file this gate must examine is missing (fail closed — a gate whose input
   vanished must not pass)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# The harnesses this gate governs.  A new dudect harness must be added here;
# tests/test_dudect_staging_gate.py pins that the list is non-empty and that
# every named file exists, so a silent drop is not possible.
HARNESS_FILES = (
    "tests/c/test_dudect.c",
    "tools/constant_time/dudect_crypto.c",
    "tools/constant_time/dudect_harness.c",
)

# A pointer bound from a class-dependent selection.  Both spellings the tree
# has used are matched: `class_idx ? A : B` and `(class_idx == 0) ? A : B`.
_CLASS_SELECT = re.compile(
    r"""
    ^\s*(?:const\s+)?              # optional const
    (?P<type>\w[\w\s]*?)           # element / struct type
    \s*\*\s*(?P<name>\w+)          # pointer being bound
    \s*=\s*                        # assignment
    (?P<rhs>.*?class_idx\s*(?:==\s*[01]\s*\))?\s*\?)   # a class-dependent ternary
    """,
    re.VERBOSE,
)

# The sanctioned staging call.
_STAGED = re.compile(r"dudect_stage\s*\(")

# `_Alignas(64) <type> name[...]` / `_Alignas(64) <type> name;`
_ALIGNED_DECL = re.compile(r"_Alignas\(64\)\s+\w[\w\s]*?\s+(?P<name>\w+)\s*(?:\[|;)")

# Any declaration of an identifier ending in `_stage`, aligned or not.
#
# re.MULTILINE is load-bearing: `^` without it anchors to the start of the
# whole file, so the alignment half of this gate matched at most one
# declaration and passed everything else.  tests/test_dudect_staging_gate.py
# pins the unaligned case, which is what caught it.
_STAGE_DECL = re.compile(
    r"^[^\S\n]*(?:_Alignas\(\d+\)[^\S\n]+)?\w[\w ]*?[^\S\n]+(?P<name>\w+_stage)\s*(?:\[|;)",
    re.MULTILINE,
)


def _logical_statements(text: str) -> list[tuple[int, str]]:
    """Join continuation lines so a statement split across lines is matched.

    A binding written as::

        const uint8_t *key =
            dudect_stage(key_stage, class_idx ? k1 : k0, sizeof key_stage);

    is one statement and must be examined as one.  Scanning raw lines would
    see ``const uint8_t *key =`` on its own, find no ``dudect_stage`` on that
    line, and report a violation that is not there — the failure mode that
    makes a gate get switched off.  Statements are accumulated to the
    terminating semicolon, and the reported line number is the one the
    statement starts on.
    """
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for idx, raw in enumerate(text.split("\n"), start=1):
        line = raw.split("//", 1)[0]
        if not buf:
            start = idx
        buf = f"{buf} {line.strip()}" if buf else line.strip()
        if ";" in line or line.strip().endswith("{") or line.strip().endswith("}"):
            out.append((start, buf.strip()))
            buf = ""
    if buf:
        out.append((start, buf.strip()))
    return out


def _strip_block_comments(text: str) -> str:
    """Remove /* ... */ comments, preserving line count so numbers stay true."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                out.append("\n" * text.count("\n", i))
                break
            out.append("\n" * text.count("\n", i, end))
            i = end + 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check_text(text: str, path: str) -> list[str]:
    """Return one message per violation found in `text`."""
    stripped = _strip_block_comments(text)
    violations: list[str] = []

    aligned = {m.group("name") for m in _ALIGNED_DECL.finditer(stripped)}
    for m in _STAGE_DECL.finditer(stripped):
        name = m.group("name")
        if name not in aligned:
            line = stripped.count("\n", 0, m.start()) + 1
            violations.append(
                f"{path}:{line}: staging buffer '{name}' is not declared "
                f"_Alignas(64). A staging buffer that straddles a cache line "
                f"reintroduces the geometry the staging exists to remove."
            )

    for lineno, stmt in _logical_statements(stripped):
        select = _CLASS_SELECT.match(stmt)
        if select is None:
            continue
        if _STAGED.search(stmt):
            continue
        name = select.group("name")
        violations.append(
            f"{path}:{lineno}: '{name}' binds a class-selected "
            f"pointer for the timed call. The two classes then differ in the "
            f"input's ADDRESS as well as its value, which is a fixed per-host "
            f"bias no threshold or round count can distinguish from a leak. "
            f"Stage it: dudect_stage({name}_stage, "
            f"class_idx ? ... : ..., sizeof {name}_stage)."
        )
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        default=".",
        help="repository root to resolve the harness files against",
    )
    args = ap.parse_args(argv)
    root = Path(args.root)

    if not HARNESS_FILES:
        print("FATAL: no harness files configured; this gate would pass vacuously.")
        return 2

    all_violations: list[str] = []
    examined = 0
    for rel in HARNESS_FILES:
        path = root / rel
        if not path.is_file():
            print(f"FATAL: {rel} is missing; refusing to report a clean gate.")
            return 2
        all_violations.extend(check_text(path.read_text(encoding="utf-8"), rel))
        examined += 1

    if all_violations:
        print(f"FAIL: {len(all_violations)} dudect class-staging violation(s):")
        for v in all_violations:
            print(f"  - {v}")
        return 1

    print(f"OK: {examined} dudect harness file(s); every lane stages its class input.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
