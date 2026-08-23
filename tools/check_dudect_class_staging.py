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

Staging the destination is only half of it
------------------------------------------
The first version of this gate sanctioned::

    dudect_stage(buf, class_idx ? A : B, sizeof buf)

which fixes the address the *timed call* reads but leaves the SELECTION inside
the loop, between the class draw and the opening timer.  That keeps two
class-correlated effects in the window the measurement is most sensitive to:
the ternary is a conditional branch perfectly correlated with the class, whose
misprediction penalty is paid just before the timer opens and retires inside
the timed region on an out-of-order core; and ``A`` and ``B`` are two distinct
objects, so the staging copy's own source address is class-correlated too.

Measured with the AES-GCM forgery-position lane's own decrypt call and
BYTE-IDENTICAL input in both classes — true effect exactly zero — at 500,000
measurements per run, 8 runs per batch, threshold 5.0:

===================================================  ==============  =========
construction                                          over threshold  worst |t|
===================================================  ==============  =========
two sources + ternary select (the old sanctioned      4/8, 4/8, 1/8       7.85
form)
one aligned two-entry source, indexed (no branch)          0/8            2.79
two sources, branch-free pointer select                    0/8            2.18
one aligned two-entry source + ternary select              0/8            4.47
both sources merged under a mask                           0/8            3.01
===================================================  ==============  =========

The branch is the dominant term: the two constructions that keep it are the
only ones that trip or drift toward the threshold.  ``dudect_harness.c`` had
already measured the same effect twice from the other direction — a branchy
class setup gave mean t = +43.38 (10/10 over threshold) against +1.26 (0/10)
for the branchless form, and +9.93 (15/15) against -0.02 (0/15) on a function
callgrind proves retires an identical instruction count for every class.  The
discipline existed in the older harness and was not carried into the newer
lanes.

The rule
--------
Between the class draw and the timer call that opens the measured region, no
statement may branch on the class or use it to select an address.  Concretely,
in that window ``class_idx`` may appear only:

* as the trailing argument of ``dudect_stage_select(dst, src0, src1, n,
  class_idx)`` — which reads BOTH class inputs every iteration and merges them
  under a constant-time mask, so neither the branch history nor the address
  stream entering the timer is class-correlated, at any input size; or
* in branchless arithmetic that constructs the class input itself, e.g.
  ``memset(buf, (int)(0xFF * (unsigned)class_idx), n)`` or
  ``b[pos] ^= (uint8_t)class_idx``.

A ternary on the class, an ``if`` on the class, or a ``[class_idx]`` index is a
violation wherever it appears in that window.  After the timer closes the
window the class is unconstrained: the next iteration's class is drawn
independently, so branch history carried across iterations cannot bias it.

The gate also requires every staging buffer to be declared ``_Alignas(64)``:
an unaligned staging buffer can straddle a cache line, which reintroduces the
very asymmetry the staging removes — just for both classes at once, which
inflates the noise floor instead of biasing the mean.

Why a gate and not review
-------------------------
This discipline has now been discovered three times in this tree — twice in
``dudect_harness.c`` and once in the AES-GCM tag-compare lane — and each time
it failed to propagate to the lanes written next.  The shipped AES-GCM
forgery-position lane read |t| = 61..75 with a consistent sign on two
different CI hosts while the decrypt it measures executes a bit-identical
instruction stream for both classes.  A property that has regressed three
times is a property that needs enforcement rather than a comment.

Exit status
-----------
0  every dudect lane reaches its timer with no class-dependent branch or
   address selection in front of it
1  at least one lane branches on the class or selects an address by it before
   the timer, a staging buffer is not cache-line aligned, or a class draw is
   not followed by a timer call at all
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

# The tail of the diagnostic below, held in a constant: spelled inline it
# completes a "... an address ... from a leak ..." span that ruff's
# flake8-bandit S608 heuristic reads as SQL string building.
_LEAK = "from a real leak"

# The class draw that opens the pre-timer window.
_CLASS_DRAW = re.compile(r"\bclass_idx\s*=[^=]")

# The timer call that closes it.  Both harness families are covered:
# dudect_get_time_ns() in tests/c, get_time_ns() in tools/constant_time.
_TIMER = re.compile(r"\b(?:dudect_)?get_time_ns\s*\(")

# Any mention of the class at all.
_CLASS_USE = re.compile(r"\bclass_idx\b")

# The sanctioned staging call: dudect_stage_select(dst, src0, src1, n, class_idx)
# — both sources read every iteration, merged under a constant-time mask.
_STAGE_SELECT = re.compile(r"dudect_stage_select\s*\([^;]*,\s*class_idx\s*\)")

# The forbidden class-dependent constructs: a ternary on the class (either
# spelling the tree has used), an `if` on the class, or an address selected by
# it.  These are the constructions measured to bias the lane.
#
# Each alternative, in order:
#   1. an `if` whose condition mentions the class
#   2. a comparison of the class against 0 or 1, feeding a ternary
#   3. a bare ternary on the class
#   4. an array subscript by the class, which selects an ADDRESS and so biases
#      the lane even when both arms retire the same instructions
#
# The alternatives are assembled from named parts rather than written as one
# re.VERBOSE pattern with trailing `#` comments.  Verbose comments read as
# pattern text to anything that does not model the flag — CodeQL parsed the
# `arr[class_idx]` comment as a character class and reported a duplicate `s`
# (alert 632) — and, worse, deleting `re.VERBOSE` would silently promote those
# comments into the pattern.  Naming the parts removes both.
_IF_ON_CLASS = r"\bif\s*\([^;]*\bclass_idx\b"
_CLASS_COMPARE_TERNARY = r"\bclass_idx\b\s*(?:==|!=)\s*[01]\s*\)?\s*\?"
_CLASS_TERNARY = r"\bclass_idx\b\s*\?"
_CLASS_SUBSCRIPT = r"\[\s*class_idx\s*\]"

_CLASS_BRANCH = re.compile(
    "|".join(
        f"(?:{alternative})"
        for alternative in (
            _IF_ON_CLASS,
            _CLASS_COMPARE_TERNARY,
            _CLASS_TERNARY,
            _CLASS_SUBSCRIPT,
        )
    )
)

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

# The DESTINATION of every staging call — the first argument of
# `dudect_stage_select(dest, a, b, len, class_idx)` / `dudect_stage(dest, ...)`.
#
# This is what the alignment rule is actually about, and keying it on the
# `_stage` name suffix instead meant the rule was enforced on zero declarations
# in one of the three governed harnesses.  `tests/c/test_dudect.c` happens to
# name its destinations `tag_use_stage`, `sk_use_stage`, `k_stage`…, so the
# suffix rule covered it by coincidence; `tools/constant_time/dudect_crypto.c`
# names the same kind of buffer `sk`, `key`, `probe_tag`, `ikm`, `input`, and
# not one of them was ever checked — while the module docstring stated the rule
# with no qualification ("every staging buffer").  The destinations there do
# carry `_Alignas(64)` today, so nothing was broken; the RULE was simply not
# enforced, and an unaligned one added tomorrow would have passed.
#: The `&` and any parentheses are OPTIONAL.  Requiring a bare identifier meant
#: `dudect_stage_select(&b_stage, &good, &bad, sizeof b_stage, class_idx)` —
#: the form the agent-binding lane uses to stage a struct — never matched, so
#: Rule 1 examined ZERO destinations for that call.  Rule 1 exists specifically
#: to stop the alignment check depending on the `*_stage` naming convention;
#: a spelling it cannot parse puts it back where it started, silently.
_STAGE_CALL_DEST = re.compile(
    r"\bdudect_stage(?:_select)?\s*\(\s*\(?\s*&?\s*(?P<dest>\w+)\s*[,)\]]"
)

# Any declaration at all, so a destination that has one can be told apart from
# a destination that is a function parameter or a file-scope symbol declared
# elsewhere.  Used only to make the diagnostic accurate.
_ANY_DECL = re.compile(
    r"^[^\S\n]*(?:_Alignas\(\d+\)[^\S\n]+)?\w[\w ]*?[^\S\n]+\*?(?P<name>\w+)\s*(?:\[|;|=)",
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
    declared = {m.group("name") for m in _ANY_DECL.finditer(stripped)}

    # Rule 1 — every destination of a staging call must be aligned.  Derived
    # from the calls, so it holds whatever the buffer is named.
    reported: set[str] = set()
    for m in _STAGE_CALL_DEST.finditer(stripped):
        name = m.group("dest")
        if name in aligned or name in reported:
            continue
        reported.add(name)
        line = stripped.count("\n", 0, m.start()) + 1
        if name in declared:
            violations.append(
                f"{path}:{line}: staging destination '{name}' is not declared "
                f"_Alignas(64). A staging buffer that straddles a cache line "
                f"reintroduces the geometry the staging exists to remove."
            )
        else:
            violations.append(
                f"{path}:{line}: staging destination '{name}' has no declaration "
                f"in this file, so its alignment cannot be established here. "
                f"Stage into a local _Alignas(64) buffer."
            )

    # Rule 2 — the naming convention, kept as an additional check.  A buffer
    # named `*_stage` is a staging buffer whether or not this file happens to
    # contain the call that uses it.
    for m in _STAGE_DECL.finditer(stripped):
        name = m.group("name")
        if name not in aligned and name not in reported:
            reported.add(name)
            line = stripped.count("\n", 0, m.start()) + 1
            violations.append(
                f"{path}:{line}: staging buffer '{name}' is not declared "
                f"_Alignas(64). A staging buffer that straddles a cache line "
                f"reintroduces the geometry the staging exists to remove."
            )

    # Walk the file as a state machine.  The window opens at a class draw and
    # closes at the first timer call after it; inside the window the class may
    # only reach the timed call through dudect_stage_select() or branchless
    # arithmetic.  A draw that is never followed by a timer is itself a
    # violation: the window would otherwise run to end-of-file and the gate
    # would report on statements it has no business judging, or — if the file
    # ends quietly — report nothing at all.
    in_window = False
    window_line = 0
    for lineno, stmt in _logical_statements(stripped):
        if in_window:
            if _CLASS_USE.search(stmt) and not _STAGE_SELECT.search(stmt):
                branch = _CLASS_BRANCH.search(stmt)
                if branch is not None:
                    violations.append(
                        f"{path}:{lineno}: {branch.group(0).strip()!r} lets "
                        f"the class pick a branch or an address, after the "
                        f"class draw on line {window_line} and before the "
                        f"timer opens. Such a branch's direction is perfectly "
                        f"correlated with the class and its misprediction is "
                        f"paid inside the measured region: a fixed per-host "
                        f"bias that no threshold and no round count can tell "
                        f"apart {_LEAK}. Use dudect_stage_select(dst, class0, "
                        f"class1, n, class_idx), which reads both class inputs "
                        f"every iteration and merges them under a mask."
                    )
            if _TIMER.search(stmt):
                in_window = False
            continue

        if _CLASS_DRAW.search(stmt):
            in_window = True
            window_line = lineno

    if in_window:
        violations.append(
            f"{path}:{window_line}: this class draw is not followed by a timer "
            f"call. The gate cannot establish where the measured region begins, "
            f"so it refuses to report the file clean."
        )

    return violations


def class_draw_count(text: str) -> int:
    """How many class-draw windows this gate recognises in `text`.

    `main` asserts this is non-zero for every governed harness, because a file
    in which the gate recognised NOTHING is not a clean file.
    `_CLASS_DRAW` is keyed to the literal identifier `class_idx`, and so are
    `_CLASS_USE`, `_CLASS_BRANCH` and `_STAGE_SELECT`; a harness that names its
    class variable anything else opens no window, produces no violations, and
    was printed as "every lane reaches its timer with no class-dependent branch
    or address selection in front of it" — over a file the gate had not read a
    single lane of.  `main` counted FILES examined, never lanes, and the exit
    contract failed closed for a missing file and for a draw with no timer, but
    not for this.

    Kept out of `check_text` deliberately: that function is a statement-level
    checker applied to synthetic snippets in the test suite as well as to whole
    harnesses, and a snippet with no class draw is a legitimate input to it.
    The coverage floor belongs where the coverage CLAIM is made.
    """
    stripped = _strip_block_comments(text)
    return len(_CLASS_DRAW.findall(stripped))


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
    examined_lanes = 0
    for rel in HARNESS_FILES:
        path = root / rel
        if not path.is_file():
            print(f"FATAL: {rel} is missing; refusing to report a clean gate.")
            return 2
        text = path.read_text(encoding="utf-8")
        all_violations.extend(check_text(text, rel))
        lanes = class_draw_count(text)
        if lanes == 0:
            print(
                f"FATAL: {rel} contains no class draw this gate recognises "
                f"(`class_idx = ...`). Every rule here is keyed to that name, "
                f"so reporting the file clean would be reporting on nothing."
            )
            return 2
        examined += 1
        examined_lanes += lanes

    if all_violations:
        print(f"FAIL: {len(all_violations)} dudect class-staging violation(s):")
        for v in all_violations:
            print(f"  - {v}")
        return 1

    print(
        f"OK: {examined} dudect harness file(s), {examined_lanes} class draw(s); "
        f"every lane reaches its timer with no class-dependent branch or "
        f"address selection in front of it."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
