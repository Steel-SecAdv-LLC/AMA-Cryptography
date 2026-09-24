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

A ternary on the class, an ``if`` on the class, or a subscript containing the
class (``[class_idx]``, ``[class_idx * N]``) is a violation wherever it appears
in that window.  After the timer closes the window the class is unconstrained:
the next iteration's class is drawn independently, so branch history carried
across iterations cannot bias it.

That list is enforced POSITIVELY, occurrence by occurrence (see
``_unsanctioned_use``): each ``class_idx`` in the window must be the trailing
argument of ``dudect_stage_select``, inside ``memset``'s fill-value argument,
or in the right-hand side of an assignment to a target the gate can establish
is an integer VALUE — a declared integer local, or an element of an integer
array or of a pointer to integers.  Anything else is a violation, including a
call to any other function (``prepare(&in, class_idx)`` may branch inside), an
assignment to a pointer (``src = base + class_idx * n``), and a target whose
type this file does not show.  The rules used to be a list of forbidden
spellings, and every form missing from the list — ``&keys[class_idx * N]``,
the class passed to a helper, arithmetic assigned to an existing pointer —
passed.  ``uintptr_t``/``intptr_t`` do not count as values: an integer whose
type exists to hold an address is an address.

What the gate does not follow is the class through an intermediate variable:
``size_t off = class_idx * N;`` is a sanctioned integer value (the lookup
lane builds its index exactly so), and a later ``p = base + off;`` does not
mention the class.  It reads spellings, not data flow.

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
1  at least one lane uses the class before the timer in a form the allowlist
   above does not sanction (a branch, an address selection, a call it may
   branch inside, or a target not established as an integer value), a staging
   buffer is not cache-line aligned, or a class draw is not followed by a
   timer call at all
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

# The forbidden class-dependent constructs: a ternary on the class (either
# spelling the tree has used), an `if` on the class, or an address selected by
# it.  These are the constructions measured to bias the lane.
#
# Each alternative, in order:
#   1. an `if` whose condition mentions the class
#   2. a comparison with the class on the LEFT (equality or relational),
#      feeding a ternary
#   3. a comparison with the class on the RIGHT — the Yoda spelling
#      `(0 == class_idx) ? a : b` — feeding a ternary
#   4. a bare ternary on the class
#   5. a `switch` on the class — a branch table is still a branch
#   6. an array subscript CONTAINING the class, which selects an ADDRESS and
#      so biases the lane even when both arms retire the same instructions.
#      It used to match only a bare `[class_idx]`, so `&keys[class_idx * N]`
#      passed.
#
# The module rule is broader than any one spelling — "a ternary on the class
# is a violation wherever it appears in that window" — and alternatives 3 and
# 5 exist because the enforced patterns had drifted narrower than the rule:
# only `class_idx (==|!=) [01] ?` in that operand order was caught, so every
# ordinary rewrite of the same branch passed the gate.  Everything that is not
# a branch is judged by the positive allowlist in `_unsanctioned_use`, not by
# more alternatives here.
#
# The alternatives are assembled from named parts rather than written as one
# re.VERBOSE pattern with trailing `#` comments.  Verbose comments read as
# pattern text to anything that does not model the flag — CodeQL parsed the
# `arr[class_idx]` comment as a character class and reported a duplicate `s`
# (alert 632) — and, worse, deleting `re.VERBOSE` would silently promote those
# comments into the pattern.  Naming the parts removes both.
_IF_ON_CLASS = r"\bif\s*\([^;]*\bclass_idx\b"
_CLASS_COMPARE_TERNARY = r"\bclass_idx\b\s*(?:==|!=|[<>]=?)[^;?]*\?"
_YODA_COMPARE_TERNARY = r"(?:==|!=|[<>]=?)\s*\(?\s*class_idx\b[^;?]*\?"
_CLASS_TERNARY = r"\bclass_idx\b\s*\?"
_SWITCH_ON_CLASS = r"\bswitch\s*\([^;]*\bclass_idx\b"
_CLASS_SUBSCRIPT = r"\[[^\[\]]*\bclass_idx\b[^\[\]]*\]"

_CLASS_BRANCH = re.compile(
    "|".join(
        f"(?:{alternative})"
        for alternative in (
            _IF_ON_CLASS,
            _CLASS_COMPARE_TERNARY,
            _YODA_COMPARE_TERNARY,
            _CLASS_TERNARY,
            _SWITCH_ON_CLASS,
            _CLASS_SUBSCRIPT,
        )
    )
)

# The calls the class may reach, and the argument it may sit in.
# `dudect_stage_select(dst, src0, src1, n, class_idx)` reads both sources every
# iteration and merges them under a constant-time mask, so its TRAILING
# argument — and only that, spelled as the bare class — is sanctioned; a class
# in a source argument selects an address before the merge.  `memset`'s fill
# VALUE (argument 1) is the branchless classed-input form the memzero lane
# uses: `memset(buf, (int)(0xFFu * (unsigned)class_idx), n)`.
_STAGE_SELECT_NAME = "dudect_stage_select"
_MEMSET_NAME = "memset"

# Integer types whose values are values.  `uintptr_t`/`intptr_t` are left out
# on purpose: an integer whose type exists to hold an address is an address.
_VALUE_TYPE = (
    r"(?:u?int(?:8|16|32|64)_t|u?int_(?:fast|least)(?:8|16|32|64)_t|u?intmax_t"
    r"|size_t|ssize_t|ptrdiff_t|int|unsigned|signed|long|short|char|bool|_Bool"
    r"|float|double)"
)
_VALUE_PREFIX = r"\b" + _VALUE_TYPE + r"(?:\s+(?:" + _VALUE_TYPE + r"|const|volatile))*"

# A declaration of the assignment target in the statement itself:
# `size_t index = ...`.  No `*` is admitted, so `const uint8_t *src = ...` is
# not a value target.  The integer form is the sanctioned branchless one both
# harness families use for the lookup lane —
# `size_t index = (size_t)class_idx * (TABLE_SIZE / 2) + ...` — with the
# measurement that justifies it recorded beside the code (branchy form mean
# t = -8.68, over threshold 9/10; this form -0.85, 0/10).
_VALUE_DECLARATION = re.compile(
    r"\s*(?:(?:const|volatile|static|register)\s+)*" + _VALUE_PREFIX + r"\s+\w+\s*"
)

# The shape of a target that is not a declaration: a plain name, optionally
# subscripted — `index`, `b[pos]`, `probe[0]`.  Member accesses and
# dereferences are not established as values (their type is not in view).
_LVALUE = re.compile(r"\s*(?P<name>[A-Za-z_]\w*)\s*(?P<subscript>\[.*\])?\s*")

# C keywords that take a parenthesised operand and are not calls.  Casts are
# recognised by what precedes the parenthesis (see `_enclosing_call`), not by
# name; `sizeof`, `while` and `for` are deliberately NOT here, so the class
# inside one of them is treated like the class inside any other call.
_NOT_A_CALL = frozenset({"if", "switch", "return"})

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


def _matching_paren(text: str, open_paren: int) -> int:
    """Offset of the `)` closing `text[open_paren]`, or `len(text)` if unclosed."""
    depth = 0
    for index in range(open_paren, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def _top_level_spans(text: str, start: int, end: int, separator: str) -> list[tuple[int, int]]:
    """`[start, end)` split at `separator` characters outside (), [] and {}."""
    spans: list[tuple[int, int]] = []
    depth = 0
    begin = start
    for index in range(start, end):
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == separator and depth == 0:
            spans.append((begin, index))
            begin = index + 1
    spans.append((begin, end))
    return spans


def _callee(stmt: str, open_paren: int) -> tuple[str, int] | None:
    """`(name, start)` of the identifier directly before `stmt[open_paren]`.

    A backward scan rather than `re.search(r"(\\w+)\\s*$", ...)`, which
    retries from every start position and is quadratic on a long word run.
    """
    end = open_paren
    while end > 0 and stmt[end - 1].isspace():
        end -= 1
    start = end
    while start > 0 and (stmt[start - 1].isalnum() or stmt[start - 1] == "_"):
        start -= 1
    name = stmt[start:end]
    if not name or name[0].isdigit():
        return None
    return name, start


def _enclosing_call(stmt: str, position: int) -> tuple[str, int, int, int] | None:
    """The innermost CALL whose parentheses enclose `position`.

    Returns `(name, name_start, open_paren, close_paren)`.  A parenthesis not
    preceded by an identifier — a cast's operand `(int)(...)`, a grouping
    `(a + b)` — is not a call and is looked through, as is the condition of
    an `_NOT_A_CALL` keyword.
    """
    stack: list[int] = []
    for index in range(position):
        if stmt[index] == "(":
            stack.append(index)
        elif stmt[index] == ")" and stack:
            stack.pop()
    for open_paren in reversed(stack):
        callee = _callee(stmt, open_paren)
        if callee is None or callee[0] in _NOT_A_CALL:
            continue
        return callee[0], callee[1], open_paren, _matching_paren(stmt, open_paren)
    return None


def _assignment(segment: str) -> tuple[int, int] | None:
    """`(operator_start, operator_end)` of the top-level assignment, if any.

    `=` and the compound operators (`^=`, `+=`, `<<=`…) count; the comparisons
    `==`, `!=`, `<=` and `>=` do not.
    """
    depth = 0
    index = 0
    while index < len(segment):
        char = segment[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "=" and depth == 0:
            if segment[index + 1 : index + 2] == "=":
                index += 2
                continue
            previous = segment[index - 1] if index else ""
            if previous == "!":
                pass
            elif previous in "<>":
                if index >= 2 and segment[index - 2] == previous:
                    return index - 2, index + 1
            elif previous and previous in "+-*/%&|^":
                return index - 1, index + 1
            else:
                return index, index + 1
        index += 1
    return None


def _is_value_target(target: str, declarations: str) -> bool:
    """Whether the assignment target is established as an integer VALUE.

    Established means: declared as an integer in the statement itself
    (`size_t index = ...`), or a plain name or an element whose declaration in
    this file (`declarations`) gives it an integer type — `uint8_t b[N]`, or a
    pointer to integers `uint8_t *b` whose ELEMENT is a value.  Anything the
    file does not show that way is not established, and fails closed.
    """
    if _VALUE_DECLARATION.fullmatch(target):
        return True
    lvalue = _LVALUE.fullmatch(target)
    if lvalue is None:
        return False
    name = re.escape(lvalue.group("name"))
    if lvalue.group("subscript"):
        element = (
            _VALUE_PREFIX + r"\s+" + name + r"\s*\["
            r"|"
            + _VALUE_PREFIX
            + r"\s*\*\s*(?:(?:const|restrict|volatile)\s+)*"
            + name
            + r"\s*[=;,)]"
        )
        return re.search(element, declarations) is not None
    return re.search(_VALUE_PREFIX + r"\s+" + name + r"\s*[=;,)]", declarations) is not None


def _unsanctioned_use(stmt: str, declarations: str) -> str | None:
    """The first use of the class in `stmt` the rule does not sanction, if any.

    A branch on the class is reported first (the most specific diagnosis).
    Then every OTHER occurrence must be one of the sanctioned forms listed in
    the module docstring: the trailing argument of `dudect_stage_select`,
    inside `memset`'s fill value, or in the right-hand side of an assignment
    to an established integer value (`_is_value_target`).  The class being
    re-drawn (`class_idx = ...`) is not a use.
    """
    branch = _CLASS_BRANCH.search(stmt)
    if branch is not None:
        return branch.group(0).strip()
    for use in _CLASS_USE.finditer(stmt):
        call = _enclosing_call(stmt, use.start())
        if call is not None:
            name, name_start, open_paren, close_paren = call
            arguments = _top_level_spans(stmt, open_paren + 1, close_paren, ",")
            position = next(
                (k for k, (begin, end) in enumerate(arguments) if begin <= use.start() < end), -1
            )
            argument = stmt[arguments[position][0] : arguments[position][1]].strip()
            if name == _STAGE_SELECT_NAME and position == len(arguments) - 1:
                if argument == "class_idx":
                    continue
            elif name == _MEMSET_NAME and position == 1:
                continue
            return stmt[name_start : close_paren + 1].strip()[:120]
        segment = next(
            (begin, end)
            for begin, end in _top_level_spans(stmt, 0, len(stmt), ",")
            if begin <= use.start() <= end
        )
        text = stmt[segment[0] : segment[1]]
        assignment = _assignment(text)
        if assignment is None:
            return text.strip()[:120]
        target = text[: assignment[0]]
        if use.start() - segment[0] < assignment[0]:
            if target.strip() == "class_idx":
                continue
            return text.strip()[:120]
        if not _is_value_target(target, declarations):
            return text.strip()[:120]
    return None


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
    # Declarations the value-target test may consult: the file with its line
    # comments dropped too, so a commented-out declaration establishes nothing.
    declarations = "\n".join(line.split("//", 1)[0] for line in stripped.split("\n"))

    in_window = False
    window_line = 0
    for lineno, stmt in _logical_statements(stripped):
        if in_window:
            construct = _unsanctioned_use(stmt, declarations) if _CLASS_USE.search(stmt) else None
            if construct is not None:
                violations.append(
                    f"{path}:{lineno}: {construct!r} lets the class pick a "
                    f"branch or an address, or reach code this gate cannot "
                    f"see into, after the class draw on line {window_line} "
                    f"and before the timer opens. A branch or an address "
                    f"correlated with the class there is paid inside the "
                    f"measured region: a fixed per-host bias that no "
                    f"threshold and no round count can tell apart {_LEAK}. "
                    f"Use dudect_stage_select(dst, class0, class1, n, "
                    f"class_idx), which reads both class inputs every "
                    f"iteration and merges them under a mask, or build the "
                    f"classed input as an integer value."
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
    `_CLASS_USE`, `_CLASS_BRANCH` and `_unsanctioned_use`; a harness that names its
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
