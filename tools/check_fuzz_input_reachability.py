#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — a fuzz target's branches must be reachable by its own lane.

Why this exists
---------------
``fuzzing.yml`` ran every target with a hard-coded ``-max_len=4096``.  Two
harnesses have branches that cannot be entered below that:

* ``fuzz_dilithium`` case 1, "verify with fully fuzzed inputs", needs
  ``payload_len >= AMA_ML_DSA_65_SIGNATURE_BYTES + AMA_ML_DSA_65_PUBLIC_KEY_BYTES``
  = 3,309 + 1,952 = **5,261**, so 5,262 bytes of input.
* ``fuzz_sphincs`` case 1 needs 49,856 + 64 = **49,920**, and case 2 needs
  **49,856** — 49,921 and 49,857 bytes of input.

libFuzzer never generates a unit longer than ``-max_len``, and — measured on
this tree rather than assumed — it TRUNCATES corpus units to that length as
well: a 60,001-byte seed loaded under ``-max_len=4096`` enters the in-memory
corpus at 4,096 bytes.  So neither the mutator nor a hand-written seed could
reach those branches.  The attacker-controlled ML-DSA verify path and both
SLH-DSA verify paths have never executed in any run this repository has done,
while the jobs reported success.

That is the same shape as a gate that cannot fail: the target exists, it is
registered in every lane ``check_fuzz_target_registration.py`` knows about, it
runs, it is green, and the code it was written for is never reached.
Registration says a harness RUNS.  This says its branches can be ENTERED.

What it does
------------
For each harness it extracts every length guard — ``size < N``,
``payload_len < N``, ``payload_len == N``, ``payload_len != N``, and the same
comparisons written the other way round (``N > payload_len``) — resolves ``N``
against the harness's own ``#define``s and the public header's, adds the
payload's offset within the input, and takes the maximum.  That is the
smallest ``-max_len`` under which every branch is reachable.  ``--max-len
TARGET`` prints it, which is what the workflow uses, so the fuzzer's ceiling
is derived from the harness instead of written down twice.

Every comparison is split into its two operands (see :func:`_comparisons`),
so a length variable is found on EITHER side and under any arithmetic.
Every earlier revision matched the variable only immediately left of the
operator, so ``9000 > payload_len``, ``payload_len - 1 < N`` and
``(payload_len) < N`` produced neither a bound nor an unresolved entry: the
guard simply vanished.

A guard it cannot resolve statically is NOT ignored.  It must be listed in
:data:`MANUAL_BOUNDS` — by its exact rendered form, with the bound and the
reasoning — or this gate fails, because a guard the tool silently skipped is
exactly the branch that would go unreachable again.

Exit status
-----------
0  every branch in every harness is reachable under the lane's ``-max_len``
1  a branch is unreachable, or a guard could not be resolved and is not
   declared, or a MANUAL_BOUNDS declaration names a guard the harness no
   longer has, or the workflow stopped deriving its ceiling from this tool
2  an input this gate must read is missing (fail closed)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
FUZZ_DIR = REPO_ROOT / "fuzz"
PUBLIC_HEADER = REPO_ROOT / "include" / "ama_cryptography.h"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "fuzzing.yml"

#: The floor.  Not a requirement of any harness — it is the general mutation
#: budget the lane has always used, kept so raising a ceiling for one target
#: does not quietly lower it for another.
DEFAULT_MAX_LEN = 4096


class ManualBound(NamedTuple):
    """A bound this gate cannot compute, worked out by hand."""

    #: The input length that makes every declared guard's branches reachable.
    bound: int
    #: The EXACT unresolved guards this entry accounts for, as the gate
    #: renders them (``"payload_len < needed"``).  Matched by equality.  The
    #: previous revision dropped any unresolved guard whose expression occurred
    #: as a SUBSTRING of the reason text, so a new guard ``payload_len < n``
    #: was silenced by any reason containing the letter n.
    guards: tuple[str, ...]
    #: How the bound is obtained, guard by guard.
    reason: str


#: Guards whose bound is a runtime value this gate cannot evaluate, with the
#: bound worked out by hand and the reasoning that gets it.  Anything not
#: listed here and not statically resolvable fails the gate, and so does a
#: listed guard that no longer occurs (a declaration must not outlive its
#: subject and pre-authorise the next guard that happens to read the same).
MANUAL_BOUNDS: dict[str, ManualBound] = {
    "fuzz_nistp": ManualBound(
        200,
        (
            "payload_len < 2u * nb",
            "payload_len < pub_len + 1u",
            "payload_len < pub_len",
            "payload_len < nb",
            "payload_len >= nb + pub_len",
            "payload_len != again_len (in a || condition)",
        ),
        "every length guard is against nb = ama_nistp_field_bytes(curve) or "
        "pub_len = ama_nistp_pubkey_bytes(curve): runtime lookups, but ranging "
        "over exactly three curves, so each is bounded by its P-521 value -- "
        "nb <= 66 (AMA_NISTP_MAX_FIELD_BYTES) and pub_len <= 132 "
        "(AMA_NISTP_MAX_PUBKEY_BYTES). Guard by guard: `2u * nb` <= 132 "
        "(case 1, raw r || s); `pub_len` <= 132 (case 4, a public key); "
        "`pub_len + 1u` <= 133 (case 3, a public key plus at least one "
        "signature octet); `nb` <= 66 (default case, a private scalar); and "
        "the widest, `nb + pub_len` <= 198 (default case, scalar plus peer "
        "key). 198 plus the 2-byte header -- data[0] curve selector, data[1] "
        "case selector -- before the payload gives 200. The sixth, "
        "`again_len != payload_len || memcmp(...)` (case 0), is the DER "
        "round-trip assertion: its true branch is a codec defect and is "
        "reachable at no length if the codec is correct; its false branch is "
        "any DER signature the parser accepts, the longest of which (P-521: "
        "a 3-byte SEQUENCE header and two 69-byte INTEGERs, 141 bytes) is "
        "inside the same 200",
    ),
    "fuzz_frost": ManualBound(
        780,
        ("payload_len < needed",),
        "case 2 gates on `needed = threshold*32 + threshold*64 + threshold + 1`, "
        "and `threshold = 2 + data[1] % (FROST_FUZZ_MAX_N - 1)` is bounded by "
        "FROST_FUZZ_MAX_N = 8, so needed <= 8*32 + 8*64 + 8 + 1 = 777, plus the "
        "3-byte header before the payload",
    ),
    "fuzz_sha3": ManualBound(
        2,
        ("payload_len > offset",),
        "case 2's `while (offset < payload_len)` chunked-absorb loop: `offset` "
        "starts at 0 and only grows by the chunk it absorbs, so the body is "
        "entered iff payload_len >= 1 and the loop exits for every length. "
        "1 payload byte plus the 1-byte case selector is 2",
    ),
    "fuzz_hkdf": ManualBound(
        0,
        ("rest_len < salt_len + ikm_len",),
        "`if (salt_len + ikm_len > rest_len)` is a defensive clamp on the "
        "salt/ikm split, not a length floor: salt_len = rest_len*salt_frac/512 "
        "and ikm_len = rest_len*ikm_frac/512 with both fractions a uint8_t "
        "(<= 255), so salt_len + ikm_len <= rest_len*510/512 < rest_len for "
        "every rest_len > 0 and the clamp's true branch is taken at NO input "
        "length -- no -max_len reaches it, and none is needed for the false "
        "branch, which every input takes. It contributes no bound",
    ),
    "fuzz_agent_binding": ManualBound(
        0,
        ("key_len > tail_len (unparseable comparison)",),
        "`if (key_len > tail_len) key_len = tail_len;` is a defensive clamp, not "
        "a length floor: key_len = ((control >> 1) * tail_len) / 128 with control "
        "a uint8_t, so control >> 1 <= 127 and key_len <= tail_len*127/128 <= "
        "tail_len for every tail_len -- the clamp's true branch is taken at NO "
        "input length and its false branch by every input. It contributes no "
        "bound",
    ),
}

_DEFINE_RE = re.compile(r"^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)\s+(?P<value>\d+)\s*$", re.M)
#: Every comparison operator, two-character forms first (alternation is
#: ordered: ``<|<=`` would take the ``<`` of ``<=``).  Shifts (``<<``, ``>>``,
#: ``<<=``, ``>>=``), ``->`` and assignments are not comparisons and are
#: excluded by the look-arounds.
#:
#: History, because each of these was once a guard that produced no signal:
#: the alternation was ``(?P<op><|==)``, so ``size <= 65536`` matched nowhere
#: (the ``=`` blocked the expression class); the variable was the literal
#: ``payload_len|size``, so ``tail_len < N`` on a derived length was
#: invisible; the variable had to sit immediately LEFT of the operator, so
#: ``N > payload_len`` and ``payload_len - 1 < N`` were invisible; and ``!=``
#: was not an operator at all.  The fail-closed path only fires for a guard
#: the scan SEES, so every one of those printed "every harness branch is
#: reachable" over a branch nobody examined.
_CMP_OP_RE = re.compile(r"(?<![<>=!\-])(?P<op><=|>=|==|!=|<|>)(?![<>=])")
#: `name = size - K;` / `name = payload_len - K1 - K2;` / `name = size;` —
#: the assignment shapes that make a variable a pure constant offset of the
#: input length.  The subtractions must each resolve (digits or macros).
_DERIVED_LEN_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<base>[A-Za-z_]\w*)"
    r"(?P<subs>(?:\s*-\s*[A-Za-z_0-9]+)*)\s*;"
)
#: Any plain assignment to a name (not ==, !=, <=, >=, or a compound op).
_ANY_ASSIGN_RE = re.compile(r"\b(?P<var>[A-Za-z_]\w*)\s*(?<![=!<>+*/%&|^-])=(?!=)")
_WORKFLOW_MAX_LEN_RE = re.compile(r"-max_len=(?P<value>\S+)")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def _macros(*paths: Path) -> dict[str, int]:
    table: dict[str, int] = {}
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        for match in _DEFINE_RE.finditer(path.read_text(encoding="utf-8")):
            table[match.group("name")] = int(match.group("value"))
    return table


def _resolve(expr: str, macros: dict[str, int]) -> int | None:
    """A sum of integer literals and known macros, or None.

    Parentheses around a pure sum are stripped — they cannot change a sum —
    so ``(N + 1)`` resolves.  Anything multiplicative, or with unbalanced
    parentheses (the lazy guard match can capture ``(N + 1`` out of a larger
    expression), returns None and therefore lands in ``unresolved``: a
    MANUAL_BOUNDS decision, never a silently wrong bound.
    """
    expr = expr.strip()
    if "*" in expr:
        return None
    if "(" in expr or ")" in expr:
        if expr.count("(") != expr.count(")"):
            return None
        expr = expr.replace("(", " ").replace(")", " ")
    total = 0
    for term in expr.split("+"):
        term = term.strip()
        if not term:
            return None
        if term.isdigit():
            total += int(term)
        elif term in macros:
            total += macros[term]
        else:
            return None
    return total


def _input_offsets(flat: str, macros: dict[str, int]) -> dict[str, int | None]:
    """Variables that are a pure constant offset of the input length.

    ``size`` (the fuzzer's own parameter) is offset 0.  A variable assigned
    ``base - K1 - K2...`` where ``base`` is already in the table and every
    subtrahend resolves inherits ``offset(base) + sum(K)``; a bare copy
    (``x = payload_len;``) inherits the offset unchanged.  A variable whose
    derivations conflict, or whose derivation subtracts something
    data-dependent (``pt_len = payload_len - aad_len`` where ``aad_len``
    comes out of the input bytes), maps to None: its guards are NOT
    input-length floors — the variable can be small at any input size — so
    they are reported (see :func:`unmodeled_guards`) rather than modeled.

    Two passes, so a derivation written before this scan reaches its base
    still resolves regardless of text order.
    """
    offsets: dict[str, int | None] = {"size": 0}
    # Every assignment to a name, vs. its assignments in the clean derived
    # shape.  A variable with any assignment OUTSIDE the clean shape is
    # poisoned even when one clean assignment exists: `key_len = ((...) *
    # tail_len) / 128u;` does not match the clean shape at all, and its
    # clamp `key_len = tail_len;` does — counting only the clean matches
    # would promote a data-dependent length to a tracked one on the
    # strength of its own clamp.
    assignments: dict[str, int] = {}
    for match in _ANY_ASSIGN_RE.finditer(flat):
        name = match.group("var")
        assignments[name] = assignments.get(name, 0) + 1
    clean: dict[str, int] = {}
    for match in _DERIVED_LEN_RE.finditer(flat):
        name = match.group("var")
        clean[name] = clean.get(name, 0) + 1
    for _ in range(2):
        for match in _DERIVED_LEN_RE.finditer(flat):
            var, base = match.group("var"), match.group("base")
            if var == "size":
                continue
            if assignments.get(var, 0) != clean.get(var, 0):
                offsets[var] = None
                continue
            if base not in offsets:
                # Not derived from the input length; a reassignment of a
                # tracked name from elsewhere makes that name ambiguous.
                if var in offsets:
                    offsets[var] = None
                continue
            base_offset = offsets[base]
            value: int | None
            if base_offset is None:
                value = None
            else:
                value = base_offset
                for sub in re.findall(r"-\s*([A-Za-z_0-9]+)", match.group("subs")):
                    resolved = _resolve(sub, macros)
                    if resolved is None:
                        value = None
                        break
                    value += resolved
            if var in offsets and offsets[var] != value:
                offsets[var] = None
            else:
                offsets[var] = value
    # Compatibility floor: every harness names its post-selector input
    # `payload_len`; if a harness spells the derivation in a shape this scan
    # does not recognise, guards on it are still modeled at offset 0 (the
    # pre-scan behaviour) rather than dropped.
    if offsets.get("payload_len") is None:
        offsets["payload_len"] = 0
    return offsets


#: A C cast at the front of an operand: ``(size_t)payload_len``.
_CAST_RE = re.compile(
    r"^\(\s*(?:const\s+)?(?:(?:unsigned|signed)\s+)?"
    r"(?:size_t|ssize_t|u?int(?:8|16|32|64)_t|int|long|short|char|unsigned|signed)"
    r"(?:\s+(?:long|int))*\s*\)\s*"
)
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


class Comparison(NamedTuple):
    """One comparison in a harness, split into its operands."""

    #: Offset of the operator in the flattened source.
    at: int
    left: str
    op: str
    right: str
    #: What ends the right operand: ``)``, ``&&``, ``||``, ``?``, ``;``, ...
    terminator: str
    #: True when the comparison closes an ``if``/``while`` condition (see
    #: :func:`_comparison_context`), False in expression context.
    guard: bool


def _balanced_outer(text: str) -> bool:
    """True when ``text``'s first ``(`` is closed by its last ``)``."""
    depth = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
    return depth == 0


def _normalise(operand: str) -> str:
    """An operand without surrounding space, ``return``, casts, or outer parens."""
    text = operand.strip()
    if text.startswith("return "):
        text = text[len("return ") :].strip()
    while True:
        cast = _CAST_RE.match(text)
        if cast is not None and cast.end() < len(text):
            text = text[cast.end() :].strip()
            continue
        if text.startswith("(") and text.endswith(")") and _balanced_outer(text):
            text = text[1:-1].strip()
            continue
        return text


def _skeleton(operand: str) -> str:
    """``operand`` with call argument lists and subscripts removed.

    A length passed to a function (``f(payload, payload_len) != AMA_SUCCESS``)
    or used as an index (``payload[payload_len - 1]``) is not being compared.
    """
    out: list[str] = []
    depth = 0
    index = 0
    while index < len(operand):
        char = operand[index]
        if depth:
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            index += 1
            continue
        if char == "[" or (char == "(" and re.search(r"[A-Za-z_0-9]\s*$", "".join(out))):
            depth = 1
            out.append(" CALL ")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _left_extent(flat: str, at: int) -> int:
    """Start of the operand that ends at ``at`` (an operator's position)."""
    depth = 0
    index = at
    while index > 0:
        char = flat[index - 1]
        if char in ")]":
            depth += 1
        elif char in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if flat[index - 2 : index] == "->":
                index -= 2
                continue
            if char in ";{},?:=<>!" or flat[index - 2 : index] in ("&&", "||"):
                break
        index -= 1
    return index


def _right_extent(flat: str, start: int) -> int:
    """End of the operand that starts at ``start`` (just past an operator)."""
    depth = 0
    index = start
    while index < len(flat):
        char = flat[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if flat[index : index + 2] == "->":
                index += 2
                continue
            if char in ";{},?:=<>!" or flat[index : index + 2] in ("&&", "||"):
                break
        index += 1
    return index


def _comparisons(flat: str) -> list[Comparison]:
    """Every comparison in ``flat``, with both operands and its context."""
    found: list[Comparison] = []
    for match in _CMP_OP_RE.finditer(flat):
        left_start = _left_extent(flat, match.start())
        right_end = _right_extent(flat, match.end())
        terminator = flat[right_end : right_end + 2]
        if terminator not in ("&&", "||"):
            terminator = terminator[:1]
        found.append(
            Comparison(
                at=match.start(),
                left=flat[left_start : match.start()],
                op=match.group("op"),
                right=flat[match.end() : right_end],
                terminator=terminator,
                guard=_comparison_context(flat, right_end) == ")",
            )
        )
    return found


#: ``N op var`` is ``var flip(op) N``.
_FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


class _Classified(NamedTuple):
    """A comparison as this gate reads it."""

    #: The length variables it mentions (outside call arguments/subscripts).
    lengths: tuple[str, ...]
    #: ``(var, op, expr)`` with the tracked variable moved to the left, when
    #: one operand IS a tracked length and the other mentions none.
    canonical: tuple[str, str, str] | None


def _classify(cmp: Comparison, offsets: dict[str, int | None]) -> _Classified:
    left, right = _normalise(cmp.left), _normalise(cmp.right)
    left_names = set(_IDENT_RE.findall(_skeleton(left)))
    right_names = set(_IDENT_RE.findall(_skeleton(right)))
    lengths = tuple(sorted(name for name in left_names | right_names if name in offsets))
    tracked = {name for name, offset in offsets.items() if offset is not None}
    canonical: tuple[str, str, str] | None = None
    if left in tracked and not right_names & set(offsets):
        canonical = (left, cmp.op, right)
    elif right in tracked and not left_names & set(offsets):
        canonical = (right, _FLIP[cmp.op], left)
    return _Classified(lengths, canonical)


def _render(cmp: Comparison, classified: _Classified) -> str:
    """The exact text an unresolved guard is reported (and declared) as."""
    if classified.canonical is not None:
        var, op, expr = classified.canonical
        text = f"{var} {op} {expr}"
        return f"{text} (in a || condition)" if cmp.terminator == "||" else text
    raw = re.sub(r"\s+", " ", f"{_normalise(cmp.left)} {cmp.op} {_normalise(cmp.right)}")
    return f"{raw} (unparseable comparison)"


def _needed(op: str, value: int) -> int:
    """How many units of the variable make BOTH branches of ``var op value`` reachable.

    Measured, not reasoned about in the abstract: libFuzzer's ``-max_len`` is
    INCLUSIVE (a harness trapping past ``if (payload_len < 100) return 0;``
    with a 1-byte selector traps under ``-max_len=101`` and never under 100,
    clang 18 libFuzzer, 2026-09-24), so:

      var <  N   true below N, false AT N              -> N
      var <= N   false needs N+1                        -> N+1
      var == N   true AT N, false anywhere else         -> N
      var != N   the same two points                    -> N
      var >  N   true needs N+1                         -> N+1
      var >= N   true AT N                              -> N

    The ``<`` row used to add one, contradicting the comment that stated this
    table, so every ``<`` ceiling was one byte past the smallest that works.
    """
    return value + (1 if op in ("<=", ">") else 0)


def _analyse(harness: Path) -> tuple[str, dict[str, int], dict[str, int | None]]:
    macros = _macros(PUBLIC_HEADER, harness)
    flat = re.sub(r"\s+", " ", _strip_comments(harness.read_text(encoding="utf-8")))
    return flat, macros, _input_offsets(flat, macros)


def required_max_len(harness: Path) -> tuple[int, list[str]]:
    """The smallest -max_len that makes every branch reachable, and the
    unresolved guards found on the way.

    Guards are collected on ``size``, ``payload_len``, and every variable
    :func:`_input_offsets` proves is a constant offset of the input length —
    so a harness gating on a derived name (``tail_len``, ``msg_len``) is
    modeled rather than invisible — on either side of the operator.

    A comparison in guard context (it closes an ``if``/``while`` condition)
    that mentions a tracked length is either MODELED — one operand is exactly
    the length, the other resolves to a constant, and the comparison ends the
    condition or leads an ``&&`` — or it is UNRESOLVED and must be declared in
    :data:`MANUAL_BOUNDS`.  There is no third outcome: that was the defect.
    ``A || B`` stays unresolved, as it always has — ``A`` false does not stop
    the branch — and so does any arithmetic on the length's own side.  Guards
    on data-dependent lengths are not length floors and are surfaced by
    :func:`unmodeled_guards` instead.
    """
    flat, macros, offsets = _analyse(harness)
    required = 0
    unresolved: list[str] = []
    for cmp in _comparisons(flat):
        if not cmp.guard:
            continue
        classified = _classify(cmp, offsets)
        if not any(offsets[name] is not None for name in classified.lengths):
            continue  # untracked, or data-dependent only: not a length floor
        if classified.canonical is None or cmp.terminator not in (")", "&&"):
            unresolved.append(_render(cmp, classified))
            continue
        var, op, expr = classified.canonical
        value = _resolve(expr, macros)
        offset = offsets[var]
        if value is None or offset is None:
            unresolved.append(_render(cmp, classified))
            continue
        # Relative to the whole input via the variable's derived offset
        # (0 for `size` itself).
        required = max(required, _needed(op, value) + offset)
    return required, unresolved


def _comparison_context(flat: str, end: int) -> str:
    """The first of ``) ? ;`` after a comparison: guard vs. expression.

    ``)`` first means the comparison closes an ``if``/``while`` condition —
    guard context, where an unparsed expression must fail closed.  ``?`` or
    ``;`` first means it selects or assigns a value (a clamp), which is not
    a length floor.
    """
    for ch in flat[end:]:
        if ch in ")?;":
            return ch
    return ";"


def unmodeled_guards(harness: Path) -> list[str]:
    """Length comparisons that contribute no bound, rendered for reporting.

    Two classes, both deliberate non-floors and both VISIBLE rather than
    silently dropped (main() prints them):

    * comparisons on a DATA-DEPENDENT length — ``pt_len = payload_len -
      aad_len`` with ``aad_len`` read out of the input bytes can be small at
      any input size, so its guards say nothing about the input length;
    * comparisons on a tracked length in EXPRESSION context — clamp
      ternaries (``payload_len > 32 ? 32 : payload_len``) and loop conditions
      select a value or bound an iteration, they do not gate a branch on a
      minimum input.
    """
    flat, _macros_table, offsets = _analyse(harness)
    rendered: list[str] = []
    for cmp in _comparisons(flat):
        classified = _classify(cmp, offsets)
        if not classified.lengths:
            continue
        data_dependent = all(offsets[name] is None for name in classified.lengths)
        if cmp.guard and not data_dependent:
            continue  # guard context on a tracked length: required_max_len owns it
        context = flat[_left_extent(flat, cmp.at) : cmp.at + 40].strip()
        kind = "data-dependent length" if data_dependent else "value-select clamp"
        rendered.append(f"`{context}...` ({kind})")
    return rendered


def _harnesses() -> list[Path]:
    return sorted(p for p in FUZZ_DIR.glob("fuzz_*.c") if p.name != "fuzz_rng.c")


def _bound_for(harness: Path) -> tuple[int, list[str]]:
    """The ceiling for one harness, and the guards still unaccounted for.

    A MANUAL_BOUNDS entry used to clear `unresolved` OUTRIGHT.  Its reason
    string explains ONE guard — the one whose expression this tool's arithmetic
    cannot evaluate — but the assignment discarded every other unresolved guard
    in the same harness, including ones added later.  So the moment a harness
    needed one manual bound it stopped being checked at all, which is the
    opposite of what an entry documenting a single exception should buy.

    The replacement dropped a guard when its expression occurred anywhere in
    the reason's prose, as a substring — so ``payload_len < n`` was covered by
    any reason containing an ``n``.  An entry now names its guards exactly
    (:attr:`ManualBound.guards`) and clears those and only those.
    """
    required, unresolved = required_max_len(harness)
    manual = MANUAL_BOUNDS.get(harness.stem)
    if manual is not None:
        required = max(required, manual.bound)
        unresolved = [guard for guard in unresolved if guard not in manual.guards]
    return required, unresolved


def stale_declarations(harness: Path) -> list[str]:
    """Guards a MANUAL_BOUNDS entry declares that the harness no longer has.

    A declaration that outlives its guard is an exemption waiting for the next
    guard that happens to render the same way.
    """
    manual = MANUAL_BOUNDS.get(harness.stem)
    if manual is None:
        return []
    _required, unresolved = required_max_len(harness)
    return [guard for guard in manual.guards if guard not in unresolved]


#: Committed seed corpora, one directory per target.
SEED_CORPUS_ROOT = REPO_ROOT / "fuzz" / "seed_corpus"


def largest_seed(target: str) -> int:
    """The size of `target`'s largest committed seed, or 0 if it has none.

    libFuzzer applies ``-max_len`` to CORPUS FILES as well as to mutations: a
    seed longer than the ceiling enters the in-memory corpus TRUNCATED.  The
    ceiling was derived from the deepest guard alone, and the PQC verify seeds
    are built as ``1 + bound + MESSAGE_BYTES`` — 5,278 and 49,937 bytes —
    against the ceilings then derived, 5,263 and 49,922 (each one byte above
    the true minimum, 5,262 and 49,921: the ``<`` row of :func:`_needed` added
    one until 2026-09-24).  Every seed the corpus
    builder writes for those two targets was therefore truncated on load, by
    15 bytes, landing just short of the branch it was constructed to reach.
    That is the same defect the ceiling derivation was introduced to fix,
    reintroduced from the other side.
    """
    directory = SEED_CORPUS_ROOT / target
    if not directory.is_dir():
        return 0
    return max((path.stat().st_size for path in directory.glob("*") if path.is_file()), default=0)


def max_len_for(target: str) -> int:
    harness = FUZZ_DIR / f"{target}.c"
    if not harness.is_file():
        raise FileNotFoundError(harness)
    required, _ = _bound_for(harness)
    return max(DEFAULT_MAX_LEN, required, largest_seed(target))


def _workflow_derives_its_ceiling() -> list[str]:
    """The workflow must ASK this tool, not restate a number.

    A hard-coded ``-max_len`` is how the unreachable branches arose; if one
    comes back, the table below would still be right and the lane would still
    be wrong.
    """
    if not WORKFLOW.is_file():
        raise FileNotFoundError(WORKFLOW)
    text = WORKFLOW.read_text(encoding="utf-8")
    problems = []
    for match in _WORKFLOW_MAX_LEN_RE.finditer(text):
        value = match.group("value")
        if not value.startswith('"$') and not value.startswith("$"):
            problems.append(
                f"-max_len={value} is written into the workflow. Derive it with "
                f"`python3 tools/check_fuzz_input_reachability.py --max-len <target>` "
                f"so the fuzzer's ceiling comes from the harness rather than from a "
                f"number that can fall behind it."
            )
    if not _WORKFLOW_MAX_LEN_RE.search(text):
        problems.append("no -max_len in the fuzzing workflow at all; this gate has no subject")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-len",
        metavar="TARGET",
        help="print the -max_len that makes every branch of TARGET reachable",
    )
    args = parser.parse_args(argv)

    try:
        if args.max_len:
            print(max_len_for(args.max_len))
            return 0
        harnesses = _harnesses()
        if not harnesses:
            print("FATAL: no fuzz harnesses found; this gate would pass vacuously.")
            return 2

        problems: list[str] = []
        rows: list[tuple[str, int, int, int]] = []
        for harness in harnesses:
            required, unresolved = _bound_for(harness)
            for guard in unresolved:
                problems.append(
                    f"{harness.name}: guard `{guard}` does not resolve to a constant. "
                    f"Declare it, exactly as written here, in MANUAL_BOUNDS[{harness.stem!r}] "
                    f"with the bound and how it is obtained — a guard this gate skips "
                    f"is a branch that can go unreachable unnoticed."
                )
            for guard in stale_declarations(harness):
                problems.append(
                    f"{harness.name}: MANUAL_BOUNDS[{harness.stem!r}] declares `{guard}`, "
                    f"which is not an unresolved guard in the harness. Remove it: a "
                    f"declaration with no subject would clear the next guard that "
                    f"renders the same."
                )
            # The ceiling the LANE uses, which is what max_len_for returns —
            # the deepest guard AND the largest committed seed.  The table
            # printed max(DEFAULT_MAX_LEN, required), so it reported a number
            # the workflow does not pass.
            seed = largest_seed(harness.stem)
            ceiling = max(DEFAULT_MAX_LEN, required, seed)
            rows.append((harness.stem, required, seed, ceiling))

        problems.extend(_workflow_derives_its_ceiling())

        print(f"{'target':<24}{'deepest guard':>15}{'largest seed':>14}{'-max_len':>12}")
        for name, required, seed, ceiling in rows:
            marker = "  <- raised" if ceiling > DEFAULT_MAX_LEN else ""
            print(f"{name:<24}{required:>15,}{seed:>14,}{ceiling:>12,}{marker}")

        # Guards on data-dependent lengths contribute no bound BY DESIGN
        # (the variable can be small at any input size), but they are shown
        # rather than silently dropped — the no-signal state is the failure
        # mode this whole gate exists to prevent.
        for harness in harnesses:
            for guard in unmodeled_guards(harness):
                print(
                    f"note: {harness.stem}: {guard} — not an input-length "
                    f"floor, contributes no bound."
                )

        if problems:
            print("\nFUZZ INPUT REACHABILITY CHECK FAILED:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print(
            "\nOK: every input-length-gated harness branch is reachable under "
            "the ceiling its lane uses."
        )
        return 0
    except FileNotFoundError as exc:
        print(f"FATAL: {exc} is missing; refusing to report a clean gate.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
