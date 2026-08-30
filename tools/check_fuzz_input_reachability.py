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
``payload_len < N``, ``payload_len == N`` — resolves ``N`` against the
harness's own ``#define``s and the public header's, adds the payload's offset
within the input, and takes the maximum.  That is the smallest ``-max_len``
under which every branch is reachable.  ``--max-len TARGET`` prints it, which
is what the workflow uses, so the fuzzer's ceiling is derived from the
harness instead of written down twice.

An expression it cannot resolve statically is NOT ignored.  It must be listed
in :data:`MANUAL_BOUNDS` with the bound and the reasoning, or this gate fails
— because a guard the tool silently skipped is exactly the branch that would
go unreachable again.

Exit status
-----------
0  every branch in every harness is reachable under the lane's ``-max_len``
1  a branch is unreachable, or a guard could not be resolved and is not
   declared, or the workflow stopped deriving its ceiling from this tool
2  an input this gate must read is missing (fail closed)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FUZZ_DIR = REPO_ROOT / "fuzz"
PUBLIC_HEADER = REPO_ROOT / "include" / "ama_cryptography.h"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "fuzzing.yml"

#: The floor.  Not a requirement of any harness — it is the general mutation
#: budget the lane has always used, kept so raising a ceiling for one target
#: does not quietly lower it for another.
DEFAULT_MAX_LEN = 4096

#: Guards whose bound is a runtime value this gate cannot evaluate, with the
#: bound worked out by hand and the reasoning that gets it.  Anything not
#: listed here and not statically resolvable fails the gate.
MANUAL_BOUNDS: dict[str, tuple[int, str]] = {
    "fuzz_frost": (
        780,
        "case 2 gates on `needed = threshold*32 + threshold*64 + threshold + 1`, "
        "and `threshold = 2 + data[1] % (FROST_FUZZ_MAX_N - 1)` is bounded by "
        "FROST_FUZZ_MAX_N = 8, so needed <= 8*32 + 8*64 + 8 + 1 = 777, plus the "
        "3-byte header before the payload",
    ),
}

_DEFINE_RE = re.compile(r"^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)\s+(?P<value>\d+)\s*$", re.M)
#: Every comparison of a length variable against something, not just `<` and
#: `==`.
#:
#: The alternation used to be `(?P<op><|==)`, which matches `<` and then
#: requires the expression to start with `[A-Za-z_0-9]`.  For `size <= 65536)`
#: the `=` blocks that, so the pattern failed to match ANYWHERE on the guard —
#: contributing neither a bound nor an entry in `unresolved`.  The fail-closed
#: path only fires for guards that MATCH but will not resolve, so a guard the
#: regex never matched produced no signal at all, under an error message
#: reading "a guard this gate skips is a branch that can go unreachable
#: unnoticed" and a success line reading "every harness branch is reachable
#: under the ceiling its lane uses".  `>=`, `>` and `<=` are all ordinary ways
#: to write a size floor.
#:
#: The two-character operators come FIRST in the alternation: regex
#: alternation is ordered, so `<|<=` would match the `<` of `<=` and leave the
#: `=` to fail the expression class all over again.
#:
#: The variable is ANY C identifier, filtered afterwards against the
#: input-derived offset table (see :func:`_input_offsets`).  It used to be the
#: literal alternation `payload_len|size`, so a harness that derived another
#: length variable and gated on it — `tail_len = size - FUZZ_HEADER_BYTES;`
#: then `if (tail_len < N)` — produced no bound and no `unresolved` entry:
#: the exact no-signal failure mode the comment above documents for `<=`
#: guards, one level up.
#:
#: The expression class admits parentheses and `*` so those spellings are
#: MATCHED and land in `unresolved` (fail closed, a MANUAL_BOUNDS decision)
#: when :func:`_resolve` cannot evaluate them, instead of contributing no
#: signal at all.
#: The expression is a sequence of plain atoms and single-level balanced
#: paren groups, so `size < (N + 1))` captures `(N + 1)` whole instead of
#: the lazy `(N + 1` that the flat char class produced (which then failed to
#: resolve as unbalanced).  Deeper nesting does not match at all — the
#: completeness check in required_max_len turns that into an `unresolved`
#: entry rather than a silent skip.
_GUARD_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*(?P<op><=|>=|==|<|>)\s*"
    r"(?P<expr>(?:[A-Za-z_0-9 +*]|\([A-Za-z_0-9 +*]*\))+?)\s*\)"
)
#: Every comparison operator occurrence, shifts included so they can be
#: recognised and skipped; used to prove _GUARD_RE missed nothing on a
#: tracked variable.
_CMP_ANY_RE = re.compile(r"\b(?P<var>[A-Za-z_]\w*)\s*(?P<op><=|>=|==|<<|>>|<|>)")
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


def required_max_len(harness: Path) -> tuple[int, list[str]]:
    """The smallest -max_len that makes every branch reachable, and the
    unresolved guards found on the way.

    Guards are collected on ``size``, ``payload_len``, and every variable
    :func:`_input_offsets` proves is a constant offset of the input length —
    so a harness gating on a derived name (``tail_len``, ``msg_len``) is
    modeled rather than invisible.  Guards on data-dependent lengths are not
    length floors and are surfaced by :func:`unmodeled_guards` instead.
    """
    macros = _macros(PUBLIC_HEADER, harness)
    body = _strip_comments(harness.read_text(encoding="utf-8"))
    flat = re.sub(r"\s+", " ", body)
    offsets = _input_offsets(flat, macros)

    required = 0
    unresolved: list[str] = []
    modeled_at: set[int] = set()
    for match in _GUARD_RE.finditer(flat):
        var = match.group("var")
        offset = offsets.get(var)
        if offset is None:
            # Untracked identifier (a loop counter, a macro, a data-dependent
            # length): not an input-length guard.
            continue
        modeled_at.add(match.start())
        value = _resolve(match.group("expr"), macros)
        if value is None:
            unresolved.append(f"{var} {match.group('op')} {match.group('expr')}")
            continue
        # How many bytes make the guard's TRUE branch reachable, per operator:
        #
        #   size <  N   the branch is taken below N, so N-1 suffices — but the
        #               FALSE branch needs N, and both must be reachable, so N.
        #   size <= N   likewise, one more: N+1.
        #   size == N   exactly N.
        #   size >  N   N+1.
        #   size >= N   N.
        #
        # Relative to the whole input via the variable's derived offset
        # (0 for `size` itself).
        operator = match.group("op")
        needed = value + (1 if operator in ("<", "<=", ">") else 0) + offset
        required = max(required, needed)

    # Completeness: every GUARD-shaped comparison on a variable this scan
    # tracks must have been either modeled above or already reported.  A
    # guard whose expression _GUARD_RE cannot parse at all (deep nesting, a
    # spelling outside the atom classes) would otherwise contribute NO
    # signal — the exact failure mode this gate exists to prevent.  A
    # comparison in EXPRESSION context — a clamp ternary
    # (`payload_len > 32 ? 32 : payload_len`) or a statement — is not a
    # reachability guard; those are surfaced by unmodeled_guards() instead.
    for match in _CMP_ANY_RE.finditer(flat):
        if match.group("op") in ("<<", ">>"):
            continue
        var = match.group("var")
        if offsets.get(var) is None or match.start() in modeled_at:
            continue
        if _comparison_context(flat, match.end()) != ")":
            continue
        context = flat[match.start() : match.start() + 60]
        unresolved.append(f"{var} (unparseable comparison: `{context.strip()}...`)")
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
      ternaries (``payload_len > 32 ? 32 : payload_len``) select a value,
      they do not gate a branch on a minimum input.
    """
    macros = _macros(PUBLIC_HEADER, harness)
    flat = re.sub(r"\s+", " ", _strip_comments(harness.read_text(encoding="utf-8")))
    offsets = _input_offsets(flat, macros)
    modeled_at = {
        match.start()
        for match in _GUARD_RE.finditer(flat)
        if offsets.get(match.group("var")) is not None
    }
    rendered: list[str] = []
    for match in _CMP_ANY_RE.finditer(flat):
        if match.group("op") in ("<<", ">>"):
            continue
        var = match.group("var")
        if var not in offsets:
            continue
        if match.start() in modeled_at:
            continue
        if offsets[var] is not None and _comparison_context(flat, match.end()) == ")":
            continue  # guard context on a tracked var: required_max_len fails it
        context = flat[match.start() : match.start() + 48].strip()
        kind = "data-dependent length" if offsets[var] is None else "value-select clamp"
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

    The declared bound still raises the ceiling; what it no longer does is
    silence the rest of the file.
    """
    required, unresolved = required_max_len(harness)
    manual = MANUAL_BOUNDS.get(harness.stem)
    if manual is not None:
        required = max(required, manual[0])
        # Drop only the guards the entry's own reason accounts for: those whose
        # expression appears verbatim in it.  Anything else stays unresolved.
        reason = manual[1]
        unresolved = [guard for guard in unresolved if _guard_expression(guard) not in reason]
    return required, unresolved


def _guard_expression(guard: str) -> str:
    """The right-hand side of a rendered ``"<var> <op> <expr>"`` guard."""
    parts = guard.split(None, 2)
    return parts[2] if len(parts) == 3 else guard


#: Committed seed corpora, one directory per target.
SEED_CORPUS_ROOT = REPO_ROOT / "fuzz" / "seed_corpus"


def largest_seed(target: str) -> int:
    """The size of `target`'s largest committed seed, or 0 if it has none.

    libFuzzer applies ``-max_len`` to CORPUS FILES as well as to mutations: a
    seed longer than the ceiling enters the in-memory corpus TRUNCATED.  The
    ceiling was derived from the deepest guard alone, and the PQC verify seeds
    are built as ``1 + bound + MESSAGE_BYTES`` — 5,278 and 49,937 bytes —
    against derived ceilings of 5,263 and 49,922.  Every seed the corpus
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
                    f"Add {harness.stem!r} to MANUAL_BOUNDS with the bound and how it "
                    f"is obtained — a guard this gate skips is a branch that can go "
                    f"unreachable unnoticed."
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
