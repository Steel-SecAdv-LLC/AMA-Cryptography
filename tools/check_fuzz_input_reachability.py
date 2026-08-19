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
_GUARD_RE = re.compile(
    r"\b(?P<var>payload_len|size)\s*(?P<op><|==)\s*(?P<expr>[A-Za-z_0-9][A-Za-z_0-9 +]*?)\s*\)"
)
_PAYLOAD_OFFSET_RE = re.compile(r"payload_len\s*=\s*size\s*-\s*(?P<offset>\d+)")
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
    """A sum of integer literals and known macros, or None."""
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


def required_max_len(harness: Path) -> tuple[int, list[str]]:
    """The smallest -max_len that makes every branch reachable, and the
    unresolved guards found on the way."""
    macros = _macros(PUBLIC_HEADER, harness)
    body = _strip_comments(harness.read_text(encoding="utf-8"))
    flat = re.sub(r"\s+", " ", body)

    offset_match = _PAYLOAD_OFFSET_RE.search(flat)
    payload_offset = int(offset_match.group("offset")) if offset_match else 0

    required = 0
    unresolved: list[str] = []
    for match in _GUARD_RE.finditer(flat):
        value = _resolve(match.group("expr"), macros)
        if value is None:
            unresolved.append(f"{match.group('var')} {match.group('op')} {match.group('expr')}")
            continue
        # `<` needs one more byte than the bound to get past it; `==` needs
        # exactly the bound.  Both are relative to the payload for a
        # payload_len guard, and to the whole input for a size guard.
        needed = value + (1 if match.group("op") == "<" else 0)
        if match.group("var") == "payload_len":
            needed += payload_offset
        required = max(required, needed)
    return required, unresolved


def _harnesses() -> list[Path]:
    return sorted(p for p in FUZZ_DIR.glob("fuzz_*.c") if p.name != "fuzz_rng.c")


def _bound_for(harness: Path) -> tuple[int, list[str]]:
    required, unresolved = required_max_len(harness)
    manual = MANUAL_BOUNDS.get(harness.stem)
    if manual is not None:
        required = max(required, manual[0])
        unresolved = []
    return required, unresolved


def max_len_for(target: str) -> int:
    harness = FUZZ_DIR / f"{target}.c"
    if not harness.is_file():
        raise FileNotFoundError(harness)
    required, _ = _bound_for(harness)
    return max(DEFAULT_MAX_LEN, required)


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
        rows: list[tuple[str, int, int]] = []
        for harness in harnesses:
            required, unresolved = _bound_for(harness)
            for guard in unresolved:
                problems.append(
                    f"{harness.name}: guard `{guard}` does not resolve to a constant. "
                    f"Add {harness.stem!r} to MANUAL_BOUNDS with the bound and how it "
                    f"is obtained — a guard this gate skips is a branch that can go "
                    f"unreachable unnoticed."
                )
            ceiling = max(DEFAULT_MAX_LEN, required)
            rows.append((harness.stem, required, ceiling))

        problems.extend(_workflow_derives_its_ceiling())

        print(f"{'target':<24}{'deepest guard':>15}{'-max_len':>12}")
        for name, required, ceiling in rows:
            marker = "  <- raised" if ceiling > DEFAULT_MAX_LEN else ""
            print(f"{name:<24}{required:>15,}{ceiling:>12,}{marker}")

        if problems:
            print("\nFUZZ INPUT REACHABILITY CHECK FAILED:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print("\nOK: every harness branch is reachable under the ceiling its lane uses.")
        return 0
    except FileNotFoundError as exc:
        print(f"FATAL: {exc} is missing; refusing to report a clean gate.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
