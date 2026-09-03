#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Classify how each PR394 claim was reproduced, and re-type the verdicts.

Why this exists
---------------
``PR394_CLAIMS.yaml`` recorded one verdict per claim — confirmed / refuted /
unverifiable — and the attestation reported the ratio as "1,815 executed
reproductions".  It was not one.  Counted here, 1,279 of the 1,815
reproductions are ``grep``/``sed``/``git``/``ls``: they establish that a string
is where a document says it is.  For a claim ABOUT a document that is exactly
the right evidence.  For a claim about run-time behaviour it is not evidence at
all, and 638 claims typed ``behavioural`` were marked confirmed on that basis.

So a verdict alone cannot carry the meaning.  This adds two fields to every
claim and re-types the verdict where the method cannot support it:

``method``
    How the reproduction observed the subject:

    ``executed``        ran a program that consumes the subject and whose exit
                        code or output IS the observation — a gate script, a
                        test binary, ctest, a type or lint checker, a compiler,
                        or the library itself.
    ``artefact-probe``  inspected a BUILT object (``nm``, ``readelf``,
                        ``objdump``, ``ldd``).  Evidence about the shipped
                        binary, not about source text.
    ``text-inspection`` read bytes at rest — source, workflow or documentation.
    ``not-executed``    a historical measurement at a superseded commit, a
                        cross-reference to another table in this audit, or a
                        GitHub API lookup.

``strength``
    What the verdict is worth FOR THIS CLAIM'S KIND:

    ``reproduced``      the claim's subject was observed doing what is claimed.
    ``text-present``    the quoted text is where the document says it is, and
                        nothing more was observed.  A behavioural or numeric
                        claim carrying this has NOT been reproduced.
    ``not-established`` the reproduction did not run here.

The re-typing rule is kind-aware, because ``grep`` is sound evidence for a
claim about text and unsound for a claim about behaviour:

* ``provenance`` and ``negative`` claims — assertions about what a document or
  a tree does or does not contain — keep ``confirmed`` under text inspection.
  Reading the bytes is the whole claim.
* ``behavioural`` and ``numeric`` claims confirmed by text inspection alone are
  re-typed ``text-only``.  The document says what it says; the behaviour was
  not exercised and the number was not re-measured.

``refuted`` is never re-typed: a reproduction that contradicted its claim
contradicted it whatever the method.

Usage::

    python docs/audit/classify_claims.py            # rewrite in place
    python docs/audit/classify_claims.py --report   # print the tally only
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLAIMS = REPO / "docs" / "audit" / "PR394_CLAIMS.yaml"

#: Programs whose invocation runs the subject of a claim.
_EXECUTES = frozenset(
    {
        "ctest",
        "cmake",
        "mypy",
        "ruff",
        "black",
        "cppcheck",
        "clang-format",
        "gcc",
        "clang",
        "pwsh",
        "pytest",
        "benchmark_c_raw",
        "curl",
    }
)
#: Programs that read a built object rather than source text.
_PROBES_ARTEFACT = frozenset(
    {
        "nm",
        "readelf",
        "objdump",
        "ldd",
        "aarch64-linux-gnu-nm",
        "aarch64-linux-gnu-objdump",
        "aarch64-linux-gnu-readelf",
    }
)
#: A Python invocation runs the subject when it drives a script, a module, or
#: the package itself.  `python -c` that only opens files and regexes their
#: text is a grep in Python's clothing: the path it reads appears inside the
#: -c string, so the script and module tests below are applied to the command
#: with quoted runs blanked, and only an actual `import ama_cryptography`
#: promotes a -c one-liner to an execution.  (CLAIM-1562 —
#: `python -c "...open('benchmarks/validation_suite.py').read()..."` — was
#: classified `executed` before this split.)
_PYTHON = re.compile(r"(?:^|/)python[0-9.]*$")
_PY_SCRIPT = re.compile(r"(?:tools|benchmarks|scripts|docs/audit)/[\w/]+\.py\b")
_PY_MODULE = re.compile(r"(?<![\w-])-m\s+[\w.]+")
_PY_RUNTIME = re.compile(r"\b(?:import|from)\s+ama_cryptography\b")
#: A bare `./build*/bin/<name>` or `<name>` that is a compiled test binary.
_TEST_BINARY = re.compile(r"(?:^|/)(?:test_|fuzz_)\w+$")

_PREFIXES = {
    "historical:": "not-executed",
    "phaseD:": "not-executed",
    "phaseE:": "not-executed",
    "phaseF:": "not-executed",
    "mcp:": "not-executed",
}


#: A quoted run, so a program name INSIDE a search pattern is not read as an
#: invocation of it.  `grep -n "cmake -B build" x.yml` runs grep, not cmake,
#: and an earlier revision of this classifier counted it as an execution —
#: which inflated `executed` and `artefact-probe`, the two buckets whose
#: inflation flatters the result.  Spot-checked survivors: CLAIM-0219,
#: CLAIM-0579 (`cmake` inside a pattern) and CLAIM-0818 (`objdump` inside one).
_QUOTED_RUN = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*\"""" + '"')


def _command_words(command: str) -> list[str]:
    """The word in COMMAND POSITION of each pipeline segment.

    A reproduction is classified by what it INVOKES, so only the first word of
    the command and of each segment after an unquoted separator is considered.
    Quoted regions are blanked first (see :data:`_QUOTED_RUN`) so a pattern
    mentioning a program is not mistaken for running it.
    """
    blanked = _QUOTED_RUN.sub(lambda m: " " * len(m.group(0)), command)
    words: list[str] = []
    for segment in re.split(r"\|\||&&|[|;&\n]", blanked):
        for token in segment.split():
            token = token.strip("()`$")
            if not token:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", token):
                continue  # leading VAR=value assignment, not the command
            words.append(token)
            break
    return words


def classify(command: str) -> str:
    """The observation method a reproduction command represents."""
    stripped = command.strip().strip("'\"")
    for prefix, method in _PREFIXES.items():
        if stripped.startswith(prefix):
            return method

    method = "text-inspection"
    for token in _command_words(stripped):
        base = token.rsplit("/", 1)[-1]
        if base in _EXECUTES or _TEST_BINARY.search(base):
            return "executed"
        if _PYTHON.search(base):
            blanked = _QUOTED_RUN.sub(" ", stripped)
            if (
                _PY_SCRIPT.search(blanked)
                or _PY_MODULE.search(blanked)
                or _PY_RUNTIME.search(stripped)
            ):
                return "executed"
        if base in _PROBES_ARTEFACT:
            method = "artefact-probe"
    return method


def strength(kind: str, verdict: str, method: str) -> str:
    if verdict == "refuted":
        return "reproduced" if method in ("executed", "artefact-probe") else "text-present"
    if method == "not-executed":
        return "not-established"
    if method in ("executed", "artefact-probe"):
        return "reproduced"
    return "text-present"


def retype(kind: str, verdict: str, method: str) -> str:
    """The verdict the method can actually support."""
    if verdict != "confirmed":
        return verdict
    if method in ("executed", "artefact-probe"):
        return "confirmed"
    if method == "not-executed":
        return "unverifiable"
    # text-inspection: sound for a claim about text, unsound for one about
    # behaviour or about a measured number.
    return "confirmed" if kind in ("provenance", "negative") else "text-only"


def _reclassify(
    lines: list[str],
) -> tuple[list[str], Counter[str], Counter[str], Counter[tuple[str, str, str]]]:
    """Rewrite every claim block, returning the new lines and three tallies."""
    out: list[str] = []
    kind = verdict = repro = original = ""
    counts: Counter[tuple[str, str, str]] = Counter()
    before: Counter[str] = Counter()
    after: Counter[str] = Counter()

    pending: list[str] = []

    def flush() -> None:
        """Emit one claim block with `method` and `strength` inserted.

        Re-typing is computed from the verdict the RUNNER produced, which a
        previous pass records in ``verdict_before_retyping``.  Reading it back
        is what makes the pass idempotent without erasing its own provenance:
        deriving from the already-re-typed value would find nothing to change
        and drop the record of what was changed.
        """
        nonlocal pending
        if not pending:
            return
        as_run = original or verdict
        method = classify(repro)
        new_verdict = retype(kind, as_run, method)
        counts[(kind, method, new_verdict)] += 1
        before[as_run] += 1
        after[new_verdict] += 1
        for line in pending:
            if line.startswith("  verdict: "):
                out.append(f"  verdict: {new_verdict}")
                out.append(f"  method: {method}")
                out.append(f"  strength: {strength(kind, as_run, method)}")
                if new_verdict != as_run:
                    out.append(f"  verdict_before_retyping: {as_run}")
            elif line.startswith(("  method:", "  strength:", "  verdict_before_retyping:")):
                continue  # regenerated above
            else:
                out.append(line)
        pending = []

    for line in lines:
        if line.startswith("- id: CLAIM-"):
            flush()
            kind = verdict = repro = original = ""
        if pending or line.startswith("- id: CLAIM-"):
            pending.append(line)
        else:
            out.append(line)
        if line.startswith("  kind: "):
            kind = line[len("  kind: ") :].strip()
        elif line.startswith("  verdict: "):
            verdict = line[len("  verdict: ") :].strip()
        elif line.startswith("  reproduction: "):
            repro = line[len("  reproduction: ") :].strip()
        elif line.startswith("  verdict_before_retyping: "):
            original = line[len("  verdict_before_retyping: ") :].strip()
    flush()
    return out, before, after, counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true", help="print the tally without rewriting")
    args = ap.parse_args(argv)

    out, before, after, counts = _reclassify(CLAIMS.read_text(encoding="utf-8").splitlines())

    total = sum(before.values())
    print(f"{total} claims\n")
    print("verdict as recorded  ->  verdict the method supports")
    for v in ("confirmed", "refuted", "unverifiable", "text-only"):
        print(f"  {v:<14} {before.get(v, 0):>6}  ->  {after.get(v, 0):>6}")
    print("\nby kind and method (re-typed verdict):")
    for (k, m, v), n in sorted(counts.items()):
        print(f"  {k:<12} {m:<16} {v:<13} {n:>5}")

    if not args.report:
        CLAIMS.write_text("\n".join(out) + "\n", encoding="utf-8")
        print(f"\nrewrote {CLAIMS.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
