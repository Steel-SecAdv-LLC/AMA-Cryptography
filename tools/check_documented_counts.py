#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Verify every count the documentation pins against the thing it counts.

Why
---
``docs/KEY_FORMATS.md`` said "``tests/test_key_formats.py`` — 301 tests". It was
true when it was written. Nothing checked it, so the only question was how long
until it stopped being true — and a documented number that has quietly gone
wrong is worse than no number, because a reader takes it as evidence and a
maintainer takes it as a baseline.

The same shape appears throughout: "15 vectors", "1530 vectors across …",
"41 tests". Each is a second declaration of a fact that lives somewhere else —
the same class of duplication ``check_version_consistency.py`` polices for
version strings, and the same failure mode.

So rather than deleting the numbers (they are genuinely useful — "the negative
space is 300 tests" tells a reviewer something "there are tests" does not), they
are *checked*.

What is checked
---------------
Five claim shapes, recognised anywhere under ``docs/``, ``tests/`` and the
repository root:

1. ``tests/<name>.py`` — N tests``  → pytest's own collection count.
2. ``<name>.json`` — N records``    → the corpus file's ``records`` array.
3. ``wycheproof_vectors/`` — N vectors across `a`, `b`, `c``
                                    → the manifest's per-file ``actualTests``.
4. ``N native entry points`` / ``N Cython binding entry points``
                                    → ``tools/check_error_state_gating.py``,
                                      which those documents already name as
                                      authoritative while carrying a figure
                                      that had drifted away from it.
5. ``N C test suites (M translation units)``
                                    → ``tests/c/**/test_*.c`` and
                                      ``tests/c/**/*.c``.  Adding a C test used
                                      to move both numbers with nothing
                                      watching.

A claim naming a file that does not exist is a failure too: a count for a
deleted corpus is the most misleading kind.

Exit code:
    0  every documented count matches
    1  at least one has drifted
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent

#: Where documentation lives. Markdown only — a count inside source is a
#: comment about that source and is reviewed with it.
DOC_ROOTS = ("docs", "tests", "wiki", ".")

#: `tests/test_key_formats.py` — 301 tests
#: Both phrasings in use: "`tests/x.py` — 12 tests" and "`tests/x.py` (12 tests)".
#: The parenthesised form was outside the pattern, so INVARIANT-35's claim that
#: `tests/test_secp256k1_ecdsa.py` had 32 tests sat two off the real number
#: while this gate reported green.
_TEST_COUNT_RE = re.compile(r"`(tests/[A-Za-z0-9_/]+\.py)`\s*(?:[—-]\s*|\()(\d+)\s+tests\b")

#: `rfc9881_ml_dsa.json` — 15 records
_RECORD_COUNT_RE = re.compile(r"`([A-Za-z0-9_./-]+\.json)`\s*[—-]\s*(\d+)\s+records\b")

#: `wycheproof_vectors/` — 1530 vectors across `a`, `b`, `c`
_WYCHEPROOF_RE = re.compile(r"`wycheproof_vectors/`\s*[—-]\s*(\d+)\s+vectors\s+across\s+([^|]+)")
_BACKTICKED = re.compile(r"`([A-Za-z0-9_.-]+)`")


def _markdown_files(repo: Path) -> list[Path]:
    seen: dict[Path, None] = {}
    for root in DOC_ROOTS:
        base = repo / root
        if not base.is_dir():
            continue
        pattern = "*.md" if root == "." else "**/*.md"
        for path in sorted(base.glob(pattern)):
            if any(part in {".git", "build", "node_modules"} for part in path.parts):
                continue
            if path.name == "CHANGELOG.md":
                continue  # historical by definition, like the version checker
            seen.setdefault(path.resolve(), None)
    return list(seen)


def collect_test_count(repo: Path, relative: str) -> int | None:
    """How many tests pytest actually collects from one file.

    Uses pytest's own collection rather than counting ``def test_`` lines:
    parametrisation multiplies a single definition into many cases, and it is
    the collected number the documentation is quoting.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            relative,
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^(\d+)\s+tests? collected", result.stdout, re.M)
    if match:
        return int(match.group(1))
    match = re.search(r"^(\d+)/(\d+) tests collected", result.stdout, re.M)
    if match:
        return int(match.group(2))
    return None


def check_test_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    claims: dict[str, list[tuple[str, int]]] = {}
    for path in _markdown_files(repo):
        for match in _TEST_COUNT_RE.finditer(path.read_text(encoding="utf-8")):
            claims.setdefault(match.group(1), []).append(
                (str(path.relative_to(repo)), int(match.group(2)))
            )
    for target, entries in sorted(claims.items()):
        if not (repo / target).is_file():
            for doc, _ in entries:
                problems.append(f"{doc}: claims a count for {target}, which does not exist")
            continue
        actual = collect_test_count(repo, target)
        if actual is None:
            problems.append(f"{target}: pytest collection produced no count")
            continue
        for doc, claimed in entries:
            if claimed != actual:
                problems.append(
                    f"{doc}: says {target} has {claimed} tests; pytest collects {actual}"
                )
    return problems


def check_record_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    corpora = {p.name: p for p in (repo / "tests" / "kat").rglob("*.json")}
    for path in _markdown_files(repo):
        for match in _RECORD_COUNT_RE.finditer(path.read_text(encoding="utf-8")):
            name, claimed = match.group(1), int(match.group(2))
            target = corpora.get(Path(name).name)
            doc = str(path.relative_to(repo))
            if target is None:
                problems.append(f"{doc}: claims {claimed} records for {name}, which does not exist")
                continue
            try:
                records = json.loads(target.read_text(encoding="utf-8")).get("records")
            except json.JSONDecodeError as exc:
                problems.append(f"{doc}: {name} is not valid JSON ({exc})")
                continue
            if not isinstance(records, list):
                problems.append(f"{doc}: {name} has no 'records' array")
                continue
            if len(records) != claimed:
                problems.append(f"{doc}: says {name} has {claimed} records; it has {len(records)}")
    return problems


def check_wycheproof_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    manifest_path = repo / "wycheproof_vectors" / "manifest.json"
    if not manifest_path.is_file():
        return problems
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files", {})
    for path in _markdown_files(repo):
        for match in _WYCHEPROOF_RE.finditer(path.read_text(encoding="utf-8")):
            claimed = int(match.group(1))
            doc = str(path.relative_to(repo))
            named = _BACKTICKED.findall(match.group(2))
            if not named:
                problems.append(f"{doc}: a Wycheproof count names no corpus files")
                continue
            total = 0
            for stem in named:
                # The documentation names the suite (`ecdsa_secp256r1_sha256`);
                # the manifest keys the vendored file (`..._test.json`). Try
                # both so a document can read naturally without the checker
                # demanding a filename in prose.
                candidates = [stem, f"{stem}.json", f"{stem}_test.json"]
                key = next((k for k in candidates if k in files), candidates[-1])
                entry = files.get(key)
                if entry is None:
                    problems.append(
                        f"{doc}: names Wycheproof corpus {key}, which the manifest " "does not list"
                    )
                    total = -1
                    break
                total += int(entry["actualTests"])
            if total >= 0 and total != claimed:
                problems.append(
                    f"{doc}: says {claimed} vectors across {', '.join(named)}; the "
                    f"manifest totals {total}"
                )
    return problems


#: Aggregate claims: "3,099 test functions across 130 Python test files".
#:
#: These are the figures docs/METRICS_REPORT.md calls authoritative and README
#: and ARCHITECTURE.md restate. Nothing checked them, so they drifted three
#: releases' worth (3,057/127 against a tree with 3,099/130) while this gate
#: passed — it only ever verified per-file claims. The report even publishes
#: the reproduction command; this just runs it.
#: Every quantifier here is bounded.  Unbounded ``[\d,]+`` / ``\s+`` made
#: ``search`` re-run the quantifier from every start offset — quadratic on a
#: long run of digits (measured 4.0x per doubling, 368 ms at 6,000 chars),
#: the polynomial-ReDoS shape CodeQL reports.  The inputs are Markdown files
#: in this repository rather than anything remote, but a count like "3,534"
#: is never more than a handful of characters and the whitespace between two
#: words is never a kilobyte, so the bounds cost nothing and remove the shape.
_AGGREGATE_RE = re.compile(
    r"([\d,]{1,15})\s{1,8}(?:static\s{1,8})?(?:Python\s{1,8})?"
    r"test functions across\s{1,8}([\d,]{1,15})\s{1,8}"
    r"(?:Python\s{1,8})?(?:test\s{1,8})?files?"
)

#: Same two numbers, as they appear in the METRICS_REPORT table rows.
_METRICS_FILES_RE = re.compile(
    r"\|\s*Python test files under `tests/` matching the static regex\s*\|\s*([\d,]+)\s*\|"
)
_METRICS_FUNCS_RE = re.compile(
    r"\|\s*Syntactic `def test_` matches under `tests/\*\*/\*\.py`\s*\|\s*\*\*([\d,]+)\*\*\s*\|"
)

#: A revision-history row: "| 3.5.0 | 2026-07-30 | Re-measured ... |".
#:
#: Those rows are records of what was true at a past release, not claims about
#: the current tree, and the repository's convention is to leave them verbatim
#: (see the `baseline_change_log` entries in benchmarks/ and the note in
#: check_version_consistency.py). Matching them would make every historically
#: accurate entry a permanent failure and force the gate to be disabled.
_HISTORY_ROW_RE = re.compile(r"^\|\s*\d+\.\d+\.\d+[^|]*\|\s*20\d\d-\d\d-\d\d\s*\|")


_DEF_TEST_RE = re.compile(r"^\s*def test_", re.MULTILINE)


#: The Lines of Code table in docs/METRICS_REPORT.md — BOTH columns.
#:
#: History of this gate, kept because each stage failed differently. First
#: nothing was gated, and both columns drifted. Then the Files column was
#: gated (4.0.0) while the line totals were left out on the argument that
#: "``wc -l`` moves on every commit and a gate that fails on every commit is
#: one that gets disabled" — and the totals drifted again, silently, within
#: two days of being re-measured (measured at 8d72b8c: four of seven totals
#: stale). The argument identified a real operational cost but drew the
#: wrong conclusion: the fix for "the gate fails whenever the tree changes"
#: is a one-command regenerator, not an ungated number. ``python
#: tools/update_docs.py --loc`` rewrites every gated figure from the same
#: measurement functions this checker verifies with, so keeping the gate
#: green after a change is one command, and a figure that was not
#: re-measured cannot survive review.
#:
#: Counting rules, stated exactly (the report publishes the matching
#: reproduction commands): files are enumerated with ``git ls-files`` —
#: tracked files only, so virtualenvs, build directories and generated
#: ``src/cython/*.c`` can never leak into a measurement — and lines are
#: counted as ``\n`` bytes per file (exact ``wc -l`` semantics,
#: locale-independent; trailing-newline-free files under-count by one).
#: For a directory that is not a git checkout (this gate's own test
#: fixtures) the enumeration falls back to a sorted filesystem walk
#: excluding ``.git``; the real repository always takes the git path.
_LOC_WHOLE_SUFFIX_RE = re.compile(r"\.(py|c|h|pyx|pxd|md|yml|yaml|toml|json|cmake)$")


def _loc_is_library_python(path: str) -> bool:
    return path.startswith("ama_cryptography/") and path.endswith(".py")


def _loc_is_native_c(path: str) -> bool:
    return (path.startswith("src/c/") or path.startswith("include/")) and path.endswith(
        (".c", ".h")
    )


def _loc_is_top_level_python(path: str) -> bool:
    return "/" not in path and path.endswith(".py")


def _loc_is_tests_python(path: str) -> bool:
    return path.startswith("tests/") and path.endswith(".py")


def _loc_is_cython(path: str) -> bool:
    return path.endswith((".pyx", ".pxd"))


def _loc_is_whole_project(path: str) -> bool:
    if path.startswith("src/cython/") and path.endswith(".c"):
        return False  # cythonize output; .gitignore excludes it, belt-and-braces
    basename = path.rsplit("/", 1)[-1]
    return (
        bool(_LOC_WHOLE_SUFFIX_RE.search(path))
        or basename == "CMakeLists.txt"
        or basename == "Makefile"
    )


#: Row label -> path predicate, in table order. Every row is gated on both
#: columns.
_LOC_TABLE_ROWS: dict[str, Callable[[str], bool]] = {
    "Library Python (`ama_cryptography/*.py`)": _loc_is_library_python,
    "Native C (`src/c/**/*.c`, `include/**/*.h`)": _loc_is_native_c,
    "Library total (Python + C + headers)": lambda p: _loc_is_library_python(p)
    or _loc_is_native_c(p),
    "Top-level Python (monitors, benchmarks, demos)": _loc_is_top_level_python,
    "Tests (`tests/**/*.py`)": _loc_is_tests_python,
    "Cython (`*.pyx`, `*.pxd`)": _loc_is_cython,
    "**Whole project** (source + docs + config)": _loc_is_whole_project,
}


def _loc_tracked_files(repo: Path) -> list[str]:
    """Tracked files as repo-relative POSIX paths.

    ``git ls-files`` is authoritative; the sorted filesystem walk exists only
    for non-git fixture directories in this gate's own tests and excludes
    nothing beyond ``.git`` (fixtures are clean by construction).
    """
    if (repo / ".git").exists():
        proc = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
        return [p.decode("utf-8") for p in proc.stdout.split(b"\0") if p]
    return sorted(
        p.relative_to(repo).as_posix()
        for p in repo.rglob("*")
        if p.is_file() and ".git" not in p.parts
    )


def measure_loc_table(repo: Path) -> dict[str, tuple[int, int]]:
    """``{row label: (file_count, line_count)}`` for every gated row."""
    counts: dict[str, tuple[int, int]] = {}
    tracked = _loc_tracked_files(repo)
    lines_cache: dict[str, int] = {}

    def _lines(rel: str) -> int:
        if rel not in lines_cache:
            lines_cache[rel] = (repo / rel).read_bytes().count(b"\n")
        return lines_cache[rel]

    for label, predicate in _LOC_TABLE_ROWS.items():
        selected = [p for p in tracked if predicate(p)]
        counts[label] = (len(selected), sum(_lines(p) for p in selected))
    return counts


def measure_scope_composition(repo: Path) -> dict[str, tuple[int, str]]:
    """``{composition row label: (line_count, percent_string)}``.

    The remainder row is derived by subtraction, so the composition always
    sums to the whole-project total by construction.
    """
    table = measure_loc_table(repo)
    whole = table["**Whole project** (source + docs + config)"][1]
    library = table["Library total (Python + C + headers)"][1]
    tests_lines = table["Tests (`tests/**/*.py`)"][1]
    top = table["Top-level Python (monitors, benchmarks, demos)"][1]
    cython = table["Cython (`*.pyx`, `*.pxd`)"][1]
    remainder = whole - library - tests_lines - top - cython

    def _pct(x: int) -> str:
        return f"{x / whole * 100:.1f}%" if whole else "0.0%"

    return {
        "Library (Python + C + headers)": (library, _pct(library)),
        "Tests": (tests_lines, _pct(tests_lines)),
        "Top-level Python": (top, _pct(top)),
        "Cython": (cython, _pct(cython)),
        "Everything else (remainder)": (remainder, _pct(remainder)),
        "**Whole-project total**": (whole, "100%"),
    }


def measure_tracked_json_lines(repo: Path) -> int:
    """Lines across tracked ``*.json`` — the corpus-dominance figure the
    Scope Composition prose quotes."""
    return sum(
        (repo / p).read_bytes().count(b"\n")
        for p in _loc_tracked_files(repo)
        if p.endswith(".json")
    )


def _loc_row_re(label: str) -> re.Pattern[str]:
    # Cells may be bold (``**86,620**``); a legacy Files cell may be ``—``
    # (the 4.0.0 table left three rows uncounted — the checker treats that
    # as a failure and the regenerator fills the real count).
    return re.compile(
        rf"\|\s*{re.escape(label)}\s*\|\s*\**\s*(\d[\d,]*|—)\s*\**\s*\|\s*\**\s*(\d[\d,]*)\s*\**\s*\|"
    )


def _composition_row_re(label: str) -> re.Pattern[str]:
    return re.compile(
        rf"\|\s*{re.escape(label)}\s*\|\s*\**\s*(\d[\d,]*)\s*\**\s*\|\s*\**\s*([\d.]+%)\s*\**\s*\|"
    )


def _num(raw: str) -> int:
    return int(raw.replace(",", ""))


def check_loc_table_file_counts(repo: Path) -> list[str]:
    """Every row of the LoC table must state the file AND line counts it
    measures, and the Scope Composition table must agree with the same
    measurement (function name kept from the Files-only 4.0.0 gate; it now
    gates both columns)."""
    problems: list[str] = []
    report = repo / "docs" / "METRICS_REPORT.md"
    if not report.is_file():
        return [f"{report} is missing; the LoC table cannot be checked"]
    text = report.read_text(encoding="utf-8")

    table = measure_loc_table(repo)
    for label, (files_measured, lines_measured) in table.items():
        matches = _loc_row_re(label).findall(text)
        if not matches:
            problems.append(
                f"docs/METRICS_REPORT.md: no LoC-table row found for {label!r}; "
                "the row was renamed or removed and this check stopped checking it"
            )
            continue
        for claimed_files, claimed_lines in matches:
            if claimed_files == "—" or _num(claimed_files) != files_measured:
                problems.append(
                    f"docs/METRICS_REPORT.md: LoC table says {claimed_files} files for "
                    f"{label}; measured {files_measured}"
                )
            if _num(claimed_lines) != lines_measured:
                problems.append(
                    f"docs/METRICS_REPORT.md: LoC table says {claimed_lines} lines for "
                    f"{label}; measured {lines_measured} "
                    "(re-measure with: python tools/update_docs.py --loc)"
                )

    composition = measure_scope_composition(repo)
    for label, (lines_measured, pct) in composition.items():
        matches2 = _composition_row_re(label).findall(text)
        if not matches2:
            problems.append(f"docs/METRICS_REPORT.md: no Scope Composition row found for {label!r}")
            continue
        for claimed_lines, claimed_pct in matches2:
            if _num(claimed_lines) != lines_measured:
                problems.append(
                    f"docs/METRICS_REPORT.md: Scope Composition says {claimed_lines} "
                    f"lines for {label}; measured {lines_measured}"
                )
            if claimed_pct != pct:
                problems.append(
                    f"docs/METRICS_REPORT.md: Scope Composition says {claimed_pct} "
                    f"for {label}; measured {pct}"
                )

    json_lines = measure_tracked_json_lines(repo)
    for claimed in re.findall(r"\((\d[\d,]*) lines of\s*`\*\.json`", text):
        if _num(claimed) != json_lines:
            problems.append(
                f"docs/METRICS_REPORT.md: prose says {claimed} lines of *.json; "
                f"measured {json_lines}"
            )
    return problems


#: Named on every count this gate can fail on, because a gate that reports a
#: number without the command that fixes it is a gate people work around.  The
#: LoC half already carried ``--loc``; the static test counts had to be found
#: and hand-edited across three documents, which is the asymmetry
#: ``update_docs.update_static_test_counts`` closes.
_REMEASURE_HINT = "re-measure with: python tools/update_docs.py --counts"


def measure_static_test_counts(repo: Path) -> tuple[int, int]:
    r"""Return ``(function_count, file_count)`` for ``tests/**/*.py``.

    Deliberately the same syntactic ``^\s*def test_`` match that
    docs/METRICS_REPORT.md publishes as its reproduction command, not pytest
    collection: a static count and a collected count legitimately differ
    (parametrisation, skips, collection errors), and the documents quote the
    static one. Measuring it a different way here would produce a gate that
    disagrees with correct documentation.
    """
    functions = 0
    files = 0
    for path in sorted((repo / "tests").rglob("*.py")):
        hits = len(_DEF_TEST_RE.findall(path.read_text(encoding="utf-8")))
        if hits:
            files += 1
            functions += hits
    return functions, files


def check_aggregate_test_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    functions, files = measure_static_test_counts(repo)

    def _num(raw: str) -> int:
        return int(raw.replace(",", ""))

    for path in _markdown_files(repo):
        rel = str(path.relative_to(repo))
        text = path.read_text(encoding="utf-8")
        live = "\n".join(line for line in text.splitlines() if not _HISTORY_ROW_RE.match(line))
        for claimed_funcs, claimed_files in _AGGREGATE_RE.findall(live):
            if _num(claimed_funcs) != functions:
                problems.append(
                    f"{rel}: claims {claimed_funcs} test functions; "
                    f"`grep -rE '^\\s*def test_' tests/` finds {functions} "
                    f"({_REMEASURE_HINT})"
                )
            if _num(claimed_files) != files:
                problems.append(
                    f"{rel}: claims {claimed_files} test files; {files} contain a "
                    f"test function ({_REMEASURE_HINT})"
                )
        for claimed in _METRICS_FILES_RE.findall(live):
            if _num(claimed) != files:
                problems.append(
                    f"{rel}: table says {claimed} test files; measured {files} "
                    f"({_REMEASURE_HINT})"
                )
        for claimed in _METRICS_FUNCS_RE.findall(live):
            if _num(claimed) != functions:
                problems.append(
                    f"{rel}: table says {claimed} `def test_` matches; measured "
                    f"{functions} ({_REMEASURE_HINT})"
                )
    return problems


# ---------------------------------------------------------------------------
# Fuzz-target count.
#
# How many libFuzzer harnesses the repository builds is a fact that lives in
# ``fuzz/CMakeLists.txt`` and is already enforced, harness by harness, by
# ``tools/check_fuzz_target_registration.py``.  The prose restates it — README,
# ARCHITECTURE.md, ENHANCED_FEATURES.md, CRYPTO_REVIEW_CHECKLIST.md,
# docs/oss-fuzz-onboarding.md and THREAT_MODEL.md each quote a target count —
# and, unchecked, those restatements had drifted to 11, 12, 13 and 16 across
# six documents, only one of which stated the correct 15, against a tree that
# builds fifteen.  This checks them against the one authority instead of
# maintaining another number by hand: the count is *imported* from the
# registration tool, never re-derived here, so the two cannot disagree.
#
# ``fuzz_rng.c`` is a support translation unit — it supplies
# ``__wrap_ama_randombytes`` to ``fuzz_frost`` — not a harness, which is why the
# authority is "libFuzzer entry points" (15), not "``fuzz_*.c`` files" (16). A
# document may legitimately state either, so only the entry-point figure — the
# one that says how many fuzzers actually run — is gated; the source-file count
# is left to the prose.
#: Bounded for the same reason as _AGGREGATE_RE above: ``\d+``, ``[\w-]*``
#: and ``\s+`` were all unbounded (4.1x per doubling, 363 ms at 6,000 chars).
#: Two adjectives of at most 40 characters each is the shape this is for
#: ("15 libFuzzer entry points", "16 fuzz targets").
_FUZZ_COUNT_RE = re.compile(
    r"(\d{1,9})\s{1,8}(?:[A-Za-z][\w-]{0,40}\s{1,8}){0,2}(?:targets?|harnesses?)\b",
    re.IGNORECASE,
)


#: "85 native entry points" / "10 Cython binding entry points" — the figures
#: INVARIANTS.md and the CHANGELOG publish for the error-state gating surface,
#: naming `tools/check_error_state_gating.py` as authoritative while carrying a
#: number that had drifted away from it (85 published, 86 reported).
_NATIVE_ENTRY_RE = re.compile(r"(\d[\d,]*) native (?:plus \d+ Cython )?entry points")
_CYTHON_ENTRY_RE = re.compile(r"(\d[\d,]*) Cython (?:binding )?entry points")

#: "59 C test suites (62 translation units)" and the bare "59 C test suites".
_C_SUITE_PAREN_RE = re.compile(r"(\d[\d,]*) C test suites \((\d[\d,]*) translation units\)")
_C_SUITE_BARE_RE = re.compile(r"(\d[\d,]*) C test suites")

#: The OTHER spellings of the same claim.  The two patterns above match the
#: phrasing README.md happens to use; three live documents said the same thing
#: differently and none of them was checked:
#:
#:   docs/METRICS_REPORT.md  | `test_*.c` files under `tests/c/` ... | 59 |
#:   ARCHITECTURE.md         59 `test_*.c` registered via ctest in `tests/c/`
#:   CHANGELOG.md            the C suite is 59 files / 62 translation units
#:
#: against a tree with 60 and 63 — and docs/METRICS_REPORT.md is the document
#: README calls authoritative, whose own preamble says "if a documented count
#: and this report disagree, the count is the bug".  Here the report was.
_C_SUITE_TABLE_RE = re.compile(
    r"`test_\*\.c`\s+files\s+under\s+`tests/c/`[^|\n]*\|\s*(\d[\d,]*)\s*\|"
)
_C_SUITE_CTEST_RE = re.compile(r"(\d[\d,]*)\s+`test_\*\.c`\s+registered\s+via\s+ctest")
#: "suite files", not "files": a "suite" is a ``tests/c/test_*.c`` and a
#: "translation unit" is any ``.c`` under ``tests/c``, so the second number is
#: the file count and calling the first one "files" made the sentence read as
#: "60 files / 63 files".  The optional group keeps the older spelling
#: matching, so a document that has not been reworded is still checked rather
#: than silently skipped.
_C_SUITE_FILES_UNITS_RE = re.compile(
    r"C suite is (\d[\d,]*) (?:suite )?files / (\d[\d,]*) translation units"
)

#: README's version-stamped C library inventory.  Two counts, neither checked:
#: "Top-level `src/c/*.c` — 27 translation units" against a tree with 29 (both
#: ama_pbkdf2.c and ama_sha512.c were added on this branch and compiled
#: unconditionally), and "25 modules + `__init__` + `__main__`" against 27.  An
#: inventory presented with a version number should be measured, not
#: transcribed.
_SRC_C_UNITS_RE = re.compile(r"Top-level `src/c/\*\.c`\s*[—-]\s*(\d[\d,]*) translation units")
_PACKAGE_MODULES_RE = re.compile(
    r"`ama_cryptography/`,\s*(\d[\d,]*) modules \+ `__init__` \+ `__main__`"
)


def count_error_state_entry_points() -> tuple[int, int]:
    """The authoritative gated-surface counts, from the gate that owns them.

    Imported rather than re-derived, for the reason this module exists: a fact
    is declared once and every other mention is checked against it.
    """
    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from tools import check_error_state_gating as gating

    return gating.entry_point_counts()


def measure_c_suite_counts(repo: Path) -> tuple[int, int]:
    """(C test suites, C translation units) under ``tests/c``.

    A "suite" is a ``tests/c/test_*.c`` — one executable per file.  A
    "translation unit" is any ``.c`` under ``tests/c``, which additionally
    counts the bench and equivalence helpers that are compiled but are not
    themselves suites.  Both figures appear in README.md, and neither was
    checked by anything: adding a C test moved them and no gate noticed.
    """
    suites = sum(1 for p in (repo / "tests" / "c").rglob("test_*.c"))
    units = sum(1 for p in (repo / "tests" / "c").rglob("*.c"))
    return suites, units


#: The CHANGELOG is excluded from ``_markdown_files`` as "historical by
#: definition", which is right for released sections and wrong for the one at
#: the top: ``## [X.Y.Z] - Unreleased`` describes the release being built, and
#: a wrong figure there is a wrong figure in the release notes, not a record of
#: what was once true.  Both drifted counts this pair of checks was written for
#: had an occurrence in exactly that section.
_UNRELEASED_HEADING_RE = re.compile(r"^##\s*\[[^\]]+\]\s*-\s*Unreleased\s*$", re.I)
_ANY_VERSION_HEADING_RE = re.compile(r"^##\s*\[")


def changelog_unreleased_section(repo: Path) -> str:
    """The text of the CHANGELOG's ``- Unreleased`` section, or ``""``.

    Returns empty when there is no such section — which is the state right
    after a release is dated — so the checks below simply find nothing rather
    than failing on a file shape they did not expect.
    """
    path = repo / "CHANGELOG.md"
    if not path.is_file():
        return ""
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if _UNRELEASED_HEADING_RE.match(line):
            inside = True
            continue
        if inside and _ANY_VERSION_HEADING_RE.match(line):
            break
        if inside:
            out.append(line)
    return "\n".join(out)


def _live_documents(repo: Path) -> list[tuple[str, str]]:
    """(display name, text) for every document these checks read.

    Markdown under the documented roots, with history rows filtered, plus the
    CHANGELOG's unreleased section.
    """
    docs: list[tuple[str, str]] = []
    for path in _markdown_files(repo):
        text = path.read_text(encoding="utf-8")
        live = "\n".join(line for line in text.splitlines() if not _HISTORY_ROW_RE.match(line))
        docs.append((str(path.relative_to(repo)), live))
    unreleased = changelog_unreleased_section(repo)
    if unreleased:
        docs.append(("CHANGELOG.md [Unreleased]", unreleased))
    return docs


def check_entry_point_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    try:
        native, cython = count_error_state_entry_points()
    except Exception as exc:  # gate absent or renamed — fail loud, never skip
        return [f"cannot resolve the authoritative entry-point counts: {exc}"]

    def _num(raw: str) -> int:
        return int(raw.replace(",", ""))

    for rel, live in _live_documents(repo):
        for claimed in _NATIVE_ENTRY_RE.findall(live):
            if _num(claimed) != native:
                problems.append(
                    f"{rel}: says {claimed} native entry points; "
                    f"tools/check_error_state_gating.py reports {native}"
                )
        for claimed in _CYTHON_ENTRY_RE.findall(live):
            if _num(claimed) != cython:
                problems.append(
                    f"{rel}: says {claimed} Cython binding entry points; "
                    f"tools/check_error_state_gating.py reports {cython}"
                )
    return problems


def check_c_suite_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    suites, units = measure_c_suite_counts(repo)

    def _num(raw: str) -> int:
        return int(raw.replace(",", ""))

    for rel, live in _live_documents(repo):
        for claimed_suites, claimed_units in _C_SUITE_PAREN_RE.findall(live):
            if _num(claimed_suites) != suites:
                problems.append(
                    f"{rel}: says {claimed_suites} C test suites; "
                    f"`tests/c/**/test_*.c` counts {suites}"
                )
            if _num(claimed_units) != units:
                problems.append(
                    f"{rel}: says {claimed_units} C translation units; "
                    f"`tests/c/**/*.c` counts {units}"
                )
        # The bare form, minus the ones the parenthesised pattern already saw.
        paren_hits = {m[0] for m in _C_SUITE_PAREN_RE.findall(live)}
        for claimed in _C_SUITE_BARE_RE.findall(live):
            if claimed in paren_hits:
                continue
            if _num(claimed) != suites:
                problems.append(
                    f"{rel}: says {claimed} C test suites; "
                    f"`tests/c/**/test_*.c` counts {suites}"
                )
        # The three spellings the patterns above cannot see.
        for claimed in _C_SUITE_TABLE_RE.findall(live) + _C_SUITE_CTEST_RE.findall(live):
            if _num(claimed) != suites:
                problems.append(
                    f"{rel}: says {claimed} `test_*.c` files under tests/c/; "
                    f"the tree has {suites}"
                )
        for claimed_suites, claimed_units in _C_SUITE_FILES_UNITS_RE.findall(live):
            if _num(claimed_suites) != suites:
                problems.append(
                    f"{rel}: says the C suite is {claimed_suites} files; " f"the tree has {suites}"
                )
            if _num(claimed_units) != units:
                problems.append(
                    f"{rel}: says the C suite is {claimed_units} translation units; "
                    f"the tree has {units}"
                )
    return problems


def measure_source_inventory(repo: Path) -> tuple[int, int]:
    """(top-level ``src/c/*.c`` count, package module count).

    The module count excludes ``__init__.py`` and ``__main__.py``, matching the
    README's own "N modules + ``__init__`` + ``__main__``" phrasing, and reads
    the tracked set so a stray scratch file in a working tree is not counted.
    """
    units = len(list((repo / "src" / "c").glob("*.c")))
    modules = [
        path
        for path in (repo / "ama_cryptography").glob("*.py")
        if path.name not in {"__init__.py", "__main__.py"}
    ]
    return units, len(modules)


def check_source_inventory_counts(repo: Path) -> list[str]:
    """README's version-stamped C and Python inventories, measured."""
    problems: list[str] = []
    units, modules = measure_source_inventory(repo)

    def _num(raw: str) -> int:
        return int(raw.replace(",", ""))

    for rel, live in _live_documents(repo):
        for claimed in _SRC_C_UNITS_RE.findall(live):
            if _num(claimed) != units:
                problems.append(
                    f"{rel}: says {claimed} top-level src/c translation units; "
                    f"`src/c/*.c` counts {units}"
                )
        for claimed in _PACKAGE_MODULES_RE.findall(live):
            if _num(claimed) != modules:
                problems.append(
                    f"{rel}: says {claimed} package modules besides __init__ and "
                    f"__main__; `ama_cryptography/*.py` counts {modules}"
                )
    return problems


def count_libfuzzer_entry_points(repo: Path) -> int:
    """The authoritative harness count, imported from the registration gate.

    Reusing ``check_fuzz_target_registration._sources`` is deliberate: this
    module's whole thesis is that a fact should be declared once and every other
    mention checked against it, so re-implementing the "a ``fuzz/*.c`` that
    *defines* ``LLVMFuzzerTestOneInput``" detection here would be the exact
    duplication it exists to police.
    """
    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from tools import check_fuzz_target_registration as registration

    return len(registration._sources(repo))


def check_fuzz_target_counts(repo: Path, authoritative: int) -> list[str]:
    """Every prose fuzz-target count must equal the number actually built.

    Scoped to lines that mention fuzzing so an unrelated "N targets" elsewhere
    is not swept in, and skips revision-history rows for the same reason
    ``check_aggregate_test_counts`` does — they record what was true at a past
    release and are meant to read stale.
    """
    problems: list[str] = []
    for path in _markdown_files(repo):
        rel = str(path.relative_to(repo))
        for line in path.read_text(encoding="utf-8").splitlines():
            if _HISTORY_ROW_RE.match(line) or "fuzz" not in line.lower():
                continue
            for match in _FUZZ_COUNT_RE.finditer(line):
                claimed = int(match.group(1))
                if claimed != authoritative:
                    problems.append(
                        f"{rel}: says {claimed} fuzz target(s)/harness(es); the "
                        f"repository builds {authoritative} libFuzzer entry point(s)"
                    )
    return problems


# ---------------------------------------------------------------------------
# Breaking-change count.
#
# A release's breaking changes are enumerated in that release's CHANGELOG
# section, under "Behavioural and breaking changes at a glance". SECURITY.md's
# supported-versions table and the wiki mirror restate the total — "superseded
# by v4.0 (three breaking changes — see CHANGELOG [4.0.0])" — and both said
# three against a table that lists six. The claim names the section to check, so
# this follows that reference and counts the Breaking rows it points at rather
# than trusting a hand-maintained number beside it.
_WORD_NUMBERS = {
    word: value
    for value, word in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve "
        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split()
    )
}
#: Bounded for the same reason as the two patterns above; this one was the
#: worst of the three (4.0x per doubling, 842 ms at 6,000 chars), because
#: ``[^)\n]*?`` rescans the tail from every start offset.  The claim it
#: matches — "(4 breaking changes ... CHANGELOG 4.0.0)" — fits comfortably
#: inside 300 characters.
_BREAKING_CLAIM_RE = re.compile(
    r"\(?\s{0,8}(\d{1,9}|[A-Za-z]{1,20})\s{1,8}breaking\s{1,8}changes?\b[^)\n]{0,300}?"
    r"CHANGELOG\s{0,8}`?\[?(\d{1,9}\.\d{1,9}\.\d{1,9})\]?`?",
    re.IGNORECASE,
)
_CHANGELOG_BREAKING_ROW_RE = re.compile(r"^\|\s*\d+\s*\|\s*\*{0,2}Breaking\*{0,2}\s*\|", re.M)


def _resolve_number(token: str) -> int | None:
    """A digit string or an English number word; ``None`` for prose like
    "several", which names no count to check against."""
    if token.isdigit():
        return int(token)
    return _WORD_NUMBERS.get(token.lower())


def count_changelog_breaking_rows(repo: Path, version: str) -> int | None:
    """Breaking rows in the CHANGELOG ``[version]`` glance table, or ``None`` if
    that section does not exist."""
    changelog = repo / "CHANGELOG.md"
    if not changelog.is_file():
        return None
    text = changelog.read_text(encoding="utf-8")
    start = re.search(rf"^##\s*\[{re.escape(version)}\]", text, re.M)
    if not start:
        return None
    rest = text[start.end() :]
    following = re.search(r"^##\s*\[", rest, re.M)
    section = rest[: following.start()] if following else rest
    return len(_CHANGELOG_BREAKING_ROW_RE.findall(section))


def check_breaking_change_counts(repo: Path) -> list[str]:
    problems: list[str] = []
    for path in _markdown_files(repo):
        rel = str(path.relative_to(repo))
        text = path.read_text(encoding="utf-8")
        live = "\n".join(line for line in text.splitlines() if not _HISTORY_ROW_RE.match(line))
        for token, version in _BREAKING_CLAIM_RE.findall(live):
            claimed = _resolve_number(token)
            if claimed is None:
                continue
            actual = count_changelog_breaking_rows(repo, version)
            if actual is None:
                problems.append(
                    f"{rel}: cites CHANGELOG [{version}] for a breaking-change "
                    "count, but no such section exists to count"
                )
                continue
            if claimed != actual:
                problems.append(
                    f"{rel}: says {token} breaking change(s) for {version}; "
                    f"CHANGELOG [{version}] enumerates {actual}"
                )
    return problems


def audit(repo: Path = REPO) -> tuple[list[str], int]:
    """Returns ``(problems, claims_checked)``.

    The second value is the non-vacuity guard: if the claim patterns stop
    matching — because a document was reformatted, say — the checker would
    otherwise pass by finding nothing to check.
    """
    problems: list[str] = []
    checked = 0
    for path in _markdown_files(repo):
        text = path.read_text(encoding="utf-8")
        checked += len(_TEST_COUNT_RE.findall(text))
        checked += len(_RECORD_COUNT_RE.findall(text))
        checked += len(_WYCHEPROOF_RE.findall(text))
        checked += len(_AGGREGATE_RE.findall(text))
        checked += len(_METRICS_FILES_RE.findall(text))
        checked += len(_METRICS_FUNCS_RE.findall(text))
        checked += len(_NATIVE_ENTRY_RE.findall(text))
        checked += len(_CYTHON_ENTRY_RE.findall(text))
        checked += len(_C_SUITE_BARE_RE.findall(text))
        live_lines = [line for line in text.splitlines() if not _HISTORY_ROW_RE.match(line)]
        for line in live_lines:
            if "fuzz" in line.lower():
                checked += len(_FUZZ_COUNT_RE.findall(line))
        checked += len(_BREAKING_CLAIM_RE.findall("\n".join(live_lines)))
        if path.name == "METRICS_REPORT.md":
            # Each LoC-table row contributes two gated claims (Files, Lines);
            # each Scope Composition row contributes two (Lines, %); the
            # *.json prose figure contributes one.
            for label in _LOC_TABLE_ROWS:
                checked += 2 * len(_loc_row_re(label).findall(text))
            for comp_label in (
                "Library (Python + C + headers)",
                "Tests",
                "Top-level Python",
                "Cython",
                "Everything else (remainder)",
                "**Whole-project total**",
            ):
                checked += 2 * len(_composition_row_re(comp_label).findall(text))
            checked += len(re.findall(r"\((\d[\d,]*) lines of\s*`\*\.json`", text))
    problems += check_record_counts(repo)
    problems += check_wycheproof_counts(repo)
    problems += check_test_counts(repo)
    problems += check_aggregate_test_counts(repo)
    problems += check_loc_table_file_counts(repo)
    try:
        fuzz_authoritative = count_libfuzzer_entry_points(repo)
    except Exception as exc:  # registration tool absent or renamed — fail loud
        problems.append(f"cannot resolve the authoritative fuzz-target count: {exc}")
    else:
        problems += check_fuzz_target_counts(repo, fuzz_authoritative)
    problems += check_breaking_change_counts(repo)
    problems += check_entry_point_counts(repo)
    problems += check_c_suite_counts(repo)
    problems += check_source_inventory_counts(repo)
    return problems, checked


#: Non-vacuity floor. Eight claims resolve today across KEY_FORMATS.md,
#: NIST_PRIME_CURVES.md and the corpus README.
MIN_CLAIMS = 5


def main() -> int:
    problems, checked = audit()
    if problems:
        print(f"FAIL: {len(problems)} documented count(s) have drifted:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if checked < MIN_CLAIMS:
        print(
            f"FAIL: only {checked} documented count(s) matched the claim patterns, "
            f"below the floor of {MIN_CLAIMS}. A checker that finds nothing to "
            "check passes vacuously.",
            file=sys.stderr,
        )
        return 1
    print(f"OK    documented counts ({checked} checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
