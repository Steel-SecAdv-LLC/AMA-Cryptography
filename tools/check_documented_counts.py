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
Three claim shapes, recognised anywhere under ``docs/``, ``tests/`` and the
repository root:

1. ``tests/<name>.py`` — N tests``  → pytest's own collection count.
2. ``<name>.json`` — N records``    → the corpus file's ``records`` array.
3. ``wycheproof_vectors/`` — N vectors across `a`, `b`, `c``
                                    → the manifest's per-file ``actualTests``.

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


#: The "Files" column of the Lines of Code table in docs/METRICS_REPORT.md.
#:
#: These went unchecked while the *other* file count in the same document —
#: "Python test files under `tests/` matching the static regex" — was gated,
#: and the two are different measures that happened to print the same number.
#: They diverged silently the moment a test file was added that the raw glob
#: counts and the regex does not (``conftest.py``, ``ref_keyformat.py``), and
#: the row that was gated is the one that stayed right. A row whose neighbour
#: is checked reads as checked.
#:
#: Each entry maps the row's scope label to the exact reproduction command the
#: report publishes for it, expressed as ``(roots, suffixes)``. Only the file
#: counts are gated, not the line totals: ``wc -l`` moves on every commit and a
#: gate that fails on every commit is one that gets disabled, whereas a file
#: count moves only when the tree's shape does — which is exactly when the
#: prose around it needs re-reading.
_LOC_ROW_SCOPES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Library Python (`ama_cryptography/*.py`)": (("ama_cryptography",), (".py",)),
    "Native C (`src/c/**/*.c`, `include/**/*.h`)": (("src/c", "include"), (".c", ".h")),
    "Library total (Python + C + headers)": (
        ("ama_cryptography", "src/c", "include"),
        (".py", ".c", ".h"),
    ),
    "Tests (`tests/**/*.py`)": (("tests",), (".py",)),
}


def _loc_row_re(label: str) -> re.Pattern[str]:
    return re.compile(rf"\|\s*{re.escape(label)}\s*\|\s*(\d[\d,]*)\s*\|")


def check_loc_table_file_counts(repo: Path) -> list[str]:
    """Every gated row of the LoC table must state the file count it measures."""
    problems: list[str] = []
    report = repo / "docs" / "METRICS_REPORT.md"
    if not report.is_file():
        return [f"{report} is missing; the LoC table cannot be checked"]
    text = report.read_text(encoding="utf-8")

    for label, (roots, suffixes) in _LOC_ROW_SCOPES.items():
        measured = 0
        for root in roots:
            base = repo / root
            if not base.is_dir():
                continue
            measured += sum(1 for p in base.rglob("*") if p.is_file() and p.suffix in suffixes)
        matches = _loc_row_re(label).findall(text)
        if not matches:
            problems.append(
                f"docs/METRICS_REPORT.md: no LoC-table row found for {label!r}; "
                "the row was renamed or removed and this check stopped checking it"
            )
            continue
        for claimed in matches:
            if int(claimed.replace(",", "")) != measured:
                problems.append(
                    f"docs/METRICS_REPORT.md: LoC table says {claimed} files for "
                    f"{label}; measured {measured}"
                )
    return problems


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
                    f"`grep -rE '^\\s*def test_' tests/` finds {functions}"
                )
            if _num(claimed_files) != files:
                problems.append(
                    f"{rel}: claims {claimed_files} test files; {files} contain a test function"
                )
        for claimed in _METRICS_FILES_RE.findall(live):
            if _num(claimed) != files:
                problems.append(f"{rel}: table says {claimed} test files; measured {files}")
        for claimed in _METRICS_FUNCS_RE.findall(live):
            if _num(claimed) != functions:
                problems.append(
                    f"{rel}: table says {claimed} `def test_` matches; measured {functions}"
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


def count_libfuzzer_entry_points(repo: Path) -> int:
    """The authoritative harness count, imported from the registration gate.

    Reusing ``check_fuzz_target_registration._sources`` is deliberate: this
    module's whole thesis is that a fact should be declared once and every other
    mention checked against it, so re-implementing the "a ``fuzz/*.c`` that
    *defines* ``LLVMFuzzerTestOneInput``" detection here would be the exact
    duplication it exists to police.
    """
    tools_dir = str(Path(__file__).resolve().parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    import check_fuzz_target_registration as registration

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
        live_lines = [line for line in text.splitlines() if not _HISTORY_ROW_RE.match(line)]
        for line in live_lines:
            if "fuzz" in line.lower():
                checked += len(_FUZZ_COUNT_RE.findall(line))
        checked += len(_BREAKING_CLAIM_RE.findall("\n".join(live_lines)))
        if path.name == "METRICS_REPORT.md":
            for label in _LOC_ROW_SCOPES:
                checked += len(_loc_row_re(label).findall(text))
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
