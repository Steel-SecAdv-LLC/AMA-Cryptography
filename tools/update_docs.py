#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — Global Auto-Documentation System
=====================================================

Updates documentation targets from source-of-truth data:
  1. CHANGELOG.md   — new section from git log since last entry
  2. README.md       — refresh version number and date stamps
  3. Benchmark docs  — regenerate tables from ``benchmarks/benchmark-results.json``
                       (canonical-host run; the actual measurement output),
                       cross-checked against ``benchmarks/baseline.json``
                       for the regression-floor secondary column. Pre-3.0.1
                       this generator pointed at ``baseline.json`` and so
                       published the *floors* (~65% of measured) as if they
                       were headline numbers — the wiki caption reflected
                       that, calling the table "Regression Baselines".
                       The published numbers now match what the suite
                       actually measures on the canonical host; the floor
                       remains visible as a secondary column so reviewers
                       see both the headline and the CI safety net.
  4. wiki/*.md       — update version and date stamps

Usage:
    python tools/update_docs.py                # full update
    python tools/update_docs.py --dry-run      # preview only
    python tools/update_docs.py --changelog-only

Text I/O
--------
Every read and write below passes ``encoding="utf-8"`` explicitly, and every
write also passes ``newline=""``.  Neither is decoration.

``Path.read_text()`` without an encoding uses the *locale* encoding, which on
Windows is the ANSI code page (cp1252 on a US/Western install).  ``CHANGELOG
.md`` is UTF-8 and full of em dashes, Greek letters and mathematical symbols,
so the read raised ``UnicodeDecodeError: 'charmap' codec can't decode byte
0x90`` on every Windows job — the doc-sync tool could not run at all on a
platform this project tests across five Python versions.

The write side was worse than an error, because it would have succeeded on the
subset that round-trips: ``write_text`` in text mode translates ``"\\n"`` to
``"\\r\\n"`` on Windows, so a single run would have rewritten every line ending
in ``CHANGELOG.md`` and ``README.md``.  ``tools/check_line_endings.py`` exists
precisely to reject that, so the tool that maintains the documentation would
have failed the repository's own gate on the documentation it maintains.
``newline=""`` disables the translation and pins LF on every platform, the
same way ``ama_cryptography/_build_sign.py`` pins the signature artefact.
"""

from __future__ import annotations

# The PEP 604 ``X | None`` union syntax in the def signatures below is
# natively supported at this project's >=3.10 floor.  Ruff's UP045 rule
# prefers this form across the rest of the project, so it is used here for
# consistency; ``from __future__ import annotations`` (above) additionally
# keeps every annotation a lazy string at parse time.

import argparse
import datetime as _dt
import json
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
# Source-of-truth split (3.0.0 audit follow-up):
#   * Headline ops/sec come from the canonical-host *measurement* file
#     produced by ``benchmarks/benchmark_runner.py --output
#     benchmarks/benchmark-results.json`` (the same command CI runs — see
#     ``.github/workflows/ci.yml``'s "Benchmark Regression Detection"
#     step, which also flows ``benchmarks/benchmark-results.json`` and
#     ``benchmark-report.md`` through to the workflow artifacts).
#   * The regression floor (a deliberately-conservative ~65% of measured)
#     stays in baseline.json and is shown in a secondary column so the
#     reader can sanity-check that measured >> floor.
BENCHMARK_RESULTS_JSON = ROOT / "benchmarks" / "benchmark-results.json"
BASELINE_JSON = ROOT / "benchmarks" / "baseline.json"
WIKI_DIR = ROOT / "wiki"
INIT_PY = ROOT / "ama_cryptography" / "__init__.py"

BENCH_START = "<!-- AUTO-BENCHMARK-TABLE-START -->"
BENCH_END = "<!-- AUTO-BENCHMARK-TABLE-END -->"

# ============================================================================
# Helpers
# ============================================================================


def _get_version() -> str:
    """Read __version__ from ama_cryptography/__init__.py."""
    text = INIT_PY.read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
    return m.group(1) if m else "2.1"


def _today() -> str:
    return date.today().isoformat()


def _run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    return result.stdout.strip()


# ============================================================================
# 1. CHANGELOG
# ============================================================================

# Conventional-commit-style classification
_CATEGORY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Security", re.compile(r"\b(security|cve|vuln|fips|cavp)\b", re.I)),
    ("Fixed", re.compile(r"\b(fix|bug|patch|resolve|repair)\b", re.I)),
    ("Added", re.compile(r"\b(add|new|implement|create|introduce)\b", re.I)),
    ("Changed", re.compile(r"\b(change|update|refactor|rename|move|migrate)\b", re.I)),
    ("Removed", re.compile(r"\b(remove|delete|drop|deprecate)\b", re.I)),
    ("Performance", re.compile(r"\b(perf|bench|optim|speed|fast)\b", re.I)),
]


def _classify_commit(subject: str) -> str:
    for category, pat in _CATEGORY_PATTERNS:
        if pat.search(subject):
            return category
    return "Changed"


def _last_changelog_date() -> str | None:
    """Extract the date from the first ## [x.y.z] - YYYY-MM-DD line."""
    if not CHANGELOG.exists():
        return None
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^##\s+\[.*?\]\s+-\s+(\d{4}-\d{2}-\d{2})", line)
        if m:
            return m.group(1)
    return None


#: A ``## [version]`` heading, with or without a trailing date.
#:
#: The date is OPTIONAL, and that is the whole point.  Requiring it made
#: :func:`_latest_changelog_version` blind to exactly the headings a
#: pre-release tree carries — ``## [Unreleased]`` under the Keep a Changelog
#: convention this file declares, and ``## [5.0.0] - Unreleased`` while a
#: version is prepared but not yet tagged.  The duplicate-section guard in
#: :func:`update_changelog` is built on that function, so with an undated top
#: section the guard read the *previous* release's version, decided the current
#: one had no section, and inserted a SECOND ``## [5.0.0]`` above the
#: hand-written one — splitting the release's notes in two and leaving
#: ``check_documented_counts``' breaking-row derivation reading an empty
#: section.  Running the repository's own documentation sync must not corrupt
#: the file it syncs.
_CHANGELOG_HEADING_RE = re.compile(r"^##\s+\[([^\]]+)\]\s*(?:-\s*(\S.*))?$")


def _latest_changelog_version() -> str | None:
    """The version of the newest release section, dated or not.

    ``[Unreleased]`` is skipped: it is a standing placeholder, never a version,
    and treating it as one would make the guard compare ``"Unreleased"`` against
    the project version and always miss.
    """
    if not CHANGELOG.exists():
        return None
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        m = _CHANGELOG_HEADING_RE.match(line)
        if m and m.group(1).strip().lower() != "unreleased":
            return m.group(1).strip()
    return None


def update_changelog(dry_run: bool = False) -> bool:
    last_date = _last_changelog_date()

    # Get commits since last changelog date (or last 20 if no date found)
    if last_date:
        log_args = ["log", f"--since={last_date}", "--format=%H|%s", "--no-merges"]
    else:
        log_args = ["log", "-20", "--format=%H|%s", "--no-merges"]

    raw = _run_git(*log_args)
    if not raw:
        print("  CHANGELOG: no new commits found")
        return False

    # Parse existing SHA7s from CHANGELOG to avoid duplicates
    existing_shas: set[str] = set()
    if CHANGELOG.exists():
        for m in re.finditer(r"\(([0-9a-f]{7})\)", CHANGELOG.read_text(encoding="utf-8")):
            existing_shas.add(m.group(1))

    commits: list[tuple[str, str]] = []
    for line in raw.splitlines():
        if "|" not in line:
            continue
        sha, subject = line.split("|", 1)
        sha7 = sha[:7]
        # Skip auto-docs commits and commits already in changelog
        if "[auto-docs]" in subject:
            continue
        if sha7 in existing_shas:
            continue
        commits.append((sha7, subject.strip()))

    if not commits:
        print("  CHANGELOG: no classifiable commits")
        return False

    # Skip adding a duplicate section when the current project version already
    # has a section at the top of the CHANGELOG. Commits landing after the
    # version bump (e.g. docs, dependabot merges) should not spawn a second
    # "## [X.Y.Z] - <today>" header for the same release.
    if _latest_changelog_version() == _get_version():
        print(
            "  CHANGELOG: latest section already at current project version;"
            " skipping new section creation"
        )
        return False

    # Group by category
    categorized: dict[str, list[tuple[str, str]]] = {}
    for sha, subject in commits:
        cat = _classify_commit(subject)
        categorized.setdefault(cat, []).append((sha, subject))

    version = _get_version()
    today = _today()

    # Build new section
    lines = [f"\n## [{version}] - {today}\n"]
    # Ordered categories
    order = ["Security", "Added", "Changed", "Fixed", "Removed", "Performance"]
    for cat in order:
        items = categorized.get(cat)
        if not items:
            continue
        lines.append(f"\n### {cat}\n")
        for sha, subject in items:
            lines.append(f"- {subject} ({sha})")
    lines.append("\n---\n")

    new_section = "\n".join(lines)

    if dry_run:
        print("  CHANGELOG: would insert:")
        print(new_section)
        return True

    # Insert after the "---" that follows "## Overview"
    text = CHANGELOG.read_text(encoding="utf-8")
    # Find the insertion point: after "## Overview" block's "---"
    insert_re = re.compile(r"(## Overview.*?---\s*\n)", re.DOTALL)
    insert_match = insert_re.search(text)
    if insert_match:
        pos = insert_match.end()
        text = text[:pos] + new_section + text[pos:]
    else:
        # Fallback: insert after first "---"
        idx = text.find("---")
        if idx != -1:
            idx = text.find("\n", idx) + 1
            text = text[:idx] + new_section + text[idx:]
        else:
            text = new_section + text

    # Update Document Version date
    text = re.sub(
        r"(\| Last Updated \|)\s*\d{4}-\d{2}-\d{2}\s*\|",
        f"\\1 {today} |",
        text,
    )

    CHANGELOG.write_text(text, encoding="utf-8", newline="")
    print(f"  CHANGELOG: updated with {len(commits)} commits")
    return True


# ============================================================================
# 2. README version/date stamps
# ============================================================================


def update_readme(dry_run: bool = False) -> bool:
    if not README.exists():
        print("  README: not found")
        return False

    text = README.read_text(encoding="utf-8")
    version = _get_version()
    today = _today()
    changed = False

    # Update **Version:** X.Y
    new_text = re.sub(
        r"(\*\*Version:\*\*)\s*\d+\.\d+(\.\d+)?",
        f"\\1 {version}",
        text,
    )
    if new_text != text:
        changed = True
        text = new_text

    # Update "Last Updated" table rows
    new_text = re.sub(
        r"(\| Last Updated \|)\s*\d{4}-\d{2}-\d{2}\s*\|",
        f"\\1 {today} |",
        text,
    )
    if new_text != text:
        changed = True
        text = new_text

    if not changed:
        print("  README: no stamps to update")
        return False

    if dry_run:
        print(f"  README: would update version to {version}, date to {today}")
        return True

    README.write_text(text, encoding="utf-8", newline="")
    print(f"  README: updated version={version} date={today}")
    return True


# ============================================================================
# 3. Benchmark table generation
# ============================================================================
#
# The auto-generated benchmark table publishes the latest *measured* ops/sec
# from ``benchmarks/benchmark-results.json`` as the headline number — the canonical-host
# run that the suite actually produced — and pairs each row with the matching
# regression floor from ``benchmarks/baseline.json``.  Reviewers see both:
#   * "Throughput (ops/sec)" — what the host actually measured.
#   * "Regression floor"     — what CI enforces (deliberately ~65% of
#                              measured, with `tolerance_percent` headroom).
#
# Headline === canonical-host run.  The pre-3.0.1 generator pointed at the
# floor file and so unintentionally published the safety-net numbers as if
# they were the canonical figures; that has been corrected here.


def _format_iso_date(timestamp: str | None) -> str:
    """Return ``YYYY-MM-DD`` from an ISO-8601 timestamp, or ``unknown``."""
    if not timestamp:
        return "unknown"
    try:
        # Python 3.11+ accepts trailing Z directly; we also strip it for safety.
        normalised = timestamp.replace("Z", "+00:00")
        return _dt.datetime.fromisoformat(normalised).date().isoformat()
    except ValueError:
        return timestamp[:10] if len(timestamp) >= 10 else "unknown"


def _baseline_index() -> dict[str, dict[str, Any]]:
    """Flatten baseline.json into ``{name: entry}`` so per-row lookup is O(1).

    Both the ``benchmarks`` and ``pqc_benchmarks`` blocks contribute.
    On a name collision the **PQC block wins**, mirroring the runner's
    own resolution order: ``benchmarks/benchmark_runner.py`` reads each
    benchmark's config from whichever block holds the matching key, and
    PQC functions (e.g. ``x25519_scalarmult``) are registered in
    ``pqc_benchmark_functions`` so the runner pulls their config from
    ``pqc_benchmarks``.  Mirroring that here ensures
    ``tools/update_docs.py`` and ``benchmark_runner.py`` agree on the
    canonical floor for every primitive.

    Devin review #10 caught a 3.0.0-audit-PR regression where a new
    ``x25519_scalarmult`` entry was added to the ``benchmarks`` block
    while the existing one in ``pqc_benchmarks`` was left at a stale
    floor (5,000 ops/sec, ~38 % of measured) — the runner kept reading
    the stale ``pqc_benchmarks`` entry and the new ``benchmarks`` entry
    was dead.  That has been fixed (the ``benchmarks`` entry was
    removed and the ``pqc_benchmarks`` entry re-floored to the
    measured 13,000 ops/sec).  This implementation tolerates a future
    ``benchmarks`` ⇄ ``pqc_benchmarks`` overlap by deterministically
    deferring to the PQC block; the existing CI lint check
    ``benchmarks/check_baseline_justification.py`` (run by
    ``.github/workflows/baseline-guard.yml``) catches baseline-floor
    regressions at PR review time, complementing this resolution
    contract.
    """
    if not BASELINE_JSON.exists():
        return {}
    data = json.loads(BASELINE_JSON.read_text(encoding="utf-8"))
    flat: dict[str, dict[str, Any]] = {}
    flat.update(data.get("benchmarks", {}))
    flat.update(data.get("pqc_benchmarks", {}))
    return flat


def _generate_benchmark_table() -> str:
    """Emit the canonical-host throughput table.

    ``benchmarks/benchmark-results.json`` is the source of truth for the headline
    numbers; if it is missing the function returns an empty string and
    ``update_benchmark_docs`` prints a remedy rather than silently
    falling back to the floors (which would re-introduce the bug this
    refactor fixes).
    """
    if not BENCHMARK_RESULTS_JSON.exists():
        return ""

    measured = json.loads(BENCHMARK_RESULTS_JSON.read_text(encoding="utf-8"))
    rows = measured.get("results", [])
    if not rows:
        return ""

    floor_for = _baseline_index()
    captured = _format_iso_date(measured.get("timestamp"))

    lines = [
        "<!-- "
        "Throughput numbers below are the canonical-host measurements written "
        "by `benchmarks/benchmark_runner.py --output benchmarks/benchmark-results.json` "
        f"(the same command CI runs) on {captured}.  The regression-floor "
        "column is the value enforced by `benchmarks/baseline.json` (CI "
        "fails when measured drops more than `tolerance_percent` below "
        "floor).  Regenerate via `python tools/update_docs.py`. -->",
        f"_Headline source: `benchmarks/benchmark-results.json` (run {captured}). "
        "Regression floor: `benchmarks/baseline.json`.  CI fails on "
        "(measured - tolerance%) < floor — both columns shown so reviewers "
        "can sanity-check the headroom._",
        "",
        "| Benchmark | Throughput (ops/sec) | Regression floor (ops/sec) | Tolerance | Tier |",
        "|-----------|---------------------:|---------------------------:|----------:|------|",
    ]

    for row in rows:
        name = row.get("name", "")
        display = name.replace("_", " ").title()
        ops = row.get("ops_per_second")
        if ops is None:
            measured_cell = "—"
        elif ops >= 10_000:
            measured_cell = f"{ops:,.0f}"
        else:
            # Sub-10k benchmarks (e.g. PQC sign / verify, full_package_*)
            # benefit from one decimal place — readers cite these numbers
            # in marketing copy, so 3,727.6 is more useful than 3,728.
            measured_cell = f"{ops:,.1f}"

        floor_entry = floor_for.get(name) or {}
        floor_value = floor_entry.get("baseline_value", row.get("baseline_value"))
        floor_cell = f"{floor_value:,}" if isinstance(floor_value, (int, float)) else "—"

        tol_value = floor_entry.get("tolerance_percent", row.get("tolerance_percent"))
        tol_cell = f"±{tol_value}%" if tol_value is not None else "—"

        tier = floor_entry.get("tier", "microbenchmark")
        optional = " *(optional)*" if row.get("optional") or floor_entry.get("optional") else ""

        lines.append(
            f"| {display}{optional} | {measured_cell} | {floor_cell} | {tol_cell} | {tier} |"
        )

    # Gate entries with no row in the results JSON (a floor added after the
    # committed run — e.g. the secp256k1 rows landed while the last published
    # results JSON predated them).  Omitting them silently would present the
    # table as the whole gate when it is not; they are emitted floor-only,
    # with the measured cell pointing at the canonical markdown report until
    # a newer results JSON is committed.
    measured_names = {row.get("name") for row in rows}
    missing = [name for name in floor_for if name not in measured_names]
    if missing:
        lines.append("")
        lines.append(
            "_Floors below were added to `benchmarks/baseline.json` after the "
            f"{captured} results-JSON run; their measured values are in "
            "[`benchmark-report.md`](https://github.com/Steel-SecAdv-LLC/"
            "AMA-Cryptography/blob/main/benchmark-report.md) until the next "
            "dual-output canonical-host run is committed._"
        )
        lines.append("")
        lines.append(
            "| Benchmark | Throughput (ops/sec) | Regression floor (ops/sec) | Tolerance | Tier |"
        )
        lines.append(
            "|-----------|---------------------:|---------------------------:|----------:|------|"
        )
        for name in missing:
            display = name.replace("_", " ").title()
            floor_entry = floor_for[name]
            floor_value = floor_entry.get("baseline_value")
            floor_cell = f"{floor_value:,}" if isinstance(floor_value, (int, float)) else "—"
            tol_value = floor_entry.get("tolerance_percent")
            tol_cell = f"±{tol_value}%" if tol_value is not None else "—"
            tier = floor_entry.get("tier", "microbenchmark")
            optional = " *(optional)*" if floor_entry.get("optional") else ""
            lines.append(
                f"| {display}{optional} | see report | {floor_cell} | {tol_cell} | {tier} |"
            )

    return "\n".join(lines)


def update_benchmark_docs(dry_run: bool = False) -> bool:
    if not BENCHMARK_RESULTS_JSON.exists():
        # Copilot review #8: the canonical producer is benchmark_runner.py
        # (not validation_suite.py).  CI runs it via the "Benchmark
        # Regression Detection" job, see .github/workflows/ci.yml.
        # validation_suite.py is the slow-runner regression-floor
        # validation harness and writes to a different output file
        # (benchmarks/validation_results.json) -- not benchmarks/benchmark-results.json.
        print(
            "  BENCHMARKS: benchmarks/benchmark-results.json missing — refusing to "
            "regenerate the auto-table from baseline floors. Re-run\n"
            "    LD_LIBRARY_PATH=build/lib python3 benchmarks/benchmark_runner.py \\\n"
            "        --output benchmarks/benchmark-results.json --markdown benchmark-report.md\n"
            "on the canonical host first."
        )
        return False

    table = _generate_benchmark_table()
    if not table:
        print("  BENCHMARKS: benchmarks/benchmark-results.json contains no `results` entries")
        return False

    changed = False

    # Find all .md files that contain the markers
    md_files = list(ROOT.glob("*.md")) + list(ROOT.glob("wiki/*.md"))
    for md_file in md_files:
        text = md_file.read_text(encoding="utf-8")
        if BENCH_START not in text:
            continue

        pattern = re.compile(
            re.escape(BENCH_START) + r".*?" + re.escape(BENCH_END),
            re.DOTALL,
        )
        replacement = f"{BENCH_START}\n{table}\n{BENCH_END}"
        new_text = pattern.sub(replacement, text)

        if new_text != text:
            if dry_run:
                print(f"  BENCHMARKS: would update {md_file.name}")
            else:
                md_file.write_text(new_text, encoding="utf-8", newline="")
                print(f"  BENCHMARKS: updated {md_file.name}")
            changed = True

    if not changed:
        print("  BENCHMARKS: no files with AUTO-BENCHMARK-TABLE markers found")

    return changed


# ============================================================================
# 4. Wiki version/date stamps
# ============================================================================


def update_wiki(dry_run: bool = False) -> bool:
    if not WIKI_DIR.is_dir():
        print("  WIKI: wiki/ directory not found")
        return False

    version = _get_version()
    today = _today()
    changed = False

    for md_file in sorted(WIKI_DIR.glob("*.md")):
        text = md_file.read_text(encoding="utf-8")
        new_text = text

        # Update "| Version | X.Y |" table rows
        new_text = re.sub(
            r"(\| Version \|)\s*\d+\.\d+(\.\d+)?\s*\|",
            f"\\1 {version} |",
            new_text,
        )

        # Update "| Last Updated | YYYY-MM-DD |" table rows
        new_text = re.sub(
            r"(\| Last Updated \|)\s*\d{4}-\d{2}-\d{2}\s*\|",
            f"\\1 {today} |",
            new_text,
        )

        if new_text != text:
            if dry_run:
                print(f"  WIKI: would update {md_file.name}")
            else:
                md_file.write_text(new_text, encoding="utf-8", newline="")
                print(f"  WIKI: updated {md_file.name}")
            changed = True

    if not changed:
        print("  WIKI: no stamps to update")

    return changed


# ============================================================================
# Main
# ============================================================================


def _counts_module() -> Any:
    """Load tools/check_documented_counts.py as a module.

    The regenerator and the gate MUST share one measurement implementation:
    a regenerator with its own counting rules is how the two would disagree
    while both looked authoritative.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_documented_counts", ROOT / "tools" / "check_documented_counts.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - loader contract
        raise RuntimeError("tools/check_documented_counts.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def update_loc_metrics(dry_run: bool = False) -> bool:
    """Re-measure and rewrite every gated Lines-of-Code figure in
    docs/METRICS_REPORT.md from the same functions the documented-counts
    gate verifies with.

    This is the one-command answer to "a line-total gate fails on every
    commit": run this after a change, review the diff, done.  A figure the
    regenerator does not know how to rewrite is a figure the gate does not
    check — keep the two lists in lockstep.
    """
    counts = _counts_module()
    report = ROOT / "docs" / "METRICS_REPORT.md"
    text = report.read_text(encoding="utf-8")
    original = text

    table = counts.measure_loc_table(ROOT)
    composition = counts.measure_scope_composition(ROOT)
    json_lines = counts.measure_tracked_json_lines(ROOT)

    def _fmt(n: int) -> str:
        return f"{n:,}"

    # --- Lines of Code table rows (bold preserved on the two flagship
    # cells: Library-total lines and the Whole-project row).
    for label, (files, lines) in table.items():
        lines_cell = _fmt(lines)
        if label in ("Library total (Python + C + headers)",):
            lines_cell = f"**{lines_cell}**"
        if label.startswith("**Whole project**"):
            lines_cell = f"**{lines_cell}**"
        text = counts._loc_row_re(label).sub(f"| {label} | {_fmt(files)} | {lines_cell} |", text)

    # --- Scope Composition table rows.
    comp_paths = {
        "Library (Python + C + headers)": "`ama_cryptography/` + `src/c/` + `include/`",
        "Tests": "`tests/**/*.py`",
        "Top-level Python": "`*.py` at repo root",
        "Cython": "`*.pyx` + `*.pxd`",
        "Everything else (remainder)": (
            "`*.md`, `*.yml`, `*.toml`, `*.json`, CMake, Makefile, plus "
            "`.c`/`.h`/`.py` outside the scopes above (`tests/c/`, `fuzz/`, "
            "`tools/`, `benchmarks/`, `examples/`)"
        ),
        "**Whole-project total**": "sum of the scopes above",
    }
    for label, (lines, pct) in composition.items():
        bold = label.startswith("**")
        lines_cell = f"**{_fmt(lines)}**" if bold else _fmt(lines)
        pct_cell = f"**{pct}**" if bold else pct
        text = re.sub(
            rf"\|\s*{re.escape(label)}\s*\|[^|]*\|[^|]*\|[^|]*\|",
            f"| {label} | {lines_cell} | {pct_cell} | {comp_paths[label]} |",
            text,
        )

    # --- Prose restatements of the measured figures.
    lib_files, lib_lines = table["Library total (Python + C + headers)"]
    whole_lines = table["**Whole project** (source + docs + config)"][1]
    tests_lines, tests_pct = composition["Tests"]
    library_pct = composition["Library (Python + C + headers)"][1]
    remainder_pct = composition["Everything else (remainder)"][1]
    ratio = tests_lines / lib_lines if lib_lines else 0.0

    text = re.sub(
        r"\d[\d,]* lines\*\* across \d[\d,]* files under",
        f"{_fmt(lib_lines)} lines** across {_fmt(lib_files)} files under",
        text,
    )
    text = re.sub(
        r"Whole-project total\*\* \(`\d[\d,]*` lines",
        f"Whole-project total** (`{_fmt(whole_lines)}` lines",
        text,
    )
    text = re.sub(
        r"only\s*\*\*[\d.]+%\*\* of the repository is library code",
        f"only **{library_pct}** of the repository is library code",
        text,
    )
    text = re.sub(
        r"Test code \([\d.]+%\) is roughly \S+ the size of the library\s*\([\d.]+%\)",
        f"Test code ({tests_pct}) is roughly {ratio:.1f}x the size of the library "
        f"({library_pct})",
        text,
    )
    text = re.sub(
        r"test-to-library ratio is roughly \*\*[\d.]+\*\*",
        f"test-to-library ratio is roughly **{ratio:.2f}**",
        text,
    )
    text = re.sub(
        r"The remainder \([\d.]+%\)",
        f"The remainder ({remainder_pct})",
        text,
    )
    text = re.sub(
        r"\(\d[\d,]* lines of\s*`\*\.json`",
        f"({_fmt(json_lines)} lines of `*.json`",
        text,
    )

    if text == original:
        print("   METRICS_REPORT.md LoC figures: already current")
        return False
    if dry_run:
        print("   METRICS_REPORT.md LoC figures: would be re-measured and rewritten")
        return True
    report.write_text(text, encoding="utf-8", newline="")
    print("   METRICS_REPORT.md LoC figures: re-measured and rewritten")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="AMA Cryptography auto-documentation updater")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without writing files",
    )
    parser.add_argument(
        "--changelog-only",
        action="store_true",
        help="Only update CHANGELOG.md",
    )
    parser.add_argument(
        "--loc",
        action="store_true",
        help="Only re-measure and rewrite the Lines-of-Code figures in "
        "docs/METRICS_REPORT.md (the one-command fix for a red LoC gate)",
    )
    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN ===\n")

    any_changed = False

    if args.loc:
        print("LoC metrics")
        any_changed = update_loc_metrics(dry_run=args.dry_run)
        print(
            "\n✓ Documentation updated" + (" (dry run)" if args.dry_run else "")
            if any_changed
            else "\n• No changes needed"
        )
        return

    print("1. CHANGELOG")
    any_changed |= update_changelog(dry_run=args.dry_run)

    if not args.changelog_only:
        print("\n2. README")
        any_changed |= update_readme(dry_run=args.dry_run)

        print("\n3. Benchmark docs")
        any_changed |= update_benchmark_docs(dry_run=args.dry_run)

        print("\n4. Wiki pages")
        any_changed |= update_wiki(dry_run=args.dry_run)

        print("\n5. LoC metrics")
        any_changed |= update_loc_metrics(dry_run=args.dry_run)

    if any_changed:
        print("\n✓ Documentation updated" + (" (dry run)" if args.dry_run else ""))
    else:
        print("\n• No changes needed")


if __name__ == "__main__":
    main()
