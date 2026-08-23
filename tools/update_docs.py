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
                       published the *floors* as if they were headline
                       numbers — the wiki caption reflected that, calling the
                       table "Regression Baselines". The published numbers now
                       match what the suite actually measures on the canonical
                       host; the floor remains visible as a secondary column
                       so reviewers see both the headline and the CI safety
                       net. Since 5.0.0 the floor is a measured median on the
                       runner class named in ``metadata.runner_cpu_class``,
                       not a fraction of the headline, so the two columns are
                       different hosts and the floor may legitimately exceed
                       the measured figure.
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
import sys
from pathlib import Path
from typing import Any, Optional

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
#   * The regression floor stays in baseline.json and is shown in a
#     secondary column.  Since 5.0.0 it is NOT a discount of the headline
#     number: it is a measured median on the CI runner class named in
#     `metadata.runner_cpu_class` (x86-64 slow-class median with a uniform
#     45% tolerance; aarch64 homogeneous, 15%/25%).  The two columns are
#     therefore different hosts, and a floor ABOVE a measured figure is an
#     ordinary result — in wiki/Performance-Benchmarks.md it is the case on
#     11 of 19 rows.  "Sanity-check that measured >> floor", which this
#     comment used to say, is not a check the current scheme supports; the
#     check is the tolerance, applied by the benchmark-regression job.
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
    return _dt.date.today().isoformat()


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

    # The host is rendered from the record's own provenance, never asserted.
    # This header used to call every run "the canonical-host measurements",
    # which was a claim about hardware the generator has no knowledge of: the
    # committed record was produced on a 4-CPU build container, and the table
    # published its numbers under a label naming an AVX-512 bench host.
    provenance = measured.get("provenance", {})
    host = str(provenance.get("host", "unrecorded host")).strip("` ")
    cpu = str(provenance.get("cpu", "")).strip("` ")
    host_desc = f"{host}" + (f", {cpu}" if cpu else "")

    lines = [
        "<!-- "
        "Throughput numbers below were written by "
        "`benchmarks/benchmark_runner.py --output benchmarks/benchmark-results.json` "
        f"(the same command CI runs) on {captured}, on the host that record "
        f"names ({host_desc}).  They describe THAT host: compare rows within "
        "the table, not against a different machine.  The regression-floor "
        "column is the value enforced by `benchmarks/baseline.json` (CI "
        "fails when measured drops more than `tolerance_percent` below "
        "floor).  Regenerate via `python tools/update_docs.py`. -->",
        f"_Headline source: `benchmarks/benchmark-results.json` (run {captured} on "
        f"{host_desc}). Regression floor: `benchmarks/baseline.json`, measured on "
        "the CI runner class named there — a floor and a throughput figure are "
        "different machines on purpose, so the gap between the columns is not "
        "headroom unless both were measured on the same host.  CI fails when "
        "measured falls more than `tolerance_percent` below floor._",
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
    carrying = 0

    # Find all .md files that contain the markers
    md_files = list(ROOT.glob("*.md")) + list(ROOT.glob("wiki/*.md"))
    for md_file in md_files:
        text = md_file.read_text(encoding="utf-8")
        if BENCH_START not in text:
            continue
        carrying += 1

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
        # Two different outcomes, and this used to print the second sentence
        # for both: a run over an already-current wiki page reported that the
        # markers could not be found, in a tree where `wiki/
        # Performance-Benchmarks.md` carries them at lines 314 and 339.  A
        # status line that says the table was not found is how a DELETED
        # marker pair — which silently stops the published table tracking the
        # measurements — reads exactly like a no-op.
        if carrying:
            print(
                f"  BENCHMARKS: {carrying} file(s) already match " f"{BENCHMARK_RESULTS_JSON.name}"
            )
        else:
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


class UnstagedAdditionsError(RuntimeError):
    """New files exist that ``git ls-files`` cannot see yet."""


def _unstaged_additions_that_would_count(repo: Path | None = None) -> list[str]:
    """Untracked, non-ignored files a gated LoC row would select.

    ``measure_loc_table`` enumerates with ``git ls-files``, which lists the
    INDEX.  A file that has been written but not ``git add``-ed is therefore
    invisible to the measurement while being very much part of the commit
    about to be made — so running ``--loc`` before staging writes figures that
    are correct for the index and wrong for the commit, and the gate goes red
    on CI for a tree the author measured as green.

    That is not hypothetical: it happened during this branch's own work, and
    it is silent in both directions (the regenerator reports success, the
    figures look plausible, and the failure surfaces one commit later
    attributed to the wrong change).  Ignored paths — build directories,
    virtualenvs, caches — are excluded by ``--exclude-standard``, so an
    ordinary working tree with build output does not trip this.

    ``repo`` overrides the tree inspected; it exists so the tests can drive a
    scratch repository without relocating ROOT, which is also where the
    predicate module is loaded from.
    """
    counts = _counts_module()
    root = ROOT if repo is None else repo
    if not (root / ".git").exists():
        return []
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    selects = counts._LOC_TABLE_ROWS["**Whole project** (source + docs + config)"]
    return sorted(
        path for path in (p.decode("utf-8") for p in proc.stdout.split(b"\0") if p) if selects(path)
    )


def update_loc_metrics(dry_run: bool = False) -> bool:
    """Re-measure and rewrite every gated Lines-of-Code figure in
    docs/METRICS_REPORT.md from the same functions the documented-counts
    gate verifies with.

    This is the one-command answer to "a line-total gate fails on every
    commit": run this after a change, review the diff, done.  A figure the
    regenerator does not know how to rewrite is a figure the gate does not
    check — keep the two lists in lockstep.

    Raises:
        UnstagedAdditionsError: when a new, non-ignored file has not been
            staged.  Measuring around it would produce figures that describe
            the index rather than the commit; see
            :func:`_unstaged_additions_that_would_count`.
    """
    pending = _unstaged_additions_that_would_count()
    if pending:
        shown = "\n  ".join(pending[:20])
        more = f"\n  … and {len(pending) - 20} more" if len(pending) > 20 else ""
        raise UnstagedAdditionsError(
            "refusing to re-measure: these files are not staged, so "
            "`git ls-files` cannot see them and the figures written here "
            "would describe the index rather than the commit:\n"
            f"  {shown}{more}\n\n"
            "Stage them first (`git add …`), then re-run.  If a file should "
            "never be committed, add it to .gitignore."
        )
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


#: The aggregate claim, with the connective text captured so a rewrite keeps
#: each document's own wording ("4,085 test functions across 173 Python test
#: files", "4,085 Python test functions across 173 test files", …).  Mirrors
#: ``check_documented_counts._AGGREGATE_RE`` exactly, with groups added around
#: the parts that must survive; the two are pinned equal by
#: ``tests/test_documented_counts_gate.py``.  Every quantifier is bounded, for
#: the reason recorded on the gate's copy.
_AGGREGATE_REWRITE_RE = re.compile(
    r"([\d,]{1,15})(\s{1,8}(?:static\s{1,8})?(?:Python\s{1,8})?"
    r"test functions across\s{1,8})([\d,]{1,15})(\s{1,8}"
    r"(?:Python\s{1,8})?(?:test\s{1,8})?files?)"
)

#: Documents carrying a gated static-test-count claim.
_TEST_COUNT_DOCUMENTS = ("README.md", "ARCHITECTURE.md", "docs/METRICS_REPORT.md")


def update_static_test_counts(dry_run: bool = False, root: Optional[Path] = None) -> bool:
    """Re-measure and rewrite every gated static test-function/file count.

    The LoC half of the documented-counts gate had a one-command fix
    (``--loc``) and this half did not, so a commit that added a test left four
    claims across three documents to be found and hand-edited — and the gate
    that catches them names no command for them.  That asymmetry is what makes
    a count gate feel like an obstacle instead of a tool, and this branch's own
    CI went red on the LoC half for exactly the reason the other half would
    have: a change landed and nobody re-measured.

    Measured with ``check_documented_counts.measure_static_test_counts`` —
    imported, never re-derived — so the regenerator and the gate cannot
    disagree about what the number is.

    Revision-history rows are skipped, on the same rule the gate applies: a row
    like ``| 3.5.0 | 2026-07-30 | … 3,057 static Python test functions across
    127 files … |`` records what was true at a past release, and rewriting it
    would falsify the record rather than update a claim.

    Args:
        dry_run: report what would change and write nothing.
        root: tree to measure and rewrite, defaulting to this repository.
            An explicit parameter rather than a patched module global, so the
            tests drive a real directory instead of redirecting the loader that
            imports the gate module.
    """
    counts = _counts_module()
    tree = ROOT if root is None else root
    functions, files = counts.measure_static_test_counts(tree)
    changed = False

    for relative in _TEST_COUNT_DOCUMENTS:
        path = tree / relative
        if not path.is_file():
            continue
        original = path.read_text(encoding="utf-8")
        rewritten_lines = []
        for line in original.splitlines(keepends=True):
            if counts._HISTORY_ROW_RE.match(line):
                rewritten_lines.append(line)
                continue
            line = _AGGREGATE_REWRITE_RE.sub(
                lambda m: f"{functions:,}{m.group(2)}{files:,}{m.group(4)}", line
            )
            line = counts._METRICS_FILES_RE.sub(
                "| Python test files under `tests/` matching the static regex " f"| {files:,} |",
                line,
            )
            line = counts._METRICS_FUNCS_RE.sub(
                "| Syntactic `def test_` matches under `tests/**/*.py` " f"| **{functions:,}** |",
                line,
            )
            rewritten_lines.append(line)
        text = "".join(rewritten_lines)
        if text == original:
            continue
        changed = True
        if not dry_run:
            path.write_text(text, encoding="utf-8", newline="")

    if not changed:
        print("   static test counts: already current")
        return False
    verb = "would be re-measured and rewritten" if dry_run else "re-measured and rewritten"
    print(f"   static test counts ({functions:,} functions / {files:,} files): {verb}")
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
    parser.add_argument(
        "--counts",
        action="store_true",
        help="Only re-measure and rewrite every count the documented-counts "
        "gate checks: the Lines-of-Code figures AND the static "
        "test-function/file claims in README.md, ARCHITECTURE.md and "
        "docs/METRICS_REPORT.md (the one-command fix for a red counts gate)",
    )
    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN ===\n")

    any_changed = False

    if args.loc or args.counts:
        print("LoC metrics")
        try:
            any_changed = update_loc_metrics(dry_run=args.dry_run)
        except UnstagedAdditionsError as exc:
            # Exit non-zero: a caller that scripted `update_docs.py --loc &&
            # git commit` must not proceed on figures the commit invalidates.
            print(f"   ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        if args.counts:
            print("\nStatic test counts")
            any_changed |= update_static_test_counts(dry_run=args.dry_run)
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
        try:
            any_changed |= update_loc_metrics(dry_run=args.dry_run)
        except UnstagedAdditionsError as exc:
            print(f"   ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        print("\n6. Static test counts")
        any_changed |= update_static_test_counts(dry_run=args.dry_run)

    if any_changed:
        print("\n✓ Documentation updated" + (" (dry run)" if args.dry_run else ""))
    else:
        print("\n• No changes needed")


if __name__ == "__main__":
    main()
