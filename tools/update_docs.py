#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
AMA Cryptography — Global Auto-Documentation System
=====================================================

Updates documentation targets from source-of-truth data:
  1. CHANGELOG.md   — new section from git log since last entry
  2. README.md       — refresh version number and date stamps
  3. Benchmark docs  — regenerate tables from ``benchmark-results.json``
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
"""

from __future__ import annotations

# `from __future__ import annotations` (above) makes every annotation in
# this module a lazy string at parse time, so the PEP 604 ``X | None``
# syntax used in def signatures below parses fine on Python 3.9 even
# though that release predates PEP 604's runtime support.  Ruff's UP045
# rule actively prefers this form across the rest of the project, so
# downgrading to ``Optional[str]`` would create cross-rule churn (the
# original PR review suggestion mistakenly flagged this as a 3.9
# SyntaxError; from __future__ annotations defers evaluation, the
# parser only needs to recognise the syntax — which it does in 3.9).

import argparse
import datetime as _dt
import json
import re
import subprocess
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
# Source-of-truth split (3.0.0 audit follow-up):
#   * Headline ops/sec come from the canonical-host *measurement* file
#     produced by ``benchmarks/benchmark_runner.py --output
#     benchmark-results.json`` (the same command CI runs — see
#     ``.github/workflows/ci.yml``'s "Benchmark Regression Detection"
#     step, which also flows ``benchmark-results.json`` and
#     ``benchmark-report.md`` through to the workflow artifacts).
#   * The regression floor (a deliberately-conservative ~65% of measured)
#     stays in baseline.json and is shown in a secondary column so the
#     reader can sanity-check that measured >> floor.
BENCHMARK_RESULTS_JSON = ROOT / "benchmark-results.json"
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
    text = INIT_PY.read_text()
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
    for line in CHANGELOG.read_text().splitlines():
        m = re.match(r"^##\s+\[.*?\]\s+-\s+(\d{4}-\d{2}-\d{2})", line)
        if m:
            return m.group(1)
    return None


def _latest_changelog_version() -> str | None:
    """Extract the version from the first ## [x.y.z] - YYYY-MM-DD line."""
    if not CHANGELOG.exists():
        return None
    for line in CHANGELOG.read_text().splitlines():
        m = re.match(r"^##\s+\[([^\]]+)\]\s+-\s+\d{4}-\d{2}-\d{2}", line)
        if m:
            return m.group(1)
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
        for m in re.finditer(r"\(([0-9a-f]{7})\)", CHANGELOG.read_text()):
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
    text = CHANGELOG.read_text()
    # Find the insertion point: after "## Overview" block's "---"
    insert_re = re.compile(r"(## Overview.*?---\s*\n)", re.DOTALL)
    m = insert_re.search(text)
    if m:
        pos = m.end()
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

    CHANGELOG.write_text(text)
    print(f"  CHANGELOG: updated with {len(commits)} commits")
    return True


# ============================================================================
# 2. README version/date stamps
# ============================================================================


def update_readme(dry_run: bool = False) -> bool:
    if not README.exists():
        print("  README: not found")
        return False

    text = README.read_text()
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

    README.write_text(text)
    print(f"  README: updated version={version} date={today}")
    return True


# ============================================================================
# 3. Benchmark table generation
# ============================================================================
#
# The auto-generated benchmark table publishes the latest *measured* ops/sec
# from ``benchmark-results.json`` as the headline number — the canonical-host
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


def _baseline_index() -> dict[str, dict]:
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
    deferring to the PQC block, but a CI lint check
    (``check_baseline_justification.py``) would catch the issue at PR
    review time.
    """
    if not BASELINE_JSON.exists():
        return {}
    data = json.loads(BASELINE_JSON.read_text())
    flat: dict[str, dict] = {}
    flat.update(data.get("benchmarks", {}))
    flat.update(data.get("pqc_benchmarks", {}))
    return flat


def _generate_benchmark_table() -> str:
    """Emit the canonical-host throughput table.

    ``benchmark-results.json`` is the source of truth for the headline
    numbers; if it is missing the function returns an empty string and
    ``update_benchmark_docs`` prints a remedy rather than silently
    falling back to the floors (which would re-introduce the bug this
    refactor fixes).
    """
    if not BENCHMARK_RESULTS_JSON.exists():
        return ""

    measured = json.loads(BENCHMARK_RESULTS_JSON.read_text())
    rows = measured.get("results", [])
    if not rows:
        return ""

    floor_for = _baseline_index()
    captured = _format_iso_date(measured.get("timestamp"))

    lines = [
        "<!-- "
        "Throughput numbers below are the canonical-host measurements written "
        "by `benchmarks/benchmark_runner.py --output benchmark-results.json` "
        f"(the same command CI runs) on {captured}.  The regression-floor "
        "column is the value enforced by `benchmarks/baseline.json` (CI "
        "fails when measured drops more than `tolerance_percent` below "
        "floor).  Regenerate via `python tools/update_docs.py`. -->",
        f"_Headline source: `benchmark-results.json` (run {captured}). "
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

    return "\n".join(lines)


def update_benchmark_docs(dry_run: bool = False) -> bool:
    if not BENCHMARK_RESULTS_JSON.exists():
        # Copilot review #8: the canonical producer is benchmark_runner.py
        # (not validation_suite.py).  CI runs it via the "Benchmark
        # Regression Detection" job, see .github/workflows/ci.yml.
        # validation_suite.py is the slow-runner regression-floor
        # validation harness and writes to a different output file
        # (benchmarks/validation_results.json) -- not benchmark-results.json.
        print(
            "  BENCHMARKS: benchmark-results.json missing — refusing to "
            "regenerate the auto-table from baseline floors. Re-run\n"
            "    LD_LIBRARY_PATH=build/lib python3 benchmarks/benchmark_runner.py \\\n"
            "        --output benchmark-results.json --markdown benchmark-report.md\n"
            "on the canonical host first."
        )
        return False

    table = _generate_benchmark_table()
    if not table:
        print("  BENCHMARKS: benchmark-results.json contains no `results` entries")
        return False

    changed = False

    # Find all .md files that contain the markers
    md_files = list(ROOT.glob("*.md")) + list(ROOT.glob("wiki/*.md"))
    for md_file in md_files:
        text = md_file.read_text()
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
                md_file.write_text(new_text)
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
        text = md_file.read_text()
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
                md_file.write_text(new_text)
                print(f"  WIKI: updated {md_file.name}")
            changed = True

    if not changed:
        print("  WIKI: no stamps to update")

    return changed


# ============================================================================
# Main
# ============================================================================


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
    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN ===\n")

    any_changed = False

    print("1. CHANGELOG")
    any_changed |= update_changelog(dry_run=args.dry_run)

    if not args.changelog_only:
        print("\n2. README")
        any_changed |= update_readme(dry_run=args.dry_run)

        print("\n3. Benchmark docs")
        any_changed |= update_benchmark_docs(dry_run=args.dry_run)

        print("\n4. Wiki pages")
        any_changed |= update_wiki(dry_run=args.dry_run)

    if any_changed:
        print("\n✓ Documentation updated" + (" (dry run)" if args.dry_run else ""))
    else:
        print("\n• No changes needed")


if __name__ == "__main__":
    main()
