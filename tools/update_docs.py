#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
AMA Cryptography — Global Auto-Documentation System
=====================================================

Updates documentation targets from source-of-truth data:
  1. CHANGELOG.md    — new section from git log since last entry
  2. README.md        — refresh version number and date stamps
  3. Benchmark docs   — regenerate tables from benchmarks/baseline.json
  4. wiki/*.md        — update version and date stamps

Usage:
    python tools/update_docs.py                # full update
    python tools/update_docs.py --dry-run      # preview only
    python tools/update_docs.py --changelog-only
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
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
    return m.group(1) if m else "2.0"


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
    insert_re = re.compile(
        r"(## Overview.*?---\s*\n)", re.DOTALL
    )
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


def _generate_benchmark_table() -> str:
    if not BASELINE_JSON.exists():
        return ""

    data = json.loads(BASELINE_JSON.read_text())
    benchmarks = data.get("benchmarks", {})
    pqc = data.get("pqc_benchmarks", {})

    lines = [
        "| Benchmark | Baseline (ops/sec) | Tolerance | Tier |",
        "|-----------|-------------------:|----------:|------|",
    ]

    for name, info in {**benchmarks, **pqc}.items():
        display = name.replace("_", " ").title()
        baseline = f"{info['baseline_value']:,}"
        tol = f"±{info['tolerance_percent']}%"
        tier = info.get("tier", "microbenchmark")
        optional = " *(optional)*" if info.get("optional") else ""
        lines.append(f"| {display}{optional} | {baseline} | {tol} | {tier} |")

    return "\n".join(lines)


def update_benchmark_docs(dry_run: bool = False) -> bool:
    table = _generate_benchmark_table()
    if not table:
        print("  BENCHMARKS: no baseline.json found")
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
    parser = argparse.ArgumentParser(
        description="AMA Cryptography auto-documentation updater"
    )
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
