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
_TEST_COUNT_RE = re.compile(r"`(tests/[A-Za-z0-9_/]+\.py)`\s*[—-]\s*(\d+)\s+tests\b")

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
    problems += check_record_counts(repo)
    problems += check_wycheproof_counts(repo)
    problems += check_test_counts(repo)
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
