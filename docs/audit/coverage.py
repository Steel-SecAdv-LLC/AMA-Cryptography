#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""PR #394 readiness falsification, Phase C: the coverage ledger.

One row per file in the union of ``origin/main...HEAD`` and the always-in-scope
trees (``src/c/**``, ``ama_cryptography/**``, ``tools/**``, the workflows, the
build files, ``fuzz/**``, ``tests/c/**``).  Each row says what was executed
against the file during this audit, whether the auditor read it, which
negative controls and findings touch it, and what the pull request's own
description says Copilot reviewed.  "none" is a permitted value; a file with
no evidence is reported as such rather than omitted.

Evidence columns are derived, not typed: the lane and gate identifiers are
looked up in ``docs/audit/ledger.tsv`` by prefix, so a lane that was never
run appears as absent, and the negative-control and finding columns are
read from the driver's recipes and the findings ledger.

Usage::

    python docs/audit/coverage.py --base origin/main --out docs/audit/PR394_COVERAGE.tsv
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs" / "audit" / "ledger.tsv"
FINDINGS = REPO / "docs" / "audit" / "PR394_FINDINGS.yaml"
CONTROLS = REPO / "docs" / "audit" / "negative_controls.py"

ALWAYS_IN_SCOPE = (
    "src/c/**",
    "ama_cryptography/**",
    "tools/**",
    ".github/workflows/**",
    "fuzz/**",
    "tests/c/**",
    "CMakeLists.txt",
    "cmake/**",
    "pyproject.toml",
    "setup.py",
    "MANIFEST.in",
    "requirements*.txt",
)

#: The two files the pull request description records Copilot as not having
#: reviewed (36-byte Ed25519 seed-corpus units).
COPILOT_SKIPPED = (
    "fuzz/seed_corpus/fuzz_ed25519/sequential_32",
    "fuzz/seed_corpus/fuzz_ed25519/zero_seed",
)

#: Files the auditor opened and read during the audit sessions, with depth.
#: Anything not listed here was covered by execution only, or not at all.
READ_BY_AUDITOR: dict[str, str] = {
    "tests/c/test_secure_free_scrub.c": "full (rewritten: FINDING-0001/0002)",
    "tests/c/CMakeLists.txt": "partial (test registration)",
    "tests/c/test_dudect.c": "partial (lane structure, self-test, vartime lane)",
    "tools/check_keygen_pct.py": "full (hardened: FINDING-0003)",
    "tools/check_workflow_commands.py": "partial (expression check: FINDING-0004)",
    "tools/check_dudect_class_staging.py": "full",
    "tools/check_secrets.py": "partial (allowlist, concatenation detector)",
    "tools/generate_visuals.py": "partial (manifest check)",
    "tools/build_keyformat_corpus.py": "partial (offline verify)",
    "tools/update_docs.py": "partial (LoC recount)",
    "ama_cryptography/pqc_backends.py": "partial (AmaContext keygen and pairwise test)",
    "ama_cryptography/_integrity_signature.py": "full (build artefact handling)",
    "tests/test_keygen_pct_gate.py": "full (extended)",
    "tests/test_workflow_command_checks.py": "partial (expression tests, extended)",
    "tests/test_dudect_staging_gate.py": "partial (fixtures and CLI tests, extended)",
    ".github/workflows/ci.yml": "partial (digest, mypy, ruff/black, gate steps)",
    ".github/workflows/ci-build-test.yml": "partial (mypy step)",
    ".github/workflows/static-analysis.yml": "partial (Valgrind lane)",
    ".github/workflows/fuzzing.yml": "partial (build and run recipe)",
    ".github/workflows/dudect.yml": "partial (build recipe, measurements)",
    ".github/workflows/arm-qemu.yml": "partial (SVE2 lanes)",
    "pyproject.toml": "partial (ruff configuration)",
    ".gitignore": "full",
    "docs/METRICS_REPORT.md": "partial (LoC table)",
    "CHANGELOG.md": "partial (5.0.0 section)",
    "README.md": "partial (claims extraction)",
    "INVARIANTS.md": "partial (claims extraction)",
    "SECURITY.md": "partial (claims extraction)",
    "src/c/ama_kyber.c": "partial (decapsulate, for NC-32)",
}

#: Path rules -> ledger id prefixes whose rows count as execution against the
#: file, plus a human description.  First match wins for the description;
#: every matching rule contributes prefixes.
RULES: list[tuple[tuple[str, ...], tuple[str, ...], str]] = [
    (
        ("src/c/**/*.c", "src/c/**/*.h", "include/**"),
        ("V-ctest", "V-strict", "D-VALGRIND", "D-FUZZ", "E-ASM", "D-DUDECT", "F-"),
        "compiled and tested by every C lane (Release/ASan+UBSan/MSan/TSan/AArch64 x4/SVE2 x5), Valgrind full set, asm division sweep at 5 levels x 3 compilers",
    ),
    (
        ("ama_cryptography/**/*.py",),
        ("V-pytest", "V-mypy", "V-ruff", "V-black", "V-gate", "F-", "B-"),
        "full pytest suite with native backends required, mypy --strict, ruff, black, integrity digest, gates",
    ),
    (
        ("ama_cryptography/**/*.pyi", "ama_cryptography/py.typed", "**/*.pyi"),
        ("V-mypy", "V-gate", "V-pytest"),
        "type stubs and the typing marker: consumed by mypy --strict and the type-check-scope gate",
    ),
    (
        ("tools/**/*.sh", ".github/scripts/**", "**/*.sh"),
        ("V-gate",),
        "shell entry points: header, line-ending and secrets gates; the workflow-command gate checks the steps that call them",
    ),
    (
        ("**/LICENSE*", "**/NOTICE*", "**/PROVENANCE*"),
        ("V-gate",),
        "vendored licence and provenance files: the vendor-isolation, corpus-originality and header gates read them",
    ),
    (
        (
            "ama_cryptography/**/*.so",
            "ama_cryptography/**/*.json",
            "ama_cryptography/_post_kats/**",
        ),
        ("V-pytest", "V-gate"),
        "loaded/verified by the pytest suite and the POST/KAT provenance gates",
    ),
    (
        ("tools/check_*.py", "tools/*.py"),
        ("V-mypy", "V-ruff", "V-black", "V-gate", "V-pytest", "NC-", "D-MUT"),
        "mypy --strict, ruff, black, executed as a gate on the tree, its pytest file, negative controls, mutation (where measured)",
    ),
    (
        ("tests/**/*.py",),
        ("V-pytest", "V-mypy", "V-ruff", "V-black"),
        "executed by the full pytest suite; mypy --strict; ruff; black",
    ),
    (
        ("tests/c/**",),
        ("V-ctest", "D-VALGRIND"),
        "built and executed by every C lane and under Valgrind",
    ),
    (
        (".github/workflows/*.yml", ".github/scripts/**", ".github/**"),
        ("V-gate", "NC-"),
        "check_workflow_commands, check_action_pins, negative controls NC-01/NC-29b/NC-29c; lanes replicated locally from these recipes",
    ),
    (
        ("fuzz/**",),
        ("D-FUZZ", "V-gate"),
        "libFuzzer build of every target, 60 s depth run per target, seed-corpus and dictionary loading, registration and reachability gates",
    ),
    (
        ("CMakeLists.txt", "cmake/**", "src/c/CMakeLists.txt"),
        ("V-ctest", "V-strict"),
        "consumed by every CMake configure of the C lanes",
    ),
    (
        ("pyproject.toml", "setup.py", "MANIFEST.in", "requirements*.txt"),
        ("V-pytest", "V-mypy", "V-ruff", "V-black", "V-gate"),
        "consumed by the editable install, pytest, mypy, ruff and black runs",
    ),
    (
        ("docs/**/*.md", "docs/**/*.rst", "*.md", "docs/conf.py"),
        ("V-gate", "B-"),
        "documentation gates (reference integrity, documented counts, source paths, release state, headers) and Phase B claim reproductions",
    ),
    (
        ("tests/kat/**", "nist_vectors/**", "wycheproof_vectors/**", "acvp_vectors/**"),
        ("V-pytest", "V-ctest", "V-gate", "F-"),
        "consumed by the KAT/ACVP/Wycheproof tests in both suites and by the provenance gates",
    ),
    (
        ("docs/audit/**",),
        ("V-mypy", "V-ruff", "V-black", "V-gate"),
        "audit artefacts themselves: mypy/ruff/black on the drivers, headers and secrets gates on all",
    ),
    (
        (
            "benchmarks/**",
            "examples/**",
            "schemas/**",
            "verification/**",
            "ama_cryptography_monitor.py",
        ),
        ("V-mypy", "V-ruff", "V-black", "V-gate", "V-pytest"),
        "mypy --strict, ruff, black; the benchmark baseline files are read by the baseline-justification gate (NC-36)",
    ),
    (
        ("assets/**", "docs/compliance/**"),
        ("V-gate", "F-", "B-"),
        "generate_visuals --check (manifest against the tree), the ACVP/compliance gates, and Phase F acceptance runs",
    ),
    (
        (
            ".clang-format",
            ".clang-tidy",
            ".cppcheck-suppressions",
            ".pre-commit-config.yaml",
            ".semgrep.yml",
            ".gitignore",
            ".editorconfig",
            ".dockerignore",
            ".readthedocs.yaml",
            "codecov.yml",
            ".github/**",
            "Makefile",
            "Dockerfile*",
            "docker-compose*.yml",
            "*.cfg",
            "*.ini",
            "*.toml",
        ),
        ("V-ruff", "V-black", "V-gate", "V-strict", "V-ctest"),
        "consumed by the analysers and builds this session ran (ruff/black/semgrep/clang-tidy/cppcheck configuration, the pre-commit set, the ignore rules) and by the workflow and pin gates",
    ),
    (
        ("docker/**", "oss-fuzz/**", "Dockerfile*", "docker-compose*.yml"),
        ("V-gate",),
        "container definitions: the Docker Build CI job builds them and check_docker_pins / check_apt_retry gate their contents",
    ),
    (
        ("tools/constant_time/**",),
        ("V-gate", "D-DUDECT"),
        "the legacy dudect harness family: check_dudect_class_staging governs these files by name, and the dudect lanes run them",
    ),
    (
        ("docs/Doxyfile", "docs/**", "*.rst"),
        ("V-gate", "B-"),
        "documentation build and gates (Sphinx/Doxygen inputs; reference-integrity, source-path and release-state gates)",
    ),
    (
        ("LICENSE*", "NOTICE*", "*.txt", "*.cff", "py.typed", "*.in"),
        ("V-gate",),
        "licence and packaging metadata: header, secrets, line-ending and packaging gates",
    ),
]


def _git(*args: str) -> list[str]:
    out = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line.strip()]


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    """fnmatch, with `**` meaning zero or more directory levels.

    Plain fnmatch has no `**`, and `*` does not cross `/`, so `src/c/**/*.h`
    would miss `src/c/fe51.h` (zero intermediate directories) — which is how
    five headers first appeared in this ledger as files no lane touched.
    """
    for pattern in patterns:
        candidates = {pattern, pattern.replace("**", "*"), pattern.replace("/**/", "/")}
        if any(fnmatch(path, candidate) for candidate in candidates):
            return True
    return False


def _ledger_ids() -> list[str]:
    if not LEDGER.is_file():
        return []
    ids = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines()[1:]:
        if line.strip():
            ids.append(line.split("\t", 1)[0])
    return ids


def _control_files() -> dict[str, list[str]]:
    """Negative-control ids keyed by the repository file each recipe edits."""
    text = CONTROLS.read_text(encoding="utf-8") if CONTROLS.is_file() else ""
    out: dict[str, list[str]] = {}
    for block in re.split(r"\n\s*Control\(\n", text)[1:]:
        m = re.match(r'\s*"(NC-[0-9a-z]+)"', block)
        if not m:
            continue
        cid = m.group(1)
        for path in set(
            re.findall(
                r"(?<![\w/])((?:[\w.-]+/)+[\w.-]+\.(?:py|c|h|yml|yaml|md|json|txt|toml|rst))", block
            )
        ):
            if (REPO / path).exists():
                out.setdefault(path, []).append(cid)
    return out


def _asm_evidence(add: Callable[[str, str], None]) -> None:
    path = REPO / "docs" / "audit" / "logs" / "phaseE" / "asm_sweep_status.tsv"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) > 4 and (REPO / fields[3]).exists():
            add(fields[3], "PR394_ASM_DIVISIONS.tsv")


def _valgrind_evidence(add: Callable[[str, str], None]) -> None:
    path = REPO / "docs" / "audit" / "PR394_VALGRIND.tsv"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        name = line.split("\t")[0]
        for candidate in (f"tests/c/{name}.c", f"tests/c/{name.split('_dispatch_only_')[0]}.c"):
            if (REPO / candidate).exists():
                add(candidate, "PR394_VALGRIND.tsv")
                break


def _fuzz_evidence(add: Callable[[str, str], None]) -> None:
    for table in ("PR394_FUZZ_DEPTH.tsv", "PR394_FUZZ_DEPTH_O2G.tsv"):
        path = REPO / "docs" / "audit" / table
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines()[1:]:
            target = line.split("\t")[0]
            if (REPO / f"fuzz/{target}.c").exists():
                add(f"fuzz/{target}.c", table)
            corpus = REPO / "fuzz" / "seed_corpus" / target
            for seed in sorted(corpus.iterdir()) if corpus.is_dir() else []:
                add(seed.relative_to(REPO).as_posix(), table)


def _acceptance_evidence(add: Callable[[str, str], None]) -> None:
    path = REPO / "docs" / "audit" / "PR394_ACCEPTANCE.tsv"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        for token in re.findall(r"(?:tests|src)/[\w./-]+\.(?:py|c|h)", line):
            if (REPO / token).exists():
                add(token, "PR394_ACCEPTANCE.tsv")


def _table_evidence() -> dict[str, list[str]]:
    """Per-file evidence held in the committed measurement tables.

    The Phase D/E sweeps write their own tables (one row per file, test
    binary or fuzz target) rather than one ledger row per unit, so their
    evidence is looked up in the tables themselves: the assembly census
    names every C source it compiled, the Valgrind sweep every CTest case it
    ran, the fuzz-depth tables every target and seed they drove, and the
    acceptance table the tests it cites.
    """
    out: dict[str, list[str]] = {}

    def add(path: str, label: str) -> None:
        out.setdefault(path, []).append(label)

    for source in (_asm_evidence, _valgrind_evidence, _fuzz_evidence, _acceptance_evidence):
        source(add)
    return out


def _claim_counts() -> dict[str, int]:
    """How many executed claim reproductions name each file as their source."""
    path = REPO / "docs" / "audit" / "PR394_CLAIMS.yaml"
    if not path.is_file():
        return {}
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = data.get("claims", data) if isinstance(data, dict) else data
    counts: dict[str, int] = {}
    for entry in entries:
        source = str(entry.get("source", ""))
        m = re.match(r"([\w./-]+\.(?:md|rst|yaml|yml|py|c|h|txt|json))", source)
        if m and (REPO / m.group(1)).exists():
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def _finding_files() -> dict[str, list[str]]:
    text = FINDINGS.read_text(encoding="utf-8") if FINDINGS.is_file() else ""
    out: dict[str, list[str]] = {}
    for block in re.split(r"\n- id: ", text)[1:]:
        fid = block.split("\n", 1)[0].strip()
        for path in set(
            re.findall(r"(?<![\w/])((?:[\w.-]+/)+[\w.-]+\.(?:py|c|h|yml|yaml|md|txt))", block)
        ):
            if (REPO / path).exists() and not path.startswith("docs/audit/logs/"):
                out.setdefault(path, []).append(fid)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    changed = set(_git("diff", "--name-only", f"{args.base}...HEAD"))
    tracked = _git("ls-files")
    universe = sorted(p for p in tracked if p in changed or _matches(p, ALWAYS_IN_SCOPE))
    ledger = _ledger_ids()
    controls = _control_files()
    findings = _finding_files()
    claim_counts = _claim_counts()
    tables = _table_evidence()

    rows = [
        "\t".join(
            [
                "path",
                "changed_in_pr",
                "copilot_reviewed",
                "executed_by",
                "ledger_ids",
                "measurement_tables",
                "read_by_auditor",
                "claims_executed",
                "negative_controls",
                "findings",
            ]
        )
    ]
    none_count = 0
    for path in universe:
        prefixes: list[str] = []
        desc = "none"
        for patterns, pref, text in RULES:
            if _matches(path, patterns):
                if desc == "none":
                    desc = text
                prefixes.extend(pref)
        ids = sorted({i for i in ledger if any(i.startswith(p) for p in prefixes)})
        # Keep the ledger column readable: prefix summaries with counts.
        summary = []
        for p in sorted(set(prefixes)):
            n = sum(1 for i in ids if i.startswith(p))
            if n:
                summary.append(f"{p}*x{n}")
        if not summary and not claim_counts.get(path) and not tables.get(path):
            desc = "none" if desc == "none" else f"{desc} [no ledger rows found for its prefixes]"
            none_count += 1
        if path in COPILOT_SKIPPED:
            copilot = "no (PR description: not reviewed)"
        elif path in changed:
            copilot = "yes (per PR description)"
        else:
            copilot = "n/a (not in the PR diff)"
        rows.append(
            "\t".join(
                [
                    path,
                    "yes" if path in changed else "no",
                    copilot,
                    desc,
                    ",".join(summary) or "none",
                    ",".join(sorted(set(tables.get(path, [])))) or "none",
                    READ_BY_AUDITOR.get(path, "no"),
                    str(claim_counts.get(path, 0)),
                    ",".join(controls.get(path, [])) or "none",
                    ",".join(findings.get(path, [])) or "none",
                ]
            )
        )
    out = REPO / args.out
    out.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(
        f"{len(universe)} rows ({len(changed & set(universe))} changed in the PR); "
        f"{none_count} with no execution evidence; {sum(1 for p in universe if p in READ_BY_AUDITOR)} read by the auditor",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
