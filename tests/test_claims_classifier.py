#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``docs/audit/classify_claims.py``.

The classifier decides whether a claim in ``PR394_CLAIMS.yaml`` was reproduced
by RUNNING its subject or by reading bytes at rest, and the attestation's
headline ratio is computed from that decision.  A classifier that over-credits
``executed`` inflates exactly the number a reader trusts most, so it needs a
test of its own — the same requirement this audit put on every gate it
examined, applied to the audit's own tooling.

Two over-crediting bugs found by sampling and pinned below:

1. A program named inside a search PATTERN was read as an invocation of it —
   ``grep -n "cmake -B build" x.yml`` counted as executing cmake (CLAIM-0219,
   CLAIM-0579), and ``grep -n '_DISASSEMBLERS = ("objdump", ...)' t.py`` as
   probing an artefact (CLAIM-0818).
2. ``python -c`` that only opens a file and regexes its text counted as an
   execution because the path it read looked like a script argument
   (CLAIM-1562).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "docs" / "audit" / "classify_claims.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("classify_claims", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestWhatCountsAsRunningTheSubject:
    @pytest.mark.parametrize(
        "command",
        [
            "python tools/check_vendor_isolation.py --library build-release/lib/x.so",
            "python benchmarks/check_baseline_justification.py",
            "AMA_CI_REQUIRE_BACKENDS=1 python -m pytest tests/ -v --no-cov",
            'python -c "from ama_cryptography.pqc_backends import dilithium_verify"',
            "ctest --test-dir build-release -N",
            "AMA_DISPATCH_ONLY=avx2 ctest --test-dir build-release -R kyber",
            "./build-release/bin/test_kyber_compress",
            "mypy --strict tools/",
            "clang-format --version",
        ],
    )
    def test_these_run_something(self, tool: ModuleType, command: str) -> None:
        assert tool.classify(command) == "executed"

    @pytest.mark.parametrize(
        "command",
        [
            "grep -n 'ama_kyber_keypair' src/c/ama_kyber.c",
            "sed -n '1,40p' README.md",
            "awk 'NR==12' CHANGELOG.md",
            "git log -1 --format=%H",
            "ls docs/audit/logs",
            "wc -l tools/check_secrets.py",
        ],
    )
    def test_these_read_bytes_at_rest(self, tool: ModuleType, command: str) -> None:
        assert tool.classify(command) == "text-inspection"

    @pytest.mark.parametrize(
        "command",
        [
            'grep -n "cmake -B build -DCMAKE_BUILD_TYPE=Release" .github/workflows/dudect.yml',
            'grep -n \'_D = ("objdump", "llvm-objdump")\' tools/check_secret_division.py',
            "grep -c 'python -m pytest' .github/workflows/ci.yml",
        ],
    )
    def test_a_program_named_inside_a_pattern_is_not_an_invocation(
        self, tool: ModuleType, command: str
    ) -> None:
        """The command in command position is grep.  Counting the pattern's
        contents would inflate `executed` and `artefact-probe` — the two
        buckets whose inflation flatters the attestation."""
        assert tool.classify(command) == "text-inspection"

    def test_a_python_one_liner_that_only_reads_files_is_not_an_execution(
        self, tool: ModuleType
    ) -> None:
        command = (
            "python -c \"import re;s=open('benchmarks/validation_suite.py').read();"
            "b=re.search(r'documented_claims:',s)\""
        )
        assert tool.classify(command) == "text-inspection"

    def test_a_heredoc_that_only_reads_files_is_not_an_execution(self, tool: ModuleType) -> None:
        command = (
            "python3 - <<EOF\nfrom pathlib import Path\nprint(Path('README.md').read_text())\nEOF"
        )
        assert tool.classify(command) == "text-inspection"

    @pytest.mark.parametrize(
        "command",
        [
            "ldd build-release/lib/libama_cryptography.so",
            "nm -D --defined-only build-release/lib/libama_cryptography.so | wc -l",
            "readelf -d build-release/lib/libama_cryptography.so | grep NEEDED",
            "aarch64-linux-gnu-objdump -d build-arm/lib/libama_cryptography.so",
        ],
    )
    def test_these_probe_the_built_object(self, tool: ModuleType, command: str) -> None:
        assert tool.classify(command) == "artefact-probe"

    @pytest.mark.parametrize(
        "command", ["historical:2dcef5c", "phaseD:ctypes_abi", "mcp:actions_get_workflow_job"]
    )
    def test_these_did_not_run_here(self, tool: ModuleType, command: str) -> None:
        assert tool.classify(command) == "not-executed"


class TestTheRetypingRuleIsKindAware:
    """``grep`` is sound evidence for a claim about text and unsound for a
    claim about behaviour.  The rule must say so in both directions."""

    def test_a_documentary_claim_confirmed_by_reading_it_stays_confirmed(
        self, tool: ModuleType
    ) -> None:
        assert tool.retype("provenance", "confirmed", "text-inspection") == "confirmed"
        assert tool.retype("negative", "confirmed", "text-inspection") == "confirmed"

    def test_a_behavioural_claim_confirmed_by_a_grep_is_not_reproduced(
        self, tool: ModuleType
    ) -> None:
        assert tool.retype("behavioural", "confirmed", "text-inspection") == "text-only"

    def test_a_measured_number_re_read_from_the_document_is_not_re_measured(
        self, tool: ModuleType
    ) -> None:
        assert tool.retype("numeric", "confirmed", "text-inspection") == "text-only"

    def test_running_the_subject_confirms_any_kind(self, tool: ModuleType) -> None:
        for kind in ("behavioural", "numeric", "provenance", "negative"):
            assert tool.retype(kind, "confirmed", "executed") == "confirmed"
            assert tool.retype(kind, "confirmed", "artefact-probe") == "confirmed"

    def test_a_reproduction_that_did_not_run_confirms_nothing(self, tool: ModuleType) -> None:
        assert tool.retype("provenance", "confirmed", "not-executed") == "unverifiable"

    def test_a_refutation_stands_whatever_the_method(self, tool: ModuleType) -> None:
        """A reproduction that contradicted its claim contradicted it."""
        for method in ("executed", "artefact-probe", "text-inspection", "not-executed"):
            assert tool.retype("behavioural", "refuted", method) == "refuted"


class TestTheLedgerCarriesTheClassification:
    def test_every_claim_has_a_method_and_a_strength(self, tool: ModuleType) -> None:
        """The ledger is regenerated by this tool; if a claim were added without
        being classified, the attestation's tally would silently omit it."""
        text = (REPO_ROOT / "docs" / "audit" / "PR394_CLAIMS.yaml").read_text(encoding="utf-8")
        ids = text.count("\n- id: CLAIM-")
        assert ids > 0
        assert text.count("\n  method: ") == ids
        assert text.count("\n  strength: ") == ids

    def test_no_behavioural_claim_is_confirmed_by_text_alone(self, tool: ModuleType) -> None:
        """The property the re-typing exists to enforce."""
        import re

        text = (REPO_ROOT / "docs" / "audit" / "PR394_CLAIMS.yaml").read_text(encoding="utf-8")
        offenders = []
        for block in re.split(r"\n(?=- id: CLAIM-)", text):
            if not block.lstrip().startswith("- id: CLAIM-"):
                continue

            def field(name: str, b: str = block) -> str:
                match = re.search(rf"^\s{{2}}{name}: (.*)$", b, re.M)
                return match.group(1).strip() if match else ""

            if (
                field("kind") in ("behavioural", "numeric")
                and field("verdict") == "confirmed"
                and field("method") == "text-inspection"
            ):
                offenders.append(field("id") or block.split("\n", 1)[0])
        assert offenders == [], offenders[:10]
