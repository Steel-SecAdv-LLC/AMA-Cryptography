#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the four documentation-integrity gates added in the 2026-09 pass.

  * ``tools/check_doc_examples.py``            — examples run, compile, link
  * ``tools/check_crypto_construction_docs.py``— constructions match the code
  * ``tools/check_public_api_docs.py``         — the API is what is documented
  * ``tools/check_benchmark_claims.py``        — numbers are re-derivable

Every gate here is pinned in **both directions**. A gate that only ever passes
is indistinguishable from a gate that has gone vacuous, and this repository has
already shipped one: ``check_verification_claim_honesty.py`` was silently
missing the plural form of the most common false claim in the tree until its
negative controls were written.

So each gate gets:

* a **positive control** — the real tree passes, which is what makes CI
  meaningful rather than decorative; and
* a **negative control per defect class** — the actual wording or code that
  shipped, reproduced in a fixture, which must fail.

The negative controls are not invented. Each is the literal text this pass
removed: the uninitialised-seed Ed25519 example, the Python HKDF fallback
claim, the three-signal posture weighting, the 0.3/0.6/0.8 threshold table,
``MASTER_OMNI_CODES``, ``len(ethical_vector) == 12``, "AMA does not implement
HSS/LMS", ``secure_mlock`` returning a boolean, the eight "always available"
submodules, the stale 76,215 floor, and the 4.20 ms ML-DSA-65 figure.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import inspect
import io
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator, Optional, Sequence, cast
from unittest import mock

import pytest

from ama_cryptography import key_management, legacy_compat, secure_memory

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"

DOC_EXAMPLES = TOOLS / "check_doc_examples.py"
CONSTRUCTION_DOCS = TOOLS / "check_crypto_construction_docs.py"
PUBLIC_API = TOOLS / "check_public_api_docs.py"
BENCHMARK_CLAIMS = TOOLS / "check_benchmark_claims.py"

#: Shared-library basenames by platform.  The first revision of this file
#: globbed ``libama_cryptography.so*`` only, so on macOS (``.dylib``) and
#: Windows (``.dll``) it found nothing and every C test "skipped" — and
#: ``tests/conftest.py`` turns a skip into a FAILURE under
#: ``AMA_CI_REQUIRE_BACKENDS=1``, which is how six errors per job appeared on
#: fourteen runners.
_LIBRARY_PATTERNS: tuple[str, ...] = (
    "libama_cryptography.so*",
    "libama_cryptography.*dylib",
    "libama_cryptography.dll*",
    "ama_cryptography.dll",
)

_BUILT_LIBRARY = next(
    (
        candidate
        for directory in (
            REPO_ROOT / "build" / "lib",
            REPO_ROOT / "build" / "bin",
            REPO_ROOT / "build",
            REPO_ROOT / "ama_cryptography",
        )
        if directory.is_dir()
        for pattern in _LIBRARY_PATTERNS
        for candidate in sorted(directory.glob(pattern))
    ),
    None,
)

#: Can a C example actually be LINKED here?  On Windows the test matrix builds
#: the package with MSVC and the import library is not laid out where a MinGW
#: ``-lama_cryptography`` finds it, so the C lane is not a capability this
#: platform has.  That is reported as a fact about the platform rather than
#: silently passing: the Linux lanes (``security-checks`` and ``c-consumer``)
#: are where the C examples are compiled, linked and run, and they are not
#: allowed to skip.
_C_LANE_AVAILABLE = _BUILT_LIBRARY is not None and sys.platform != "win32"

requires_c_lane = pytest.mark.skipif(
    not _C_LANE_AVAILABLE,
    reason=(
        "the C example lane needs a linkable libama_cryptography; "
        "it is exercised on the Linux lanes, where it may not skip"
    ),
)


def _load(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=False,
    )


#: Everything tools/check_benchmark_claims.py reads: the two floor ledgers, the
#: results record, the generator it re-derives the tables with, and the two
#: pages that carry the generated blocks.
_SCRATCH_REPO_FILES: tuple[str, ...] = (
    "benchmarks/benchmark-results.json",
    "benchmarks/baseline.json",
    "benchmarks/arm-baseline.json",
    "tools/update_docs.py",
    "ama_cryptography/__init__.py",
    "ARCHITECTURE.md",
    "wiki/Performance-Benchmarks.md",
)


def _scratch_repo(tmp_path: Path) -> Path:
    """A throwaway copy of the files the benchmark gate reads.

    The gate has to be driven against a tree a test may freely corrupt, and the
    working copy is not that tree.  ``newline=""`` on every write keeps the
    copies byte-identical to the originals on every platform, so a test that
    mutates one cell is testing that cell and not the line endings.
    """
    scratch = tmp_path / "scratch_repo"
    for relative in _SCRATCH_REPO_FILES:
        source = REPO_ROOT / relative
        assert source.is_file(), f"{relative} is missing; the scratch repo would be incomplete"
        destination = scratch / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="")
    return scratch


#: A workflow line that runs one of the gate scripts, optionally behind leading
#: ``VAR=value`` assignments.
#:
#: The name side is ``[^\s=]+`` rather than ``\S+`` so each assignment splits at
#: exactly one place.  With ``\S+=\S+`` the ``=`` is itself a ``\S``, so a run of
#: ``!==!`` tokens can be divided between name and value in exponentially many
#: ways, all of which are tried before the match fails: CodeQL flagged it
#: py/redos at security-severity 7.5, and measured here, 22 repetitions took
#: 0.73s against 0.0003s for this form.
_GATE_INVOCATION = re.compile(r"^(?:[^\s=]+=\S+ )*python3? tools/check_[a-z_]+\.py")


class _ParserBuiltError(Exception):
    """Raised once a gate's parser has accepted its argv, before it does work."""


def _flag_rejection(module: ModuleType, argv: list[str]) -> Optional[str]:
    """argparse's "unrecognized arguments" message for ``argv``, or ``None``.

    Asks the real parser the real question and reads the answer, rather than
    introspecting the parser's structure. Two earlier attempts were measured
    and rejected:

    * ``--help`` as a probe: a gate that does not use argparse ignores it and
      RUNS.
    * recording ``ArgumentParser.add_argument``: ``check_headers.py`` declares
      ``--check`` on a mutually-exclusive GROUP, whose ``add_argument`` belongs
      to a different class, so the recorder never saw it and the test failed on
      a workflow line that works.

    Only an unrecognised FLAG is reported. A rejected VALUE ("invalid choice",
    "expected one argument") is a matrix variable this scan substituted and
    cannot resolve; the job that runs the gate checks those for real.
    """
    real_parse_args = argparse.ArgumentParser.parse_args

    def _stop(self: argparse.ArgumentParser, *a: Any, **kw: Any) -> Any:
        real_parse_args(self, *a, **kw)
        raise _ParserBuiltError

    captured_stderr = io.StringIO()
    with mock.patch.object(argparse.ArgumentParser, "parse_args", _stop):
        try:
            with contextlib.redirect_stderr(captured_stderr):
                module.main(argv)
        except _ParserBuiltError:
            return None
        except SystemExit:
            text = captured_stderr.getvalue()
            return text.strip() if "unrecognized arguments" in text else None
        # A gate that got past parsing and then failed doing real work has
        # accepted its argv, which is the only thing this probe asks about.
        except Exception:
            return None
    return None


@pytest.fixture()
def doc_fixture(tmp_path: Path) -> Iterator[Path]:
    """A scratch Markdown file the example gate is pointed at.

    It lives in ``tmp_path``, NOT in the repository. An earlier revision wrote
    fixtures into ``wiki/`` and ``docs/`` and rewrote ``ARCHITECTURE.md`` in
    place; on Windows that rewrite went through ``write_text`` in text mode and
    replaced every LF with CRLF, so ``test_line_endings_gate`` then failed on a
    file no commit had touched. A test that mutates the working copy is a test
    that can corrupt it.
    """
    yield tmp_path / "gate_fixture.md"


# ===========================================================================
# tools/check_doc_examples.py
# ===========================================================================


class TestDocExamples:
    def test_the_real_documentation_passes_python(self) -> None:
        """Positive control for the Python lane, on every platform.

        Split from the C lane deliberately. The Python examples are promised to
        run wherever the package runs, so this must not skip anywhere — and it
        is the assertion that catches a cp1252-unencodable ``print`` before a
        Windows reader does.
        """
        completed = _run(DOC_EXAMPLES, "--lang", "python")
        assert completed.returncode == 0, completed.stderr

    @requires_c_lane
    def test_the_real_documentation_passes_c(self) -> None:
        """Positive control for the C lane, where a library can be linked."""
        completed = _run(DOC_EXAMPLES, "--lang", "c")
        assert completed.returncode == 0, completed.stderr

    def test_an_unmarked_block_fails(self, doc_fixture: Path) -> None:
        """Coverage is mandatory: a block with no directive is a failure.

        This is what stops the gate decaying — a new example cannot be added
        without declaring what it claims.
        """
        doc_fixture.write_text("# fixture\n\n```python\nprint('hello')\n```\n", encoding="utf-8")
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 1
        assert "no `<!-- example:" in completed.stderr

    def test_a_missing_required_argument_fails(self, doc_fixture: Path) -> None:
        """The literal wiki/Quick-Start.md defect: `author` omitted."""
        doc_fixture.write_text(
            "<!-- example: python-run -->\n"
            "```python\n"
            "from ama_cryptography.legacy_compat import (\n"
            "    generate_key_management_system,\n"
            "    create_crypto_package,\n"
            ")\n"
            "kms = generate_key_management_system('Org')\n"
            "create_crypto_package('1. x\\n', [(20.0, 0.7)], kms)\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 1
        assert "TypeError" in completed.stderr

    def test_a_wrong_return_type_in_a_listing_fails(self, doc_fixture: Path) -> None:
        """The literal wiki/API-Reference.md defect: secure_mlock -> bool."""
        doc_fixture.write_text(
            "<!-- example: python-signature module=ama_cryptography.secure_memory -->\n"
            "```python\n"
            "secure_mlock(data: bytearray) -> bool\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 1
        assert "returning" in completed.stderr and "bool" in completed.stderr

    def test_a_nonexistent_name_in_a_listing_fails(self, doc_fixture: Path) -> None:
        doc_fixture.write_text(
            "<!-- example: python-names module=ama_cryptography.legacy_compat -->\n"
            "```python\n"
            "from ama_cryptography.legacy_compat import MASTER_OMNI_CODES\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 1
        assert "MASTER_OMNI_CODES" in completed.stderr

    def test_every_tracked_page_is_covered_and_the_record_is_not(self, tmp_path: Path) -> None:
        """Coverage is derived from ``git ls-files``, not listed.

        INVARIANT-53 promises every ``python``/``c`` block on a page; the gate
        covered a seven-entry tuple of wiki pages, and 83 blocks on seventeen
        other pages ran under nothing.  Here a fresh repository tracks one new
        page with an unmarked block — which must fail — and a CHANGELOG.md
        with one, which is the historical record and must not.
        """
        if shutil.which("git") is None:
            pytest.skip("git is required to enumerate the tracked pages")
        repo = tmp_path / "repo"
        (repo / "ama_cryptography").mkdir(parents=True)
        (repo / "ama_cryptography" / "__init__.py").write_text("", encoding="utf-8")
        (repo / "docs").mkdir()
        (repo / "docs" / "NEW-PAGE.md").write_text(
            "# new\n\n```python\nprint('never marked')\n```\n", encoding="utf-8"
        )
        (repo / "CHANGELOG.md").write_text(
            "# history\n\n```python\nretired_example()\n```\n", encoding="utf-8"
        )
        (repo / "UNTRACKED.md").write_text("```python\nnot tracked\n```\n", encoding="utf-8")
        for argv in (
            ["git", "init", "-q"],
            ["git", "add", "ama_cryptography/__init__.py", "docs/NEW-PAGE.md", "CHANGELOG.md"],
        ):
            subprocess.run(argv, cwd=repo, check=True, capture_output=True)

        gate = _load(DOC_EXAMPLES)
        assert gate.covered_files(repo) == ("docs/NEW-PAGE.md",)

        completed = _run(DOC_EXAMPLES, "--repo", str(repo), "--lang", "python")
        assert completed.returncode == 1, completed.stdout + completed.stderr
        assert "docs/NEW-PAGE.md" in completed.stderr
        assert "no `<!-- example:" in completed.stderr
        assert "CHANGELOG.md" not in completed.stderr

    def test_the_real_pages_that_were_uncovered_are_covered_now(self) -> None:
        gate = _load(DOC_EXAMPLES)
        covered = set(gate.covered_files(REPO_ROOT))
        assert {
            "IMPLEMENTATION_GUIDE.md",
            "wiki/Adaptive-Posture.md",
            "wiki/Cryptography-Algorithms.md",
            "MONITORING.md",
            "README.md",
            "wiki/Post-Quantum-Cryptography.md",
            "CRYPTOGRAPHY.md",
            "wiki/Quick-Start.md",
        } <= covered
        assert "CHANGELOG.md" not in covered
        assert not any(name.startswith("docs/changelog/") for name in covered)

    def test_a_continuing_block_runs_after_the_one_before_it(self, doc_fixture: Path) -> None:
        """``python-run continues``: the next step of the page's running example."""
        doc_fixture.write_text(
            "<!-- example: python-run -->\n"
            "```python\nvalue = 41\n```\n\n"
            "<!-- example: python-run continues -->\n"
            "```python\nassert value + 1 == 42\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 0, completed.stderr
        assert "2 executed" in completed.stdout

    def test_without_continues_the_same_block_fails(self, doc_fixture: Path) -> None:
        """Non-vacuity for the test above: each block is its own interpreter."""
        doc_fixture.write_text(
            "<!-- example: python-run -->\n"
            "```python\nvalue = 41\n```\n\n"
            "<!-- example: python-run -->\n"
            "```python\nassert value + 1 == 42\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 1
        assert "NameError" in completed.stderr

    def test_continues_with_nothing_before_it_fails(self, doc_fixture: Path) -> None:
        doc_fixture.write_text(
            "<!-- example: python-run continues -->\n```python\nprint('first')\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 1
        assert "nothing for it to continue" in completed.stderr

    @pytest.mark.parametrize(("ret", "passes"), [("bool", True), ("int", False)])
    def test_a_def_header_with_a_bare_colon_is_a_declaration(
        self, doc_fixture: Path, ret: str, passes: bool
    ) -> None:
        """CONSTANT_TIME_VERIFICATION.md writes ``def constant_time_compare(a:
        bytes, b: bytes) -> bool:`` with a comment body.  The colon used to be
        read into the return annotation, so the correct listing reported
        ``'bool:'``; the wrong one must still fail."""
        doc_fixture.write_text(
            "<!-- example: python-signature module=ama_cryptography.secure_memory -->\n"
            "```python\n"
            f"def constant_time_compare(a: bytes, b: bytes) -> {ret}:\n"
            "    # delegates to ama_consttime_memcmp\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert (completed.returncode == 0) is passes, completed.stderr

    def test_pseudocode_needs_a_reason(self, doc_fixture: Path) -> None:
        """The escape hatch has to cost something, or everything uses it."""
        doc_fixture.write_text(
            "<!-- example: pseudocode: nope -->\n```python\nnot python at all\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 1
        assert "reason" in completed.stderr

    def test_pseudocode_with_a_reason_is_skipped(self, doc_fixture: Path) -> None:
        doc_fixture.write_text(
            "<!-- example: pseudocode: needs a physically attached hardware token -->\n"
            "```python\nnot python at all\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 0, completed.stderr
        assert "1 skipped" in completed.stdout

    #: Every fence spelling GitHub renders as a Python code block.  The gate
    #: recognised exactly three backticks followed immediately by ``python``,
    #: ``py`` or ``c``; measured before the fix, a page holding one passing
    #: block plus any one of these — raising ``SystemExit(3)`` and carrying no
    #: directive — exited 0 with "1 executed/checked, 0 skipped".
    _FENCES: tuple[tuple[str, str], ...] = (
        ("~~~python", "~~~"),
        ("~~~~python", "~~~~"),
        ("````python", "````"),
        ("``` python", "```"),
        ("```python3", "```"),
        ("```py3", "```"),
        ("```pyi", "```"),
    )

    @pytest.mark.parametrize(("opening", "closing"), _FENCES)
    def test_every_python_fence_spelling_needs_a_directive(
        self, doc_fixture: Path, opening: str, closing: str
    ) -> None:
        doc_fixture.write_text(
            f"# fixture\n\n{opening}\nraise SystemExit(3)\n{closing}\n", encoding="utf-8"
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture))
        assert completed.returncode == 1, (opening, completed.stdout, completed.stderr)
        assert "no `<!-- example:" in completed.stderr

    @pytest.mark.parametrize(("opening", "closing"), _FENCES)
    def test_every_python_fence_spelling_is_executed(
        self, doc_fixture: Path, opening: str, closing: str
    ) -> None:
        doc_fixture.write_text(
            f"<!-- example: python-run -->\n{opening}\nraise SystemExit(3)\n{closing}\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 1, (opening, completed.stdout, completed.stderr)

    def test_a_pycon_block_needs_a_directive(self, doc_fixture: Path) -> None:
        """Measured before the fix: invisible, like the fences above."""
        doc_fixture.write_text(
            "<!-- example: python-run -->\n```python\nprint('ok')\n```\n\n"
            "```pycon\n>>> raise SystemExit(3)\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 1, completed.stdout
        assert "no `<!-- example:" in completed.stderr

    def test_a_c_block_in_a_tilde_fence_needs_a_directive(self, doc_fixture: Path) -> None:
        doc_fixture.write_text(
            "<!-- example: python-run -->\n```python\nprint('ok')\n```\n\n"
            "~~~c\nint main(void) { return 3; }\n~~~\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 1, completed.stdout
        assert "no `<!-- example:" in completed.stderr

    def test_a_fence_inside_a_longer_fence_is_content_not_a_block(self, doc_fixture: Path) -> None:
        """A page that SHOWS how to write a fence is not an example.

        GitHub renders the inner lines as text inside the four-backtick block;
        treating them as a block would demand a directive for prose.
        """
        doc_fixture.write_text(
            "<!-- example: python-run -->\n```python\nprint('ok')\n```\n\n"
            "````markdown\n```python\nraise SystemExit(3)\n```\n````\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 0, completed.stderr
        assert "1 example block(s)" in completed.stdout

    def test_a_pycon_transcript_is_run_and_its_output_checked(self, doc_fixture: Path) -> None:
        """A transcript's output lines are claims: doctest holds it to them."""
        doc_fixture.write_text(
            "<!-- example: python-run -->\n```pycon\n>>> 1 + 1\n3\n```\n", encoding="utf-8"
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 1, completed.stdout
        assert "Expected" in completed.stderr and "Got" in completed.stderr

    def test_a_true_pycon_transcript_passes(self, doc_fixture: Path) -> None:
        doc_fixture.write_text(
            "<!-- example: python-run -->\n```pycon\n>>> x = [1, 2]\n"
            ">>> for item in x:\n...     print(item)\n1\n2\n>>> len(x)\n2\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "python")
        assert completed.returncode == 0, completed.stderr

    def test_a_pycon_block_reads_as_its_source_lines(self) -> None:
        """Every other mode reads a transcript's code, prompts stripped."""
        module = _load(DOC_EXAMPLES)
        source = module.pycon_source(">>> import os\n>>> for c in 'ab':\n...     print(c)\na\nb\n")
        assert source == "import os\nfor c in 'ab':\n    print(c)\n"

    def test_a_c_run_block_with_no_library_is_not_a_skip(self, tmp_path: Path) -> None:
        """No library to link means the example was never run: exit 2, not 0.

        Measured before the fix: against a tree with no built library this
        page exited 0 with "0 executed/checked, 1 skipped" — a C example that
        was never compiled reported the same as one that ran.
        """
        repo = tmp_path / "repo"
        (repo / "ama_cryptography").mkdir(parents=True)
        (repo / "ama_cryptography" / "__init__.py").write_text("", encoding="utf-8")
        page = tmp_path / "page.md"
        page.write_text(
            "<!-- example: c-run -->\n```c\nint main(void) { return 3; }\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--repo", str(repo), "--file", str(page))
        assert completed.returncode == 2, (completed.stdout, completed.stderr)
        assert "no built" in completed.stderr
        # Asking for the Python lane only is the explicit way to not need one.
        completed = _run(DOC_EXAMPLES, "--repo", str(repo), "--file", str(page), "--lang", "python")
        assert completed.returncode == 0, completed.stderr

    def test_check_blocks_fails_a_c_run_block_it_cannot_link(self) -> None:
        """The same verdict for a caller that drives check_blocks() itself."""
        module = _load(DOC_EXAMPLES)
        block = module.Block(
            path="page.md", line=1, language="c", directive="c-run", code="int main(void){}\n"
        )
        report = module.check_blocks([block], include_dir=REPO_ROOT / "include", library_dir=None)
        assert report.skipped == 0
        assert len(report.findings) == 1 and "was not run" in report.findings[0].detail

    @requires_c_lane
    def test_the_uninitialised_ed25519_seed_example_fails(self, doc_fixture: Path) -> None:
        """The defect this gate was built for.

        ``ama_ed25519_keypair`` does not generate the seed — the caller must
        place 32 CSPRNG bytes in ``secret_key[0..31]``. The example below,
        which shipped in ``wiki/C-API-Reference.md``, hands it uninitialised
        stack memory. It compiles clean under ``-Wall -Wextra -Werror`` and
        prints ``valid=1``: nothing but a memory checker can see it.
        """
        if shutil.which("valgrind") is None:
            pytest.skip("valgrind not installed; the uninitialised-read oracle is unavailable")
        doc_fixture.write_text(
            "<!-- example: c-run -->\n"
            "```c\n"
            "#include <ama_cryptography.h>\n"
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    uint8_t pk[AMA_ED25519_PUBLIC_KEY_BYTES];\n"
            "    uint8_t sk[AMA_ED25519_SECRET_KEY_BYTES];\n"
            "    ama_ed25519_keypair(pk, sk);\n"
            "    uint8_t sig[AMA_ED25519_SIGNATURE_BYTES];\n"
            '    const uint8_t *msg = (const uint8_t *)"Hello";\n'
            "    ama_ed25519_sign(sig, msg, 5, sk);\n"
            '    printf("valid=%d\\n", ama_ed25519_verify(sig, msg, 5, pk) == AMA_SUCCESS);\n'
            "    return 0;\n"
            "}\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "c")
        assert completed.returncode == 1, completed.stdout
        assert "uninitialised" in completed.stderr.lower()

    @requires_c_lane
    def test_the_safe_ed25519_example_passes(self, doc_fixture: Path) -> None:
        """The positive control that keeps the test above non-vacuous."""
        if shutil.which("valgrind") is None:
            pytest.skip("valgrind not installed")
        doc_fixture.write_text(
            "<!-- example: c-run -->\n"
            "```c\n"
            "#include <ama_cryptography.h>\n"
            "int main(void) {\n"
            "    uint8_t pk[AMA_ED25519_PUBLIC_KEY_BYTES] = {0};\n"
            "    uint8_t sk[AMA_ED25519_SECRET_KEY_BYTES] = {0};\n"
            "    ama_context_t *ctx = ama_context_init(AMA_ALG_ED25519);\n"
            "    if (ctx == NULL) { return 1; }\n"
            "    ama_error_t rc = ama_keypair_generate(ctx, pk, sizeof(pk), sk, sizeof(sk));\n"
            "    ama_context_free(ctx);\n"
            "    if (rc != AMA_SUCCESS) { return 1; }\n"
            "    uint8_t sig[AMA_ED25519_SIGNATURE_BYTES] = {0};\n"
            '    const uint8_t *msg = (const uint8_t *)"Hello";\n'
            "    if (ama_ed25519_sign(sig, msg, 5, sk) != AMA_SUCCESS) { return 1; }\n"
            "    int ok = ama_ed25519_verify(sig, msg, 5, pk) == AMA_SUCCESS;\n"
            "    ama_secure_memzero(sk, sizeof(sk));\n"
            "    return ok ? 0 : 1;\n"
            "}\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "c")
        assert completed.returncode == 0, completed.stderr

    @requires_c_lane
    def test_a_localised_symbol_documented_as_linkable_fails(self, doc_fixture: Path) -> None:
        """``ama_randombytes`` is in the version script's ``local:`` list."""
        doc_fixture.write_text(
            "<!-- example: c-decl -->\n"
            "```c\n"
            "ama_error_t ama_randombytes(uint8_t *buf, size_t len);\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "c")
        assert completed.returncode == 1
        assert "ama_randombytes" in completed.stderr

    @requires_c_lane
    def test_a_wrong_documented_key_size_fails(self, doc_fixture: Path) -> None:
        """A drifted buffer size is a stack overflow in every derived program."""
        doc_fixture.write_text(
            "<!-- example: c-const -->\n"
            "```c\n"
            "#define AMA_ML_DSA_65_SECRET_KEY_BYTES 2048\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", str(doc_fixture), "--lang", "c")
        assert completed.returncode == 1
        assert "4032" in completed.stderr


#: The two annotations whose rendering moved under CPython 3.14. Read off the
#: live objects rather than restated here, so the pins below compare against
#: what the interpreter running them actually produces.
_RETRIEVE_KEY_RETURN = inspect.signature(
    key_management.SecureKeyStorage.retrieve_key
).return_annotation
_GET_STATUS_RETURN = inspect.signature(secure_memory.get_status).return_annotation


class TestTheReturnTypeComparisonDoesNotDependOnTheInterpreter:
    """A documented return type is true of the code or it is not.

    The first revision compared ``str(annotation)`` against the documented
    text. CPython 3.14 renders ``Optional[bytes]`` as ``bytes | None`` and
    ``Dict[str, Union[bool, str]]`` as ``typing.Dict[str, bool | str]``, so two
    correct ``wiki/API-Reference.md`` lines passed on 3.10-3.13 and failed the
    3.14 matrix cell of PR #394 — the gate reported a documentation defect that
    did not exist, and would equally have stayed silent on a wrong claim whose
    spelling happened to match the new rendering.

    The comparison now resolves both sides to type objects and walks them with
    ``typing.get_origin``/``get_args``. Each equivalence below fails under the
    string comparison on at least one supported interpreter, which is what
    makes them pins rather than smoke.
    """

    @staticmethod
    def _matches(declared: str, actual: object) -> bool:
        module = _load(DOC_EXAMPLES)
        # `get_status` is a real target on a covered page, so the declared text
        # resolves against the namespace the annotation was written in.
        return bool(module._return_matches(declared, actual, secure_memory.get_status))

    @pytest.mark.parametrize(
        "declared",
        [
            "Optional[bytes]",
            "bytes | None",  # PEP 604; how 3.14 renders the annotation
            "Union[bytes, None]",
            "Union[None, bytes]",  # a union is a set, not a sequence
            "typing.Optional[bytes]",
        ],
    )
    def test_every_spelling_of_one_type_is_accepted(self, declared: str) -> None:
        assert self._matches(declared, _RETRIEVE_KEY_RETURN)

    @pytest.mark.parametrize(
        "declared",
        [
            "Dict[str, Union[bool, str]]",
            "Dict[str, Union[str, bool]]",
            "dict[str, Union[bool, str]]",  # PEP 585
            "typing.Dict[str, bool | str]",  # how 3.14 renders the annotation
        ],
    )
    def test_every_spelling_of_one_generic_is_accepted(self, declared: str) -> None:
        assert self._matches(declared, _GET_STATUS_RETURN)

    @pytest.mark.parametrize(
        ("declared", "actual"),
        [
            ("Optional[str]", _RETRIEVE_KEY_RETURN),
            ("bytes", _RETRIEVE_KEY_RETURN),
            ("Dict[str, bool]", _GET_STATUS_RETURN),
            ("Dict[str, Union[bool, int]]", _GET_STATUS_RETURN),
            ("List[bytes]", _GET_STATUS_RETURN),
        ],
    )
    def test_a_wrong_type_is_still_rejected(self, declared: str, actual: object) -> None:
        """Negative control: normalising spellings must not normalise meaning."""
        assert not self._matches(declared, actual)

    @pytest.mark.parametrize(
        "declared",
        [
            "Optional[bytes]",
            "bytes | None",
            "Union[None, bytes]",
        ],
    )
    def test_a_pep_563_annotation_is_resolved_before_it_is_compared(self, declared: str) -> None:
        """Ten package modules carry ``from __future__ import annotations``.

        ``inspect.signature`` hands those back as SOURCE TEXT — measured:
        ``legacy_compat.get_rfc3161_timestamp`` yields the string
        ``'Optional[bytes]'``, not the type.  Comparing a type object against
        that string reports a mismatch on a page that is correct, so the actual
        side is resolved through the same grammar before either is canonicalised.
        """
        module = _load(DOC_EXAMPLES)
        actual = inspect.signature(legacy_compat.get_rfc3161_timestamp).return_annotation
        assert isinstance(actual, str), "PEP 563 no longer defers this annotation"
        assert module._return_matches(declared, actual, legacy_compat.get_rfc3161_timestamp)

    def test_a_pep_563_annotation_still_rejects_a_wrong_type(self) -> None:
        """Negative control for the resolution above."""
        module = _load(DOC_EXAMPLES)
        actual = inspect.signature(legacy_compat.get_rfc3161_timestamp).return_annotation
        assert not module._return_matches(
            "Optional[str]", actual, legacy_compat.get_rfc3161_timestamp
        )

    def test_prose_that_names_no_type_falls_back_to_the_text_and_fails(self) -> None:
        """A page may describe a return in prose; it is then compared as text."""
        assert not self._matches("a mapping of flags", _GET_STATUS_RETURN)

    @pytest.mark.parametrize(
        "declared",
        [
            "__import__('os').system('true')",
            "open('/etc/passwd')",
            "[x for x in ().__class__.__mro__]",
            "(lambda: 1)()",
        ],
    )
    def test_a_type_expression_is_resolved_without_executing_anything(self, declared: str) -> None:
        """The resolver is a grammar, not ``eval``.

        ``eval`` would satisfy the version-independence requirement and would
        also run whatever a covered page contains — and would need a bandit
        suppression to pass this repository's own lint gate. The resolver
        accepts names, dotted names, subscripts, tuples, lists, ``X | Y`` and
        the constants ``None``/``...``; a call node is not in the grammar, so it
        resolves to nothing and the text path reports the mismatch.
        """
        module = _load(DOC_EXAMPLES)
        assert module._resolve_annotation(declared, secure_memory.get_status) is (
            module._UNRESOLVED
        )


# ===========================================================================
# tools/check_crypto_construction_docs.py
# ===========================================================================


class TestCryptoConstructionDocs:
    def test_the_real_documentation_passes(self) -> None:
        completed = _run(CONSTRUCTION_DOCS)
        assert completed.returncode == 0, completed.stderr

    def test_the_authority_is_derived_not_asserted(self) -> None:
        """The gate must learn the numbers from the source, not carry them.

        If this ever reads a constant out of the gate instead of the module,
        the gate stops tracking the code — which is the whole failure mode it
        exists to prevent.
        """
        gate = _load(CONSTRUCTION_DOCS)
        authority = gate.build_authority(REPO_ROOT)

        from ama_cryptography.adaptive_posture import PostureEvaluator
        from ama_cryptography.equations import ETHICAL_VECTOR

        assert authority.posture_thresholds == (
            PostureEvaluator.DEFAULT_ELEVATED_THRESHOLD,
            PostureEvaluator.DEFAULT_HIGH_THRESHOLD,
            PostureEvaluator.DEFAULT_CRITICAL_THRESHOLD,
        )
        assert authority.ethical_vector_length == len(ETHICAL_VECTOR)
        assert abs(sum(authority.posture_weights) - 1.0) < 1e-9
        assert authority.combine_raises_on_missing_native is True
        assert authority.native_memzero_has_barrier is True
        assert authority.lms_verify_implemented and authority.hss_verify_implemented
        assert authority.secure_wipe_delegates_to_memzero is True

    def test_the_composite_weights_are_read_in_source_order(self) -> None:
        """A permutation would make the gate reject the correct documentation.

        An earlier revision flattened the ``+`` chain with ``ast.walk``, which
        yields terms in tree order rather than source order, and demanded
        ``(0.25, 0.45, 0.15, 0.15)``.
        """
        gate = _load(CONSTRUCTION_DOCS)
        authority = gate.build_authority(REPO_ROOT)
        assert authority.posture_weights == (0.45, 0.25, 0.15, 0.15)

    @pytest.mark.parametrize(
        ("claim", "expected_fragment"),
        [
            (
                "Uses native C `ama_hkdf` (HMAC-SHA3-256) with pure Python SHA3-256 fallback.",
                "Python HKDF fallback",
            ),
            (
                "- **PostureEvaluator** — Weighted scoring: timing (50%), "
                "pattern (30%), resonance (20%) with exponential decay",
                "posture signals",
            ),
            ("| ELEVATED | 0.3-0.6 | Increase monitoring |", "ELEVATED row"),
            ("| HIGH | 0.6-0.8 | Rotate keys |", "HIGH row"),
            # wiki/Adaptive-Posture.md wrote the level as inline code, which
            # the bare-word row pattern did not match.
            ("| `ELEVATED` | 0.2 \u2013 0.5 | Increase 3R monitoring frequency |", "ELEVATED row"),
            ("    assert len(pkg_v2.ethical_vector) == 12", "ETHICAL_VECTOR has 4 keys"),
            ("**AMA does not implement HSS/LMS.** This corpus is the answer key.", "HSS/LMS"),
            ("pkg = sign_codes(MASTER_OMNI_CODES, MASTER_HELIX_PARAMS, kms)", "MASTER_OMNI_CODES"),
            ("| C Compiler | GCC 7 / Clang 6 | GCC 12 / Clang 16 |", "GCC below 12"),
            (
                "`secure_memzero()` performs multiple overwrite passes to defeat the optimiser.",
                "multi-pass",
            ),
            ("- **Bottleneck**: ML-DSA-65 signing (4.20 ms, dominant signing cost)", "4.20 ms"),
        ],
    )
    def test_each_shipped_defect_is_caught(
        self, tmp_path: Path, claim: str, expected_fragment: str
    ) -> None:
        """Every entry here is wording that actually shipped."""
        fixture = tmp_path / "claim.md"
        fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert expected_fragment.lower() in completed.stderr.lower()

    def test_the_corrected_wording_passes(self, tmp_path: Path) -> None:
        """Non-vacuity: the replacement text must NOT fail.

        A gate that rejects the correction as well as the defect is a gate
        nobody can satisfy, and it gets disabled.
        """
        fixture = tmp_path / "corrected.md"
        fixture.write_text(
            "# fixture\n\n"
            "Uses native C `ama_hkdf` and nothing else — with the native backend\n"
            "unavailable, `HybridCombiner.combine()` raises `RuntimeError`.\n\n"
            "- **PostureEvaluator** — four signals: timing 0.45, pattern 0.25,\n"
            "  resonance 0.15, Lyapunov 0.15.\n\n"
            "| ELEVATED | 0.15 – 0.45 | Increase monitoring |\n"
            "| HIGH | 0.45 – 0.80 | Rotate keys |\n"
            "| `HIGH` | 0.45 – 0.8 | Rotate keys (`ROTATE_KEYS`) |\n\n"
            "    assert len(pkg_v2.ethical_vector) == 4\n\n"
            "AMA implements HSS/LMS verification; only signing is withheld.\n\n"
            "| C Compiler | GCC 12 / Clang 15 | GCC 13+ / Clang 17+ |\n\n"
            "`secure_memzero()` writes zeros once and issues a compiler barrier.\n",
            encoding="utf-8",
        )
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 0, completed.stderr

    def test_the_waiver_is_explicit_and_scoped(self, tmp_path: Path) -> None:
        """A correction note may quote what it retires — but only with the marker."""
        gate = _load(CONSTRUCTION_DOCS)
        fixture = tmp_path / "waiver.md"
        claim = "This used to say MASTER_OMNI_CODES, which never existed."

        fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
        assert _run(CONSTRUCTION_DOCS, "--file", str(fixture)).returncode == 1

        fixture.write_text(f"# fixture\n\n{gate.WAIVER}\n{claim}\n", encoding="utf-8")
        assert _run(CONSTRUCTION_DOCS, "--file", str(fixture)).returncode == 0

    @pytest.mark.parametrize(
        ("claim", "expected_fragment"),
        [
            # The finding's own examples: each passed while ANY negative word on
            # the line switched every assertion rule off.
            (
                "If the C library is not built, the hybrid combiner uses a pure-Python "
                "SHA3-256 fallback.",
                "Python HKDF fallback",
            ),
            (
                "Without the native library, the hybrid combiner uses a pure Python "
                "SHA3-256 fallback.",
                "Python HKDF fallback",
            ),
            (
                "`secure_memzero()` performs multiple overwrite passes so no data remains.",
                "multi-pass",
            ),
            ("| ELEVATED | 0.3-0.6 | Increase monitoring, no rotation |", "ELEVATED row"),
            (
                "- **PostureEvaluator** — Weighted scoring (not configurable): timing (50%), "
                "pattern (30%), resonance (20%)",
                "posture signals",
            ),
            ("    assert len(pkg.ethical_vector) == 12  # not 4", "ETHICAL_VECTOR has 4 keys"),
            # "INVARIANT-7" anywhere on the line was a cue of its own.
            (
                "Per INVARIANT-7 the hybrid combiner keeps a pure Python SHA3-256 fallback.",
                "Python HKDF fallback",
            ),
            # The one real line the waiver hid: HybridCombiner(native_lib=None)
            # loads the native library; there is no Python fallback to use.
            (
                '"""Return a HybridCombiner using the Python fallback (no native lib)."""',
                "Python HKDF fallback",
            ),
            # One denied mention does not excuse a second, asserted one.
            (
                "There is no Python fallback for HMAC, but the hybrid combiner uses a "
                "pure Python fallback.",
                "Python HKDF fallback",
            ),
            # A denial does not reach across a clause boundary ...
            (
                "Where HKDF is not native, a pure Python fallback serves the hybrid combiner.",
                "Python HKDF fallback",
            ),
            # ... nor further than three words back ...
            (
                "If the native library is not present the hybrid combiner uses a pure "
                "Python fallback.",
                "Python HKDF fallback",
            ),
            # ... nor past a word that opens a new clause after the phrase.
            (
                "The hybrid combiner has a pure Python fallback for callers who can't build C.",
                "Python HKDF fallback",
            ),
        ],
    )
    def test_a_negative_word_elsewhere_on_the_line_does_not_excuse_the_claim(
        self, tmp_path: Path, claim: str, expected_fragment: str
    ) -> None:
        fixture = tmp_path / "claim.md"
        fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert expected_fragment.lower() in completed.stderr.lower()

    def test_a_denial_in_the_claims_own_clause_still_passes(self, tmp_path: Path) -> None:
        """Non-vacuity: the corrected wording, in each denial shape the scope admits.

        The first three are the real lines the old line-wide waiver was
        excusing that are genuine denials (ENHANCED_FEATURES.md,
        requirements.txt, tests/test_invariant_upgrades.py).
        """
        denials = (
            "- Uses native C HKDF-SHA3-256. **There is no Python fallback.**",
            "#   - HKDF-SHA3-256 key derivation (RFC 5869) — INVARIANT-7: no Python fallback",
            '"""Verify no pure-Python fallback exists in the HMAC/HKDF functions."""',
            "The hybrid combiner does not use a pure Python fallback.",
            "The hybrid combiner no longer ships a pure Python fallback.",
            "A pure-Python SHA3-256 fallback for the hybrid combiner does not exist.",
            "A pure Python fallback isn't provided for the hybrid combiner.",
            "INVARIANT-7 forbids a pure Python fallback in the hybrid combiner.",
            "`combine()` raises rather than using a pure Python fallback in the hybrid combiner.",
            "`secure_memzero()` writes zeros once, not in three passes.",
            "The native kernel is not multi-pass: `secure_memzero()` writes once and "
            "issues a barrier.",
        )
        fixture = tmp_path / "denials.md"
        fixture.write_text("# fixture\n\n" + "\n\n".join(denials) + "\n", encoding="utf-8")
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 0, completed.stderr

    @pytest.mark.parametrize(
        ("claim", "expected_fragment"),
        [
            # Single-boundary rows: the NOMINAL and CRITICAL rows of every shipped
            # table are written this way, and none of them was read.
            ("| CRITICAL | >= 0.90 | Rotate keys + switch algorithm + alert |", "CRITICAL row"),
            ("| CRITICAL | ≥ 0.90 | Rotate keys + switch algorithm + alert |", "CRITICAL row"),
            ("| NOMINAL | < 0.30 | No action |", "NOMINAL row"),
            ("| HIGH | > 0.50 | Rotate keys |", "HIGH row"),
            # The constants named in prose.
            (
                "The thresholds are `DEFAULT_ELEVATED_THRESHOLD` = 0.30,",
                "DEFAULT_ELEVATED_THRESHOLD as 0.3",
            ),
            (
                "`DEFAULT_HIGH_THRESHOLD` = 0.45 and `DEFAULT_CRITICAL_THRESHOLD` = 0.90",
                "DEFAULT_CRITICAL_THRESHOLD as 0.9",
            ),
            # A threshold triple in prose.
            (
                "Threat-level boundaries are 0.30 / 0.60 / 0.80 "
                "(3σ / 5σ / 7σ in composite-score space).",
                "posture thresholds as 0.30 / 0.60 / 0.80",
            ),
        ],
    )
    def test_every_documented_form_of_a_threshold_is_checked(
        self, tmp_path: Path, claim: str, expected_fragment: str
    ) -> None:
        """The rule read only ``| LEVEL | a-b |`` rows; every other form passed."""
        fixture = tmp_path / "claim.md"
        fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert expected_fragment.lower() in completed.stderr.lower()

    def test_the_shipped_threshold_forms_pass(self, tmp_path: Path) -> None:
        """Non-vacuity: the forms the real tables and prose use, with the real values.

        The ARCHITECTURE.md sentence is the one the weights rule used to misread
        as three weights: its threshold triple must be read as the thresholds.
        """
        fixture = tmp_path / "thresholds.md"
        fixture.write_text(
            "# fixture\n\n"
            "| NOMINAL | < 0.15 | No action |\n"
            "| ELEVATED | 0.15 – 0.45 | Increase monitoring frequency |\n"
            "| HIGH | 0.45-0.80 | Rotate keys |\n"
            "| CRITICAL | ≥ 0.80 | Rotate keys + switch algorithm + alert |\n"
            "| CRITICAL | >= 0.80 | Rotate keys + switch algorithm + alert |\n\n"
            "The thresholds are `DEFAULT_ELEVATED_THRESHOLD` = 0.15,\n"
            "`DEFAULT_HIGH_THRESHOLD` = 0.45 and `DEFAULT_CRITICAL_THRESHOLD` = 0.80\n\n"
            "- `PostureEvaluator`: Weighted scoring model consuming **four** signals — "
            "timing 0.45, pattern 0.25, resonance 0.15 and Lyapunov stability 0.15. "
            "Threat-level boundaries are 0.15 / 0.45 / 0.80 (3σ / 5σ / 7σ in "
            "composite-score space). Exponential decay on accumulated score prevents "
            "stale anomalies from driving permanent escalation.\n\n"
            "The weights 0.45/0.25/0.15/0.15 sum to 1.0, so the CRITICAL threshold "
            "is reachable.\n",
            encoding="utf-8",
        )
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 0, completed.stderr

    def test_source_comments_are_scanned_too(self, tmp_path: Path) -> None:
        """A stale comment in the package is a claim like any other.

        ``crypto_api.py`` carried "Import HMAC and HKDF from pqc_backends
        (native C) with pure-Python fallback" four lines above the module's own
        INVARIANT-7 guard.
        """
        fixture = tmp_path / "stale_comment.py"
        fixture.write_text(
            "# Import HMAC and HKDF from pqc_backends (native C) with pure-Python fallback\n",
            encoding="utf-8",
        )
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert "Python HKDF fallback" in completed.stderr

    def test_a_document_that_is_not_utf8_fails_and_is_still_scanned(self, tmp_path: Path) -> None:
        """One cp1252 byte used to drop the whole file from every rule.

        ``read_text`` raised ``UnicodeDecodeError``, the loop ``continue``d, and
        the run printed ``OK 1 document(s)`` over a file carrying a retired
        claim.  The encoding error is now a finding of its own, and the rules
        still run on the rest of the file, so the claim on line 5 is reported
        as well.
        """
        fixture = tmp_path / "cp1252.md"
        fixture.write_bytes(
            b"# fixture\n\nAn em dash \x97 pasted from a Windows editor.\n\n"
            b"pkg = sign_codes(MASTER_OMNI_CODES, MASTER_HELIX_PARAMS, kms)\n"
        )
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert "cp1252.md:3" in completed.stderr
        assert "not valid UTF-8 (byte 0x97" in completed.stderr
        assert "cp1252.md:5" in completed.stderr, "the rest of the file was not scanned"
        assert "MASTER_OMNI_CODES does not exist" in completed.stderr

    def test_an_encoding_error_alone_fails(self, tmp_path: Path) -> None:
        """No claim in the file at all: the undecodable byte is enough."""
        fixture = tmp_path / "latin1.md"
        fixture.write_bytes(b"# fixture\n\nCaf\xe9 au lait.\n")
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert "not valid UTF-8 (byte 0xe9" in completed.stderr
        assert "Caf\\xe9" in completed.stderr, "the offending byte is named, not replaced"

    def test_a_document_that_cannot_be_read_fails(self, tmp_path: Path) -> None:
        """An ``OSError`` was swallowed by the same ``continue``."""
        completed = _run(CONSTRUCTION_DOCS, "--file", str(tmp_path / "absent.md"))
        assert completed.returncode == 1, completed.stdout
        assert "absent.md" in completed.stderr
        assert "cannot be read" in completed.stderr

    @pytest.mark.parametrize(
        "claim",
        [
            # wiki/Security-Model.md and wiki/Cryptography-Algorithms.md, as
            # they shipped: the squaring function is fe51_sq, and nothing
            # named fe25519_sq has existed in this tree.
            "| Ed25519 signing | `ama_ed25519.c` with `fe25519_sq()` (secret scalar) | OK |",
            "- Dedicated `fe25519_sq()` field squaring (~55 multiplications vs ~100)",
            # CSRC_ALIGN_REPORT.md section 2.4: the function left with ama_sphincs.c.
            "Updated `spx_prf_msg()` to use HMAC-SHA-512 with Trunc_n output truncation.",
            # An ama_-prefixed name the header never declared.  Before this
            # rule the gate derived the header's symbol set, printed it, and
            # compared nothing against it.
            "Call `ama_ed25519_sign_prehashed(sig, digest, sk)` for Ed25519ph.",
        ],
    )
    def test_a_named_c_function_that_does_not_exist_fails(self, tmp_path: Path, claim: str) -> None:
        fixture = tmp_path / "c_symbol.md"
        fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert "which no code under src/c/" in completed.stderr

    def test_c_functions_that_exist_pass(self, tmp_path: Path) -> None:
        """Positive control: the corrected names, a header symbol, a Python
        function with a C-family prefix, and the calls this rule deliberately
        does not read (dotted, and a caller's own helper)."""
        fixture = tmp_path / "c_symbol_ok.md"
        fixture.write_text(
            "# fixture\n\n"
            "| Ed25519 signing | `ama_ed25519.c` with `fe51_sq()` (secret scalar) |\n\n"
            "PRF_msg is `sha2_PRF_msg()`; the header exports `ama_ed25519_sign()`.\n\n"
            "`secure_memzero(buf)` delegates to the native kernel.\n\n"
            "Byte-identical to `hashlib.sha3_512(data).digest()`, and a helper this\n"
            "page defines for you, `store_master_secret_hsm(secret)`, is the page's.\n\n"
            "```python\n"
            "def store_master_secret_hsm(secret: bytes) -> str:\n"
            "    ...\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 0, completed.stderr

    def test_a_helper_the_page_does_not_define_is_still_checked(self, tmp_path: Path) -> None:
        """The document-local exception is exactly that: remove the definition
        and the same sentence is a claim about the library again."""
        fixture = tmp_path / "c_symbol_helper.md"
        fixture.write_text(
            "# fixture\n\nCall `store_master_secret_hsm(secret)` after keygen.\n",
            encoding="utf-8",
        )
        completed = _run(CONSTRUCTION_DOCS, "--file", str(fixture))
        assert completed.returncode == 1, completed.stdout
        assert "store_master_secret_hsm" in completed.stderr

    def test_a_c_symbol_mentioned_only_in_a_comment_does_not_count(self) -> None:
        """Existence is read from CODE.  A comment that names a function is
        not evidence the function exists — the comment may be the drift."""
        gate = _load(CONSTRUCTION_DOCS)
        code = gate._c_code(
            "/* fe25519_sq(h, f) was the old name */\n"
            '// see "fe25519_sq(" too\n'
            "static void fe51_sq(fe51 h, const fe51 f) { (void)h; (void)f; }\n"
        )
        assert "fe25519_sq" not in code and "fe51_sq" in code

    def test_the_c_symbol_authority_is_derived_from_the_tree(self) -> None:
        gate = _load(CONSTRUCTION_DOCS)
        authority = gate.build_authority(REPO_ROOT)
        assert {"ama", "fe51", "slh", "spx", "sha2"} <= authority.c_call_prefixes
        assert {"fe51_sq", "sha2_PRF_msg", "ama_ed25519_sign"} <= (
            authority.implementation_identifiers
        )
        assert "fe25519_sq" not in authority.implementation_identifiers
        assert authority.c_symbols <= authority.implementation_identifiers

    def test_the_self_referential_exemptions_all_exist(self) -> None:
        """An exemption that outlives its file is a silently widened exemption."""
        gate = _load(CONSTRUCTION_DOCS)
        for relative in gate.SELF_REFERENTIAL:
            assert (REPO_ROOT / relative).is_file(), relative

    def test_a_partial_authority_fails_closed(self, tmp_path: Path) -> None:
        """A gate that learns nothing from the source must not report green."""
        shutil.copytree(REPO_ROOT / "ama_cryptography", tmp_path / "ama_cryptography")
        (tmp_path / "include").mkdir()
        (tmp_path / "include" / "ama_cryptography.h").write_text("", encoding="utf-8")
        (tmp_path / "src" / "c").mkdir(parents=True)
        (tmp_path / "src" / "c" / "ama_consttime.c").write_text("", encoding="utf-8")
        completed = _run(CONSTRUCTION_DOCS, "--repo", str(tmp_path))
        assert completed.returncode == 2
        assert "partial authority" in completed.stderr


# ===========================================================================
# tools/check_public_api_docs.py
# ===========================================================================


def _minimal_pe(exports: Sequence[str]) -> bytes:
    """A PE32+ image whose export directory names exactly ``exports``.

    Synthesised rather than compiled: the parser under test must be pinned on
    every runner, and macOS and Windows have no MinGW to produce a DLL. The
    parser itself was validated in the field against a real cross-built
    ``libama_cryptography.dll`` — this keeps that reading honest without a
    toolchain. Layout per the PE/COFF specification, §3 (headers) and §5.3
    (the export directory); every field the parser does not read is left zero.
    """
    pe_offset = 0x80
    optional_size = 240  # >= 112 + 16 * 8, so data directory 0 is inside it
    optional = pe_offset + 24
    section_table = optional + optional_size
    raw = section_table + 40  # one section header
    section_rva = 0x1000

    directory = bytearray(40)
    name_pointers = bytearray()
    blob = bytearray()
    names_rva = section_rva + 40 + 4 * len(exports)
    for name in exports:
        name_pointers += (names_rva + len(blob)).to_bytes(4, "little")
        blob += name.encode("ascii") + b"\0"
    directory[24:28] = len(exports).to_bytes(4, "little")  # NumberOfNamePointers
    directory[32:36] = (section_rva + 40).to_bytes(4, "little")  # NamePointerRVA
    section = bytes(directory) + bytes(name_pointers) + bytes(blob)

    image = bytearray(raw + len(section))
    image[0:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 4 : pe_offset + 6] = (0x8664).to_bytes(2, "little")  # Machine
    image[pe_offset + 6 : pe_offset + 8] = (1).to_bytes(2, "little")  # NumberOfSections
    image[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")  # PE32+
    image[optional + 112 : optional + 116] = section_rva.to_bytes(4, "little")
    image[optional + 116 : optional + 120] = len(section).to_bytes(4, "little")
    image[section_table : section_table + 8] = b".edata\0\0"
    image[section_table + 8 : section_table + 12] = len(section).to_bytes(4, "little")
    image[section_table + 12 : section_table + 16] = section_rva.to_bytes(4, "little")
    image[section_table + 16 : section_table + 20] = len(section).to_bytes(4, "little")
    image[section_table + 20 : section_table + 24] = raw.to_bytes(4, "little")
    image[raw:] = section
    return bytes(image)


class TestThePublicApiGateReadsTheImageInFrontOfIt:
    """``nm --dynamic`` reads ELF. The gate is handed three formats.

    On a098d8ba the windows-latest lane reported sixteen missing exports.
    Measured against a MinGW-built DLL that demonstrably exports them:
    ``nm --dynamic --defined-only --format=posix`` prints "no symbols" and
    **exits zero**, so the gate saw an empty set and read it as a catastrophic
    ABI failure. The sixteen were a reading error, and a genuinely dropped
    export would have been indistinguishable from it.
    """

    def test_the_format_comes_from_the_magic_bytes(self, tmp_path: Path) -> None:
        module = _load(PUBLIC_API)
        cases = {
            "an.so": b"\x7fELF\x02\x01\x01\x00",
            "a.dll": _minimal_pe(["ama_x"]),
            "a.dylib": b"\xcf\xfa\xed\xfe" + bytes(16),
        }
        formats = []
        for name, payload in cases.items():
            path = tmp_path / name
            path.write_bytes(payload)
            formats.append(module.object_format(path))
        assert formats == ["elf", "pe", "macho"]

    def test_a_format_it_cannot_read_is_named_not_guessed(self, tmp_path: Path) -> None:
        """An unreadable image is an error, never an empty export set."""
        path = tmp_path / "not-an-object"
        path.write_bytes(b"#!/bin/sh\nexit 0\n")
        module = _load(PUBLIC_API)
        with pytest.raises(RuntimeError, match="not an object file"):
            module.object_format(path)

    def test_pe_exports_are_read_from_the_export_directory(self, tmp_path: Path) -> None:
        names = ["ama_sha3_256", "ama_ed25519_sign", "ama_hkdf"]
        path = tmp_path / "ama_cryptography.dll"
        path.write_bytes(_minimal_pe(names))
        module = _load(PUBLIC_API)
        assert module.pe_export_names(path) == frozenset(names)
        assert module.dynamic_symbols(path) == frozenset(names)

    def test_reading_no_ama_symbols_raises_instead_of_reporting_them_missing(
        self, tmp_path: Path
    ) -> None:
        """The pin on the whole defect class.

        Returning an empty set here is what turned an unreadable image into
        sixteen invented documentation failures. It must be impossible to
        confuse "I could not read this" with "this exports nothing".
        """
        path = tmp_path / "ama_cryptography.dll"
        path.write_bytes(_minimal_pe(["unrelated_symbol"]))
        module = _load(PUBLIC_API)
        with pytest.raises(RuntimeError, match=r"read 0 ama_\* symbols"):
            module.dynamic_symbols(path)

    def test_the_elf_reader_still_reads_the_built_library(self) -> None:
        """Positive control: the format this gate has always read."""
        if _BUILT_LIBRARY is None or _BUILT_LIBRARY.read_bytes()[:4] != b"\x7fELF":
            pytest.skip("this host's build is not ELF; the PE and Mach-O paths cover it")
        module = _load(PUBLIC_API)
        symbols = module.dynamic_symbols(_BUILT_LIBRARY)
        assert {"ama_sha3_256", "ama_ed25519_sign"} <= symbols

    def test_macho_is_read_by_whichever_nm_the_runner_ships(self) -> None:
        """Xcode ships LLVM nm; older images ship cctools nm.

        They do not accept the same spelling of "defined external symbols",
        and which one is ``/usr/bin/nm`` is a property of the runner image.
        Before this work the macOS lanes never reached the export check at all
        (``find_library`` globbed ``.so*`` only), so a wrong flag would have
        turned ten green jobs red on its first run.

        ``_nm_symbols`` is substituted rather than run. The first version of
        this test invoked the real nm against this host's built library, which
        on windows-latest is a PE DLL with no nm to read it — it failed four
        Windows jobs for a reason that had nothing to do with what it claims to
        test. What is under test is the invocation sequence, so the sequence is
        what is driven.
        """
        module = _load(PUBLIC_API)
        seen: list[tuple[str, ...]] = []

        def fake(library: Path, argv: Sequence[str]) -> frozenset[str]:
            seen.append(tuple(argv))
            if tuple(argv) == module._MACHO_NM_ARGV[0]:
                raise RuntimeError("nm: unknown argument")
            return frozenset({"ama_sha3_256", "_unrelated"})

        with mock.patch.object(module, "_nm_symbols", fake):
            symbols = module._macho_symbols(Path("libama_cryptography.dylib"))

        assert symbols == frozenset({"ama_sha3_256", "_unrelated"})
        assert seen == [module._MACHO_NM_ARGV[0], module._MACHO_NM_ARGV[1]]

    def test_an_nm_that_exits_zero_and_names_nothing_is_not_accepted(self) -> None:
        """Exit status is not the question; whether it read the file is.

        cctools nm answers an option it does not know by printing usage and
        exiting zero on some images. A reader that took that as "no symbols"
        is exactly the Windows defect, in a second costume.
        """
        module = _load(PUBLIC_API)

        def fake(library: Path, argv: Sequence[str]) -> frozenset[str]:
            if tuple(argv) == module._MACHO_NM_ARGV[0]:
                return frozenset({"_not_an_ama_symbol"})
            return frozenset({"ama_sha3_256"})

        with mock.patch.object(module, "_nm_symbols", fake):
            symbols = module._macho_symbols(Path("libama_cryptography.dylib"))
        assert symbols == frozenset({"ama_sha3_256"})

    def test_when_no_nm_spelling_works_every_attempt_is_named(self) -> None:
        """Failing closed is not enough; it has to say what it tried."""
        module = _load(PUBLIC_API)

        def fake(library: Path, argv: Sequence[str]) -> frozenset[str]:
            raise RuntimeError(f"nm: unknown argument {argv[0]}")

        with mock.patch.object(module, "_nm_symbols", fake):
            with pytest.raises(RuntimeError) as caught:
                module._macho_symbols(Path("libama_cryptography.dylib"))
        message = str(caught.value)
        for argv in module._MACHO_NM_ARGV:
            assert argv[0] in message

    def test_a_compiler_clone_never_reaches_the_exported_abi(self, tmp_path: Path) -> None:
        """Measured on the cross-built DLL: ``ama_hmac_sha256.part.0``.

        A GCC interprocedural clone inherits the entry point's dllexport, so it
        lands on the PE export table with a compiler-chosen signature and none
        of the entry point's argument checks — the guard-bypass surface
        ``cmake/ama_exports.map`` keeps off the ELF ABI. Naming clones is not
        the fix and this asserts the failure says so: suppressing
        ``-fpartial-inlining`` moved the symbol to ``.constprop.0``.
        """
        module = _load(PUBLIC_API)
        declared = set(module._AMA_API.findall(Path("include/ama_cryptography.h").read_text()))
        clean = sorted(declared | set(module.MUST_BE_EXPORTED))
        path = tmp_path / "ama_cryptography.dll"

        path.write_bytes(_minimal_pe(clean))
        report = module.Report()
        module.check_exports(report, REPO_ROOT, path)
        assert report.failures == [], report.failures

        path.write_bytes(_minimal_pe([*clean, "ama_hmac_sha256.part.0"]))
        report = module.Report()
        module.check_exports(report, REPO_ROOT, path)
        assert len(report.failures) == 1
        assert "ama_hmac_sha256.part.0" in report.failures[0]
        assert "never by naming the clones" in report.failures[0]


class TestPublicApiDocs:
    def test_the_real_package_matches_its_documentation(self) -> None:
        """Positive control, whatever this runner built.

        With a findable library every claim, the exported ABI included, must
        hold (exit 0).  Without one the export checks are SKIPPED, and the
        gate must say so in its exit status (3) rather than exit 0 — which is
        what its docstring always promised and what it did not do.
        """
        completed = _run(PUBLIC_API)
        library = _load(PUBLIC_API).find_library(REPO_ROOT)
        expected = 0 if library is not None else 3
        assert completed.returncode == expected, (library, completed.stdout, completed.stderr)

    def test_a_skipped_export_check_is_not_exit_zero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The docstring: "the exit status distinguishes the two".

        ``main`` returned 0 whether or not the C export checks ran, so a caller
        could not tell a verified ABI from an unexamined one.  Driven with the
        library search forced empty, so this pins the skip path on every
        runner, including the ones that do have a library.
        """
        module = _load(PUBLIC_API)
        monkeypatch.setattr(module, "find_library", lambda *_args, **_kwargs: None)
        rc = module.main([])
        out = capsys.readouterr().out
        assert rc == 3, out
        assert "SKIP  C export verification" in out
        assert module.main(["--require-library"]) == 2

    def test_the_documented_bare_import_set_is_the_real_one(self) -> None:
        """The wiki's list and the gate's list must be the same list.

        The reference claimed eight "always available" submodules; five raise
        AttributeError on a fresh interpreter.

        This runs in a SUBPROCESS, and that is load-bearing rather than
        fastidious: Python's import machinery binds a submodule as an
        attribute of its parent package the moment **anything** in the process
        imports it. Run in-process, this assertion passes or fails according to
        which tests ran first — it saw ``adaptive_posture`` and
        ``key_management`` bound purely because earlier tests in the same
        session had imported them. An oracle for "what a bare import gives
        you" has to start from a bare interpreter.
        """
        gate = _load(PUBLIC_API)
        script = (
            "import types, ama_cryptography as a;"
            "print(' '.join(sorted(n for n, v in vars(a).items()"
            " if isinstance(v, types.ModuleType)"
            " and getattr(v, '__name__', '').startswith('ama_cryptography.')"
            " and not n.startswith('_'))))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        bound = set(completed.stdout.split()) - set(gate.CYTHON_BINDING_SUBMODULES)
        assert bound == set(gate.EXPECTED_BARE_IMPORT_SUBMODULES)

    @pytest.mark.parametrize("name", ["crypto_api", "key_management", "hybrid_combiner"])
    def test_the_lazily_imported_submodules_really_are_unreachable(self, name: str) -> None:
        """The other half of the same claim, asserted as behaviour.

        A subprocess for the same reason as above: in-process, any earlier
        ``import ama_cryptography.key_management`` anywhere in the session
        makes this pass vacuously.
        """
        script = (
            "import ama_cryptography\n"
            f"try:\n    ama_cryptography.{name}\n"
            "except AttributeError:\n    pass\n"
            "else:\n    raise SystemExit('reachable')\n"
            f"import ama_cryptography.{name}\n"
            f"assert ama_cryptography.{name} is not None\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        assert completed.returncode == 0, (
            f"ama_cryptography.{name} is reachable from a bare import; "
            "wiki/API-Reference.md says it is not.\n" + completed.stderr
        )

    def test_secure_mlock_returns_none_not_a_boolean(self) -> None:
        """Documented as `-> bool`; a caller branching on it always loses."""
        from ama_cryptography.secure_memory import secure_mlock, secure_munlock

        buffer = bytearray(32)
        # `cast` because mypy --strict rejects comparing a `-> None` call to
        # None as a no-op; here the runtime value IS the claim under test —
        # the page documented `-> bool`, and a caller writing
        # `if secure_mlock(buf):` takes the failure branch on every success.
        assert cast(object, secure_mlock(buffer)) is None
        assert cast(object, secure_munlock(buffer)) is None

    def test_secure_buffer_yields_the_bytearray(self) -> None:
        from ama_cryptography.secure_memory import SecureBuffer

        with SecureBuffer(32) as buffer:
            assert isinstance(buffer, bytearray)
            assert not hasattr(buffer, "data")

    def test_get_pqc_status_returns_an_enum(self) -> None:
        from ama_cryptography.pqc_backends import PQCStatus, get_pqc_status

        assert isinstance(get_pqc_status(), PQCStatus)

    @requires_c_lane
    def test_localised_symbols_are_absent_from_the_library(self) -> None:
        gate = _load(PUBLIC_API)
        assert _BUILT_LIBRARY is not None
        exported = gate.dynamic_symbols(_BUILT_LIBRARY)
        for name in gate.MUST_NOT_BE_EXPORTED:
            assert name not in exported, f"{name} is on the public ABI but is meant to be internal"

    @requires_c_lane
    def test_hss_lms_verification_is_exported(self) -> None:
        """Documented for a long time as not existing at all."""
        gate = _load(PUBLIC_API)
        assert _BUILT_LIBRARY is not None
        exported = gate.dynamic_symbols(_BUILT_LIBRARY)
        assert {"ama_lms_verify", "ama_hss_verify"} <= exported

    def test_the_neon_inventory_has_no_ed25519_kernel(self) -> None:
        """README.md listed one for years. The file has never existed."""
        neon = sorted(path.name for path in (REPO_ROOT / "src" / "c" / "neon").glob("*.c"))
        assert len(neon) == 7
        assert "ama_ed25519_neon.c" not in neon


# ===========================================================================
# tools/check_benchmark_claims.py
# ===========================================================================


class TestBenchmarkClaims:
    def test_the_real_records_are_consistent(self) -> None:
        completed = _run(BENCHMARK_CLAIMS)
        assert completed.returncode == 0, completed.stderr

    def test_every_floor_declares_its_units_and_tolerance(self) -> None:
        """Provenance, asserted directly rather than only through the gate."""
        gate = _load(BENCHMARK_CLAIMS)
        for relative in (gate.X86_BASELINE_JSON, gate.ARM_BASELINE_JSON):
            baseline = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
            floors = gate._floors(baseline)
            assert floors, relative
            for name, entry in floors.items():
                for required in gate.REQUIRED_BASELINE_FIELDS:
                    assert required in entry, f"{relative}:{name} lacks {required}"

    def test_the_results_record_carries_reproduction_provenance(self) -> None:
        gate = _load(BENCHMARK_CLAIMS)
        record = json.loads((REPO_ROOT / gate.RESULTS_JSON).read_text(encoding="utf-8"))
        provenance = record["provenance"]
        for key, _why in gate.REQUIRED_PROVENANCE:
            assert provenance.get(key), f"{gate.RESULTS_JSON} lacks provenance.{key}"

    def test_a_hand_edited_generated_cell_fails(self, tmp_path: Path) -> None:
        """The 4.20 ms defect, reintroduced into the generated block.

        Driven against a SCRATCH repository. An earlier revision rewrote the
        real ARCHITECTURE.md in place and restored it in a ``finally``; on
        Windows that round-trip converted the file to CRLF and left it that
        way, so ``test_line_endings_gate`` failed on a file no commit touched.
        """
        scratch = _scratch_repo(tmp_path)
        target = scratch / "ARCHITECTURE.md"
        original = target.read_text(encoding="utf-8")
        assert "AUTO-PIPELINE-LATENCY-START" in original
        target.write_text(
            original.replace(
                "| ML-DSA-65 Sign (dominant package-creation cost) | < 5 ms |",
                "| ML-DSA-65 Sign (dominant package-creation cost) | < 5 ms | 4.200 |#",
                1,
            ),
            encoding="utf-8",
            newline="",
        )
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 1, completed.stdout
        assert "AUTO-PIPELINE-LATENCY" in completed.stderr

    def test_a_stale_documented_floor_fails(self, tmp_path: Path) -> None:
        """The 76,215 defect: a floor cited in prose that enforces nothing."""
        scratch = _scratch_repo(tmp_path)
        (scratch / "STALE.md").write_text(
            "The enforced floor is 76,215 ops/sec on x86-64.\n", encoding="utf-8", newline=""
        )
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 1, completed.stdout
        assert "76,215" in completed.stderr

    @staticmethod
    def _record_measuring(tmp_path: Path, name: str, value: object) -> Path:
        """A scratch tree whose record gives ``name`` the throughput ``value``.

        The generated tables are then re-derived from that record, which is
        the state a units error reaches once ``tools/update_docs.py`` has run:
        rule 1 agrees with the bad record, so only the range rule and the
        provenance rule are left to object.
        """
        scratch = _scratch_repo(tmp_path)
        record_path = scratch / "benchmarks" / "benchmark-results.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        rows = [row for row in record["results"] if row.get("name") == name]
        assert len(rows) == 1, name
        rows[0]["ops_per_second"] = value
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="")
        # Loaded by path under a private name and never registered in
        # sys.modules: the copy's ROOT is the scratch tree.
        spec = importlib.util.spec_from_file_location(
            "_scratch_update_docs", scratch / "tools" / "update_docs.py"
        )
        assert spec is not None and spec.loader is not None
        update_docs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(update_docs)
        with contextlib.redirect_stdout(io.StringIO()):
            update_docs.update_pipeline_latency_docs()
            update_docs.update_benchmark_docs()
        return scratch

    @staticmethod
    def _x86_floor(name: str) -> float:
        baseline = json.loads(
            (REPO_ROOT / "benchmarks" / "baseline.json").read_text(encoding="utf-8")
        )
        entry = baseline.get("benchmarks", {}).get(name) or baseline["pqc_benchmarks"][name]
        return float(entry["baseline_value"])

    @pytest.mark.parametrize(
        "ops",
        [
            pytest.param(1000.0 / 4.20, id="the-4.20-ms-figure-as-a-throughput"),
            pytest.param(0.379, id="a-ms-per-op-latency-in-the-ops-field"),
        ],
    )
    def test_a_measurement_far_below_its_floor_fails(self, tmp_path: Path, ops: float) -> None:
        """The range rule read only ``ratio > 8``; the 4.20 ms defect is ``ratio < 1/8``.

        Both values are under an eleventh of the 2,636 ops/sec x86-64
        ``dilithium_sign`` floor, and both passed the one-sided check.
        """
        gate = _load(BENCHMARK_CLAIMS)
        assert ops < self._x86_floor("dilithium_sign") / gate.MAX_MEASURED_OVER_FLOOR
        scratch = self._record_measuring(tmp_path, "dilithium_sign", ops)
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 1, completed.stdout
        assert "dilithium_sign: the committed measurement" in completed.stderr
        assert "either direction" in completed.stderr

    def test_a_measurement_far_above_its_floor_still_fails(self, tmp_path: Path) -> None:
        gate = _load(BENCHMARK_CLAIMS)
        ops = self._x86_floor("dilithium_sign") * (gate.MAX_MEASURED_OVER_FLOOR + 1)
        scratch = self._record_measuring(tmp_path, "dilithium_sign", ops)
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 1, completed.stdout
        assert "dilithium_sign: the committed measurement" in completed.stderr

    @pytest.mark.parametrize("factor", [0.13, 7.9])
    def test_a_measurement_inside_the_declared_factor_passes(
        self, tmp_path: Path, factor: float
    ) -> None:
        """Non-vacuity: hardware spread short of the factor, either way, is not an error."""
        ops = round(self._x86_floor("dilithium_sign") * factor, 2)
        scratch = self._record_measuring(tmp_path, "dilithium_sign", ops)
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 0, completed.stderr

    @pytest.mark.parametrize(
        "value",
        [0, -5.0, float("nan"), True],
        ids=["zero", "negative", "nan", "bool"],
    )
    def test_a_throughput_that_is_not_a_positive_finite_number_fails(
        self, tmp_path: Path, value: object
    ) -> None:
        """``if not (name and ops and entry): continue`` skipped a zero, and the
        provenance rule rejected only ``None``: a zero, a negative, NaN (which
        ``json`` accepts and which compares False against every bound) and a
        boolean all reached the published tables with exit 0.
        """
        scratch = self._record_measuring(tmp_path, "dilithium_sign", value)
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 1, completed.stdout
        assert "not a positive, finite number" in completed.stderr

    def test_a_documented_floor_that_exists_passes(self, tmp_path: Path) -> None:
        """Non-vacuity: the corrected number must not fail."""
        scratch = _scratch_repo(tmp_path)
        (scratch / "CURRENT.md").write_text(
            "The enforced hmac_sha3_256 floor is 215,299 ops/sec on x86-64.\n",
            encoding="utf-8",
            newline="",
        )
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 0, completed.stderr

    def test_the_ed25519_sign_floor_tracks_invariant_51(self) -> None:
        """The floor must be a post-INVARIANT-51 value, not the old one.

        70,496 was measured before ``ama_ed25519_sign`` began deriving its own
        public half; the check adds a second fixed-base scalar multiplication,
        so the old floor no longer describes the code.  This used to pin the
        derived replacement (70,496 / 1.8469 = 38,170) as a literal, which a
        measurement then superseded (38,811, the canonical runner's four-run
        median of 2026-09-22).  The property is what matters: the floor sits
        below the pre-check median by the structural cost of the second
        multiplication — between the worst case the structure admits (2.0x)
        and the 1.7x that leaves room for the runner's median to land above
        the C-level derivation — and never at the pre-check value itself.
        """
        x86 = json.loads((REPO_ROOT / "benchmarks" / "baseline.json").read_text(encoding="utf-8"))
        floor = x86["benchmarks"]["ed25519_sign"]["baseline_value"]
        pre_invariant_51_median = 70496
        assert floor != pre_invariant_51_median
        assert pre_invariant_51_median / 2.0 <= floor <= pre_invariant_51_median / 1.7


# ===========================================================================
# The CI invocations themselves
# ===========================================================================


class TestEveryLocalisedSymbolIsCheckedOnEveryPlatform:
    """The export rule covered seven names out of thirty.

    What that cost showed the first time the check reached a macOS runner:
    ``cmake/ama_exports.macos.sym`` listed ``_ama_*`` and nothing else, so the
    shipped dylib published all thirty internal helpers — among them
    ``ama_randombytes`` and ``ama_keccak_f1600_generic``, a raw permutation
    with no NULL checks and no CPUID gate. The seven-name subset reported
    three of them. A subset of an invariant is not the invariant.
    """

    def test_the_gate_reads_the_whole_local_block(self) -> None:
        module = _load(PUBLIC_API)
        localised = module.localised_symbols(REPO_ROOT)
        # Read independently of the gate, so this compares two readings rather
        # than one reading with itself.
        script = (REPO_ROOT / "cmake" / "ama_exports.map").read_text(encoding="utf-8")
        expected = set(re.findall(r"^\s+(ama_[A-Za-z0-9_]+);", script.split("local:", 1)[1], re.M))
        assert localised == frozenset(expected)
        assert len(localised) >= 30, "the local: block shrank; that is an ABI change"
        assert set(module.MUST_NOT_BE_EXPORTED) <= localised

    def test_indentation_does_not_empty_the_set(self, tmp_path: Path) -> None:
        """The first reading required exactly eight leading spaces.

        Re-indenting the version script would have emptied the set, and every
        rule built on it would then have passed over nothing — the failure mode
        the non-vacuity check in ``check_exports`` exists to catch.
        """
        module = _load(PUBLIC_API)
        script = (REPO_ROOT / "cmake" / "ama_exports.map").read_text(encoding="utf-8")
        scratch = tmp_path / "cmake"
        scratch.mkdir()
        reindented = "\n".join(
            "    " + line.strip() if line.strip().startswith("ama_") else line
            for line in script.splitlines()
        )
        (scratch / "ama_exports.map").write_text(reindented, encoding="utf-8")
        assert module.localised_symbols(tmp_path) == module.localised_symbols(REPO_ROOT)

    def test_a_localised_symbol_that_is_exported_is_reported(self, tmp_path: Path) -> None:
        """Every localised name is checked, not a chosen few."""
        module = _load(PUBLIC_API)
        localised = sorted(module.localised_symbols(REPO_ROOT))
        declared = set(module._AMA_API.findall(Path("include/ama_cryptography.h").read_text()))
        clean = sorted(declared | set(module.MUST_BE_EXPORTED))
        path = tmp_path / "ama_cryptography.dll"

        # Every internal helper leaked onto the ABI, as the dylib published them.
        path.write_bytes(_minimal_pe([*clean, *localised]))
        report = module.Report()
        module.check_exports(report, REPO_ROOT, path)
        leaked = [f for f in report.failures if "IS exported" in f]
        assert len(leaked) == len(localised), (
            f"{len(leaked)} of {len(localised)} localised symbols reported; "
            "a subset check would report only the handful it names"
        )
        for name in ("ama_randombytes", "ama_keccak_f1600_generic", "ama_sha256_init"):
            assert any(name in f for f in leaked)

    def test_the_macos_link_control_is_derived_from_the_same_block(self) -> None:
        """One declaration of what is internal, not two hand-kept lists.

        Two lists are how the platforms came to disagree: the ELF version
        script localised thirty names and the Mach-O list exported all of them.
        CMake now generates the unexported-symbols list from the version
        script's own ``local:`` block, so re-deriving it here must reproduce
        exactly what the gate reads.
        """
        module = _load(PUBLIC_API)
        cmakelists = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "-Wl,-unexported_symbols_list," in cmakelists
        # The property is that the retired list is not a LINK INPUT — not that
        # its name never appears. The comment above the new branch names it
        # deliberately, so that the next reader knows what was wrong with it.
        assert "-Wl,-exported_symbols_list," not in cmakelists, (
            "the superseded inclusion list is on the link line again; it "
            "published every ama_* symbol, the localised ones included"
        )
        assert not (REPO_ROOT / "cmake" / "ama_exports.macos.sym").exists()
        # The generator's own rule, applied here: the `local:` names, each
        # given the leading underscore Mach-O puts on a C symbol.
        expected = {f"_{name}" for name in module.localised_symbols(REPO_ROOT)}
        assert len(expected) >= 30


class TestThePeExportTableIsStatedNotInherited:
    """A compiler clone reached the MinGW DLL's ABI and no flag could remove it.

    GCC propagates a public entry point's ``__declspec(dllexport)`` to the
    clones its interprocedural passes create, so ``ama_hmac_sha256.part.0`` was
    exported: a partial-inlining fragment with a compiler-chosen signature and
    none of the entry point's argument checks. Three controls were measured
    before the fourth was built:

    * ``-Wl,--exclude-all-symbols`` suppresses AUTO-export, not an explicit
      dllexport — 191 exports either way.
    * ``-fno-partial-inlining`` produced ``.constprop.0`` in its place. The
      suffix is not a fixed set, so naming clones is not a fix.
    * a ``.def`` ALONE changes nothing, because GNU ld unions it with the
      dllexport'd set rather than restricting to it.

    What works is removing the attribute so the ``.def`` is the sole authority
    (``AMA_EXPORTS_FROM_DEF``), and generating that ``.def`` from the AMA_API
    declarations so it can never name a clone — nothing declares one.

    The declarations alone are not enough, though: the headers declare every
    entry point in every configuration, GNU ld refuses a ``.def`` entry nothing
    defines, and with ``AMA_USE_NATIVE_PQC=OFF`` that was 92 names and no DLL.
    So the list is also restricted to what the configuration's translation
    units define (``AMA_DEF_SOURCES``). ``ci-build-test.yml`` links that
    configuration's DLL with MinGW and reads its export table back.
    """

    GENERATOR = REPO_ROOT / "cmake" / "generate_pe_def.cmake"

    @staticmethod
    def _tree_sources(repo: Path) -> list[str]:
        """Every translation unit under ``src/c`` -- a superset of any configuration."""
        return sorted(p.relative_to(repo).as_posix() for p in (repo / "src" / "c").rglob("*.c"))

    def _invoke(
        self, tmp_path: Path, repo: Path, sources: Optional[Sequence[str]]
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        output = tmp_path / "ama_cryptography.def"
        argv = ["cmake", f"-DAMA_SOURCE_DIR={repo}", f"-DAMA_DEF_OUTPUT={output}"]
        if sources is not None:
            # One argument, semicolons and all: `-P` reads it back as a list,
            # exactly as CMakeLists.txt passes the target's SOURCES.
            argv.append(f"-DAMA_DEF_SOURCES={';'.join(sources)}")
        argv += ["-P", str(self.GENERATOR)]
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
        return completed, output

    def _generate(
        self, tmp_path: Path, repo: Path, sources: Optional[Sequence[str]] = None
    ) -> list[str]:
        completed, output = self._invoke(
            tmp_path, repo, self._tree_sources(repo) if sources is None else sources
        )
        assert completed.returncode == 0, completed.stderr
        body = output.read_text(encoding="utf-8")
        assert "EXPORTS" in body
        return [line.strip() for line in body.splitlines() if line.startswith("    ama_")]

    @staticmethod
    def _synthetic_repo(tmp_path: Path, header: str, sources: dict[str, str], local: str) -> Path:
        repo = tmp_path / "repo"
        (repo / "cmake").mkdir(parents=True)
        (repo / "include").mkdir()
        (repo / "src" / "c").mkdir(parents=True)
        (repo / "include" / "x.h").write_text(header, encoding="utf-8")
        for name, body in sources.items():
            (repo / "src" / "c" / name).write_text(body, encoding="utf-8")
        (repo / "cmake" / "ama_exports.map").write_text(
            "{\n    global:\n        ama_*;\n    local:\n        " + local + ";\n};\n",
            encoding="utf-8",
        )
        return repo

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_the_generated_list_is_the_declared_abi(self, tmp_path: Path) -> None:
        """Two independent derivations of the same set must agree.

        The generator is CMake reading lines; this reads the same headers with
        the gate's own multi-line regex. Agreement is what makes the generated
        file trustworthy without a Windows host to link on.
        """
        module = _load(PUBLIC_API)
        declared: set[str] = set()
        for header in sorted((REPO_ROOT / "include").rglob("*.h")) + sorted(
            (REPO_ROOT / "src" / "c").rglob("*.h")
        ):
            declared |= set(module._AMA_API.findall(header.read_text(encoding="utf-8")))
        expected = declared - module.localised_symbols(REPO_ROOT)

        generated = self._generate(tmp_path, REPO_ROOT)
        assert sorted(set(generated)) == sorted(expected)
        assert len(generated) == len(set(generated)), "the .def repeats a name"
        assert len(generated) >= 150, "the declared ABI collapsed; that is an ABI change"

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_no_localised_symbol_is_in_the_real_export_table(self, tmp_path: Path) -> None:
        """SMOKE, and labelled so deliberately.

        Measured: on this tree none of the localised names is AMA_API-declared
        (not one of the thirty the map held when this was first written, nor
        of the larger set it holds now), so ``declared - localised`` equals
        ``declared`` and this holds with or without the subtraction — removing
        it from the generator leaves this test passing. It stays as a standing
        check on the real tree; ``test_a_localised_declaration_is_subtracted`` is what
        actually constrains the subtraction.
        """
        module = _load(PUBLIC_API)
        generated = set(self._generate(tmp_path, REPO_ROOT))
        assert not (generated & module.localised_symbols(REPO_ROOT))

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_a_localised_declaration_is_subtracted(self, tmp_path: Path) -> None:
        """The PIN on the subtraction, over a tree where it is not a no-op.

        A header can declare AMA_API on something the version script localises —
        exactly the case the subtraction exists for, and the case the real tree
        happens not to exercise. Built here on purpose: without the subtraction
        the internal name lands in EXPORTS and is published.
        """
        repo = self._synthetic_repo(
            tmp_path,
            "AMA_API int ama_public_entry(void);\n"
            "AMA_API void ama_internal_kernel_avx2(void);\n",
            {
                "x.c": "\nint ama_public_entry(void) { return 0; }\n"
                "\nvoid ama_internal_kernel_avx2(void) {\n}\n"
            },
            local="ama_internal_kernel_avx2",
        )
        assert self._generate(tmp_path, repo) == ["ama_public_entry"]

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_a_configuration_exports_only_what_it_compiles(self, tmp_path: Path) -> None:
        """The PIN on the configuration dependence.

        The headers declare every entry point unconditionally, and GNU ld stops
        on a .def entry nothing defines ("cannot export ama_argon2id: symbol not
        defined"). With the list derived from the headers alone, the MinGW DLL
        with AMA_USE_NATIVE_PQC=OFF named 92 functions it does not compile and
        did not link. Here a header declares two entry points in two files and
        the configuration compiles one of them.
        """
        repo = self._synthetic_repo(
            tmp_path,
            "AMA_API int ama_always(void);\nAMA_API int ama_optional(const unsigned char *k);\n",
            {
                "always.c": "/* built everywhere */\nint ama_always(void)\n{\n    return 0;\n}\n",
                "optional.c": "\nAMA_API int ama_optional(\n    const unsigned char *k) {\n"
                "    return k[0];\n}\n",
            },
            local="ama_never_declared",
        )
        assert self._generate(tmp_path, repo, ["src/c/always.c"]) == ["ama_always"]
        assert self._generate(tmp_path, repo, ["src/c/always.c", "src/c/optional.c"]) == [
            "ama_always",
            "ama_optional",
        ]

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_a_call_or_a_prototype_is_not_a_definition(self, tmp_path: Path) -> None:
        """What would put an undefined name back in the list.

        The compiled file mentions ``ama_optional`` three ways -- a prototype, a
        call in a condition, a call statement -- and defines it in none of them.
        """
        repo = self._synthetic_repo(
            tmp_path,
            "AMA_API int ama_always(void);\nAMA_API int ama_optional(void);\n",
            {
                "always.c": "\nextern int ama_optional(void);\n"
                "int ama_optional(void);\n"
                "int ama_always(void) {\n"
                "    if (ama_optional() != 0) {\n        return 1;\n    }\n"
                "    ama_optional();\n    return 0;\n}\n",
                "optional.c": "\nint ama_optional(void) { return 0; }\n",
            },
            local="ama_never_declared",
        )
        assert self._generate(tmp_path, repo, ["src/c/always.c"]) == ["ama_always"]

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_leaving_out_a_translation_unit_drops_exactly_its_definitions(
        self, tmp_path: Path
    ) -> None:
        """The real tree, with one of the AMA_USE_NATIVE_PQC=OFF sources left out.

        Independent of the generator's CMake regex: the dropped set is computed
        here with a Python regex over the file that is left out. The three
        Argon2id entry points are among the 92 names that stopped the MinGW
        link with native PQC off.
        """
        left_out = REPO_ROOT / "src" / "c" / "ama_argon2.c"
        text = left_out.read_text(encoding="utf-8")
        defined_there = set(
            re.findall(r"(?m)^(?:[A-Za-z_][\w \t*]*[ \t*])?(ama_\w+)[ \t]*\([^;{}]*\)\s*\{", text)
        )
        full = self._generate(tmp_path, REPO_ROOT)
        dropped = set(full) & defined_there
        assert {"ama_argon2id", "ama_argon2id_legacy", "ama_argon2id_legacy_verify"} <= dropped
        sources = [s for s in self._tree_sources(REPO_ROOT) if s != "src/c/ama_argon2.c"]
        assert sorted(self._generate(tmp_path, REPO_ROOT, sources)) == sorted(set(full) - dropped)

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_a_declaration_defined_nowhere_fails_the_configure(self, tmp_path: Path) -> None:
        """Fail-closed where dropping a name would be silent.

        A declared name whose definition the scan cannot find anywhere in the
        tree -- a header lie, or a definition written in a form the scan does
        not read -- must stop the configure, not quietly leave the DLL without
        an entry point its header promises.
        """
        repo = self._synthetic_repo(
            tmp_path,
            "AMA_API int ama_always(void);\nAMA_API int ama_phantom(void);\n",
            {"always.c": "\nint ama_always(void) { return 0; }\n"},
            local="ama_never_declared",
        )
        completed, output = self._invoke(tmp_path, repo, ["src/c/always.c"])
        assert completed.returncode != 0
        assert "ama_phantom" in completed.stderr
        assert not output.exists()

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_no_source_list_fails_the_configure(self, tmp_path: Path) -> None:
        """Without the configuration's sources the list cannot be right; say so."""
        completed, output = self._invoke(tmp_path, REPO_ROOT, None)
        assert completed.returncode != 0
        assert "AMA_DEF_SOURCES" in completed.stderr
        assert not output.exists()

    def test_cmake_passes_the_shared_targets_own_sources(self) -> None:
        """The list the generator reads is the DLL's, not a restatement of it."""
        cmakelists = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "get_target_property(_ama_def_sources ama_cryptography_shared SOURCES)" in (
            cmakelists
        )
        assert '"-DAMA_DEF_SOURCES=${_ama_def_sources}"' in cmakelists

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_a_clone_cannot_appear_in_the_generated_list(self, tmp_path: Path) -> None:
        """The property that closes the class, rather than one clone's name."""
        module = _load(PUBLIC_API)
        for name in self._generate(tmp_path, REPO_ROOT):
            assert module._PLAIN_SYMBOL.fullmatch(name), name

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_an_empty_local_block_fails_the_configure(self, tmp_path: Path) -> None:
        """Non-vacuity: a map that stops parsing must not publish the internals.

        This is the failure the macOS list had — an export control that silently
        covers nothing reads exactly like one that works.
        """
        repo = self._synthetic_repo(
            tmp_path,
            "AMA_API int ama_thing(void);\n",
            {"x.c": "\nint ama_thing(void) { return 0; }\n"},
            local="ama_placeholder",
        )
        (repo / "cmake" / "ama_exports.map").write_text("{ global: ama_*; };\n", encoding="utf-8")
        completed, output = self._invoke(tmp_path, repo, ["src/c/x.c"])
        assert completed.returncode != 0
        assert "local:" in completed.stderr
        assert not output.exists()

    @pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is not on PATH")
    def test_no_declarations_fails_the_configure(self, tmp_path: Path) -> None:
        """An empty EXPORTS section links a DLL that exports nothing."""
        repo = self._synthetic_repo(
            tmp_path,
            "int plain_function(void);\n",
            {"x.c": "\nint plain_function(void) { return 0; }\n"},
            local="ama_secret",
        )
        completed, output = self._invoke(tmp_path, repo, ["src/c/x.c"])
        assert completed.returncode != 0
        assert "AMA_API" in completed.stderr
        assert not output.exists()

    def test_the_def_is_the_sole_authority_on_mingw(self) -> None:
        """A .def beside dllexport would be decoration.

        Measured: GNU ld exports the union, so a .def naming one of two
        dllexport'd functions still exports both. The build therefore has to
        remove the attribute as well, and the header has to honour that define.
        """
        cmakelists = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "AMA_EXPORTS_FROM_DEF" in cmakelists
        assert "WIN32 AND NOT MSVC" in cmakelists
        header = (REPO_ROOT / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
        assert "defined(AMA_BUILDING_SHARED) && defined(AMA_EXPORTS_FROM_DEF)" in header
        # MSVC keeps dllexport: it emits no such clones, and link.exe takes no
        # -Wl flag. Losing that branch would unexport the whole Windows ABI.
        assert "#elif defined(AMA_BUILDING_SHARED)" in header
        assert "__declspec(dllexport)" in header


class TestTheGateInvocationPatternCannotBacktrack:
    """CodeQL py/redos, security-severity 7.5, on this file's own regex.

    ``^(\\S+=\\S+ )*python3? tools/...`` splits each ``VAR=value`` token at any
    of its ``=`` characters, because ``=`` is itself a ``\\S``. A line of
    ``!==!`` tokens that does not end in a gate invocation is therefore retried
    in exponentially many ways before the match fails. A scan over every
    workflow file is exactly where a pathological line can arrive.
    """

    def test_a_pathological_line_does_not_blow_up(self) -> None:
        # The line must NOT end in a gate invocation. A line that matches
        # settles on the first split and never backtracks — the first version
        # of this test appended a real `python3 tools/...` and so passed
        # against the vulnerable pattern, which the mutation run caught.
        line = "!==! " * 26 + "no-gate-here"
        start = time.perf_counter()
        _GATE_INVOCATION.match(line)
        elapsed = time.perf_counter() - start
        # Measured: the ambiguous form took 0.73s at 22 repetitions and roughly
        # quadruples with each further one; this form is ~0.0003s at any length.
        # The budget is four orders of magnitude above the fixed cost, so a
        # loaded runner cannot reach it but the defect cannot hide under it.
        assert elapsed < 1.0, f"{elapsed:.3f}s — the pattern is backtracking again"

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("python tools/check_headers.py", True),
            ("python3 tools/check_doc_examples.py --library-dir build/lib", True),
            ("CC=gcc python tools/check_doc_examples.py --lang c", True),
            ("A=1 B=2 python3 tools/check_public_api_docs.py", True),
            ("PYTHONPATH=a=b python tools/check_headers.py", True),
            ("pytest tests/ -q", False),
            ("python tools/refresh_derived_docs.py", False),
        ],
    )
    def test_it_still_recognises_exactly_what_it_did(self, line: str, expected: bool) -> None:
        """A faster pattern that matches a different set is not the same check."""
        assert bool(_GATE_INVOCATION.match(line)) is expected


class TestTheWorkflowInvokesTheseGatesCorrectly:
    """Every `python tools/check_*.py ...` line in ci.yml must be a valid call.

    This exists because of a defect it would have caught in seconds. The
    workflow ran::

        python tools/check_public_api_docs.py --library-dir build/lib --require-library

    and the gate takes ``--library``, not ``--library-dir``. argparse exited 2,
    the Security Checks job went red, and the whole CI Gate with it — on a gate
    whose own tests were green, because the tests invoked the script with no
    arguments and nothing ever executed the string the workflow actually uses.

    Parsing the argv is enough and is deliberately all this does: it answers
    "would this line start?" without running four gates per assertion. A wrong
    FLAG is the failure mode that shipped; a wrong VALUE fails in the job where
    the gate runs for real.
    """

    @staticmethod
    def _gate_invocations() -> list[list[str]]:
        """Every gate command line in the workflows, as argv."""
        import shlex

        found: list[list[str]] = []
        for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            # Join backslash continuations FIRST. An earlier revision skipped
            # them, which left the one multi-line invocation in the tree — the
            # c-consumer step, the only place the C lane runs against an
            # installed prefix — unchecked by the very test written to stop an
            # invalid invocation shipping.
            joined: list[str] = []
            buffer = ""
            for raw in workflow.read_text(encoding="utf-8").splitlines():
                stripped = raw.strip()
                if buffer:
                    buffer += " " + stripped.rstrip("\\").strip()
                elif stripped.endswith("\\"):
                    buffer = stripped.rstrip("\\").strip()
                else:
                    joined.append(stripped)
                    continue
                if not stripped.endswith("\\"):
                    joined.append(buffer)
                    buffer = ""
            if buffer:
                joined.append(buffer)

            for line in joined:
                line = line.lstrip("-").strip()
                if not _GATE_INVOCATION.match(line):
                    continue
                try:
                    argv = shlex.split(line)
                except ValueError:
                    continue  # unbalanced quoting from a YAML fragment
                while argv and "=" in argv[0] and not argv[0].startswith("-"):
                    argv = argv[1:]  # strip leading VAR=value assignments
                # Shell variables ($PREFIX, "$cc") cannot be resolved here, but
                # they must be SUBSTITUTED rather than dropped: removing
                # `"$cc"` from `--compiler "$cc" --include-dir ...` leaves
                # `--compiler --include-dir`, and argparse then reports
                # "expected one argument" for a command line that is perfectly
                # well formed in the job. The placeholder keeps argv's arity,
                # which is what makes the flag check meaningful.
                argv = ["placeholder" if "$" in part else part for part in argv[1:]]
                found.append(argv)
        return found

    def test_the_c_example_lane_is_wired_into_ci(self) -> None:
        """The C lane is Linux-only here; it must therefore actually run there.

        ``tests/conftest.py`` escalates a backend-related skip into a failure on
        the principle that a skip must not stand in for coverage the lane was
        configured to have. The C example tests above skip on Windows, where no
        ``-lama_cryptography`` link path exists — so this asserts the coverage
        lives somewhere rather than nowhere: a workflow step must compile, link
        and run the documented C examples on a Linux runner. Delete that step
        and this fails, which is the hole the escalation rule exists to close.
        """
        wired: list[str] = []
        for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for raw in text.splitlines():
                line = raw.strip()
                if "check_doc_examples.py" not in line:
                    continue
                # Either the all-languages default, or an explicit C lane.
                if "--lang" not in line or "--lang c" in line or '--lang", "c' in line:
                    wired.append(f"{workflow.name}: {line}")
        assert wired, (
            "no workflow compiles and runs the documented C examples. The C "
            "lane skips on Windows, so if no Linux lane runs it the coverage "
            "is gone entirely."
        )

    def test_the_workflows_invoke_at_least_the_four_new_gates(self) -> None:
        """Non-vacuity: an empty scan would make the assertion below pass."""
        scripts = {argv[0] for argv in self._gate_invocations() if argv}
        for gate in (
            "tools/check_doc_examples.py",
            "tools/check_crypto_construction_docs.py",
            "tools/check_public_api_docs.py",
            "tools/check_benchmark_claims.py",
        ):
            assert gate in scripts, f"{gate} is not invoked by any workflow"

    def test_every_gate_invocation_uses_flags_its_parser_declares(self) -> None:
        """Every ``--flag`` in a workflow line must exist on that gate's parser.

        Scoped to flag RECOGNITION on purpose. That is exactly the defect that
        shipped — ``--library-dir`` against a parser declaring ``--library`` —
        and it is the part a static scan can prove. A flag's VALUE often comes
        from a matrix variable or a shell expansion (``--target
        ${{ matrix.slot }}``), which no scan can resolve and which the job that
        runs the gate checks for real.
        """
        checked = 0
        for argv in self._gate_invocations():
            if not argv:
                continue
            script = REPO_ROOT / argv[0]
            if not script.is_file():
                continue
            if "argparse" not in script.read_text(encoding="utf-8"):
                continue  # no parser to hold it to; the job itself is the check
            module = _load(script)
            if not hasattr(module, "main"):
                continue
            rejection = _flag_rejection(module, argv[1:])
            assert rejection is None, (
                f"the workflow line `python {' '.join(argv)}` passes a flag "
                f"{argv[0]} does not declare:\n  {rejection}"
            )
            checked += 1

        assert checked >= 4, f"only {checked} invocation(s) were checked; the scan is broken"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
