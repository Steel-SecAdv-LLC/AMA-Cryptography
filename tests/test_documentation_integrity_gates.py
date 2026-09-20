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
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator, Optional, cast
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
            "| HIGH | 0.45 – 0.80 | Rotate keys |\n\n"
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


class TestPublicApiDocs:
    def test_the_real_package_matches_its_documentation(self) -> None:
        completed = _run(PUBLIC_API)
        assert completed.returncode == 0, completed.stderr

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

    def test_a_documented_floor_that_exists_passes(self, tmp_path: Path) -> None:
        """Non-vacuity: the corrected number must not fail."""
        scratch = _scratch_repo(tmp_path)
        (scratch / "CURRENT.md").write_text(
            "The enforced floor is 215,299 ops/sec on x86-64.\n", encoding="utf-8", newline=""
        )
        completed = _run(BENCHMARK_CLAIMS, "--repo", str(scratch))
        assert completed.returncode == 0, completed.stderr

    def test_the_ed25519_sign_floor_tracks_invariant_51(self) -> None:
        """The floor must be the post-INVARIANT-51 value, not the old one.

        70,496 was measured before ``ama_ed25519_sign`` began deriving its own
        public half; the check adds a second fixed-base scalar multiplication,
        so the old floor no longer describes the code.
        """
        x86 = json.loads((REPO_ROOT / "benchmarks" / "baseline.json").read_text(encoding="utf-8"))
        assert x86["benchmarks"]["ed25519_sign"]["baseline_value"] == 38170


# ===========================================================================
# The CI invocations themselves
# ===========================================================================


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
                if not re.match(r"^(\S+=\S+ )*python3? tools/check_[a-z_]+\.py", line):
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
