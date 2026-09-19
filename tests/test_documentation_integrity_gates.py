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

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterator, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"

DOC_EXAMPLES = TOOLS / "check_doc_examples.py"
CONSTRUCTION_DOCS = TOOLS / "check_crypto_construction_docs.py"
PUBLIC_API = TOOLS / "check_public_api_docs.py"
BENCHMARK_CLAIMS = TOOLS / "check_benchmark_claims.py"

#: The C gates need a built shared library; a source-only checkout skips them
#: rather than passing vacuously.
_BUILT_LIBRARY = next(
    (
        candidate
        for directory in (REPO_ROOT / "build" / "lib", REPO_ROOT / "ama_cryptography")
        for candidate in sorted(directory.glob("libama_cryptography.so*"))
    ),
    None,
)

requires_native = pytest.mark.skipif(
    _BUILT_LIBRARY is None,
    reason="no built libama_cryptography.so; build with cmake -B build -DAMA_USE_NATIVE_PQC=ON",
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


@pytest.fixture()
def doc_fixture(tmp_path: Path) -> Iterator[Path]:
    """A scratch Markdown file the example gate can be pointed at."""
    scratch = REPO_ROOT / "wiki" / "_gate_fixture_tmp.md"
    try:
        yield scratch
    finally:
        scratch.unlink(missing_ok=True)


# ===========================================================================
# tools/check_doc_examples.py
# ===========================================================================


class TestDocExamples:
    def test_the_real_documentation_passes(self) -> None:
        """Positive control: the shipped pages' examples all run or match."""
        completed = _run(DOC_EXAMPLES)
        assert completed.returncode == 0, completed.stderr

    def test_an_unmarked_block_fails(self, doc_fixture: Path) -> None:
        """Coverage is mandatory: a block with no directive is a failure.

        This is what stops the gate decaying — a new example cannot be added
        without declaring what it claims.
        """
        doc_fixture.write_text("# fixture\n\n```python\nprint('hello')\n```\n", encoding="utf-8")
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}")
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
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}")
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
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}")
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
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}")
        assert completed.returncode == 1
        assert "MASTER_OMNI_CODES" in completed.stderr

    def test_pseudocode_needs_a_reason(self, doc_fixture: Path) -> None:
        """The escape hatch has to cost something, or everything uses it."""
        doc_fixture.write_text(
            "<!-- example: pseudocode: nope -->\n```python\nnot python at all\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}")
        assert completed.returncode == 1
        assert "reason" in completed.stderr

    def test_pseudocode_with_a_reason_is_skipped(self, doc_fixture: Path) -> None:
        doc_fixture.write_text(
            "<!-- example: pseudocode: needs a physically attached hardware token -->\n"
            "```python\nnot python at all\n```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}")
        assert completed.returncode == 0, completed.stderr
        assert "1 skipped" in completed.stdout

    @requires_native
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
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}", "--lang", "c")
        assert completed.returncode == 1, completed.stdout
        assert "uninitialised" in completed.stderr.lower()

    @requires_native
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
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}", "--lang", "c")
        assert completed.returncode == 0, completed.stderr

    @requires_native
    def test_a_localised_symbol_documented_as_linkable_fails(self, doc_fixture: Path) -> None:
        """``ama_randombytes`` is in the version script's ``local:`` list."""
        doc_fixture.write_text(
            "<!-- example: c-decl -->\n"
            "```c\n"
            "ama_error_t ama_randombytes(uint8_t *buf, size_t len);\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}", "--lang", "c")
        assert completed.returncode == 1
        assert "ama_randombytes" in completed.stderr

    @requires_native
    def test_a_wrong_documented_key_size_fails(self, doc_fixture: Path) -> None:
        """A drifted buffer size is a stack overflow in every derived program."""
        doc_fixture.write_text(
            "<!-- example: c-const -->\n"
            "```c\n"
            "#define AMA_ML_DSA_65_SECRET_KEY_BYTES 2048\n"
            "```\n",
            encoding="utf-8",
        )
        completed = _run(DOC_EXAMPLES, "--file", f"wiki/{doc_fixture.name}", "--lang", "c")
        assert completed.returncode == 1
        assert "4032" in completed.stderr


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
        fixture = REPO_ROOT / "docs" / "_gate_fixture_tmp.md"
        fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
        try:
            completed = _run(CONSTRUCTION_DOCS, "--file", "docs/_gate_fixture_tmp.md")
            assert completed.returncode == 1, completed.stdout
            assert expected_fragment.lower() in completed.stderr.lower()
        finally:
            fixture.unlink(missing_ok=True)

    def test_the_corrected_wording_passes(self) -> None:
        """Non-vacuity: the replacement text must NOT fail.

        A gate that rejects the correction as well as the defect is a gate
        nobody can satisfy, and it gets disabled.
        """
        fixture = REPO_ROOT / "docs" / "_gate_fixture_tmp.md"
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
        try:
            completed = _run(CONSTRUCTION_DOCS, "--file", "docs/_gate_fixture_tmp.md")
            assert completed.returncode == 0, completed.stderr
        finally:
            fixture.unlink(missing_ok=True)

    def test_the_waiver_is_explicit_and_scoped(self) -> None:
        """A correction note may quote what it retires — but only with the marker."""
        gate = _load(CONSTRUCTION_DOCS)
        fixture = REPO_ROOT / "docs" / "_gate_fixture_tmp.md"
        claim = "This used to say MASTER_OMNI_CODES, which never existed."
        try:
            fixture.write_text(f"# fixture\n\n{claim}\n", encoding="utf-8")
            assert _run(CONSTRUCTION_DOCS, "--file", "docs/_gate_fixture_tmp.md").returncode == 1

            fixture.write_text(f"# fixture\n\n{gate.WAIVER}\n{claim}\n", encoding="utf-8")
            assert _run(CONSTRUCTION_DOCS, "--file", "docs/_gate_fixture_tmp.md").returncode == 0
        finally:
            fixture.unlink(missing_ok=True)

    def test_source_comments_are_scanned_too(self, tmp_path: Path) -> None:
        """A stale comment in the package is a claim like any other.

        ``crypto_api.py`` carried "Import HMAC and HKDF from pqc_backends
        (native C) with pure-Python fallback" four lines above the module's own
        INVARIANT-7 guard.
        """
        fixture = REPO_ROOT / "tools" / "_gate_fixture_tmp.py"
        fixture.write_text(
            "# Import HMAC and HKDF from pqc_backends (native C) with " "pure-Python fallback\n",
            encoding="utf-8",
        )
        try:
            completed = _run(CONSTRUCTION_DOCS, "--file", "tools/_gate_fixture_tmp.py")
            assert completed.returncode == 1, completed.stdout
            assert "Python HKDF fallback" in completed.stderr
        finally:
            fixture.unlink(missing_ok=True)

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

    @requires_native
    def test_localised_symbols_are_absent_from_the_library(self) -> None:
        gate = _load(PUBLIC_API)
        assert _BUILT_LIBRARY is not None
        exported = gate.dynamic_symbols(_BUILT_LIBRARY)
        for name in gate.MUST_NOT_BE_EXPORTED:
            assert name not in exported, f"{name} is on the public ABI but is meant to be internal"

    @requires_native
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

    def test_a_hand_edited_generated_cell_fails(self) -> None:
        """The 4.20 ms defect, reintroduced into the generated block."""
        target = REPO_ROOT / "ARCHITECTURE.md"
        original = target.read_text(encoding="utf-8")
        assert "AUTO-PIPELINE-LATENCY-START" in original
        try:
            target.write_text(
                original.replace(
                    "| ML-DSA-65 Sign (dominant package-creation cost) | < 5 ms |",
                    "| ML-DSA-65 Sign (dominant package-creation cost) | < 5 ms | 4.200 |#",
                    1,
                ),
                encoding="utf-8",
            )
            completed = _run(BENCHMARK_CLAIMS)
            assert completed.returncode == 1
            assert "AUTO-PIPELINE-LATENCY" in completed.stderr
        finally:
            target.write_text(original, encoding="utf-8")

    def test_a_stale_documented_floor_fails(self) -> None:
        """The 76,215 defect: a floor cited in prose that enforces nothing."""
        target = REPO_ROOT / "wiki" / "_gate_fixture_tmp.md"
        target.write_text("The enforced floor is 76,215 ops/sec on x86-64.\n", encoding="utf-8")
        try:
            completed = _run(BENCHMARK_CLAIMS)
            assert completed.returncode == 1
            assert "76,215" in completed.stderr
        finally:
            target.unlink(missing_ok=True)

    def test_a_documented_floor_that_exists_passes(self) -> None:
        """Non-vacuity: the corrected number must not fail."""
        target = REPO_ROOT / "wiki" / "_gate_fixture_tmp.md"
        target.write_text("The enforced floor is 215,299 ops/sec on x86-64.\n", encoding="utf-8")
        try:
            assert _run(BENCHMARK_CLAIMS).returncode == 0
        finally:
            target.unlink(missing_ok=True)

    def test_the_ed25519_sign_floor_tracks_invariant_51(self) -> None:
        """The floor must be the post-INVARIANT-51 value, not the old one.

        70,496 was measured before ``ama_ed25519_sign`` began deriving its own
        public half; the check adds a second fixed-base scalar multiplication,
        so the old floor no longer describes the code.
        """
        x86 = json.loads((REPO_ROOT / "benchmarks" / "baseline.json").read_text(encoding="utf-8"))
        assert x86["benchmarks"]["ed25519_sign"]["baseline_value"] == 38170


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
