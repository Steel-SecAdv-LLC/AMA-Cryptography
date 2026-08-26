# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The ISA scoping gate must fail on the global-per-file-flag regression.

``tools/check_avx_scoping.py`` disassembles the built object and fails if any
YMM/ZMM operand appears in a symbol that is not an AVX2/AVX-512 kernel.  The
defect it exists for (audit M3): a library-wide ``-mavx2`` auto-vectorises the
whole object with 256-bit YMM code, so a build runs AVX2 on paths the dispatcher
never gated on a CPUID check.  Reintroducing it builds clean and passes the
functional suite, so only a gate over the emitted object catches it.

Both directions are pinned: kernel code carrying YMM/ZMM passes, and non-kernel
code carrying it fails; the non-vacuity floors and required-symbol checks fail
closed on an object the gate could not really read.

AVX2 was not the only per-file ISA flag, and the gate now covers all of them.
``CMakeLists.txt`` scopes seven families this way — AVX/AVX2/AVX-512, AES-NI,
PCLMULQDQ, SHA-NI, BMI1/BMI2/ADX, SSSE3 and SSE4.1 — and each raises the same
hazard: make the flag global and the compiler may emit that ISA in the portable
fallback the dispatcher selects *because* the CPU lacks the feature, which is a
#UD on a host the wheel claims to support.  Measured: a build with
``-maes -mpclmul -msha -mssse3 -msse4.1 -mbmi -mbmi2 -madx`` applied globally
puts those instructions in **172** non-kernel symbols, and the AVX-only gate
exited **0** on it — a clean report over the exact regression it exists to
catch, because none of the leaks were YMM.  The parametrised tests below run
that experiment one family at a time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# One import form only.  Binding the module under an alias AND pulling names
# out of it with ``from`` imports the same module twice by two different
# mechanisms, which is what CodeQL's py/import-and-import-from reports
# (alert 647).  The rest of this file already reaches the gate's constants
# and ``main`` through ``gate.``; ``inventory`` and ``is_kernel_symbol`` now
# do the same, matching the pattern tests/test_benchmark_baseline_infra.py
# and tests/test_timing_detector_calibration.py already use.
import tools.check_avx_scoping as gate


def _disassembly(*blocks: tuple[str, list[str]]) -> str:
    """Synthesise objdump output: ``(symbol, [instruction-body strings])``."""
    lines = ["", "Disassembly of section .text:", ""]
    for offset, (symbol, bodies) in enumerate(blocks):
        lines.append(f"{offset + 1:016x} <{symbol}>:")
        for i, body in enumerate(bodies):
            lines.append(f"  {offset + 1:x}{i:03x}:\t{body}")
        lines.append("")
    return "\n".join(lines)


def test_the_gate_file_names_the_defect_class() -> None:
    body = (Path(__file__).resolve().parent.parent / "tools" / "check_avx_scoping.py").read_text(
        encoding="utf-8"
    )
    assert "avx2" in body.lower() and "M3" in body


# --------------------------------------------------------------------------
# Symbol classification
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "ama_kyber_ntt_avx2",
        "ama_dilithium_invntt_avx2",
        "ama_keccak_f1600_x4_avx512",
        "ama_sphincs_wots_chain_avx2.part.0",  # gcc partial-inline split
        "ama_kyber_ntt_avx2.constprop.0",  # gcc const-propagation clone
        "fe_mul_x4",  # allowlisted helper
        "fe25519_10_contract",  # allowlisted helper
    ],
)
def test_kernel_symbols_are_allowed_to_carry_vectors(name: str) -> None:
    assert gate.is_kernel_symbol(name)


@pytest.mark.parametrize(
    "name",
    [
        "ama_aes_sbox_consttime",
        "ama_argon2id_core",
        "kyber_decapsulate_internal",
        "ama_ed25519_keypair",
        "some_avx2_helper",  # marker not terminal / not before a .fragment
        "memcpy",
    ],
)
def test_non_kernel_symbols_are_not(name: str) -> None:
    assert not gate.is_kernel_symbol(name)


# --------------------------------------------------------------------------
# The inventory
# --------------------------------------------------------------------------


def test_vector_operands_are_attributed_to_their_enclosing_symbol() -> None:
    text = _disassembly(
        ("plain_function", ["mov %rax,%rbx", "add %rcx,%rdx", "ret"]),
        ("ama_kyber_ntt_avx2", ["vpxor %ymm0,%ymm1,%ymm2", "vpaddw %ymm3,%ymm4,%ymm5", "ret"]),
    )
    vector_ops, symbols, instructions = gate.inventory(text)
    assert vector_ops == {"ama_kyber_ntt_avx2": 2}
    assert symbols == {"plain_function", "ama_kyber_ntt_avx2"}
    assert instructions == 6


def test_zmm_operands_are_counted() -> None:
    text = _disassembly(("ama_keccak_f1600_x4_avx512", ["vmovdqa64 %zmm0,%zmm1", "ret"]))
    vector_ops, _symbols, _instructions = gate.inventory(text)
    assert vector_ops == {"ama_keccak_f1600_x4_avx512": 1}


def test_intel_syntax_bare_registers_are_counted() -> None:
    """llvm-objdump / an Intel-syntax rendering writes ``ymm3`` without ``%``."""
    text = _disassembly(("k_avx2", ["vpxor ymm0, ymm1, ymm2", "ret"]))
    vector_ops, _symbols, _instructions = gate.inventory(text)
    assert vector_ops == {"k_avx2": 1}


def test_xmm_is_not_counted() -> None:
    """128-bit SSE/AES-NI is baseline x86-64, enabled everywhere; per-file
    -mavx2 does not scope it, so XMM operands must not register as a leak."""
    text = _disassembly(("ama_aes_sbox_consttime", ["pxor %xmm0,%xmm1", "aesenc %xmm2,%xmm3"]))
    vector_ops, _symbols, _instructions = gate.inventory(text)
    assert vector_ops == {}


# --------------------------------------------------------------------------
# main(): the leak verdict and the non-vacuity floors
# --------------------------------------------------------------------------


#: One instruction per ISA family that its pattern must match, keyed by family
#: name.  Used both to build a synthetic object every family accepts and to
#: plant a per-family leak.  Kept beside the family table rather than inside it
#: so the gate itself carries no test fixture.
FAMILY_SAMPLE_INSN = {
    "AVX/AVX2/AVX-512 (YMM/ZMM)": "vpxor %ymm0,%ymm1,%ymm2",
    "AES-NI": "aesenc %xmm1,%xmm0",
    "PCLMULQDQ": "pclmullqlqdq %xmm1,%xmm0",
    "SHA-NI (Intel SHA Extensions)": "sha256rnds2 %xmm0,%xmm1,%xmm2",
    "BMI1/BMI2/ADX": "mulx %rdx,%rax,%rbx",
    "SSSE3": "pshufb %xmm1,%xmm0",
    "SSE4.1": "pmulld %xmm1,%xmm0",
}


def test_every_family_has_a_sample_instruction() -> None:
    """The fixtures below are only meaningful if they cover the real table."""
    assert {f.name for f in gate.ISA_FAMILIES} == set(FAMILY_SAMPLE_INSN)


def _clean_object() -> str:
    """A synthetic object that clears the floors and satisfies every family.

    Each family's required kernels carry an instruction of that family, and
    plenty of filler symbols carry none.  The AVX-only version of this helper
    stopped being a "clean object" the moment the gate grew past one ISA: it
    described a build with no AES-NI, SHA-NI or BMI kernel at all, which the
    gate must (and now does) reject rather than pass.
    """
    blocks: list[tuple[str, list[str]]] = []
    # A symbol may be the required kernel of more than one family
    # (ama_aes256_gcm_encrypt_avx2 for AES-NI and PCLMULQDQ,
    # ama_sha256_compress_x86_shani for SHA-NI and SSSE3), so accumulate the
    # instructions per symbol rather than emitting a block per family.
    per_symbol: dict[str, list[str]] = {}
    for family in gate.ISA_FAMILIES:
        for sym in family.required:
            per_symbol.setdefault(sym, []).extend([FAMILY_SAMPLE_INSN[family.name]] * 3)
    for sym, bodies in per_symbol.items():
        blocks.append((sym, [*bodies, "ret"]))
    # Filler: >= MIN_SYMBOLS symbols and >= MIN_INSTRUCTIONS instructions, none
    # carrying an instruction from any family.
    per = (gate.MIN_INSTRUCTIONS // gate.MIN_SYMBOLS) + 2
    for i in range(gate.MIN_SYMBOLS + 10):
        blocks.append((f"plain_{i}", ["mov %rax,%rbx"] * per))
    return _disassembly(*blocks)


# --------------------------------------------------------------------------
# Every ISA family the build scopes per file, not only AVX
# --------------------------------------------------------------------------


@pytest.mark.parametrize("family", gate.ISA_FAMILIES, ids=lambda f: f.name)
def test_each_family_pattern_matches_its_own_instruction(family: gate.IsaFamily) -> None:
    assert family.pattern.search(FAMILY_SAMPLE_INSN[family.name])


@pytest.mark.parametrize("family", gate.ISA_FAMILIES, ids=lambda f: f.name)
def test_each_family_owns_its_required_kernels(family: gate.IsaFamily) -> None:
    """A required symbol the family does not own would fail the gate on every
    correct build — the non-vacuity check and the leak check would disagree."""
    for sym in family.required:
        assert family.owns(sym), sym


@pytest.mark.parametrize("family", gate.ISA_FAMILIES, ids=lambda f: f.name)
def test_a_leak_in_any_family_fails_the_gate(
    family: gate.IsaFamily, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The global-flag regression, one family at a time.

    Before the gate covered more than AVX, an object carrying BMI2, SSSE3 or
    SSE4.1 in 172 non-kernel symbols — the real output of a build with those
    flags applied globally — exited 0.
    """
    lib = tmp_path / "libama_cryptography.so"
    lib.write_bytes(b"\x7fELF")
    insn = FAMILY_SAMPLE_INSN[family.name]

    def _leaky(_lib: object) -> str:
        return _clean_object().replace(
            f"{gate.MIN_SYMBOLS + 9:x}000:\tmov %rax,%rbx",
            f"{gate.MIN_SYMBOLS + 9:x}000:\t{insn}",
        )

    monkeypatch.setattr(gate, "disassemble", _leaky)
    assert gate.main(["--lib", str(lib)]) == 1


@pytest.mark.parametrize("family", gate.ISA_FAMILIES, ids=lambda f: f.name)
def test_a_missing_required_kernel_fails_the_gate(
    family: gate.IsaFamily, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Non-vacuity, per family: an object without a family's kernel must not
    report that family clean — there was nothing to find."""
    required = family.required
    if not required:
        pytest.skip(f"{family.name} declares no required kernel by design")
    lib = tmp_path / "libama_cryptography.so"
    lib.write_bytes(b"\x7fELF")

    def _without(_lib: object) -> str:
        text = _clean_object()
        for sym in required:
            text = text.replace(f"<{sym}>:", "<dropped_kernel>:")
        return text

    monkeypatch.setattr(gate, "disassemble", _without)
    assert gate.main(["--lib", str(lib)]) == 1


def test_call_sites_of_a_kernel_are_not_read_as_occurrences() -> None:
    """objdump renders a call as ``call <ama_aes256_gcm_encrypt_avx2>``.

    Matching the family pattern against the whole line rather than the
    mnemonic column would turn every CALLER of a kernel into a leak — and the
    callers are, by construction, exactly the non-kernel symbols.
    """
    text = _disassembly(
        (
            "ama_aes256_gcm_encrypt",
            [
                "e8 00 00 00 00       \tcall   1030 <ama_aes256_gcm_encrypt_avx2>",
                "e8 00 00 00 00       \tcall   1040 <ama_sha256_compress_x86_shani>",
                "ret",
            ],
        )
    )
    per_family, _symbols, _instructions = gate.scan_families(text)
    for family in gate.ISA_FAMILIES:
        assert per_family[family.name] == {}, family.name


def test_main_passes_a_scoped_object(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lib = tmp_path / "libama_cryptography.so"
    lib.write_bytes(b"\x7fELF")  # only is_file() is consulted; disassemble is stubbed
    monkeypatch.setattr(gate, "disassemble", lambda _lib: _clean_object())
    assert gate.main(["--lib", str(lib)]) == 0


def test_main_fails_when_a_non_kernel_symbol_carries_a_vector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lib = tmp_path / "libama_cryptography.so"
    lib.write_bytes(b"\x7fELF")

    def _leaky(_lib: object) -> str:
        # The global-`-mavx2` regression: a non-kernel symbol auto-vectorised.
        return _clean_object().replace(
            f"{gate.MIN_SYMBOLS + 9:x}000:\tmov %rax,%rbx",
            f"{gate.MIN_SYMBOLS + 9:x}000:\tvpxor %ymm7,%ymm8,%ymm9",
        )

    monkeypatch.setattr(gate, "disassemble", _leaky)
    assert gate.main(["--lib", str(lib)]) == 1


def test_main_fails_when_a_required_kernel_is_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lib = tmp_path / "libama_cryptography.so"
    lib.write_bytes(b"\x7fELF")

    def _no_kyber(_lib: object) -> str:
        # AVX2 disabled / kernels dropped: "no leaks" must not read as a pass.
        blocks: list[tuple[str, list[str]]] = []
        per = (gate.MIN_INSTRUCTIONS // gate.MIN_SYMBOLS) + 2
        for i in range(gate.MIN_SYMBOLS + 10):
            blocks.append((f"plain_{i}", ["mov %rax,%rbx"] * per))
        return _disassembly(*blocks)

    monkeypatch.setattr(gate, "disassemble", _no_kyber)
    assert gate.main(["--lib", str(lib)]) == 1


def test_main_fails_closed_below_the_floor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lib = tmp_path / "libama_cryptography.so"
    lib.write_bytes(b"\x7fELF")
    monkeypatch.setattr(
        gate, "disassemble", lambda _lib: _disassembly(("only_one", ["vpxor %ymm0,%ymm1,%ymm2"]))
    )
    assert gate.main(["--lib", str(lib)]) == 2


def test_main_fails_closed_on_a_missing_object(tmp_path: Path) -> None:
    assert gate.main(["--lib", str(tmp_path / "does-not-exist.so")]) == 2
