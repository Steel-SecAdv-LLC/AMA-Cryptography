# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The AVX2/AVX-512 scoping gate must fail on the global-``-mavx2`` regression.

``tools/check_avx_scoping.py`` disassembles the built object and fails if any
YMM/ZMM operand appears in a symbol that is not an AVX2/AVX-512 kernel.  The
defect it exists for (audit M3): a library-wide ``-mavx2`` auto-vectorises the
whole object with 256-bit YMM code, so a build runs AVX2 on paths the dispatcher
never gated on a CPUID check.  Reintroducing it builds clean and passes the
functional suite, so only a gate over the emitted object catches it.

Both directions are pinned: kernel code carrying YMM/ZMM passes, and non-kernel
code carrying it fails; the non-vacuity floors and required-symbol checks fail
closed on an object the gate could not really read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import tools.check_avx_scoping as gate
from tools.check_avx_scoping import inventory, is_kernel_symbol


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
    assert is_kernel_symbol(name)


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
    assert not is_kernel_symbol(name)


# --------------------------------------------------------------------------
# The inventory
# --------------------------------------------------------------------------


def test_vector_operands_are_attributed_to_their_enclosing_symbol() -> None:
    text = _disassembly(
        ("plain_function", ["mov %rax,%rbx", "add %rcx,%rdx", "ret"]),
        ("ama_kyber_ntt_avx2", ["vpxor %ymm0,%ymm1,%ymm2", "vpaddw %ymm3,%ymm4,%ymm5", "ret"]),
    )
    vector_ops, symbols, instructions = inventory(text)
    assert vector_ops == {"ama_kyber_ntt_avx2": 2}
    assert symbols == {"plain_function", "ama_kyber_ntt_avx2"}
    assert instructions == 6


def test_zmm_operands_are_counted() -> None:
    text = _disassembly(("ama_keccak_f1600_x4_avx512", ["vmovdqa64 %zmm0,%zmm1", "ret"]))
    vector_ops, _symbols, _instructions = inventory(text)
    assert vector_ops == {"ama_keccak_f1600_x4_avx512": 1}


def test_intel_syntax_bare_registers_are_counted() -> None:
    """llvm-objdump / an Intel-syntax rendering writes ``ymm3`` without ``%``."""
    text = _disassembly(("k_avx2", ["vpxor ymm0, ymm1, ymm2", "ret"]))
    vector_ops, _symbols, _instructions = inventory(text)
    assert vector_ops == {"k_avx2": 1}


def test_xmm_is_not_counted() -> None:
    """128-bit SSE/AES-NI is baseline x86-64, enabled everywhere; per-file
    -mavx2 does not scope it, so XMM operands must not register as a leak."""
    text = _disassembly(("ama_aes_sbox_consttime", ["pxor %xmm0,%xmm1", "aesenc %xmm2,%xmm3"]))
    vector_ops, _symbols, _instructions = inventory(text)
    assert vector_ops == {}


# --------------------------------------------------------------------------
# main(): the leak verdict and the non-vacuity floors
# --------------------------------------------------------------------------


def _clean_object() -> str:
    """A synthetic object that clears the floors: the three required kernels
    carry YMM, plenty of filler symbols carry none."""
    blocks: list[tuple[str, list[str]]] = [
        (sym, ["vpxor %ymm0,%ymm1,%ymm2"] * 3 + ["ret"]) for sym in gate.REQUIRED_VECTOR_SYMBOLS
    ]
    # Filler: >= MIN_SYMBOLS symbols and >= MIN_INSTRUCTIONS instructions, none
    # carrying a vector operand.
    per = (gate.MIN_INSTRUCTIONS // gate.MIN_SYMBOLS) + 2
    for i in range(gate.MIN_SYMBOLS + 10):
        blocks.append((f"plain_{i}", ["mov %rax,%rbx"] * per))
    return _disassembly(*blocks)


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
