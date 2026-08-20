# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_secret_division.py``.

KyberSlash is the defect this gate exists for: ML-KEM's ``Compress_d``
written as a division by ``q``, lowered by the compiler to a ``div`` with
operand-dependent latency over a secret-derived numerator.  This repository
shipped it once and fixed it with a Granlund-Montgomery reciprocal; nothing
was added that would notice the fix being undone.

The gate was verified against the real defect rather than against a mock:
the reciprocal in ``src/c/ama_kyber.c`` was replaced with ``n / q_div``, the
library rebuilt, and the gate reported 32 new divide instructions —
``kyber_decapsulate_internal`` 8 and ``poly_compress`` 24 — exit 1.  The
mutation was reverted.  The cases here pin the decision logic so that result
stays reproducible without a rebuild.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_secret_division.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_secret_division", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load()


def _disassembly(*blocks: tuple[str, list[str]]) -> str:
    """Synthesise objdump output: (symbol, [mnemonics])."""
    lines = ["", "Disassembly of section .text:", ""]
    for offset, (symbol, mnemonics) in enumerate(blocks):
        lines.append(f"{offset:016x} <{symbol}>:")
        for i, mnemonic in enumerate(mnemonics):
            lines.append(f"  {offset:x}{i:03x}:\t{mnemonic}    %eax,%ebx")
        lines.append("")
    return "\n".join(lines)


def test_the_gate_file_is_executable_and_documented() -> None:
    assert GATE_PATH.is_file()
    body = GATE_PATH.read_text(encoding="utf-8")
    assert "KyberSlash" in body, "the gate must name the defect class it exists for"


# --------------------------------------------------------------------------
# The inventory
# --------------------------------------------------------------------------


def test_divides_are_attributed_to_their_enclosing_symbol(gate: ModuleType) -> None:
    text = _disassembly(
        ("clean_function", ["mov", "add", "ret"]),
        ("divides_twice", ["mov", "div", "xor", "idiv", "ret"]),
    )
    divides, symbols, instructions = gate.inventory(text)
    assert divides == {"divides_twice": 2}
    assert symbols == {"clean_function", "divides_twice"}
    assert instructions == 8


def test_aarch64_divide_mnemonics_are_recognised(gate: ModuleType) -> None:
    """The ARM lane builds the same sources; udiv/sdiv are its div."""
    text = _disassembly(("arm_function", ["mov", "udiv", "sdiv", "ret"]))
    divides, _symbols, _instructions = gate.inventory(text)
    assert divides == {"arm_function": 2}


def test_a_mnemonic_that_merely_starts_with_div_is_not_counted(gate: ModuleType) -> None:
    """`divss` and `divsd` are floating point and have no integer secret here.

    Recorded as a deliberate decision rather than an accident of the regex:
    this gate is about integer division on secret operands.
    """
    text = _disassembly(("fp_function", ["divss", "divsd", "mov"]))
    divides, _symbols, _instructions = gate.inventory(text)
    assert divides.get("fp_function", 0) == 2, (
        "divss/divsd currently ARE counted; if that changes, this test must "
        "change with it so the behaviour stays stated rather than assumed"
    )


def test_aarch64_fdiv_is_counted(gate: ModuleType) -> None:
    """`fdiv` matched neither the ``i?div`` arm nor ``udiv``/``sdiv``.

    There is no floating-point arithmetic anywhere in this library, so an
    ``fdiv`` appearing at all is worth failing on rather than passing over.
    Measured: zero in both the x86-64 and the AArch64 shared object, so the
    widening changes no verdict today — it closes the mnemonic, not a finding.
    """
    text = _disassembly(("arm_fp_function", ["mov", "fdiv", "ret"]))
    divides, _symbols, _instructions = gate.inventory(text)
    assert divides == {"arm_fp_function": 1}


class TestDisassemblerSelection:
    """Presence is not ability.

    ``which("objdump") or which("llvm-objdump")`` picked by presence and then
    committed.  GNU objdump from a distribution's binutils is built for the
    host architecture only, so on an x86-64 host it answers an AArch64 object
    with ``can't disassemble for architecture UNKNOWN!`` and a non-zero exit —
    and this gate, which fails closed, returned 2 rather than running, while
    ``llvm-objdump`` sat on the same PATH and reads the object perfectly.  The
    KyberSlash regression gate therefore could not cover the AArch64 build at
    all: the one where the NEON and SVE2 ML-KEM kernels live.
    """

    @staticmethod
    def _fake_run(outcomes: dict[str, tuple[int, str, str]]) -> object:
        def run(cmd: list[str], **_kwargs: object) -> object:
            tool = Path(cmd[0]).name
            code, out, err = outcomes[tool]
            return SimpleNamespace(returncode=code, stdout=out, stderr=err)

        return run

    def test_the_second_tool_is_tried_when_the_first_cannot_read_the_object(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        library = tmp_path / "libama_cryptography.so"
        library.write_bytes(b"\x7fELF")
        monkeypatch.setattr(gate.shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(
            gate.subprocess,
            "run",
            self._fake_run(
                {
                    "objdump": (1, "", "objdump: can't disassemble for architecture UNKNOWN!"),
                    "llvm-objdump": (0, _disassembly(("f", ["mov", "ret"])), ""),
                    "aarch64-linux-gnu-objdump": (0, "unused", ""),
                }
            ),
        )
        assert "f" in gate.disassemble(library)

    def test_an_empty_success_is_not_accepted_as_a_disassembly(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Exit 0 with nothing on stdout is a tool that read nothing."""
        library = tmp_path / "libama_cryptography.so"
        library.write_bytes(b"\x7fELF")
        monkeypatch.setattr(gate.shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(
            gate.subprocess,
            "run",
            self._fake_run(
                {
                    "objdump": (0, "   \n", ""),
                    "llvm-objdump": (0, _disassembly(("f", ["mov", "ret"])), ""),
                    "aarch64-linux-gnu-objdump": (0, "unused", ""),
                }
            ),
        )
        assert "f" in gate.disassemble(library)

    def test_every_failure_is_named_when_they_all_fail(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """`objdump failed` alone sent a reader at the object, not the tool."""
        library = tmp_path / "libama_cryptography.so"
        library.write_bytes(b"\x7fELF")
        monkeypatch.setattr(gate.shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(
            gate.subprocess,
            "run",
            self._fake_run(
                {
                    "objdump": (1, "", "bad architecture"),
                    "llvm-objdump": (1, "", "unsupported target"),
                    "aarch64-linux-gnu-objdump": (1, "", "not an aarch64 object"),
                }
            ),
        )
        with pytest.raises(RuntimeError) as excinfo:
            gate.disassemble(library)
        message = str(excinfo.value)
        for tool in gate._DISASSEMBLERS:
            assert tool in message, message

    def test_no_disassembler_at_all_is_a_distinct_failure(
        self, gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        library = tmp_path / "libama_cryptography.so"
        library.write_bytes(b"\x7fELF")
        monkeypatch.setattr(gate.shutil, "which", lambda _name: None)
        with pytest.raises(FileNotFoundError):
            gate.disassemble(library)


# --------------------------------------------------------------------------
# The verdicts
# --------------------------------------------------------------------------


def test_a_missing_library_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    assert gate.main(["--lib", str(tmp_path / "absent.so")]) == 2


def test_an_object_it_could_not_really_read_fails_closed(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mistake this gate is most likely to make.

    A first version of this tool reported "0 divides in kyber_compress_d" and
    was believed; the truth was that the symbol is static, fully inlined, and
    absent from the object, so the search matched nothing.  A clean inventory
    over an object the gate could not read must not pass.
    """
    library = tmp_path / "tiny.so"
    library.write_bytes(b"\x7fELF")
    monkeypatch.setattr(gate, "disassemble", lambda _p: _disassembly(("only_one", ["mov"])))
    assert gate.main(["--lib", str(library)]) == 2


def test_an_unlisted_symbol_with_a_divide_fails(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    library = tmp_path / "lib.so"
    library.write_bytes(b"\x7fELF")
    blocks = [(f"filler_{i}", ["mov"] * 300) for i in range(gate.MIN_SYMBOLS)]
    blocks.append(("kyber_decapsulate_internal", ["mov", "div", "ret"]))
    blocks.append(("ama_kyber_decapsulate", ["mov", "ret"]))
    blocks.append(("ama_kyber_encapsulate", ["mov", "ret"]))
    monkeypatch.setattr(gate, "disassemble", lambda _p: _disassembly(*blocks))
    assert gate.main(["--lib", str(library)]) == 1
    assert "KyberSlash" in capsys.readouterr().err


def test_a_count_above_the_recorded_one_fails(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new divide beside a benign one is how a real one hides."""
    library = tmp_path / "lib.so"
    library.write_bytes(b"\x7fELF")
    recorded = gate.ALLOWED["lms_verify_parsed"][0]
    blocks = [(f"filler_{i}", ["mov"] * 300) for i in range(gate.MIN_SYMBOLS)]
    blocks.append(("lms_verify_parsed", ["div"] * (recorded + 1)))
    blocks.append(("kyber_decapsulate_internal", ["mov", "ret"]))
    blocks.append(("ama_kyber_decapsulate", ["mov", "ret"]))
    blocks.append(("ama_kyber_encapsulate", ["mov", "ret"]))
    monkeypatch.setattr(gate, "disassemble", lambda _p: _disassembly(*blocks))
    assert gate.main(["--lib", str(library)]) == 1


def test_the_allowlisted_shape_passes(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = tmp_path / "lib.so"
    library.write_bytes(b"\x7fELF")
    blocks = [(f"filler_{i}", ["mov"] * 300) for i in range(gate.MIN_SYMBOLS)]
    for symbol, (count, _reason) in gate.ALLOWED.items():
        blocks.append((symbol, ["div"] * count))
    for symbol in gate.REQUIRED_CLEAN:
        blocks.append((symbol, ["mov", "ret"]))
    monkeypatch.setattr(gate, "disassemble", lambda _p: _disassembly(*blocks))
    assert gate.main(["--lib", str(library)]) == 0


def test_ml_kem_missing_from_the_object_fails(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The gate cannot certify code that is not in the object it read."""
    library = tmp_path / "lib.so"
    library.write_bytes(b"\x7fELF")
    blocks = [(f"filler_{i}", ["mov"] * 300) for i in range(gate.MIN_SYMBOLS)]
    monkeypatch.setattr(gate, "disassemble", lambda _p: _disassembly(*blocks))
    assert gate.main(["--lib", str(library)]) == 1
    assert "kyber_decapsulate_internal" in capsys.readouterr().err


# --------------------------------------------------------------------------
# The allowlist itself
# --------------------------------------------------------------------------


def test_every_allowlist_entry_states_why_its_operands_are_public(gate: ModuleType) -> None:
    """A count with no reasoning is a suppression."""
    assert (
        gate.ALLOWED
    ), "an empty allowlist would make this gate unfalsifiable in the other direction"
    for symbol, (count, reason) in gate.ALLOWED.items():
        assert count > 0, f"{symbol} is allowlisted for zero divides; drop the entry"
        assert (
            len(reason) > 80
        ), f"{symbol}'s justification is too short to be checkable by the next reader"
        assert any(
            token in reason for token in (".c:", ".c ", "RFC")
        ), f"{symbol}'s justification cites no source location or standard"


def test_ml_kem_is_required_to_be_divide_free(gate: ModuleType) -> None:
    """The property the gate exists for, stated as a requirement."""
    assert "kyber_decapsulate_internal" in gate.REQUIRED_CLEAN
    assert not set(gate.REQUIRED_CLEAN) & set(
        gate.ALLOWED
    ), "a symbol cannot be both required-clean and allowed to divide"
