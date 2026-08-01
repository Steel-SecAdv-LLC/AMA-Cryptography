# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_ghash_constant_time.py``.

This gate shipped without any. INVARIANT-2 states the consequence in as many
words — *"a gate with no negative control has not been shown to be a gate at
all"* — and the consequence arrived on schedule.

``_instruction_count`` parsed callgrind's ``I refs:`` line and never looked at
the driver's exit status. Callgrind prints that line for any process it
supervises, including one that dies in the dynamic loader before reaching
``main``. Handing ``--lib`` a shared object rather than the static archive did
exactly that: the driver linked, failed to load, and every key class returned
the same ~109,000 instructions of loader work. All classes agreed, the delta
was zero, and the gate printed::

    ECDSA CONSTANT-TIME CHECK PASSED — count is key-independent.

over a program that had performed no cryptography. It printed the same verdict
for a build carrying two live secret-dependent branches in
``src/c/ama_secp256k1.c`` and for a build with none — which is the definition
of a gate that gates nothing.

So the properties pinned here are, in order of what actually failed:

1. **A driver that did not run is INCONCLUSIVE, never PASS.** Both the
   exit-status rule in ``_instruction_count`` and its propagation to the exit
   code of ``main``.
2. **The verdict arithmetic.** Above threshold fails, below passes, and an
   unusable noise floor is inconclusive rather than either.
3. **The calibration is not decorative.** The ECDSA threshold must stay small
   enough to catch the class of defect that was getting through at 3,000.
4. **The sampling cannot silently collapse.** Key classes must be distinct
   single-byte ASCII: a non-ASCII character is UTF-8 encoded by the caller and
   the driver would see only the lead byte, so two "different" classes could
   become one and the check would compare a key against itself.
5. **The drivers must not use degenerate key material.** ``memset``-ing one
   byte across the key caps the sampled key space at 256 highly structured
   values.
6. **CI must actually invoke both targets.**
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Optional

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_ghash_constant_time.py"
DUDECT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dudect.yml"

#: Retired instructions the failing-to-load driver reported. Any value works;
#: the point is that it is stable across key classes, which is what made the
#: old code call it a pass.
LOADER_ONLY_COUNT = 109_165


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_ghash_constant_time", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fake_proc(returncode: int, count: int = LOADER_ONLY_COUNT) -> SimpleNamespace:
    """A completed valgrind run that printed a count and exited ``returncode``."""
    return SimpleNamespace(
        returncode=returncode,
        stdout="",
        stderr=f"==1234== I   refs:      {count:,}\n",
    )


class TestADriverThatDidNotRunIsNotAMeasurement:
    """The defect itself: a count is only a count if the workload executed."""

    def test_nonzero_exit_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Exit 127 is what a driver that cannot find its .so returns."""
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(127))
        assert tool._instruction_count(tmp_path / "driver", "A", tmp_path) is None

    def test_crash_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(139))
        assert tool._instruction_count(tmp_path / "driver", "A", tmp_path) is None

    def test_failed_crypto_call_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The drivers ``return 1`` when any crypto call fails."""
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(1))
        assert tool._instruction_count(tmp_path / "driver", "A", tmp_path) is None

    def test_clean_exit_is_accepted(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Non-vacuity: the rule must not reject everything."""
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(0, 12_345))
        assert tool._instruction_count(tmp_path / "driver", "A", tmp_path) == 12_345

    def test_missing_irefs_line_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr="valgrind: ???"),
        )
        assert tool._instruction_count(tmp_path / "driver", "A", tmp_path) is None


def _run_main(
    tool: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    counts: dict[str, Optional[int]],
    target: str = "ecdsa",
) -> int:
    """Drive ``main`` with the build steps stubbed and counts supplied."""
    lib = tmp_path / "libama_cryptography_test.a"
    lib.write_bytes(b"")

    monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/stub")
    # The compile step is the only other subprocess main() runs directly.
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    calls: list[str] = []

    def _counted(driver: Path, key_class: str, workdir: Path) -> Optional[int]:
        calls.append(key_class)
        return counts[key_class]

    monkeypatch.setattr(tool, "_instruction_count", _counted)
    return int(tool.main(["--lib", str(lib), "--include", str(tmp_path), "--target", target]))


class TestVerdict:
    def test_identical_counts_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        counts: dict[str, Optional[int]] = dict.fromkeys(tool.KEY_CLASSES, 11_628_800)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 0

    def test_delta_above_threshold_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The 576-instruction spread the two secp256k1 leaks produced.

        This is the number that must not pass, and did at the old threshold of
        3,000.
        """
        counts: dict[str, Optional[int]] = dict.fromkeys(tool.KEY_CLASSES, 11_628_800)
        counts[tool.KEY_CLASSES[-1]] = 11_628_800 + 576
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 1

    def test_delta_below_threshold_passes(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The 24-instruction benign DER spread must not turn the gate red."""
        counts: dict[str, Optional[int]] = dict.fromkeys(tool.KEY_CLASSES, 11_628_800)
        counts[tool.KEY_CLASSES[-1]] = 11_628_800 + 24
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 0

    def test_unusable_noise_floor_is_inconclusive_not_passing(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Same key twice differing by more than the threshold resolves nothing.

        ``main`` measures the first class twice, so returning a moving value
        for it simulates a machine that cannot reproduce itself.
        """
        lib = tmp_path / "libama_cryptography_test.a"
        lib.write_bytes(b"")
        monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/stub")
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        seq = iter([1_000_000, 1_999_999])

        def _drifting(driver: Path, key_class: str, workdir: Path) -> Optional[int]:
            return next(seq)

        monkeypatch.setattr(tool, "_instruction_count", _drifting)
        rc = tool.main(["--lib", str(lib), "--include", str(tmp_path), "--target", "ecdsa"])
        assert rc == 2

    def test_a_driver_that_never_ran_is_inconclusive_not_passing(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """End to end, the exact historical failure.

        Every class returns None because the driver exited non-zero. The old
        code returned a stable ~109,165 for each and reported PASS; anything
        other than 2 here is that regression.
        """
        counts: dict[str, Optional[int]] = dict.fromkeys(tool.KEY_CLASSES)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 2

    def test_missing_library_is_inconclusive(self, tool: ModuleType, tmp_path: Path) -> None:
        rc = tool.main(
            ["--lib", str(tmp_path / "absent.a"), "--include", str(tmp_path), "--target", "ghash"]
        )
        assert rc == 2


class TestCalibration:
    def test_ecdsa_threshold_would_catch_the_defect_it_missed(self, tool: ModuleType) -> None:
        """576 was measured on a git-reverted control build; 24 is benign.

        The threshold has to sit strictly between them. At the original 3,000
        it sat above both, so the gate passed the very defect class it was
        added for.
        """
        assert 24 < tool.THRESHOLDS["ecdsa"] < 576

    def test_ghash_threshold_is_between_its_own_noise_and_defect(self, tool: ModuleType) -> None:
        assert 26 < tool.THRESHOLDS["ghash"] < 3226


class TestSamplingCannotSilentlyCollapse:
    def test_key_classes_are_distinct(self, tool: ModuleType) -> None:
        assert len(set(tool.KEY_CLASSES)) == len(tool.KEY_CLASSES)

    def test_key_classes_are_single_byte_ascii(self, tool: ModuleType) -> None:
        """A non-ASCII class would reach the driver as its UTF-8 lead byte.

        ``argv[1][0]`` reads one byte. ``"\\xb7"`` and ``"\\xe9"`` encode to
        ``c2 b7`` and ``c3 a9``, so a set mixing them with ``"\\xc2"`` would
        compare a key against itself while appearing to test two.
        """
        for key_class in tool.KEY_CLASSES:
            assert len(key_class) == 1
            assert len(key_class.encode("utf-8")) == 1
            assert key_class.isascii()

    def test_enough_classes_to_have_detection_power(self, tool: ModuleType) -> None:
        """Four classes saw 288 of the 576 instructions actually available."""
        assert len(tool.KEY_CLASSES) >= 8

    @pytest.mark.parametrize("target", ["ghash", "ecdsa"])
    def test_driver_does_not_memset_the_key_from_one_byte(
        self, tool: ModuleType, target: str
    ) -> None:
        """A repeated-byte key samples 256 highly structured values, no more."""
        driver = tool._DRIVERS[target]
        assert "memset(key, (int)fill" not in driver
        assert "memset(sk, (int)fill" not in driver
        assert "fill * 31u" in driver

    @pytest.mark.parametrize("target", ["ghash", "ecdsa"])
    def test_driver_returns_nonzero_when_a_crypto_call_fails(
        self, tool: ModuleType, target: str
    ) -> None:
        """The exit-status rule is only a witness if the driver sets one."""
        assert "return 1;" in tool._DRIVERS[target]

    def test_ecdsa_driver_consumes_a_fixed_byte_count(self, tool: ModuleType) -> None:
        """Iterating to ``siglen`` made the driver itself variable-time.

        That put ~9 instructions per DER byte into the measurement and is what
        the old 728-instruction "benign spread" was partly made of.
        """
        assert "j < sizeof sig" in tool._DRIVERS["ecdsa"]
        assert "j < siglen" not in tool._DRIVERS["ecdsa"]


class TestCIRunsBothTargets:
    def test_dudect_workflow_invokes_each_target(self) -> None:
        text = DUDECT_WORKFLOW.read_text(encoding="utf-8")
        assert yaml.safe_load(text) is not None, "dudect.yml must parse"
        for target in ("ghash", "ecdsa"):
            assert f"--target {target}" in text, f"no CI step runs --target {target}"
