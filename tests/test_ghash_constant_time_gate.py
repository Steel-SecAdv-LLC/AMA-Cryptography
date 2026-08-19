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
   enough to catch the class of defect that was getting through at 3,000 —
   which, measured on the archive build CI uses, spread 2,952 against an old
   threshold of 3,000.
4. **The sampling cannot silently collapse.** Key classes must be distinct
   single-byte ASCII: a non-ASCII character is UTF-8 encoded by the caller and
   the driver would see only the lead byte, so two "different" classes could
   become one and the check would compare a key against itself.
5. **The drivers must not use degenerate key material.** ``memset``-ing one
   byte across the key caps the sampled key space at 256 highly structured
   values.
6. **CI must actually invoke both targets.**
7. **An unoptimized library is INCONCLUSIVE, never PASS.** Every target here
   looks for a transformation the optimizer performs, so at ``-O0`` there is
   nothing to find. The gate ran that way in CI for the life of this branch —
   ``dudect.yml`` configured CMake with no ``CMAKE_BUILD_TYPE`` and this
   project defines no default, so the archive carried no ``-O`` flag at all —
   and behind that, ``--target ecdsa`` at ``-O3`` was measuring a
   9,424-instruction key-dependent spread in ``sc_mont_mul``.
8. **A secret-dependent memory ACCESS fails even when the instruction count
   does not move.** An instruction count cannot see a table lookup indexed by
   a secret; the data-reference and cache-miss figures can.
"""

from __future__ import annotations

import importlib.util
import re
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


def _strip_c_comments(source: str) -> str:
    """Drop C comments so a structural check matches code, not prose.

    The first version of the assertion below searched the raw driver text for
    ``if (cls`` and matched the comment that explains why that branch is
    *absent*. That is the same false positive INVARIANT-13 records the
    suppression scanner learning about — "it made no distinction between a
    marker and prose describing one".
    """
    return re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)


def _fake_proc(
    returncode: int,
    count: int = LOADER_ONLY_COUNT,
    d_refs: int = 1_000,
    d1: int = 10,
    lld: int = 5,
) -> SimpleNamespace:
    """A completed valgrind run that printed every metric and exited ``returncode``."""
    return SimpleNamespace(
        returncode=returncode,
        stdout="",
        stderr=(
            f"==1234== I   refs:      {count:,}\n"
            f"==1234== D   refs:      {d_refs:,}  ({d_refs:,} rd + 0 wr)\n"
            f"==1234== D1  misses:    {d1:,}  ({d1:,} rd + 0 wr)\n"
            f"==1234== LLd misses:    {lld:,}  ({lld:,} rd + 0 wr)\n"
        ),
    )


def _m(ir: int, d_refs: int = 1_000, d1: int = 10, lld: int = 5) -> dict[str, int]:
    """One measurement, as :func:`_measure` returns it."""
    return {"I refs": ir, "D refs": d_refs, "D1 misses": d1, "LLd misses": lld}


class TestADriverThatDidNotRunIsNotAMeasurement:
    """The defect itself: a count is only a count if the workload executed."""

    def test_nonzero_exit_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Exit 127 is what a driver that cannot find its .so returns."""
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(127))
        assert tool._measure(tmp_path / "driver", "A", tmp_path) is None

    def test_crash_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(139))
        assert tool._measure(tmp_path / "driver", "A", tmp_path) is None

    def test_failed_crypto_call_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The drivers ``return 1`` when any crypto call fails."""
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(1))
        assert tool._measure(tmp_path / "driver", "A", tmp_path) is None

    def test_clean_exit_is_accepted(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Non-vacuity: the rule must not reject everything."""
        monkeypatch.setattr(tool.subprocess, "run", lambda *a, **k: _fake_proc(0, 12_345))
        assert tool._measure(tmp_path / "driver", "A", tmp_path) == _m(12_345)

    def test_missing_irefs_line_is_rejected(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr="valgrind: ???"),
        )
        assert tool._measure(tmp_path / "driver", "A", tmp_path) is None

    def test_a_missing_cache_metric_is_rejected_not_zeroed(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A figure callgrind did not print is a broken run, not a zero.

        Defaulting it to 0 would make every class agree on it and turn the
        strongest of the four metrics into a constant that always passes —
        the same shape as the loader-only count this file exists for.
        """
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(
                returncode=0,
                stdout="",
                # --cache-sim silently unavailable: I refs present, misses not.
                stderr="==1== I   refs:      12,345\n==1== D   refs:      1,000 (1,000 rd + 0 wr)\n",
            ),
        )
        assert tool._measure(tmp_path / "driver", "A", tmp_path) is None

    def test_the_cache_geometry_is_pinned_on_the_command_line(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Miss counts read out of the host's CPUID are a property of the runner.

        Pinning I1/D1/LL is what makes the published figures reproducible off
        the machine that took them.
        """
        seen: list[list[str]] = []

        def _capture(cmd: list[str], *a: object, **k: object) -> SimpleNamespace:
            seen.append(list(cmd))
            return _fake_proc(0)

        monkeypatch.setattr(tool.subprocess, "run", _capture)
        tool._measure(tmp_path / "driver", "A", tmp_path)
        assert seen, "no valgrind invocation"
        assert "--cache-sim=yes" in seen[0]
        for flag in tool._CACHE_GEOMETRY:
            assert flag in seen[0]


def _run_main(
    tool: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    counts: dict[str, Optional[dict[str, int]]],
    target: str = "ecdsa",
    optimized: Optional[int] = 1,
) -> int:
    """Drive ``main`` with the build steps stubbed and measurements supplied."""
    lib = tmp_path / "libama_cryptography_test.a"
    lib.write_bytes(b"")

    monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/stub")
    # The compile step is the only other subprocess main() runs directly.
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(tool, "_library_is_optimized", lambda *a, **k: optimized)

    calls: list[str] = []

    def _counted(driver: Path, key_class: str, workdir: Path) -> Optional[dict[str, int]]:
        calls.append(key_class)
        return counts[key_class]

    monkeypatch.setattr(tool, "_measure", _counted)
    return int(tool.main(["--lib", str(lib), "--include", str(tmp_path), "--target", target]))


class TestVerdict:
    def test_identical_counts_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 0

    def test_delta_above_threshold_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The spread the two secp256k1 leaks produced.

        2,952 instructions on the AMA_TESTING_MODE static archive CI builds.
        The old threshold of 3,000 sat 48 instructions above it.
        """
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800 + 2_952)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 1

    def test_delta_below_threshold_passes(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The measured benign DER spread must not turn the gate red.

        80 instructions on the archive build; 24 on a shared-library build.
        """
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800 + 80)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 0

    def test_a_cache_miss_delta_fails_with_the_instruction_count_unchanged(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The detection an instruction count cannot make.

        A table lookup indexed by a secret retires identical instructions
        whichever entry it touches; what moves is the address stream, and a
        different address stream through a fixed cache produces a different
        miss count. Measured live: the `kyber-decaps` driver written without
        its staging buffer reports 36,589 D1 misses for one class against
        36,764 for the other at -O3, with `I refs` byte-identical.
        """
        counts: dict[str, Optional[dict[str, int]]] = {
            k: _m(11_628_800, d1=36_589) for k in tool.KEY_CLASSES
        }
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800, d1=36_764)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 1

    def test_a_data_reference_delta_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800, d_refs=1_000 + 2_952)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 1

    def test_the_miss_threshold_reserves_no_benign_band(self, tool: ModuleType) -> None:
        """Measured, not chosen: every cross-class miss delta observed is 0.

        Across all ten targets under gcc 13 -O3 and clang 18 -O3, including
        `ecdsa`, the one target with a legitimate public-data spread (24
        instructions, 8 data references, 0 misses).
        """
        assert tool.MISS_THRESHOLD == 0

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
        monkeypatch.setattr(tool, "_library_is_optimized", lambda *a, **k: 1)
        seq = iter([_m(1_000_000), _m(1_999_999)])

        def _drifting(driver: Path, key_class: str, workdir: Path) -> Optional[dict[str, int]]:
            return next(seq)

        monkeypatch.setattr(tool, "_measure", _drifting)
        rc = tool.main(["--lib", str(lib), "--include", str(tmp_path), "--target", "ecdsa"])
        assert rc == 2

    def test_an_unusable_miss_floor_is_inconclusive_not_passing(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A machine that cannot reproduce its own miss count resolves nothing."""
        lib = tmp_path / "libama_cryptography_test.a"
        lib.write_bytes(b"")
        monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/stub")
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        monkeypatch.setattr(tool, "_library_is_optimized", lambda *a, **k: 1)
        seq = iter([_m(1_000_000, d1=10), _m(1_000_000, d1=11)])
        monkeypatch.setattr(tool, "_measure", lambda *a, **k: next(seq))
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
        counts: dict[str, Optional[dict[str, int]]] = dict.fromkeys(tool.KEY_CLASSES)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 2

    def test_missing_library_is_inconclusive(self, tool: ModuleType, tmp_path: Path) -> None:
        rc = tool.main(
            ["--lib", str(tmp_path / "absent.a"), "--include", str(tmp_path), "--target", "ghash"]
        )
        assert rc == 2


class TestAnUnoptimizedLibraryIsNotAMeasurement:
    """The second historical failure, and the larger of the two.

    ``dudect.yml`` configured the AMA_TESTING_MODE archive with

        cmake -B build -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON \
              -DAMA_ENABLE_LTO=OFF

    and ``CMakeLists.txt`` sets no default ``CMAKE_BUILD_TYPE``, so the archive
    carried no ``-O`` flag at all.  Every target here exists to catch a
    transformation the *optimizer* performs, so all ten reported PASS over a
    program in which their defect class is unreachable — and behind that,
    ``--target ecdsa`` rebuilt at ``-O3`` measured a 9,424-instruction
    key-dependent spread in ``sc_mont_mul``/``sc_cond_sub_n`` under clang 18.
    """

    def test_unoptimized_library_is_inconclusive_not_passing(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        assert _run_main(tool, monkeypatch, tmp_path, counts, optimized=0) == 2

    def test_an_unanswerable_probe_is_inconclusive_not_passing(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A library too old to export the probe cannot vouch for itself."""
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        assert _run_main(tool, monkeypatch, tmp_path, counts, optimized=None) == 2
        assert _run_main(tool, monkeypatch, tmp_path, counts, optimized=-1) == 2

    def test_an_optimized_library_still_passes(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Non-vacuity: the guard must not reject everything."""
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        assert _run_main(tool, monkeypatch, tmp_path, counts, optimized=1) == 0

    def test_the_probe_reads_the_library_not_the_driver(self, tool: ModuleType) -> None:
        """The drivers are compiled at -O2 by this tool regardless.

        A probe that reported its own translation unit's setting would answer
        "optimized" for every library it was handed.
        """
        assert "ama_build_optimization_probe" in tool._OPT_PROBE
        assert "-O2" not in tool._OPT_PROBE

    def test_every_ci_step_that_runs_a_target_builds_an_optimized_library(
        self, tool: ModuleType
    ) -> None:
        """The workflow side of the same property, asserted on the file.

        The guard above makes a misconfigured job fail loudly instead of
        passing quietly; this keeps it from failing at all.
        """
        document = yaml.safe_load(DUDECT_WORKFLOW.read_text(encoding="utf-8"))
        for job_id, job in document["jobs"].items():
            runs = [
                step.get("run") or "" for step in job.get("steps", []) if isinstance(step, dict)
            ]
            if not any("check_ghash_constant_time.py" in run for run in runs):
                continue
            configures = [run for run in runs if "cmake -B build" in run]
            assert configures, f"{job_id} runs a target but configures no build"
            assert all(
                "-DCMAKE_BUILD_TYPE=Release" in run for run in configures
            ), f"{job_id} must measure an optimized library"


class TestCalibration:
    def test_ecdsa_threshold_would_catch_the_defect_it_missed(self, tool: ModuleType) -> None:
        """2,952 on a git-reverted control build; 80 is the benign floor.

        Both measured on the AMA_TESTING_MODE static archive, which is what
        the dudect workflow builds. The threshold has to sit strictly between
        them. At the original 3,000 it sat 48 instructions above the defect,
        so the gate could not have fired on the thing it was added for.
        """
        assert 80 < tool.THRESHOLDS["ecdsa"] < 2952

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
        """Four classes saw 288 of the 576 instructions actually available.

        (Shared-library measurement; the archive build is larger still.)
        """
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


class TestTheConsttimeTarget:
    """The deterministic counterpart to a dudect lane that flakes."""

    def test_it_is_registered(self, tool: ModuleType) -> None:
        assert "consttime" in tool._DRIVERS
        assert "consttime" in tool.THRESHOLDS
        assert "consttime" in tool._REMEDY

    def test_the_driver_has_no_class_dependent_branch(self, tool: ModuleType) -> None:
        """A driver for a constant-time check must be constant-time itself.

        Written the obvious way — ``if (cls > 0) { ...mutate... }`` — the
        harness contributed ~11 instructions of its own, and the measurement
        stopped being a statement about the library. The mutation is always
        performed, with an XOR mask of 0 for the equal class.
        """
        driver = _strip_c_comments(tool._DRIVERS["consttime"])
        assert "if (cls" not in driver
        assert "mask" in driver
        assert "ama_consttime_memcmp" in driver

    def test_the_equal_case_is_covered(self, tool: ModuleType) -> None:
        """Class 'A' (0x41) makes the buffers equal.

        Without it every class would differ somewhere and the check could not
        see an implementation that early-exits only on a full match.
        """
        assert "0x41u" in tool._DRIVERS["consttime"]
        assert "A" in tool.KEY_CLASSES


class TestCIRunsEveryTarget:
    def test_dudect_workflow_invokes_each_target(self, tool: ModuleType) -> None:
        """Every registered target must have a CI step.

        Derived from ``_DRIVERS`` rather than a hand-written list, so adding a
        target without wiring it up fails here instead of shipping a check
        nothing runs.
        """
        text = DUDECT_WORKFLOW.read_text(encoding="utf-8")
        assert yaml.safe_load(text) is not None, "dudect.yml must parse"
        for target in tool._DRIVERS:
            assert f"--target {target}" in text, f"no CI step runs --target {target}"
