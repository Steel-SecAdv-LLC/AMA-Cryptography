# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_ghash_constant_time.py``.

This gate shipped without any. INVARIANT-2 states the consequence in as many
words — *"a gate with no negative control has not been shown to be a gate at
all"* — and the consequence arrived on schedule.

``_measure`` (then named ``_instruction_count``) parsed callgrind's
``I refs:`` line and never looked at the driver's exit status. Callgrind
prints that line for any process it supervises, including one that dies in
the dynamic loader before reaching
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
   exit-status rule in ``_measure`` and its propagation to the exit
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
from typing import Callable, Optional

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
                stderr=(
                    "==1== I   refs:      12,345\n" "==1== D   refs:      1,000 (1,000 rd + 0 wr)\n"
                ),
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

    def test_an_identical_count_across_every_class_passes(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Zero delta is now the only thing that passes this target.

        An earlier revision asserted that a delta of 24 passed, because
        secp256k1 exposed only the DER form and the leading-zero handling of
        the public r and s stayed inside the count — 24 retired instructions
        over 8 signatures under gcc 13 -O3, 16 under clang 18. That term is
        gone: the driver signs through ``ama_secp256k1_ecdsa_sign_raw``, which
        emits a constant 64 octets, and the limit is 0. Asserting that 24
        still passes would now be asserting the gate is looser than it is.
        """
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 0

    def test_the_old_benign_der_delta_now_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The tolerance really is gone, not merely renamed.

        24 was the largest benign spread ever measured on this target and was
        explicitly inside its old limit of 64. It has to be a failure now, or
        removing the DER term bought nothing.
        """
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800 + 24)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 1

    def test_a_delta_one_above_the_ecdsa_limit_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A limit of zero still has to be a limit: one instruction fails."""
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800 + tool.THRESHOLDS["ecdsa"] + 1)
        assert _run_main(tool, monkeypatch, tmp_path, counts) == 1

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


class TestAnOrderArtefactIsNotALeak:
    """A delta that follows the ORDER of measurement must not read as a leak.

    Every threshold in this gate is 0, and each class used to be measured
    exactly once, in a fixed order, with the noise floor sampled only at the
    start.  Any one-time cost that falls away after the first few processes —
    a cache directory created on first use, a page-cache warm-up, an ASLR
    layout that lands differently in the simulated cache — therefore attaches
    itself entirely to the classes measured first and is indistinguishable, in
    the report, from a key-dependent measurement.

    Observed on a clean tree: `--target aead-verify` reported 456 I refs of
    "key-dependent measurement" whose high/low split followed measurement order
    (first three high, last six low) and cut across the accept/reject split the
    driver actually varies — 1 false FAIL in 6 runs, against a driver that
    showed zero variance over 24 standalone runs.

    A leak is deterministic under callgrind and reproduces in either order.
    These are the controls for that distinction.
    """

    @staticmethod
    def _order_artefact(
        tool: ModuleType, high_for_first: int, delta: int
    ) -> Callable[[Path, str, Path], Optional[dict[str, int]]]:
        """A ``_measure`` stub whose value depends on CALL ORDER, not on class."""
        state = {"n": 0}

        def _stub(driver: Path, key_class: str, workdir: Path) -> Optional[dict[str, int]]:
            state["n"] += 1
            base = 11_628_800
            return _m(base + delta if state["n"] <= high_for_first else base)

        return _stub

    def test_an_order_dependent_delta_is_inconclusive_not_failed(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Exit 2, not 1: the instrument is what is wrong, and it says so."""
        lib = tmp_path / "libama_cryptography_test.a"
        lib.write_bytes(b"")
        monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/stub")
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        monkeypatch.setattr(tool, "_library_is_optimized", lambda *a, **k: 1)
        # The first three measurements carry the artefact — floor_a, floor_b and
        # the first non-floor class — exactly the shape observed on the tree.
        # floor_a and floor_b agree with each other, so the opening floor check
        # cannot see it; the cross-class comparison then does.
        monkeypatch.setattr(tool, "_measure", self._order_artefact(tool, 3, 456))
        rc = tool.main(["--lib", str(lib), "--include", str(tmp_path), "--target", "aead-verify"])
        assert rc == 2, "an order-dependent delta must be INCONCLUSIVE, not a leak verdict"

    def test_a_real_leak_still_fails_after_the_confirmation_sweep(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Sensitivity is unchanged: a class-keyed delta reproduces in reverse.

        This is the other half of the control.  If the confirmation sweep had
        made the gate merely quieter, this would now pass.
        """
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        counts[tool.KEY_CLASSES[-1]] = _m(11_628_800 + 456)
        assert _run_main(tool, monkeypatch, tmp_path, counts, target="aead-verify") == 1

    def test_the_closing_floor_is_measured_and_reported(
        self,
        tool: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`drift` — the same-class difference across the whole sweep — is printed.

        Without it, a bias that develops during the sweep is invisible: the
        opening floor only says the instrument could reproduce itself before
        any of the cross-class work began.
        """
        counts: dict[str, Optional[dict[str, int]]] = {k: _m(11_628_800) for k in tool.KEY_CLASSES}
        assert _run_main(tool, monkeypatch, tmp_path, counts, target="aead-verify") == 0
        out = capsys.readouterr().out
        assert "  drift  " in out, out

    def test_every_class_is_measured_at_least_twice_when_a_breach_is_seen(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The confirmation sweep really runs, and really covers every class."""
        lib = tmp_path / "libama_cryptography_test.a"
        lib.write_bytes(b"")
        monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/stub")
        monkeypatch.setattr(
            tool.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        monkeypatch.setattr(tool, "_library_is_optimized", lambda *a, **k: 1)

        seen: list[str] = []

        def _stub(driver: Path, key_class: str, workdir: Path) -> Optional[dict[str, int]]:
            seen.append(key_class)
            base = 11_628_800
            return _m(base + 456 if key_class == tool.KEY_CLASSES[-1] else base)

        monkeypatch.setattr(tool, "_measure", _stub)
        rc = tool.main(["--lib", str(lib), "--include", str(tmp_path), "--target", "aead-verify"])
        assert rc == 1
        for key_class in tool.KEY_CLASSES:
            assert seen.count(key_class) >= 2, (key_class, seen)


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
    """The limits are measurements, and these tests are what keeps them so.

    A deterministic instrument that reserves a benign band it does not need
    has bought the right to pass a real divergence of that size. Measured on
    the AMA_TESTING_MODE static archive at -O3 under both compilers CI uses,
    all fourteen targets have a cross-class delta of exactly zero and a
    same-class floor of exactly zero. ``ecdsa`` was the last to carry a benign
    term — the DER encoding of the public r and s — and reached zero by
    signing through a fixed-width entry point rather than by tolerating it.

    ``secp256k1-scalarmult`` is the fourteenth, added because the dudect lane
    for that ladder was information-only and the file its comment named as
    carrying the "fail-loud variant" contains no secp256k1 scalar-multiplication
    case: a 256-step Montgomery ladder over a secret scalar was covered only by
    a lane that cannot fail CI. Measured at limit 0 on all four metrics —
    16,020,324 instruction references and 3,835,722 data references,
    byte-identical across all eight classes, with identical D1 and LL misses.
    """

    #: Every target whose count is invariant by construction — measured 0/0
    #: under gcc 13 and clang 18. Their limit must be 0.
    INVARIANT_TARGETS = frozenset(
        {
            "ghash",
            "consttime",
            "aead-verify",
            "ascon-hash",
            "ascon-encrypt",
            "agent-binding",
            "kyber-decaps",
            "sha3-256",
            "ed25519-sign",
            "nistp-ecdsa",
            "x25519",
            "x25519-batch",
            "ecdsa",
            "secp256k1-scalarmult",
        }
    )

    def test_every_invariant_target_reserves_no_benign_band(self, tool: ModuleType) -> None:
        """Zero, for the same reason ``MISS_THRESHOLD`` is zero.

        These targets state that two classes execute the same instructions.
        One retired instruction of difference falsifies that, so there is
        nothing for a threshold to be headroom for — and the same-class floor
        check already reports INCONCLUSIVE rather than passing if a host
        cannot reproduce itself.
        """
        for target in self.INVARIANT_TARGETS:
            assert tool.THRESHOLDS[target] == 0, target

    def test_the_invariant_set_is_every_target(self, tool: ModuleType) -> None:
        """A new target must state its own limit and the measurement for it.

        Without this, a target added with a copied non-zero limit would
        inherit a benign band nobody measured.

        This used to assert the difference was exactly ``{"ecdsa"}`` — the one
        target allowed a tolerance. That carve-out passed only because it
        encoded the world before secp256k1 got a fixed-width signing entry
        point. It is empty now, and a target that appears outside the
        invariant set has to come here and say why.
        """
        assert set(tool.THRESHOLDS) - self.INVARIANT_TARGETS == set()
        assert (
            self.INVARIANT_TARGETS - set(tool.THRESHOLDS) == set()
        ), "the invariant set names a target THRESHOLDS does not have"

    def test_the_default_for_an_unlisted_target_is_zero(self, tool: ModuleType) -> None:
        assert tool.DEFAULT_THRESHOLD == 0

    def test_ecdsa_reaches_zero_by_removing_der_not_by_tolerating_it(
        self, tool: ModuleType
    ) -> None:
        """secp256k1's limit is 0, and the driver is why.

        The history this replaces: 2,952 is the Montgomery extra-reduction
        leak this target was added for, measured on a reverted build. The
        original limit of 3,000 sat 48 instructions ABOVE that defect. The
        flat 200 that replaced it still let 25 instructions per signature of
        real divergence pass. 64 — clearing the 24-instruction benign DER
        spread under gcc 13 and 16 under clang 18 — still left 8 instructions
        per signature of room.

        The room is gone, and not by lowering a number over unchanged code:
        ``ama_secp256k1_ecdsa_sign_raw`` runs identical arithmetic to the DER
        entry point and writes a fixed 64 octets, so the encoder's
        key-dependent length term is outside the measurement. Signing through
        the DER form again would put it back while the limit stayed at 0,
        which is a flaky gate rather than a strict one — so the driver is
        asserted, not just the number. This is the pairing
        ``nistp-ecdsa`` already had.
        """
        driver = tool._DRIVERS["ecdsa"]
        assert "ama_secp256k1_ecdsa_sign_raw(" in driver
        assert "ama_secp256k1_ecdsa_sign(" not in driver
        assert tool.THRESHOLDS["ecdsa"] == 0
        assert tool.THRESHOLDS["ecdsa"] < 2952

    def test_every_target_now_sits_at_zero(self, tool: ModuleType) -> None:
        """The last non-zero threshold is gone.

        Recorded as an assertion rather than prose so that reintroducing a
        tolerance has to come here and say which target needs one and why.
        """
        nonzero = {k: v for k, v in tool.THRESHOLDS.items() if v != 0}
        assert not nonzero, (
            f"these targets carry a tolerance: {nonzero}. A non-zero limit is "
            f"room a real divergence can hide in; if one is genuinely needed, "
            f"state the benign term it covers and how it was measured."
        )

    def test_nistp_reaches_zero_by_removing_der_not_by_tolerating_it(
        self, tool: ModuleType
    ) -> None:
        """The raw entry point is what makes a limit of 0 honest there.

        ``ama_nistp_ecdsa_sign_raw`` runs identical arithmetic to the DER
        entry point and writes a fixed 64 octets, so the encoder's
        key-dependent length term is not in the measurement at all. Signing
        through the DER form again would put it back while the limit stayed
        at 0, which would be a flaky gate rather than a strict one.
        """
        driver = tool._DRIVERS["nistp-ecdsa"]
        assert "ama_nistp_ecdsa_sign_raw(" in driver
        assert "ama_nistp_ecdsa_sign(" not in driver
        assert tool.THRESHOLDS["nistp-ecdsa"] == 0


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
