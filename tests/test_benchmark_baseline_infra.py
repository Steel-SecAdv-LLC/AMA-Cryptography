#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for benchmark baseline runner-class enforcement."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

# One import style throughout: the module object.  This file also patches
# attributes on the module (monkeypatch through the "benchmarks.benchmark_runner"
# string target), and mixing `from ... import name` with `import ... as br`
# left half the references bound to stale objects the patches never touched —
# and tripped CodeQL's imported-both-ways check once benchmarks/ became a real
# package.
import benchmarks.benchmark_runner as br

REPO_ROOT = Path(__file__).resolve().parent.parent


def _baseline(runner_cpu_class: str = "aarch64", baseline_value: int = 1) -> dict[str, Any]:
    return {
        "metadata": {"runner_cpu_class": runner_cpu_class},
        "benchmarks": {
            "ama_sha3_256_hash": {
                "description": "SHA3-256",
                "baseline_value": baseline_value,
            }
        },
        "pqc_benchmarks": {},
    }


def test_normalize_runner_cpu_class_aliases() -> None:
    """Common architecture spellings collapse to the matrix baseline key."""
    assert br.normalize_runner_cpu_class("arm64") == "aarch64"
    assert br.normalize_runner_cpu_class("AMD64") == "x86_64"


def test_validate_baseline_contract_accepts_matching_arm_alias() -> None:
    """A GitHub arm64 runner may consume an aarch64 baseline."""
    br.validate_baseline_contract(
        _baseline("aarch64"),
        Path("benchmarks/arm-baseline.json"),
        expected_runner_cpu_class="arm64",
    )


def test_validate_baseline_contract_rejects_runner_mismatch() -> None:
    """x86 baselines must not be used on the AArch64 matrix entry."""
    with pytest.raises(ValueError, match="runner_cpu_class"):
        br.validate_baseline_contract(
            _baseline("x86_64"),
            Path("benchmarks/baseline.json"),
            expected_runner_cpu_class="aarch64",
        )


def test_validate_baseline_contract_rejects_zero_when_required() -> None:
    """Strict baseline publication mode refuses first-run zero placeholders."""
    with pytest.raises(ValueError, match="unpopulated zero baselines"):
        br.validate_baseline_contract(
            _baseline("aarch64", baseline_value=0),
            Path("benchmarks/arm-baseline.json"),
            expected_runner_cpu_class="aarch64",
            require_populated_baseline=True,
        )


def test_benchmark_operation_best_of_uses_fastest_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Latency-spiky composite benchmarks compare steady-state throughput."""

    measurements = iter([10.0, 42.0, 17.0])

    def fake_benchmark_operation(
        operation: Callable[[], object], iterations: int = 100, warmup: int = 5
    ) -> float:
        assert iterations == 20
        assert warmup == 2
        return next(measurements)

    monkeypatch.setattr(br, "benchmark_operation", fake_benchmark_operation)

    assert br.benchmark_operation_best_of(lambda: None, iterations=20, warmup=2, rounds=3) == 42.0


def test_the_two_composites_are_sampled_identically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``full_package_create`` and ``full_package_verify`` are compared to each
    other and to their own floors, so they must be measured the same way.

    ``full_package_create`` used to call
    ``benchmark_operation_best_of(..., rounds=5)`` while ``_SAMPLING_REPEATS``
    ALSO registered it for ``_COMPOSITE_SAMPLED_ROUNDS`` (5).  The two compound:
    ``_measure_benchmark`` calls the function 5 times and keeps the max, and
    each call ran ``benchmark_operation`` 5 more times — 25 whole measurements
    and 75 windows, against 5 and 15 for its sibling with the same registry
    entry.  The published provenance said "x5".

    Measured: 17.7 s -> 5.5 s for the row, and 1,446.8 -> 1,371.7 ops/sec
    (-5.2%) against a floor of 1,983 with a 45% tolerance (1,091 minimum).
    """
    calls: list[tuple[int, int]] = []

    def fake_operation(
        operation: Callable[[], object], iterations: int = 100, warmup: int = 5
    ) -> float:
        calls.append((iterations, warmup))
        return 123.0

    monkeypatch.setattr(br, "benchmark_operation", fake_operation)

    assert br.run_full_package_create_benchmark() == 123.0
    assert br.run_full_package_verify_benchmark() == 123.0
    assert calls == [(20, 2), (20, 2)], calls


def test_no_registered_benchmark_double_samples(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row in ``_SAMPLING_REPEATS`` must not also take its own best-of.

    Read statically, because the compounding is invisible at run time: each
    mechanism is correct on its own and the product is what is wrong.
    """
    import ast
    import inspect

    source = inspect.getsource(br)
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        name = node.name
        if not (name.startswith("run_") and name.endswith("_benchmark")):
            continue
        registry_key = name[len("run_") : -len("_benchmark")]
        if registry_key not in br._SAMPLING_REPEATS:
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "benchmark_operation_best_of"
            ):
                offenders.append(f"{name} (registry key {registry_key!r})")
    assert offenders == [], (
        "these benchmarks are sampled by _SAMPLING_REPEATS AND take their own "
        f"best-of, so the two multiply: {offenders}"
    )


class TestSampleWindow:
    """Every benchmark must be measured over a window long enough to mean something.

    The per-benchmark ``iterations`` defaults span 20-100 across primitives whose
    costs differ by three orders of magnitude, so they bought very different
    amounts of signal — 20 ML-DSA-65 signatures is roughly 6 ms, and the whole
    19-benchmark suite finished in about 0.4 s on the CI runner. Measured
    directly on an unchanged binary, ``dilithium_sign`` reported 917, 1845 and
    3086 ops/sec on three consecutive runs: a 3.4x spread against a 10%
    regression threshold. These pin the batch sizing that fixes it.
    """

    @staticmethod
    def _virtual_clock(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
        """A perf_counter that only advances when the operation says it did.

        Real timing would make these tests flaky for exactly the reason the
        suite is being fixed.

        Patched through the string target rather than ``br.time`` so that
        ``mypy --strict`` does not read it as importing a name the runner
        never re-exported (``no_implicit_reexport``). monkeypatch restores it
        when the test ends.
        """
        clock = {"t": 0.0}
        monkeypatch.setattr("benchmarks.benchmark_runner.time.perf_counter", lambda: clock["t"])
        return clock

    def test_batch_grows_until_the_window_is_reached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A too-small starting batch is grown, not accepted."""
        clock = self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)

        def op() -> None:
            clock["t"] += 0.001  # 1 ms per op -> 150 needed for a 0.15 s window

        rate = br.benchmark_operation(op, iterations=5, warmup=0, rounds=2)
        assert rate == pytest.approx(1000.0, rel=0.05)
        assert sizes[0] == 5, "should start from the caller's floor"
        assert (
            sizes[-1] >= br._MIN_SAMPLE_SECONDS / 0.001
        ), f"settled batch {sizes[-1]} spans less than _MIN_SAMPLE_SECONDS at 1 ms/op"

    def test_batch_growth_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An operation too cheap to fill the window cannot run unbounded."""
        clock = self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)

        def op() -> None:
            clock["t"] += 1e-9  # would need 150M iterations to fill the window

        br.benchmark_operation(op, iterations=1, warmup=0, rounds=1)
        assert max(sizes) <= br._MAX_ITERATIONS

    def test_an_unlucky_slow_batch_does_not_lock_in_a_short_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case that broke the first version of this sizing.

        A batch that is slow because it was unlucky satisfies an
        elapsed-time target with very few iterations. Sizing on elapsed time
        alone therefore accepted a 5-iteration batch and reused it for every
        remaining round. Keying the target off the fastest rate seen recovers,
        because interference can only make an operation look slower.
        """
        clock = self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)
        calls = {"n": 0}

        def op() -> None:
            calls["n"] += 1
            # The first batch of 5 stalls at 100 ms/op; everything after is 1 ms.
            clock["t"] += 0.1 if calls["n"] <= 5 else 0.001

        rate = br.benchmark_operation(op, iterations=5, warmup=0, rounds=2)
        assert (
            sizes[-1] >= br._MIN_SAMPLE_SECONDS / 0.001
        ), f"settled batch {sizes[-1]} was locked in by the stalled first batch"
        assert rate == pytest.approx(
            1000.0, rel=0.05
        ), "the stalled batch's rate was reported instead of the recovered one"

    def test_reported_rate_is_the_fastest_full_window_round(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Throughput noise is one-sided, so the fastest round is the estimate.

        Fails if the mean is reported: the mean of these rounds is well below
        the fastest.
        """
        self._virtual_clock(monkeypatch)
        rates = iter([500.0, 2000.0, 800.0])
        # Every batch is already full-window, so sizing never intervenes.
        monkeypatch.setattr(br, "_required_batch", lambda rate: 1)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (next(rates), 0.2))

        assert br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=3) == 2000.0

    def test_a_slow_batch_cannot_shrink_the_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing keys off the fastest rate seen, not the most recent one.

        With the target derived from the latest batch, one slow reading while
        the batch is still small drops the requirement to almost nothing, and
        that small batch is accepted — reporting the slow rate. Because
        interference is one-sided, the fastest rate seen is the better
        estimate of what the batch must be to fill the window.
        """
        self._virtual_clock(monkeypatch)
        # Fast, then a stall while the batch is still tiny, then fast again.
        rates = iter([1_000.0, 10.0] + [1_000.0] * 40)
        sizes: list[int] = []

        def scripted(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return next(rates), 0.0

        monkeypatch.setattr(br, "_timed_batch", scripted)

        rate = br.benchmark_operation(lambda: None, iterations=1, warmup=0, rounds=1)
        needed = br._required_batch(1_000.0)
        assert sizes[-1] >= needed, (
            f"settled at batch {sizes[-1]}, below the {needed} needed at the "
            f"fastest observed rate — a slow batch shrank the target"
        )
        assert rate == pytest.approx(1_000.0), f"reported the stalled rate ({rate})"

    def test_undersized_batches_cannot_inflate_the_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Baselines are floors, so a lucky short batch must not be reported.

        The first batch is undersized and reports an implausibly high rate.
        It may inform sizing; it must not be the number that ships.
        """
        self._virtual_clock(monkeypatch)
        rates = iter([9_999.0, 1_000.0, 1_000.0])
        monkeypatch.setattr(br, "_required_batch", lambda rate: 50)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (next(rates), 0.2))

        rate = br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=1)
        assert rate == 1_000.0, f"an undersized batch's {rate} ops/sec reached the report"


class TestAnUnderSampledRunIsNotReported:
    """The fallbacks below the sampling loop published numbers the loop refused.

    ``benchmark_operation`` ends with the loop having either satisfied the
    sampling rule (``completed >= rounds`` full-window batches) or not.  It used
    to report a rate in both cases:

      * ``if best > 0.0: return best`` returned the fastest FULL-WINDOW batch
        even when fewer than ``rounds`` of them completed — a run sampled less
        than the rule the docstring states.
      * ``if observed > 0.0 ...: return observed`` returned the fastest
        UNDER-TARGET batch, which is precisely what the docstring forbids:
        "Only full-window batches are eligible to be reported. An undersized
        batch can report a lucky-high rate off a very short window, and since
        the baselines this feeds are *floors*, an inflated number makes the
        gate weaker."

    ``TestSampleWindow.test_undersized_batches_cannot_inflate_the_result``
    pins the loop's own behaviour, and passed throughout: it scripts a run that
    DOES reach ``rounds``, so the fallback is never taken.  These two cases are
    the ones that reach it.
    """

    def test_a_never_full_window_run_raises_instead_of_reporting_a_short_batch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No batch ever reaches the target, so only under-target rates exist."""
        monkeypatch.setattr(br, "_required_batch", lambda rate: br._MAX_ITERATIONS + 1)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (9_999.0, 0.001))

        with pytest.raises(RuntimeError, match="full-window batches"):
            br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=3)

    def test_a_partly_sampled_run_raises_instead_of_reporting_fewer_rounds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full-window batches happen, but the streak never reaches ``rounds``.

        Every second attempt is under-target, which resets the streak, so the
        loop exhausts its attempt budget holding ``completed == 1`` and a
        non-zero ``best``.  That is the input on which ``return best`` reported
        a one-round measurement as if it were a three-round one.

        ``_MAX_SIZING_ATTEMPTS`` is pinned rather than inherited: the loop runs
        ``rounds + _MAX_SIZING_ATTEMPTS`` times, so which of the alternating
        attempts is LAST — and therefore whether the run ends holding
        ``completed == 1`` or ``completed == 0`` — is decided by the parity of
        that sum.  Reading the shipped constant would make this assertion
        change meaning if the constant ever moved by one, for a reason that has
        nothing to do with the property under test.
        """
        monkeypatch.setattr(br, "_MAX_SIZING_ATTEMPTS", 4)  # 3 + 4 = 7 attempts, odd
        calls = {"n": 0}

        def alternating_target(rate: float) -> int:
            calls["n"] += 1
            return 1 if calls["n"] % 2 else br._MAX_ITERATIONS + 1

        monkeypatch.setattr(br, "_required_batch", alternating_target)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (1_000.0, 0.2))

        with pytest.raises(RuntimeError, match=r"completed 1 of 3 full-window"):
            br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=3)

    def test_a_fully_sampled_run_still_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The control: a run that satisfies the rule must not start raising."""
        monkeypatch.setattr(br, "_required_batch", lambda rate: 1)
        monkeypatch.setattr(br, "_timed_batch", lambda op, n: (1_000.0, 0.2))

        assert br.benchmark_operation(lambda: None, iterations=10, warmup=0, rounds=3) == 1_000.0


class TestAnUnmeasurableBatchCannotBecomeAnInfiniteRate:
    """`elapsed == 0` used to be reported as an infinite throughput.

    ``_timed_batch`` yields ``float("inf")`` when the clock reads exactly zero
    for a batch, and ``benchmark_operation`` returned that straight out. It is
    a fail-open twice over: ``inf`` serialises as ``Infinity``, which is not
    JSON (RFC 8259) and which a strict reader rejects, and an infinite rate
    clears every regression FLOOR it is compared against — so the one value
    that means "not measured" would have passed the gate that exists to catch
    a slowdown.

    A batch too short to time is a sizing problem, and is now treated as one.
    """

    @staticmethod
    def _virtual_clock(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
        clock = {"t": 0.0}
        monkeypatch.setattr("benchmarks.benchmark_runner.time.perf_counter", lambda: clock["t"])
        return clock

    def test_an_unmeasurable_batch_grows_instead_of_returning_infinity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It must try to measure, not give up with a number it cannot stand behind."""
        self._virtual_clock(monkeypatch)
        sizes: list[int] = []
        real_batch = br._timed_batch

        def spy(op: Callable[[], object], n: int) -> tuple[float, float]:
            sizes.append(n)
            return real_batch(op, n)

        monkeypatch.setattr(br, "_timed_batch", spy)

        def op() -> None:
            """Never advances the clock: every batch reads as zero elapsed."""

        with pytest.raises(RuntimeError, match="zero elapsed time"):
            br.benchmark_operation(op, iterations=1, warmup=0, rounds=1)
        assert len(sizes) > 1, "the batch was never grown; it gave up on the first read"
        assert max(sizes) > sizes[0], "the batch did not grow"

    def test_it_recovers_when_the_batch_becomes_measurable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Growing is the point; raising is only the terminal case.

        A batch that is briefly too short to time must end up measured, not
        abandoned — otherwise this fix would trade a fail-open for a
        fail-noisy on a fast primitive.
        """
        clock = self._virtual_clock(monkeypatch)
        calls = {"n": 0}

        def op() -> None:
            calls["n"] += 1
            # The first 8 operations are free; everything after costs 1 ms.
            if calls["n"] > 8:
                clock["t"] += 0.001

        rate = br.benchmark_operation(op, iterations=8, warmup=0, rounds=1)
        assert rate == pytest.approx(1000.0, rel=0.05)
        assert rate != float("inf")

    def test_the_json_record_refuses_a_non_finite_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The writer is the second line, and it fails closed.

        Even if some future path produced a non-finite rate, the record must
        not be written: ``Infinity`` in a results file is unparseable by a
        strict reader (RFC 8259) and clears every floor it is compared
        against.

        This drives ``benchmark_runner.main()``.  It used to be::

            with pytest.raises(ValueError):
                with open(out, "w") as handle:
                    json.dump({"ops_per_sec": float("inf")}, handle, allow_nan=False)

        which touches no repository code at all: it asserts that CPython's
        ``json.dump`` raises on ``inf`` when the caller passes
        ``allow_nan=False``.  No change to this repository could make it fail,
        and it was counted as one of the tests pinning the control.
        """
        out = tmp_path / "results.json"
        # Built from the runner's OWN report generator so the fixture cannot
        # drift from the schema main() consumes, then poisoned in one field.
        poisoned = br.generate_report([])
        poisoned["benchmarks"] = {"widget": {"ops_per_sec": float("inf")}}
        monkeypatch.setattr(br, "run_all_benchmarks", lambda *a, **k: {})
        monkeypatch.setattr(br, "generate_report", lambda *a, **k: poisoned)
        monkeypatch.setattr(sys, "argv", ["benchmark_runner.py", "--output", str(out)])

        with pytest.raises(ValueError):
            br.main()

        assert not out.exists(), (
            "a truncated record was left on disk. json.dump() encodes into the "
            "open file and raises part way through; a downstream step that "
            "checks whether the artefact exists would call that a run. "
            "Serialise with json.dumps() before opening the file."
        )

    def test_the_same_path_writes_a_finite_record(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-vacuity for the test above: ``main()`` must otherwise write."""
        out = tmp_path / "results.json"
        clean = br.generate_report([])
        clean["benchmarks"] = {"widget": {"ops_per_sec": 1234.5}}
        monkeypatch.setattr(br, "run_all_benchmarks", lambda *a, **k: {})
        monkeypatch.setattr(br, "generate_report", lambda *a, **k: clean)
        monkeypatch.setattr(sys, "argv", ["benchmark_runner.py", "--output", str(out)])

        br.main()

        assert json.loads(out.read_text(encoding="utf-8")) == clean

    def test_the_runner_writes_with_allow_nan_disabled(self) -> None:
        """Stated at the call site, because the default is the unsafe one."""
        source = (REPO_ROOT / "benchmarks" / "benchmark_runner.py").read_text(encoding="utf-8")
        assert "allow_nan=False" in source
        assert "json.dump(report, f, indent=2)" not in source


class TestPerPrimitiveSampling:
    """The high-variance primitives get more measurements, and the map stays real.

    Fourteen of the nineteen benchmarks agree within 3% across whole runs on a
    quiet host.  Five do not, and they share a shape: each is either
    rejection-sampled (the ML-DSA family — the rejection count is a constant
    per (key, message) pair, so one run samples a pair's luck) or a composite
    containing one.  The 256-input pool removed the message half of that
    variance; the key half is redrawn per run, so the remedy is more
    independent measurements.

    These pin the mechanism rather than a measured number, so they are
    meaningful on any host.
    """

    def test_every_repeated_name_is_a_registered_benchmark(self) -> None:
        """A rename must not silently drop a primitive back to one measurement."""
        registered: set[str] = set()
        for path in (Path("benchmarks/baseline.json"), Path("benchmarks/arm-baseline.json")):
            baseline = br.load_baseline(path)
            registered |= set(baseline.get("benchmarks", {}))
            registered |= set(baseline.get("pqc_benchmarks", {}))
        unknown = set(br._SAMPLING_REPEATS) - registered
        assert not unknown, (
            f"_SAMPLING_REPEATS names primitives the baseline does not define: "
            f"{sorted(unknown)} — a rename left the extra sampling pointing at "
            f"nothing, and the primitive it was meant to cover is back to a "
            f"single measurement"
        )

    def test_repeat_counts_are_greater_than_one(self) -> None:
        """An entry of 1 is a no-op that reads like coverage."""
        for name, repeats in br._SAMPLING_REPEATS.items():
            assert repeats > 1, f"{name}: a repeat count of {repeats} measures nothing extra"

    def test_a_repeated_benchmark_is_actually_invoked_repeatedly(self) -> None:
        calls = {"n": 0}

        def fake() -> float:
            calls["n"] += 1
            return float(calls["n"])

        name = next(iter(br._SAMPLING_REPEATS))
        result = br._measure_benchmark(name, fake)
        assert calls["n"] == br._SAMPLING_REPEATS[name]
        # Fastest wins, matching benchmark_operation's estimator.
        assert result == float(br._SAMPLING_REPEATS[name])

    def test_an_unlisted_benchmark_is_invoked_once(self) -> None:
        calls = {"n": 0}

        def fake() -> float:
            calls["n"] += 1
            return 1.0

        assert br._measure_benchmark("not-a-registered-name", fake) == 1.0
        assert calls["n"] == 1

    def test_none_short_circuits_without_further_calls(self) -> None:
        """An absent primitive must not be probed once per repeat."""
        calls = {"n": 0}

        def absent() -> None:
            calls["n"] += 1
            return None

        name = next(iter(br._SAMPLING_REPEATS))
        assert br._measure_benchmark(name, absent) is None
        assert calls["n"] == 1

    def test_the_rejection_sampled_primitives_are_covered(self) -> None:
        """The ML-DSA family is a reason this exists; it must stay covered.

        Named individually rather than derived, because the point is that a
        future addition to the suite gets a deliberate decision rather than the
        default.
        """
        for name in ("dilithium_keygen", "dilithium_sign"):
            assert name in br._SAMPLING_REPEATS, (
                f"{name} is rejection-sampled and needs more than one whole-run "
                f"measurement to produce a stable floor"
            )


class TestValidityWindowCannotBeExtendedWithoutRemeasuring:
    """The escape hatch in the freshness test, closed.

    ``tests/test_benchmark_baseline_freshness.py`` fails once the package
    version passes a baseline's ``applies_through_release`` — but bumping that
    field is itself a way to satisfy it, and nothing required the floors to be
    re-measured first. The cheapest way to make the freshness test green was to
    declare the stale floors valid for longer.

    ``arm-baseline.json`` shows the shape: ``baseline_source_release: 3.1.0``
    against ``applies_through_release: 4.0.0``, floors measured nine minor
    releases before the window they are declared valid for, with the file's own
    notes recording that the 2026-07-29 recalibration skipped AArch64. The
    freshness gate passed throughout.

    The rule is about the diff, not the current state, so it constrains the
    next extension rather than retroactively failing the files as they stand.
    """

    @staticmethod
    def _install_refs(
        monkeypatch: pytest.MonkeyPatch,
        before: dict[str, Any],
        after: dict[str, Any],
    ) -> Any:
        """Stub ``_run_git`` so the guard reads synthetic before/after files."""
        import subprocess

        import benchmarks.check_baseline_justification as guard

        def fake_run_git(*args: str) -> str:
            ref, _, path = args[1].partition(":")
            if path != guard.ARM_BASELINE_PATH:
                raise subprocess.CalledProcessError(1, "git")
            return json.dumps(before if ref == "BASE" else after)

        monkeypatch.setattr(guard, "_run_git", fake_run_git)
        return guard

    @staticmethod
    def _baseline(through: str, source: str, value: int) -> dict[str, Any]:
        return {
            "metadata": {
                "applies_through_release": through,
                "baseline_source_release": source,
            },
            "benchmarks": {"ama_sha3_256_hash": {"baseline_value": value}},
            "pqc_benchmarks": {},
        }

    def test_extending_the_window_alone_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        guard = self._install_refs(
            monkeypatch,
            self._baseline("4.0.0", "3.1.0", 100),
            self._baseline("5.0.0", "3.1.0", 100),
        )
        failures = guard._check_validity_window("BASE", "HEAD")
        assert len(failures) == 1, failures
        assert "no floor was re-measured" in failures[0]

    @pytest.mark.parametrize(
        "after,why",
        [
            (("5.0.0", "3.1.0", 150), "a floor was re-measured"),
            (("5.0.0", "5.0.0", 100), "baseline_source_release advanced"),
            (("4.0.0", "3.1.0", 100), "the window did not move"),
            (("3.5.0", "3.1.0", 100), "the window was narrowed"),
        ],
    )
    def test_legitimate_edits_are_allowed(
        self, monkeypatch: pytest.MonkeyPatch, after: tuple[str, str, int], why: str
    ) -> None:
        guard = self._install_refs(
            monkeypatch,
            self._baseline("4.0.0", "3.1.0", 100),
            self._baseline(*after),
        )
        assert guard._check_validity_window("BASE", "HEAD") == [], why

    def test_the_current_tree_satisfies_the_rule(self) -> None:
        """This branch must not itself be extending a window silently."""
        import subprocess

        import benchmarks.check_baseline_justification as guard

        try:
            assert guard._check_validity_window("origin/main", "HEAD") == []
        except subprocess.CalledProcessError:  # pragma: no cover - shallow clone
            pytest.skip("origin/main is not available in this checkout")


class TestReleaseParsing:
    """The release parser must be exact, and must not be quadratic.

    ``re.fullmatch(r"(\\d+)\\.(\\d+)\\.(\\d+)")`` — three unbounded quantifiers
    separated by literals — is the shape CodeQL reports as a polynomial ReDoS.
    Measured before the rewrite: 4.2x per doubling, 1,545 ms on a 16,000-character
    run. The parsed value comes from a JSON file in this repository rather than
    from a remote party, so the exposure was small; a version parser simply has
    no need of a regex, and "the input is trusted today" is a weaker guarantee
    than not being quadratic at all.
    """

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("4.0.0", (4, 0, 0)),
            (" 3.1.0 ", (3, 1, 0)),
            ("10.20.30", (10, 20, 30)),
            ("4.0", None),
            ("4.0.0.1", None),
            ("4..0", None),
            ("a.b.c", None),
            ("", None),
            ("-1.0.0", None),
            ("99999.0.0", None),  # beyond the component width bound
            ("٤.٠.٠", None),  # non-ASCII digits: isdigit() is true, int() would accept
            (None, None),
            (4.0, None),
        ],
    )
    def test_parses_exactly(self, value: object, expected: tuple[int, ...] | None) -> None:
        import benchmarks.check_baseline_justification as guard

        assert guard._release_tuple(value) == expected

    def test_is_linear_on_a_long_run_of_digits(self) -> None:
        """The input that cost 1.5 s before."""
        import time

        import benchmarks.check_baseline_justification as guard

        pathological = "0" * 200_000
        start = time.perf_counter()
        assert guard._release_tuple(pathological) is None
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"parsing 200k digits took {elapsed:.2f}s"

    def test_ordering_is_by_component_not_lexicographic(self) -> None:
        """The comparison the window rule depends on.

        Each parse is asserted non-None first: the return type is Optional, and
        comparing through it would make the ordering assertions unreachable on
        a parser regression rather than failing them.
        """
        import benchmarks.check_baseline_justification as guard

        for higher, lower in (("4.10.0", "4.9.0"), ("10.0.0", "9.9.9")):
            a = guard._release_tuple(higher)
            b = guard._release_tuple(lower)
            assert a is not None and b is not None, (higher, lower)
            assert a > b


class TestProvenanceRecordsTheMeasuredTree:
    """The tree state in the provenance block must describe the measured tree.

    ``_provenance`` used to sample ``git status --porcelain`` at the moment the
    markdown was rendered. A normal run writes ``benchmarks/benchmark-results.
    json`` — a tracked file — before rendering, so the working tree was always
    dirty by then and every report the tool had ever produced carried
    ``(working tree DIRTY)``, including reports produced from a pristine
    checkout.

    A field that always prints the same value carries no information; one that
    always prints the alarming value trains the reader to ignore it. The state
    is now captured once, before the first measurement.
    """

    def test_the_snapshot_is_used_in_preference_to_a_live_query(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(br, "_TREE_STATE", ("c0ffee" * 6 + "abcd", False))

        def _fail(*args: str) -> str:
            raise AssertionError("_provenance queried git despite a captured snapshot")

        monkeypatch.setattr(br, "_git", _fail)
        rendered = dict(br._provenance())["Commit"]
        assert "DIRTY" not in rendered
        assert "c0ffee" in rendered

    def test_a_dirty_snapshot_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The flag must still fire when the tree really was modified."""
        monkeypatch.setattr(br, "_TREE_STATE", ("deadbeef", True))
        assert "working tree DIRTY" in dict(br._provenance())["Commit"]

    def test_writing_the_report_files_does_not_make_the_snapshot_dirty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The regression itself, exercised through the ordering that caused it.

        ``capture_tree_state`` reads a clean tree; the run then modifies it;
        the rendered provenance must still describe what was measured.
        """
        observed: list[tuple[str, ...]] = []

        def _fake_git(*args: str) -> str:
            observed.append(args)
            # Clean on the first status query, dirty on every later one — the
            # shape a run has once it has written its own tracked output.
            if args[0] == "status":
                return "" if len(observed) <= 2 else " M benchmarks/benchmark-results.json"
            return "1234567890abcdef"

        monkeypatch.setattr(br, "_git", _fake_git)
        monkeypatch.setattr(br, "_TREE_STATE", None)

        captured = br.capture_tree_state()
        assert captured[1] is False, "precondition: the tree was clean when measuring began"

        monkeypatch.setattr(br, "_TREE_STATE", captured)
        assert "DIRTY" not in dict(br._provenance())["Commit"]

    def test_without_a_snapshot_it_still_produces_a_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Direct calls (tests, embeddings) must not crash on the fallback."""
        monkeypatch.setattr(br, "_TREE_STATE", None)
        block = dict(br._provenance())
        assert "Commit" in block and "Aggregation" in block

    def test_git_failures_degrade_rather_than_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*args: str) -> str:
            raise OSError("no git here")

        monkeypatch.setattr(subprocess, "run", _boom)
        monkeypatch.setattr(br, "_TREE_STATE", None)
        commit, dirty = br.capture_tree_state()
        assert commit == "unknown"
        assert dirty is False, "an unavailable git must not be reported as a modified tree"


class TestBothRecordsCarryProvenance:
    """The JSON record is the machine-readable one; it had no provenance.

    ``benchmark-report.md`` recorded commit, host, sampling and aggregation;
    ``benchmarks/benchmark-results.json`` recorded none of it. That put the two
    published records on different footings, and left the record another tool
    is most likely to consume unable to say what produced it.
    """

    def test_the_json_report_carries_the_same_fields_as_the_markdown(self) -> None:
        report = br.generate_report([])
        assert "provenance" in report, "the JSON record must carry provenance"
        rendered = {br._provenance_key(label) for label, _ in br._provenance()}
        assert set(report["provenance"]) == rendered, "the two blocks must not drift apart"

    def test_keys_are_machine_readable(self) -> None:
        keys = set(br.generate_report([])["provenance"])
        assert "extra_whole_run_repeats" in keys
        assert all(k == k.lower() and " " not in k for k in keys)

    def test_the_shipped_json_record_has_provenance(self) -> None:
        """The committed record, not just a freshly generated one."""
        path = Path(__file__).resolve().parent.parent / "benchmarks" / "benchmark-results.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        provenance = record.get("provenance")
        assert provenance, f"{path.name} was regenerated without provenance"
        assert provenance.get("commit", "").strip("`") not in ("", "unknown")
        assert "version" in provenance and "host" in provenance


class TestTheRecordedCommandIsTheCommandThatRan:
    """It was a hard-coded string that omitted the flag writing the record.

    Every real run passes ``--output`` as well as ``--baseline``/``--markdown``,
    so copying the recorded command would not reproduce the JSON file it was
    printed in.
    """

    def test_the_flags_actually_used_are_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            ["benchmarks/benchmark_runner.py", "--baseline", "b.json", "--output", "o.json"],
        )
        rendered = br._invocation()
        assert "--output o.json" in rendered
        assert "--baseline b.json" in rendered

    def test_arguments_needing_quoting_are_quoted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys, "argv", ["benchmarks/benchmark_runner.py", "--baseline", "a file.json"]
        )
        assert "'a file.json'" in br._invocation()

    def test_an_absolute_script_path_is_made_repository_relative(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        absolute = str(Path(br.__file__).resolve())
        monkeypatch.setattr(sys, "argv", [absolute, "--verbose"])
        rendered = br._invocation()
        assert rendered.startswith("python benchmarks/benchmark_runner.py")
        assert str(Path(absolute).parent.parent) not in rendered

    def test_the_script_path_is_rendered_the_same_on_every_platform(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Windows regression, asserted as the property it violated.

        ``str(Path(...))`` yields ``benchmarks\\benchmark_runner.py`` on
        Windows, and ``shlex.quote`` then wraps it in single quotes because a
        backslash is a POSIX metacharacter — producing
        ``python 'benchmarks\\benchmark_runner.py'``, which is neither valid
        Windows nor comparable with the same run recorded on Linux. A
        provenance field that renders differently per platform cannot be used
        to compare two measurements, which is most of what it is for.
        """
        monkeypatch.setattr(sys, "argv", [str(Path(br.__file__).resolve())])
        rendered = br._invocation()
        assert "\\" not in rendered, f"platform-specific separator leaked: {rendered!r}"
        assert "'" not in rendered, f"the script path was needlessly quoted: {rendered!r}"
        assert rendered == "python benchmarks/benchmark_runner.py"

    def test_caller_arguments_are_reproduced_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the script path is normalised; the caller's strings are not.

        Rewriting an argument the caller actually passed would make the field
        describe a command that did not run — the defect it was added to fix.
        """
        monkeypatch.setattr(
            sys, "argv", ["benchmarks/benchmark_runner.py", "--baseline", r"C:\\bench\\b.json"]
        )
        assert r"C:\\bench\\b.json" in br._invocation()

    def test_an_unrelated_script_path_degrades_to_its_basename(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["/opt/elsewhere/runner.py"])
        assert br._invocation() == "python runner.py"

    def test_an_empty_argv_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", [])
        assert "benchmark_runner.py" in br._invocation()


class TestPqcRowsAreHardGated:
    """A measured AEAD/PQC/X25519 row must be able to fail the run.

    These rows were built ``optional=True``, which ``main()`` maps to
    warn-and-exit-0 — so all nine populated floors had an infinite blind
    spot while both baseline files described a 15–25% firing threshold and
    cited the 2.1x AES-GCM wrapper regression as the case the recalibration
    prevents.  Reproduced against the real arm baseline: halving the
    aes_256_gcm_encrypt floor's measured rate printed ``[WARN]`` and exited
    0.  A row is only built after a successful measurement (the None path
    skips an absent backend before any row exists), so "optional" carried
    no availability meaning — only the blind spot.
    """

    def _run_one_pqc_row(
        self, monkeypatch: pytest.MonkeyPatch, measured_rate: float | None
    ) -> list[br.BenchmarkResult]:
        baseline = {
            "thresholds": {"regression_threshold_percent": 10},
            "benchmarks": {},
            "pqc_benchmarks": {
                "aes_256_gcm_encrypt": {
                    "description": "synthetic",
                    "baseline_value": 1000.0,
                    "tolerance_percent": 15,
                }
            },
        }
        monkeypatch.setattr(br, "_measure_benchmark", lambda name, func: measured_rate)
        return br.run_all_benchmarks(baseline)

    def test_a_breached_measured_row_fails_the_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        results = self._run_one_pqc_row(monkeypatch, measured_rate=400.0)  # -60%
        assert len(results) == 1
        row = results[0]
        assert row.passed is False
        assert row.optional is False, (
            "a measured PQC row must be hard-gated — optional=True is the "
            "warn-and-exit-0 blind spot the baseline notes claim does not exist"
        )
        # main()'s failure collapse: the row must survive the filter.
        failed = [r for r in results if not r.passed and not r.optional]
        assert failed, "the breached row must reach the CI-failing branch"

    def test_a_healthy_measured_row_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        results = self._run_one_pqc_row(monkeypatch, measured_rate=1000.0)
        assert len(results) == 1 and results[0].passed is True

    def test_an_absent_backend_still_skips_without_a_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        results = self._run_one_pqc_row(monkeypatch, measured_rate=None)
        assert results == [], "no measurement, no row — the only meaning 'optional' ever had"

    def test_no_populated_baseline_row_is_optional(self) -> None:
        """Both committed baseline files must carry optional=false everywhere."""
        for name in ("baseline.json", "arm-baseline.json"):
            data = json.loads((Path(br.__file__).parent / name).read_text(encoding="utf-8"))
            offenders = [
                key
                for key, row in data.get("pqc_benchmarks", {}).items()
                if row.get("optional") is True
            ]
            assert offenders == [], f"{name}: rows opted back out of the gate: {offenders}"


class TestTheReportDoesNotInvertItsOwnColumn:
    """A row 43% slower than its floor rendered as ``+43.0%`` under "Delta".

    ``regression_percent`` is ``-pct_change`` and ``pct_change`` is positive
    when FASTER, so the number is positive when the primitive is SLOWER.  The
    machine-readable sibling names the field honestly
    (``regression_percent`` in ``benchmark-results.json``); the human-facing
    table called the same number "Delta", which a reader takes to mean change
    in throughput, and nothing in the header, legend or provenance block said
    otherwise.  Only the artefact a person reads was ambiguous.
    """

    @staticmethod
    def _render(rows: list[tuple[float, float, float]]) -> str:
        results = [
            br.BenchmarkResult(
                name=f"row{i}",
                description=f"row {i}",
                ops_per_second=ops,
                baseline_value=floor,
                tolerance_percent=45.0,
                regression_percent=regression,
                passed=True,
            )
            for i, (ops, floor, regression) in enumerate(rows)
        ]
        return br.generate_markdown_report(results, br.generate_report(results))

    def test_the_column_is_named_for_the_field_it_carries(self) -> None:
        md = self._render([(100.0, 200.0, 50.0)])
        assert "| Regression |" in md
        assert "| Delta |" not in md

    def test_the_legend_states_the_direction(self) -> None:
        md = self._render([(100.0, 200.0, 50.0)])
        assert "positive means SLOWER" in md

    def test_a_slower_row_renders_positive_and_a_faster_row_negative(self) -> None:
        """The property itself, in both directions.

        Slower than the floor is ``+``; faster is ``-``.  Whichever convention
        is chosen, the legend and the sign must agree, and this is what would
        catch a future "fix" that negated one without the other.
        """
        md = self._render([(100.0, 200.0, 50.0), (300.0, 200.0, -50.0)])
        slower = next(line for line in md.splitlines() if "| row 0 |" in line)
        faster = next(line for line in md.splitlines() if "| row 1 |" in line)
        assert "+50.0%" in slower, slower
        assert "-50.0%" in faster, faster

    def test_the_published_report_matches_the_generator(self) -> None:
        """The committed artefact must be what the current generator emits.

        Rendered from the committed ``benchmark-results.json``, so this
        compares presentation only — the numbers are that run's, not this
        host's.
        """
        data = json.loads(
            (REPO_ROOT / "benchmarks" / "benchmark-results.json").read_text(encoding="utf-8")
        )
        results = [br.BenchmarkResult(**row) for row in data["results"]]
        expected = br.generate_markdown_report(results, data)
        published = (REPO_ROOT / "benchmark-report.md").read_text(encoding="utf-8")
        assert published == expected, (
            "benchmark-report.md is not what benchmark_runner would produce from "
            "benchmarks/benchmark-results.json; regenerate it rather than editing "
            "it by hand"
        )


class TestTheTwoPublishedArtefactsCannotDisagreeByARounding:
    """The markdown must render the numbers the JSON record stores.

    ``generate_report()`` quantises every published measurement to
    ``PUBLISHED_DECIMALS`` (2); the table displays fewer digits than that.  The
    table used to format the RAW value, so wherever the two roundings disagree
    the pair contradicted itself: ``hkdf_derive``'s regression was
    6.747801524276505%,
    which the table rendered ``+6.7%`` while the JSON stored ``6.75``, from
    which the same generator renders ``+6.8%``.

    ``test_the_published_report_matches_the_generator`` above caught that
    instance, but only because the committed record happened to contain a
    half-way value.  A later run whose numbers all round the same way would
    make that assertion pass over the same defect, so the property is pinned
    here directly, on values chosen to exercise it in both columns.
    """

    @staticmethod
    def _rendered_both_ways(result: br.BenchmarkResult) -> tuple[str, str]:
        """The page from live results, and from those results JSON round-tripped.

        The same ``report`` dict feeds both renders, so the timestamp and
        provenance are identical and any difference is the measurements.
        """
        report = br.generate_report([result])
        from_live = br.generate_markdown_report([result], report)
        stored = [br.BenchmarkResult(**row) for row in json.loads(json.dumps(report))["results"]]
        return from_live, br.generate_markdown_report(stored, report)

    def test_a_half_way_regression_renders_identically_from_both(self) -> None:
        """6.7478 -> raw ``+6.7%``; stored as 6.75 -> ``+6.8%``.

        The three numbers are the repaired record's own: ``hkdf_derive`` at
        122,478.37 ops/sec against a 131,341 floor is a regression of
        6.747801524276505%.  ``BenchmarkResult`` does not derive
        ``regression_percent`` from the other two, so a fixture is free to set
        them inconsistently — this one does not, because a reader checking the
        arithmetic should find it holds.
        """
        result = br.BenchmarkResult(
            name="row0",
            description="row 0",
            ops_per_second=122478.37,
            baseline_value=131341.0,
            tolerance_percent=45.0,
            regression_percent=6.747801524276505,
            passed=True,
        )
        from_live, from_json = self._rendered_both_ways(result)
        assert from_live == from_json
        assert "+6.8%" in from_live

    def test_a_half_way_throughput_renders_identically_from_both(self) -> None:
        """The Ops/sec column has the same hazard: 1.4999 -> ``1``; 1.5 -> ``2``."""
        result = br.BenchmarkResult(
            name="row0",
            description="row 0",
            ops_per_second=1.4999,
            baseline_value=2.0,
            tolerance_percent=45.0,
            regression_percent=25.005,  # (2.0 - 1.4999) / 2.0 * 100, exactly
            passed=True,
        )
        from_live, from_json = self._rendered_both_ways(result)
        assert from_live == from_json

    def test_an_ordinary_row_is_unaffected(self) -> None:
        """The control: quantising must not move a number that needs no rounding."""
        result = br.BenchmarkResult(
            name="row0",
            description="row 0",
            ops_per_second=1234.0,
            baseline_value=1000.0,
            tolerance_percent=45.0,
            regression_percent=-23.4,
            passed=True,
        )
        from_live, from_json = self._rendered_both_ways(result)
        assert from_live == from_json
        assert "| 1,234 |" in from_live
        assert "-23.4%" in from_live


class TestTheJsonProvenanceIsMachineReadable:
    """The JSON block's values must be values, not rendered markdown.

    `_provenance()` renders ONE list for two artefacts, which is the point.
    What it emits is markdown, and `generate_report()` copied it into the JSON
    verbatim, so `provenance.commit` carried the markdown backticks and — on a
    dirty tree — the ``(working tree DIRTY)`` suffix as well:

        "commit": "`3ce4b588…`"                     (clean)
        "commit": "`3ce4b588…` (working tree DIRTY)" (dirty)

    Splitting cleanliness into its own "Tree" row was supposed to fix exactly
    this, and did not touch the commit row.  A consumer comparing the field to
    `git rev-parse HEAD` gets a mismatch it cannot interpret, in both states.
    """

    def test_commit_is_a_bare_hash_on_a_clean_tree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(br, "_TREE_STATE", ("a" * 40, False))
        provenance = br.generate_report([])["provenance"]
        assert provenance["commit"] == "a" * 40, provenance["commit"]
        assert provenance["tree"] == "clean"

    def test_commit_is_a_bare_hash_on_a_dirty_tree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(br, "_TREE_STATE", ("b" * 40, True))
        provenance = br.generate_report([])["provenance"]
        assert provenance["commit"] == "b" * 40, (
            "the dirty marker is still glued to the commit id, which is what "
            "the Tree row was added to stop"
        )
        assert "DIRTY" in provenance["tree"]

    def test_the_markdown_still_shows_the_dirt_on_the_commit_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The human-facing rendering is unchanged: only the JSON was wrong."""
        monkeypatch.setattr(br, "_TREE_STATE", ("c" * 40, True))
        commit_cell = dict(br._provenance())["Commit"]
        assert commit_cell.startswith("`c" + "c" * 39 + "`")
        assert "working tree DIRTY" in commit_cell

    def test_no_json_provenance_value_carries_markdown_ticks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(br, "_TREE_STATE", ("d" * 40, False))
        provenance = br.generate_report([])["provenance"]
        ticked = {k: v for k, v in provenance.items() if isinstance(v, str) and "`" in v}
        assert not ticked, f"markdown formatting reached the JSON block: {ticked}"
