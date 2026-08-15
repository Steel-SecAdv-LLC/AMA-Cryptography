#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for benchmark baseline runner-class enforcement."""

from __future__ import annotations

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


def test_full_package_create_uses_best_of_rounds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The GC-heavy package-create benchmark samples multiple rounds."""

    calls: list[tuple[int, int, int]] = []

    def fake_best_of(
        operation: Callable[[], object], iterations: int, warmup: int, rounds: int
    ) -> float:
        calls.append((iterations, warmup, rounds))
        return 123.0

    monkeypatch.setattr("benchmarks.benchmark_runner.benchmark_operation_best_of", fake_best_of)

    assert br.run_full_package_create_benchmark() == 123.0
    assert calls == [(20, 2, 5)]


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
        import json
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
        import json

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

    def test_an_unrelated_script_path_degrades_to_its_basename(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["/opt/elsewhere/runner.py"])
        assert br._invocation() == "python runner.py"

    def test_an_empty_argv_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", [])
        assert "benchmark_runner.py" in br._invocation()
