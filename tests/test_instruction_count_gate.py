#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_instruction_counts.py``.

The gate under test replaces a performance lane that could not do its job.
``benchmarks/baseline.json`` compares ``operations_per_second`` sampled with
``time.perf_counter()`` on shared CI runners; ``benchmark_runner.py`` records
one UNCHANGED binary measuring 917, 1845 and 3086 ops/sec, and the x86
tolerances sit at 45% so the lane stops flapping.  A 45% band cannot detect a
30% regression.

A replacement gate is worth nothing until it is shown to FAIL on the thing it
claims to catch, so every failure mode below is driven with synthesised
baseline/measurement pairs rather than asserted in prose.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_instruction_counts.py"
BASELINE_PATH = REPO_ROOT / "benchmarks" / "instruction-baseline.json"
MEASURE_PATH = REPO_ROOT / "benchmarks" / "measure_instruction_counts.py"
DRIVER_PATH = REPO_ROOT / "benchmarks" / "ic_driver.c"

FINGERPRINT = "arch=x86-64 sha3=AVX2 kyber=AVX2"
OTHER_FINGERPRINT = "arch=aarch64 sha3=NEON kyber=NEON"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_instruction_counts", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load()


BASE_OPS = {"sha3_256": 38_072, "ed25519_sign": 206_910, "kyber_keygen": 744_872}


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def _baseline(
    tmp_path: Path, operations: dict[str, int] | None = None, fingerprint: str = FINGERPRINT
) -> Path:
    return _write(
        tmp_path / "baseline.json",
        {"profiles": {fingerprint: {"operations": operations or dict(BASE_OPS)}}},
    )


def _measured(
    tmp_path: Path,
    operations: dict[str, int] | None = None,
    fingerprint: str = FINGERPRINT,
    **extra: Any,
) -> Path:
    document: dict[str, Any] = {
        "fingerprint": fingerprint,
        "operations": operations if operations is not None else dict(BASE_OPS),
    }
    document.update(extra)
    return _write(tmp_path / "measured.json", document)


def _run(gate: ModuleType, baseline: Path, measured: Path, *extra: str) -> int:
    return int(gate.main(["--baseline", str(baseline), "--measured", str(measured), *extra]))


# --------------------------------------------------------------------------
# The passing shape
# --------------------------------------------------------------------------


def test_identical_counts_pass(gate: ModuleType, tmp_path: Path) -> None:
    assert _run(gate, _baseline(tmp_path), _measured(tmp_path)) == 0


def test_a_change_inside_tolerance_passes(gate: ModuleType, tmp_path: Path) -> None:
    """Codegen drift between compiler versions must not fail the gate."""
    drifted = dict(BASE_OPS)
    drifted["sha3_256"] = int(38_072 * 1.01)  # +1%, inside the 2% band
    assert _run(gate, _baseline(tmp_path), _measured(tmp_path, drifted)) == 0


# --------------------------------------------------------------------------
# What it must catch
# --------------------------------------------------------------------------


def test_a_regression_beyond_tolerance_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case the gate exists for."""
    regressed = dict(BASE_OPS)
    regressed["sha3_256"] = int(38_072 * 1.05)  # +5%
    assert _run(gate, _baseline(tmp_path), _measured(tmp_path, regressed)) == 1
    assert "REGRESSED" in capsys.readouterr().err


def test_the_measured_simd_demotion_would_fail(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Real numbers: ChaCha20-Poly1305 forced off its AVX2 kernel.

    Measured while building this gate — 11,483 Ir with the AVX2 kernel wired,
    28,265 Ir without. A silent kernel demotion is exactly the regression the
    wall-clock lane's 45% tolerance can swallow.
    """
    baseline = _baseline(tmp_path, {"chacha20poly1305_encrypt": 11_483})
    measured = _measured(tmp_path, {"chacha20poly1305_encrypt": 28_265})
    assert _run(gate, baseline, measured) == 1
    assert "+146" in capsys.readouterr().err


def test_an_unexplained_improvement_also_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A large drop is a claim about the code and must be acknowledged.

    Work silently disappearing is as much a signal as work appearing: a
    correctness bug that skips a step reads as an improvement.
    """
    improved = dict(BASE_OPS)
    improved["kyber_keygen"] = int(744_872 * 0.80)
    assert _run(gate, _baseline(tmp_path), _measured(tmp_path, improved)) == 1
    assert "IMPROVED" in capsys.readouterr().err


# --------------------------------------------------------------------------
# Fail-closed: a comparison that did not happen is never a pass
# --------------------------------------------------------------------------


def test_an_unknown_dispatch_configuration_fails_closed(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AVX-512 counts are not comparable to NEON counts."""
    measured = _measured(tmp_path, fingerprint=OTHER_FINGERPRINT)
    assert _run(gate, _baseline(tmp_path), measured) == 2
    assert "no baseline profile" in capsys.readouterr().err


def test_a_baselined_operation_that_was_not_measured_fails(
    gate: ModuleType, tmp_path: Path
) -> None:
    """Coverage must not shrink silently."""
    partial = {"sha3_256": 38_072}
    assert _run(gate, _baseline(tmp_path), _measured(tmp_path, partial)) == 1


def test_a_subset_run_is_permitted_only_when_asked(gate: ModuleType, tmp_path: Path) -> None:
    partial = {"sha3_256": 38_072}
    baseline = _baseline(tmp_path)
    measured = _measured(tmp_path, partial)
    assert _run(gate, baseline, measured) == 1
    assert _run(gate, baseline, measured, "--allow-subset") == 0


def test_an_unbaselined_operation_fails_even_in_a_subset_run(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--allow-subset relaxes missing operations, never ungated ones."""
    extra = dict(BASE_OPS)
    extra["brand_new_primitive"] = 12_345
    result = _run(gate, _baseline(tmp_path), _measured(tmp_path, extra), "--allow-subset")
    assert result == 1
    assert "brand_new_primitive" in capsys.readouterr().err


def test_a_non_reproducible_measurement_is_never_a_pass(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    measured = _measured(tmp_path, not_reproducible={"dilithium_sign": [1, 2]})
    assert _run(gate, _baseline(tmp_path), measured) == 2
    assert "did not reproduce" in capsys.readouterr().err


def test_a_measurement_without_a_fingerprint_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    measured = _write(tmp_path / "measured.json", {"operations": dict(BASE_OPS)})
    assert _run(gate, _baseline(tmp_path), measured) == 2


def test_an_empty_baseline_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    baseline = _write(tmp_path / "baseline.json", {"profiles": {}})
    assert _run(gate, baseline, _measured(tmp_path)) == 2


def test_an_empty_measurement_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    measured = _write(tmp_path / "measured.json", {"fingerprint": FINGERPRINT, "operations": {}})
    assert _run(gate, _baseline(tmp_path), measured) == 2


def test_a_missing_file_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    assert _run(gate, tmp_path / "nope.json", _measured(tmp_path)) == 2


# --------------------------------------------------------------------------
# A/B mode: two measurements on one runner, no stored baseline
# --------------------------------------------------------------------------


def test_a_measurement_file_is_accepted_as_the_reference(gate: ModuleType, tmp_path: Path) -> None:
    """A/B is what CI uses: merge-base build vs head build, same runner.

    A stored baseline cannot serve that role, because ubuntu-latest spans two
    CPU classes and whichever one did not record the profile would fail closed.
    """
    reference = _write(
        tmp_path / "base.json",
        {"fingerprint": FINGERPRINT, "operations": dict(BASE_OPS)},
    )
    assert _run(gate, reference, _measured(tmp_path)) == 0


def test_ab_mode_catches_a_regression(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reference = _write(
        tmp_path / "base.json",
        {"fingerprint": FINGERPRINT, "operations": dict(BASE_OPS)},
    )
    worse = dict(BASE_OPS)
    worse["ed25519_sign"] = int(206_910 * 1.30)
    assert _run(gate, reference, _measured(tmp_path, worse)) == 1
    assert "REGRESSED" in capsys.readouterr().err


def test_ab_mode_refuses_to_compare_across_runners(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two different machines' counts are not a regression signal."""
    reference = _write(
        tmp_path / "base.json",
        {"fingerprint": OTHER_FINGERPRINT, "operations": dict(BASE_OPS)},
    )
    assert _run(gate, reference, _measured(tmp_path)) == 2
    assert "not comparable" in capsys.readouterr().err


# --------------------------------------------------------------------------
# The shipped baseline, and the parts that must stay wired
# --------------------------------------------------------------------------


def test_the_shipped_baseline_is_well_formed() -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    profiles = document["profiles"]
    assert profiles, "a baseline with no profile gates nothing"
    for fingerprint, profile in profiles.items():
        assert "arch=" in fingerprint, f"{fingerprint} is not a dispatch fingerprint"
        operations = profile["operations"]
        assert operations, f"{fingerprint} records no operations"
        for name, count in operations.items():
            assert isinstance(count, int) and count > 0, f"{name} has a bad count"


def test_the_baseline_covers_every_primitive_family() -> None:
    """A gate that covers only hashing would not have caught the AEAD case."""
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    covered = set()
    for profile in document["profiles"].values():
        covered.update(profile["operations"])
    for family in (
        "sha3_",
        "sha512",
        "hmac_",
        "hkdf_",
        "ed25519_",
        "x25519_",
        "aes_256_gcm",
        "chacha20poly1305",
        "secp256k1_",
        "kyber_",
        "dilithium_",
    ):
        assert any(
            name.startswith(family) or family in name for name in covered
        ), f"no operation covers {family}; that primitive is ungated"


def test_the_tolerance_is_far_tighter_than_the_wall_clock_lane() -> None:
    """The whole point is a band that can detect a real regression."""
    gate_module = _load()
    assert gate_module.DEFAULT_TOLERANCE_PERCENT <= 5.0, (
        "a wide band here would reproduce the defect this gate replaces: "
        "benchmarks/baseline.json sits at 45%, which cannot detect a 30% "
        "regression."
    )


def test_the_driver_and_measurement_tool_are_present() -> None:
    """A gate whose measurement half is missing cannot be run at all."""
    assert DRIVER_PATH.is_file(), "benchmarks/ic_driver.c is missing"
    assert MEASURE_PATH.is_file(), "benchmarks/measure_instruction_counts.py is missing"


def test_the_driver_pins_autotune_off() -> None:
    """Auto-tune live means the process executes different code between runs.

    Measured: with auto-tune enabled the first ``ama_sha3_256`` call cost
    2,601,289,188 instructions against 632,977 with it disabled, and the
    dispatcher's verdict depends on host load. Without this pin no count is
    reproducible and the gate is worthless.
    """
    source = MEASURE_PATH.read_text(encoding="utf-8")
    assert (
        "AMA_DISPATCH_NO_AUTOTUNE" in source
    ), "the measurement tool no longer disables dispatch auto-tune"
