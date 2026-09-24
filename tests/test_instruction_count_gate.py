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
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_instruction_counts.py"
BASELINE_PATH = REPO_ROOT / "benchmarks" / "instruction-baseline.json"
MEASURE_PATH = REPO_ROOT / "benchmarks" / "measure_instruction_counts.py"
DRIVER_PATH = REPO_ROOT / "benchmarks" / "ic_driver.c"
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci-build-test.yml"
AB_JOB = "instruction-count-regression"

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
# Acknowledged changes: a branch that means to move a count says so
# --------------------------------------------------------------------------


ACK_PATH = REPO_ROOT / "benchmarks" / "instruction-count-acknowledgements.json"

LONG_REASON = (
    "Keccak gains the AVX2 kernel on this branch, which is why every "
    "Keccak-driven row moves by the same proportion."
)


def _acks(tmp_path: Path, entries: dict[str, dict[str, object]]) -> Path:
    return _write(tmp_path / "acks.json", {"acknowledgements": entries})


def test_an_acknowledged_change_passes(gate: ModuleType, tmp_path: Path) -> None:
    moved = dict(BASE_OPS)
    moved["sha3_256"] = 12_000  # -68%
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 12_000, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _baseline(tmp_path),
        _measured(tmp_path, moved),
        "--acknowledgements",
        str(acks),
    )
    assert result == 0


def test_an_unacknowledged_change_still_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The acknowledgement file must not become a blanket exemption."""
    moved = dict(BASE_OPS)
    moved["ed25519_sign"] = 300_000
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 38_072, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _baseline(tmp_path),
        _measured(tmp_path, moved),
        "--acknowledgements",
        str(acks),
    )
    assert result == 1
    assert "not acknowledged" in capsys.readouterr().err


def test_an_operation_that_moved_again_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An acknowledgement covers ONE measured change, not all future drift."""
    moved = dict(BASE_OPS)
    moved["sha3_256"] = 9_000  # acknowledged at 12,000
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 12_000, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _baseline(tmp_path),
        _measured(tmp_path, moved),
        "--acknowledgements",
        str(acks),
    )
    assert result == 1
    assert "moved again" in capsys.readouterr().err


def test_a_stale_acknowledgement_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file of entries that no longer apply hides the ones that do."""
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 12_000, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _baseline(tmp_path),
        _measured(tmp_path),  # nothing moved
        "--acknowledgements",
        str(acks),
    )
    assert result == 1
    assert "stale" in capsys.readouterr().err


# --------------------------------------------------------------------------
# After the branch that wrote an acknowledgement merges
#
# The file records moves between a merge-base and a branch head. Once that
# branch merges, the next pull request's merge-base already contains every
# move, the A/B comparison shows none of them, and an entry is no longer
# "out of tolerance". Treating that as stale failed the first unrelated pull
# request after a merge on every entry in the file — fifteen of them for the
# 5.0.0 branch — until somebody edited a file the pull request never touched.
# --------------------------------------------------------------------------


def _reference(tmp_path: Path, operations: dict[str, int]) -> Path:
    """An A/B reference measurement (what CI measures on the merge-base)."""
    return _write(
        tmp_path / "base.json",
        {"fingerprint": FINGERPRINT, "operations": operations},
    )


def test_an_acknowledgement_whose_change_has_landed_passes(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reference measures the entry's ``to``: the change is in the base."""
    landed = dict(BASE_OPS)
    landed["sha3_256"] = 12_000
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 12_000, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _reference(tmp_path, landed),
        _measured(tmp_path, dict(landed)),  # an unrelated pull request
        "--acknowledgements",
        str(acks),
    )
    out = capsys.readouterr().out
    assert result == 0, out
    assert "Landed (L): 1" in out and "sha3_256" in out


def test_the_shipped_acknowledgements_do_not_fail_the_next_pull_request(
    gate: ModuleType, tmp_path: Path
) -> None:
    """The real file, in the state it is in once this branch has merged.

    Every acknowledged operation is at its recorded ``to`` on BOTH sides —
    the merge-base contains the change and the next pull request does not
    touch it. This is the exact input the first A/B run after the merge sees.
    """
    shipped = json.loads(ACK_PATH.read_text(encoding="utf-8"))["acknowledgements"]
    after_merge = dict(BASE_OPS)
    after_merge.update({name: int(entry["to"]) for name, entry in shipped.items()})
    result = _run(
        gate,
        _reference(tmp_path, after_merge),
        _measured(tmp_path, dict(after_merge)),
        "--acknowledgements",
        str(ACK_PATH),
    )
    assert result == 0


def test_a_landed_acknowledgement_excuses_no_later_move(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Landed is only ever a verdict on an operation INSIDE tolerance.

    With the change in the base, a later pull request that moves the same
    operation again is compared against the entry's ``from`` — which the base
    no longer measures — and fails until it is re-acknowledged.
    """
    landed = dict(BASE_OPS)
    landed["sha3_256"] = 12_000
    moved = dict(landed)
    moved["sha3_256"] = 15_000  # +25% on top of the landed change
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 12_000, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _reference(tmp_path, landed),
        _measured(tmp_path, moved),
        "--acknowledgements",
        str(acks),
    )
    assert result == 1
    assert "different comparison" in capsys.readouterr().err


def test_an_acknowledgement_still_matching_its_from_is_stale_not_landed(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``from`` test comes first, so an entry that moves nothing is stale.

    An entry whose ``from`` and ``to`` lie within tolerance of each other
    matches the reference on BOTH sides. Classified as landed, it would stay
    in the file forever explaining nothing; the reference still measuring its
    ``from`` is what says the acknowledged move is not there.
    """
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 38_500, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _reference(tmp_path, dict(BASE_OPS)),
        _measured(tmp_path),  # nothing moved
        "--acknowledgements",
        str(acks),
    )
    captured = capsys.readouterr()
    assert result == 1
    assert "still measures its 'from'" in captured.err
    assert "Landed" not in captured.out


def test_an_acknowledgement_the_reference_matches_on_neither_side_fails(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reference measures neither ``from`` nor ``to``: the entry is stale.

    The numbers are chosen so that the HEAD value is within tolerance of the
    entry's ``to`` while the REFERENCE is not (12,400 is 3.3% from 12,000;
    12,200 is 1.7% from it and 1.6% from 12,400). A gate that asked the head
    rather than the reference whether the change had landed would pass this.
    """
    reference = dict(BASE_OPS)
    reference["sha3_256"] = 12_400
    head = dict(BASE_OPS)
    head["sha3_256"] = 12_200
    acks = _acks(
        tmp_path,
        {"sha3_256": {"from": 38_072, "to": 12_000, "reason": LONG_REASON}},
    )
    result = _run(
        gate,
        _reference(tmp_path, reference),
        _measured(tmp_path, head),
        "--acknowledgements",
        str(acks),
    )
    assert result == 1
    assert "neither" in capsys.readouterr().err


def test_an_acknowledgement_without_a_reason_is_rejected(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    acks = _acks(tmp_path, {"sha3_256": {"from": 1, "to": 2, "reason": "faster"}})
    result = _run(
        gate,
        _baseline(tmp_path),
        _measured(tmp_path),
        "--acknowledgements",
        str(acks),
    )
    assert result == 2
    assert "no real reason" in capsys.readouterr().err


def test_an_acknowledgement_without_measured_values_is_rejected(
    gate: ModuleType, tmp_path: Path
) -> None:
    """Values are what let the gate check the entry against reality."""
    acks = _acks(tmp_path, {"sha3_256": {"reason": LONG_REASON}})
    result = _run(
        gate,
        _baseline(tmp_path),
        _measured(tmp_path),
        "--acknowledgements",
        str(acks),
    )
    assert result == 2


def test_the_shipped_acknowledgements_are_well_formed() -> None:
    document = json.loads(ACK_PATH.read_text(encoding="utf-8"))
    entries = document["acknowledgements"]
    assert entries, "an empty acknowledgements file gates nothing"
    for operation, entry in entries.items():
        assert entry["from"] > 0 and entry["to"] > 0, operation
        assert len(entry["reason"]) >= 40, f"{operation} gives no real reason"
        assert entry.get("commits"), f"{operation} names no commit"


def test_the_ml_dsa_signing_change_is_acknowledged_as_breaking() -> None:
    """The largest change on this branch is a declared interoperability break.

    `ama_dilithium_sign` moved from ML-DSA.Sign_internal (FIPS 204 Algorithm 7)
    to the Sec 5.2 external interface, which changes mu and therefore every
    rejection-sampling decision. Measured: the same seed gives an identical
    public key on both sides but different signatures, and each side rejects
    the other's. Anyone reading this file must find that, not "+146%, faster
    NTT".
    """
    document = json.loads(ACK_PATH.read_text(encoding="utf-8"))
    entry = document["acknowledgements"]["dilithium_sign"]
    reason = entry["reason"].lower()
    assert "breaking" in reason, "the reason does not say this is breaking"
    assert (
        "do not verify" in reason or "not verify" in reason
    ), "the reason does not state that 4.x signatures stop verifying"


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


# --------------------------------------------------------------------------
# The dispatch auto-tune's startup cost
# --------------------------------------------------------------------------


def _load_measure() -> ModuleType:
    spec = importlib.util.spec_from_file_location("measure_instruction_counts", MEASURE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_autotune_startup_cost_has_a_ceiling() -> None:
    """Measured: 2,602,494,880 instructions before any application work.

    The dispatcher microbenchmarks its SIMD kernels against scalar at the
    first call that touches one. On an AVX-512 host that takes the first
    cryptographic operation from 4-5 ms to 130-170 ms of wall time — amortised
    to nothing in a long-lived server, dominant in a CLI or a serverless cold
    start. The ceiling stops it growing further unnoticed; it is not an
    endorsement of the current figure.
    """
    measure = _load_measure()
    assert (
        measure.STARTUP_INSTRUCTION_CEILING >= 2_602_494_880
    ), "the ceiling is below the measured cost, so the gate cannot pass"
    assert (
        measure.STARTUP_INSTRUCTION_CEILING <= 4_000_000_000
    ), "a ceiling far above the measured cost would let it grow silently"


def test_exceeding_the_startup_ceiling_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: the ceiling must actually reject."""
    measure = _load_measure()
    monkeypatch.setattr(measure, "dispatch_fingerprint", lambda driver: FINGERPRINT)
    monkeypatch.setattr(measure, "list_operations", lambda driver: ["sha3_256"])
    monkeypatch.setattr(
        measure,
        "measure_startup",
        lambda driver, operation="sha3_256": {
            "init_autotuned": 9_000_000_000,
            "init_pinned": 12_000_000,
            "autotune_cost": measure.STARTUP_INSTRUCTION_CEILING + 1,
        },
    )
    monkeypatch.setattr(measure.shutil, "which", lambda name: "/usr/bin/valgrind")
    driver = tmp_path / "ic_driver"
    driver.write_text("#!/bin/sh\n")
    driver.chmod(0o755)
    assert measure.main(["--driver", str(driver), "--measure-startup"]) == 1


def test_the_startup_probe_uses_zero_iterations() -> None:
    """Guard against a subtly wrong probe that measures one hash instead.

    The driver performs its Ed25519/ML-KEM/ML-DSA key setup BEFORE the loop,
    so dispatch is already initialised by the time iteration 1 runs. An
    ``Ir(1) - Ir(0)`` probe therefore measures a single hash — 38,068 Ir — and
    reports it as the tuning cost, understating the real figure by four orders
    of magnitude. The probe must compare two ZERO-iteration runs that differ
    only in whether the auto-tune ran.
    """
    source = MEASURE_PATH.read_text(encoding="utf-8")
    start = source.index("def measure_startup(")
    end = source.index("def list_operations(")
    body = source[start:end]
    assert '"0",' in body, "the startup probe no longer runs the driver at 0 iterations"
    assert (
        "AMA_DISPATCH_NO_AUTOTUNE" in body
    ), "the startup probe must compare auto-tune live against auto-tune pinned"


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


# --------------------------------------------------------------------------
# The A/B lane's reference step, run for real
#
# ci-build-test.yml triggers on push to main, where HEAD IS the merge-base.
# The lane's handling of that case was `cp head.json base.json` under
# `set -e`, executed before head.json existed, so every push to main failed
# the job with "cp: cannot stat 'head.json'". Skipping the comparison is not
# a fix open to this job — ci-gate fails a skipped job, and a step skipped on
# a self-probe inside a gated job is what check_workflow_commands rejects —
# so on a push the lane compares HEAD against what the push advanced from.
# A workflow step is shell, and the only honest test of shell is to run it:
# these tests take the step out of the workflow file as it stands and
# execute it against real git repositories in each state.
# --------------------------------------------------------------------------

_POSIX_SHELL = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None or shutil.which("git") is None,
    reason=(
        "the A/B lane runs this step under bash on ubuntu-latest; the Windows "
        "runners have no POSIX bash guaranteed on PATH"
    ),
)

_ZERO_SHA = "0" * 40


def _ab_steps() -> list[dict[str, Any]]:
    workflow = yaml.safe_load(CI_WORKFLOW_PATH.read_text(encoding="utf-8"))
    steps = workflow["jobs"][AB_JOB]["steps"]
    assert isinstance(steps, list) and steps, f"{AB_JOB} has no steps"
    return steps


def _reference_step() -> dict[str, Any]:
    """The step that decides what the head is compared against."""
    matches = [s for s in _ab_steps() if "git merge-base FETCH_HEAD HEAD" in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected one reference step in {AB_JOB}, found {len(matches)}"
    return matches[0]


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


class _Repo:
    """A bare ``origin`` whose ``main`` has ``history`` commits, and a clone."""

    def __init__(self, tmp_path: Path, history: int) -> None:
        self.tmp_path = tmp_path
        self.origin = tmp_path / "origin.git"
        self.work = tmp_path / "work"
        _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(self.origin))
        _git(tmp_path, "init", "-q", "-b", "main", str(self.work))
        self.main: list[str] = []
        for index in range(history):
            _git(self.work, "commit", "-q", "--allow-empty", "-m", f"main {index}")
            self.main.append(_git(self.work, "rev-parse", "HEAD"))
        _git(self.work, "remote", "add", "origin", str(self.origin))
        _git(self.work, "push", "-q", "origin", "main")

    def commit_ahead(self, count: int) -> None:
        for index in range(count):
            _git(self.work, "commit", "-q", "--allow-empty", "-m", f"ahead {index}")

    def run_step(self, *, before: str) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        """Run the step as a push event would; ``before`` is the push's old tip."""
        step = _reference_step()
        known = {"${{ github.event.before }}": before}
        env = dict(os.environ)
        for name, value in dict(step.get("env") or {}).items():
            assert str(value) in known, f"the step reads {value!r}, which this harness does not set"
            env[str(name)] = known[str(value)]
        script = str(step["run"])
        # A push event: no pull_request payload, so the step falls back to the
        # default branch -- the path a push to main takes.
        script = script.replace("${{ github.event.pull_request.base.sha }}", "")
        script = script.replace("${{ github.event.repository.default_branch }}", "main")
        assert "${{" not in script, "the step grew an expression this harness does not substitute"
        script_path = self.tmp_path / "step.sh"
        script_path.write_text(script, encoding="utf-8")
        output_path = self.tmp_path / "github_output"
        output_path.write_text("", encoding="utf-8")
        env["GITHUB_OUTPUT"] = str(output_path)
        # GitHub runs a `run:` block as `bash -e {0}`.
        completed = subprocess.run(
            ["bash", "-e", str(script_path)], cwd=self.work, capture_output=True, text=True, env=env
        )
        outputs: dict[str, str] = {}
        for line in output_path.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            outputs[key] = value
        return completed, outputs


@_POSIX_SHELL
def test_a_push_to_main_is_compared_against_what_it_advanced_from(tmp_path: Path) -> None:
    """HEAD is the merge-base. The reference is the push's old tip, not HEAD.

    Three commits pushed at once (a rebase merge): the old tip is main~3, and
    comparing against it covers all three, where the first parent would
    cover only the last.
    """
    repo = _Repo(tmp_path, history=4)
    completed, outputs = repo.run_step(before=repo.main[0])
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert outputs.get("sha") == repo.main[0], outputs
    assert not (repo.work / "base.json").exists(), "a reference measurement was fabricated"


@_POSIX_SHELL
@pytest.mark.parametrize(
    "before",
    ["", _ZERO_SHA, "1" * 40],
    ids=["dispatch-no-before", "new-branch-zero-sha", "force-push-unknown-sha"],
)
def test_without_a_usable_old_tip_the_first_parent_is_the_reference(
    tmp_path: Path, before: str
) -> None:
    repo = _Repo(tmp_path, history=3)
    completed, outputs = repo.run_step(before=before)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert outputs.get("sha") == repo.main[1], outputs


@_POSIX_SHELL
def test_an_old_tip_that_is_head_itself_is_not_a_reference(tmp_path: Path) -> None:
    """A re-run where ``before`` equals HEAD would compare HEAD with HEAD."""
    repo = _Repo(tmp_path, history=3)
    completed, outputs = repo.run_step(before=repo.main[-1])
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert outputs.get("sha") == repo.main[1], outputs


@_POSIX_SHELL
def test_a_root_commit_with_nothing_to_compare_fails(tmp_path: Path) -> None:
    """No old tip and no parent: a failure, never a comparison of nothing."""
    repo = _Repo(tmp_path, history=1)
    completed, outputs = repo.run_step(before="")
    assert completed.returncode != 0
    assert "nothing to compare" in completed.stdout + completed.stderr
    assert "sha" not in outputs, outputs


@_POSIX_SHELL
def test_a_branch_ahead_of_main_is_compared_against_the_merge_base(tmp_path: Path) -> None:
    """The old tip is ignored off main: the branch's whole change is measured."""
    repo = _Repo(tmp_path, history=2)
    repo.commit_ahead(2)
    completed, outputs = repo.run_step(before=repo.main[0])
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert outputs.get("sha") == repo.main[-1], outputs


def test_the_reference_is_built_and_compared_on_every_run() -> None:
    """No step of the comparison may be skipped, and the build uses the step's sha.

    The job sits in ci-gate's ``needs:``; a comparison step skipped inside it
    would let the job report success having compared nothing.
    """
    step = _reference_step()
    step_id = step.get("id")
    assert step_id, "the reference step has no id, so the build cannot read its sha"
    names = {str(s.get("name")): s for s in _ab_steps()}
    build = names.get("Build the reference and measure")
    compare = names.get("Compare head against the reference")
    assert build is not None and compare is not None, sorted(names)
    for s in (step, build, compare):
        assert "if" not in s, f"step {s.get('name')!r} is conditional: {s.get('if')!r}"
    assert (build.get("env") or {}).get("BASE") == f"${{{{ steps.{step_id}.outputs.sha }}}}"
