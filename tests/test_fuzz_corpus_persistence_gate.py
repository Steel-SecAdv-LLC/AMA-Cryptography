# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The fuzzing lane must be able to deepen.

A corpus that persists, a campaign that runs long, an OSS-Fuzz integration
that is exercised.

Every run of ``.github/workflows/fuzzing.yml`` used to start from
``fuzz/seed_corpus`` and discard what it found after 60 seconds, so no run
ever stood on the shoulders of the previous one — the deep branches
(ML-DSA verify at 5,262 bytes, SLH-DSA verify at 49,921) were reachable in
principle and reached by nobody.  ``oss-fuzz/`` had never been built by
anything, and ClusterFuzzLite was not configured.

These tests pin the three mechanisms and the properties that make each one
real rather than decorative:

* both libFuzzer matrix jobs restore the corpus before fuzzing, merge it down
  to its coverage-adding units after, and save it under a run-unique key with
  prefix restore-keys — so every run starts from the newest corpus and leaves
  a newer one;
* the merge step runs after a failed fuzz step too (a crash is not a reason to
  throw away the coverage found before it) and reports the growth numbers;
* the nightly schedule exists, fuzzes for much longer than a pull request run,
  and the job budgets accommodate it;
* the OSS-Fuzz integration is built and checked by OSS-Fuzz's own driver in
  the gate's ``needs``, through the same script a developer runs;
* ClusterFuzzLite is wired with batch, prune and coverage modes on a
  schedule, and its build integration is the OSS-Fuzz one, not a second copy.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parent.parent
FUZZING_YML = REPO_ROOT / ".github" / "workflows" / "fuzzing.yml"
CFLITE_YML = REPO_ROOT / ".github" / "workflows" / "clusterfuzzlite.yml"
OSS_FUZZ_SCRIPT = REPO_ROOT / "tools" / "test_oss_fuzz_build.sh"
OSS_FUZZ_BUILD = REPO_ROOT / "oss-fuzz" / "build.sh"
CFLITE_DIR = REPO_ROOT / ".clusterfuzzlite"

MATRIX_JOBS = ("fuzz-core", "fuzz-pqc")
_SHA_PIN = re.compile(r"@[0-9a-f]{40}\b")


def _fuzzing() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(FUZZING_YML.read_text(encoding="utf-8"))
    return doc


def _triggers(doc: dict[Any, Any]) -> dict[str, Any]:
    """YAML 1.1 reads the bare key ``on`` as the boolean True."""
    triggers: dict[str, Any] = doc.get("on") or doc.get(True) or {}
    return triggers


def _steps(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(s.get("id") or s.get("name")): s for s in job["steps"]}


def _step_by_uses(job: dict[str, Any], fragment: str) -> dict[str, Any]:
    for step in job["steps"]:
        if fragment in str(step.get("uses", "")):
            return dict(step)
    raise AssertionError(f"no step uses {fragment!r}")


# ---------------------------------------------------------------------------
# Persistence in both matrix jobs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("job_id", MATRIX_JOBS)
def test_the_corpus_is_restored_before_fuzzing_and_saved_after(job_id: str) -> None:
    job = _fuzzing()["jobs"][job_id]
    names = [str(s.get("name")) for s in job["steps"]]
    restore = _step_by_uses(job, "actions/cache/restore@")
    save = _step_by_uses(job, "actions/cache/save@")
    assert _SHA_PIN.search(str(restore["uses"])) and _SHA_PIN.search(str(save["uses"]))
    assert restore.get("id") == "corpus"
    assert restore["with"]["path"] == "corpus/${{ matrix.target }}"
    assert save["with"]["path"] == "corpus/${{ matrix.target }}"
    assert (
        save["with"]["key"] == "${{ steps.corpus.outputs.cache-primary-key }}"
    ), "the save must reuse the restore's primary key, or the two drift apart"
    order = [names.index(str(restore["name"])), names.index("Run fuzzer (${{ matrix.target }})")]
    order += [
        names.index(next(n for n in names if n.startswith("Merge the corpus"))),
        names.index(str(save["name"])),
    ]
    assert order == sorted(order), f"restore -> fuzz -> merge -> save is out of order in {job_id}"


@pytest.mark.parametrize("job_id", MATRIX_JOBS)
def test_the_key_is_run_unique_and_the_restore_keys_are_prefixes_of_it(job_id: str) -> None:
    restore = _step_by_uses(_fuzzing()["jobs"][job_id], "actions/cache/restore@")
    key = str(restore["with"]["key"])
    assert "${{ github.run_id }}" in key, "a fixed key would never be overwritten: no growth"
    assert "${{ matrix.target }}" in key, "one cache per target, or targets overwrite each other"
    prefixes = [
        line.strip() for line in str(restore["with"]["restore-keys"]).splitlines() if line.strip()
    ]
    assert len(prefixes) >= 2
    for prefix in prefixes:
        assert key.startswith(prefix), f"{prefix!r} is not a prefix of the primary key"
    assert (
        prefixes[-1] == "fuzz-corpus-${{ matrix.target }}-"
    ), "the last resort must match any earlier corpus for the target, whatever the harness hash"


@pytest.mark.parametrize("job_id", MATRIX_JOBS)
def test_the_merge_keeps_only_coverage_adding_units_and_runs_after_a_crash(job_id: str) -> None:
    steps = _steps(_fuzzing()["jobs"][job_id])
    merge = steps["merge"]
    run = str(merge["run"])
    assert "-merge=1" in run
    assert (
        "check_fuzz_input_reachability.py --max-len" in run
    ), "the merge ceiling must come from the harness"
    assert "MERGE-OUTER" in run, "the growth signal is parsed from libFuzzer's own summary"
    assert "$GITHUB_STEP_SUMMARY" in run
    assert "always()" in str(merge["if"]) and "steps.fuzz.outcome != 'cancelled'" in str(
        merge["if"]
    )
    assert "steps.fuzz.outputs.restored_units" in str(
        merge.get("env", {}).get("RESTORED_UNITS", "")
    )
    fuzz = steps["fuzz"]
    assert 'echo "restored_units=' in str(fuzz["run"])
    save = _step_by_uses(_fuzzing()["jobs"][job_id], "actions/cache/save@")
    assert "steps.merge.outcome == 'success'" in str(save["if"])


@pytest.mark.parametrize("job_id", MATRIX_JOBS)
def test_the_fuzzer_starts_from_the_restored_corpus_not_only_the_seeds(job_id: str) -> None:
    run = str(_steps(_fuzzing()["jobs"][job_id])["fuzz"]["run"])
    assert "cp -r fuzz/seed_corpus/${{ matrix.target }}/. corpus/${{ matrix.target }}/" in run
    assert (
        "rm -rf corpus/" not in run
    ), "clearing the corpus before fuzzing would discard the restore"
    assert "corpus/${{ matrix.target }}/" in run.splitlines()[-1]


# ---------------------------------------------------------------------------
# The nightly campaign
# ---------------------------------------------------------------------------
def test_a_nightly_schedule_fuzzes_far_longer_than_a_pull_request_run() -> None:
    doc = _fuzzing()
    schedules = [str(s["cron"]) for s in _triggers(doc)["schedule"]]
    assert schedules, "no schedule: the corpus can only deepen by 60 s per push"
    for job_id in MATRIX_JOBS:
        job = doc["jobs"][job_id]
        duration = str(_steps(job)["fuzz"]["env"]["FUZZ_DURATION"])
        m = re.search(r"github\.event_name == 'schedule' && '(\d+)'", duration)
        assert m is not None, f"{job_id}: the schedule does not lengthen the run"
        assert int(m.group(1)) >= 600
        assert "'60'" in duration, "the per-PR default must stay short"
        timeout = str(job["timeout-minutes"])
        tm = re.search(r"github\.event_name == 'schedule' && (\d+) \|\| (\d+)", timeout)
        assert tm is not None, f"{job_id}: the job budget does not grow with the schedule"
        assert (
            int(tm.group(1)) * 60 > int(m.group(1)) + 600
        ), "no room for the build around the fuzzing"


def test_scheduled_runs_are_not_cancelled_by_the_concurrency_group() -> None:
    cancel = str(_fuzzing()["concurrency"]["cancel-in-progress"])
    assert "github.event_name != 'schedule'" in cancel


# ---------------------------------------------------------------------------
# The OSS-Fuzz integration is exercised
# ---------------------------------------------------------------------------
def test_the_oss_fuzz_build_job_runs_the_real_driver_and_gates_the_workflow() -> None:
    doc = _fuzzing()
    job = doc["jobs"]["oss-fuzz-build"]
    assert "if" not in job, "the job must run on every trigger so the gate can require it"
    runs = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "tools/test_oss_fuzz_build.sh" in runs, "CI and the developer must run the same script"
    env = {k: str(v) for s in job["steps"] for k, v in (s.get("env") or {}).items()}
    assert re.fullmatch(r"[0-9a-f]{40}", env.get("OSS_FUZZ_REF", "")), "the infra must be pinned"
    assert "oss-fuzz-build" in doc["jobs"]["fuzzing-gate"]["needs"]


def test_the_script_mounts_the_checkout_and_runs_check_build() -> None:
    body = OSS_FUZZ_SCRIPT.read_text(encoding="utf-8")
    build = re.search(r"helper\.py build_fuzzers.*?\"\$PROJECT_NAME\" \"\$REPO_ROOT\"", body, re.S)
    assert build is not None, (
        "build_fuzzers must be given the checkout as its source path; without it the "
        "Dockerfile's clone of the default branch is what gets built"
    )
    assert "helper.py check_build" in body
    assert 'OSS_FUZZ_REF="${OSS_FUZZ_REF:-' in body
    assert 'fetch -q --depth 1 origin "$OSS_FUZZ_REF"' in body
    assert "set -euo pipefail" in body


def test_the_oss_fuzz_build_writes_intermediates_outside_the_mounted_tree() -> None:
    body = OSS_FUZZ_BUILD.read_text(encoding="utf-8")
    assert 'BUILD_DIR="${WORK:-/work}/ama-build"' in body
    assert 'cmake -B "$BUILD_DIR"' in body
    assert "cmake -B build " not in body and "cmake -B build\\" not in body
    assert re.search(r'-o "\$BUILD_DIR/\$\{target\}\.o"', body)


# ---------------------------------------------------------------------------
# ClusterFuzzLite
# ---------------------------------------------------------------------------
def test_clusterfuzzlite_reuses_the_oss_fuzz_build_integration() -> None:
    shim = (CFLITE_DIR / "build.sh").read_text(encoding="utf-8")
    assert 'exec "$SRC/ama-cryptography/oss-fuzz/build.sh"' in shim
    dockerfile = (CFLITE_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM gcr.io/oss-fuzz-base/base-builder" in dockerfile
    assert "COPY . $SRC/ama-cryptography" in dockerfile
    assert "COPY .clusterfuzzlite/build.sh $SRC/" in dockerfile
    project: dict[str, Any] = yaml.safe_load(
        (CFLITE_DIR / "project.yaml").read_text(encoding="utf-8")
    )
    assert project["language"] == "c"
    assert set(project["sanitizers"]) >= {"address", "undefined", "memory"}


def test_clusterfuzzlite_runs_batch_prune_and_coverage_on_a_schedule() -> None:
    doc: dict[str, Any] = yaml.safe_load(CFLITE_YML.read_text(encoding="utf-8"))
    assert "pull_request" not in _triggers(
        doc
    ), "ClusterFuzzLite is a background campaign, not a PR gate"
    assert len(_triggers(doc)["schedule"]) >= 2
    modes: dict[str, set[str]] = {}
    for job_id, job in doc["jobs"].items():
        for step in job["steps"]:
            uses = str(step.get("uses", ""))
            assert _SHA_PIN.search(uses), f"{job_id}: {uses} is not SHA-pinned"
            if "run_fuzzers" in uses:
                modes.setdefault(job_id, set()).add(str(step["with"]["mode"]))
                assert step["with"]["github-token"] == "${{ secrets.GITHUB_TOKEN }}"
    assert (
        modes["batch"] == {"batch"}
        and modes["prune"] == {"prune"}
        and modes["coverage"] == {"coverage"}
    )
    batch = doc["jobs"]["batch"]
    assert set(batch["strategy"]["matrix"]["sanitizer"]) == {"address", "undefined", "memory"}
    seconds = str(_steps(batch)["Fuzz (${{ matrix.sanitizer }})"]["with"]["fuzz-seconds"])
    assert "'3600'" in seconds
