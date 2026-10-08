# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The competitive harnesses' provenance names the build that was measured.

``benchmarks/comparative_benchmark.py`` stamped every result file with
``git rev-parse HEAD`` of the working tree, run with ``check=True`` AFTER the
benchmarks:

* on a host without git, or from an sdist or ``git archive`` export, the
  ``CalledProcessError`` (or ``FileNotFoundError``) arrived after minutes of
  measuring and no results file was written;
* with an installed wheel from another commit imported, the file was stamped
  with the checkout's HEAD anyway, and ``generate_competitive.py`` then
  published "Measured at commit <HEAD>" over another build's numbers -- the
  relabelling the provenance block was added to prevent;
* nothing recorded whether the measured code carried uncommitted changes.

``pqc_comparative_bench.py`` shared the function and called it inside the
``json.dump`` argument, after ``open(out, "w")`` had truncated its own
tracked output.  These tests pin the repair on both harnesses and on the
page generator that consumes the block.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import ama_cryptography
import benchmarks.comparative_benchmark as cb

REPO_ROOT = Path(__file__).resolve().parent.parent
HEAD = "a" * 40


def _fake_git(monkeypatch: pytest.MonkeyPatch, *, toplevel: str | None, status: str = "") -> None:
    answers: dict[str, str | None] = {
        "--show-toplevel": None if toplevel is None else toplevel + "\n",
        "HEAD": None if toplevel is None else HEAD + "\n",
        "--porcelain": None if toplevel is None else status,
    }

    def fake(*args: str, cwd: Path) -> str | None:
        for key, value in answers.items():
            if key in args:
                return value
        raise AssertionError(f"unexpected git query {args}")

    monkeypatch.setattr(cb, "_git_stdout", fake)


def _pinned_attestation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: bytes) -> Path:
    """Attest a synthetic backend with mapped-bytes evidence.

    The first form of these tests read the LIVE loader's attestation,
    which carries mapped-bytes evidence only where the loader allows a
    procfs re-read -- green on the Linux lanes, red on macOS (measured:
    ``Python 3.14 on macos-latest`` on a3508b6, where the preload
    digest is not of the mapped bytes by design).  A synthetic pinned
    backend exercises the pinned path identically on every platform;
    the no-evidence path is the demotion test below, which every macOS
    lane also takes against its live loader semantics.
    """
    import ama_cryptography._self_test as self_test
    from ama_cryptography.pqc_backends import native_sha3_256

    lib = tmp_path / "libama_cryptography_synthetic.so"
    lib.write_bytes(payload)
    attestation = {
        "native_backend": {
            "loaded": True,
            "path": str(lib),
            "preload_digest_hex": native_sha3_256(payload).hex(),
            "preload_digest_is_of_mapped_bytes": True,
        }
    }
    monkeypatch.setattr(self_test, "module_attestation", lambda: attestation)
    # The demotion rule also requires a digest-matched build configuration
    # (review finding on f0582cf); the synthetic object matches no real
    # build tree, so the attribution is pinned synthetically too.
    import benchmarks.benchmark_runner as benchmark_runner

    monkeypatch.setattr(
        benchmark_runner,
        "_native_build_configuration",
        lambda: "GNU 13.3.0; cmake -DCMAKE_BUILD_TYPE=Release (synthetic digest-match)",
    )
    return lib


class TestTheBlockNamesOnlyWhatItCanShow:
    def test_a_clean_checkout_that_is_the_imported_build_is_attributed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Non-vacuity: every refusal below could otherwise be a block that never attributes."""
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        block = cb._measurement_provenance()
        assert block["attributable"] is True
        assert block["ama_commit"] == HEAD
        assert block["ama_version"] == ama_cryptography.__version__
        assert block["tree_dirty"] is False
        assert "unattributable_because" not in block

    def test_a_host_without_git_still_produces_a_block(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Real subprocess, no git on PATH: the old code raised here, after the run."""
        monkeypatch.setenv("PATH", str(tmp_path))
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("git" in reason for reason in block["unattributable_because"])

    def test_an_imported_build_outside_the_checkout_is_not_stamped_with_its_head(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        elsewhere = tmp_path / "site-packages" / "ama_cryptography" / "__init__.py"
        monkeypatch.setattr(ama_cryptography, "__file__", str(elsewhere))
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert (
            block["ama_commit"] == "unknown"
        ), "the checkout's HEAD does not name a build imported from outside it"
        assert any("outside the checkout" in r for r in block["unattributable_because"])

    def test_uncommitted_changes_to_the_measured_code_are_unattributable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT), status=" M src/c/ama_sha3.c\n")
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert block["dirty_paths"] == ["src/c/ama_sha3.c"]

    def test_unrelated_dirt_is_recorded_without_disowning_the_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An earlier run's output is not a change to the measured build."""
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT), status=" M benchmarks/pqc_results.json\n")
        block = cb._measurement_provenance()
        assert block["attributable"] is True
        assert block["ama_commit"] == HEAD
        assert block["tree_dirty"] is True
        assert block["dirty_paths"] == ["benchmarks/pqc_results.json"]


class TestTheNativeArtifactIsPinned:
    """A commit names the sources; these pin the compiled object too.

    Review finding on b8471c4: the block carried only ``ama_commit``, so a
    stale ``build/lib`` object could be linked by the C harness and its
    timings published as ``attributable: true`` under the fresh commit.
    """

    def test_the_block_pins_the_loaded_backend_and_its_build(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """RANGE: with mapped-bytes evidence attested and a digest-matched
        build attribution (both synthetic, from _pinned_attestation — the
        demotion rule requires the build too), the block carries the
        digest and the build line, and the commit attribution stands."""
        from ama_cryptography.pqc_backends import native_sha3_256

        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        block = cb._measurement_provenance()
        artifact = block["native_artifact"]
        assert isinstance(artifact, dict), artifact
        assert artifact["sha3_256"] == native_sha3_256(b"synthetic backend bytes").hex()
        assert isinstance(block["native_build"], str) and block["native_build"]
        assert block["attributable"] is True
        assert block["ama_commit"] == HEAD

    def test_stamping_pins_a_byte_identical_linked_object(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The harness-recorded loaded object, matching the attested
        backend byte for byte, is pinned, and the stamped file carries the
        block the generator requires.  The evidence is the harness's OWN
        ``loaded_library`` record (dladdr + self-hash), never a
        caller-supplied path the loader may not have mapped (review
        finding on 8a26498)."""
        from ama_cryptography.pqc_backends import native_sha3_256

        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        digest = native_sha3_256(b"synthetic backend bytes").hex()
        results = tmp_path / "multi_library_results.json"
        results.write_text(
            json.dumps(
                {
                    "harness_source_sha3": cb.harness_source_digest(),
                    "loaded_library": {
                        "path": "/opt/run/libama_cryptography.so",
                        "sha3_256": digest,
                        "method": "dladdr(ama_sha3_256); self-hash",
                    },
                    "results": [],
                }
            ),
            encoding="utf-8",
        )
        block = cb.stamp_c_harness_provenance(results)
        assert block["linked_library"]["byte_identical_to_loaded_backend"] is True
        assert block["attributable"] is True
        written = json.loads(results.read_text(encoding="utf-8"))
        assert written["provenance"]["linked_library"] == block["linked_library"]
        assert written["provenance"]["native_artifact"]["sha3_256"] == digest

    def test_a_differing_loaded_object_disowns_the_record(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PIN (mutation-earned): a harness-recorded loaded object whose
        bytes differ from the attested backend marks the record
        unattributable with the stale-build reason and clears the commit.
        Mutation: with the mismatch branch removed, exactly this test
        fails while the byte-identical case still passes."""
        from ama_cryptography.pqc_backends import native_sha3_256

        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        results = tmp_path / "multi_library_results.json"
        results.write_text(
            json.dumps(
                {
                    "harness_source_sha3": cb.harness_source_digest(),
                    "loaded_library": {
                        "path": "/opt/stale/libama_cryptography.so",
                        "sha3_256": native_sha3_256(b"a stale build").hex(),
                        "method": "dladdr(ama_sha3_256); self-hash",
                    },
                    "results": [],
                }
            ),
            encoding="utf-8",
        )
        block = cb.stamp_c_harness_provenance(results)
        assert block["linked_library"]["byte_identical_to_loaded_backend"] is False
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("byte-identical" in r for r in block["unattributable_because"])

    def test_a_stale_or_unbound_harness_binary_is_disowned(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PIN (review finding on 0bc915a, mutation-earned): a clean
        checkout can still run a stale multibench built from an older
        revision, and the loaded-library digest proves only the AMA
        object.  The binary now attests the source it was compiled from
        (AMA_HARNESS_SOURCE_SHA3), and the stamp requires that digest to
        equal the tree's multi_library_bench.cpp — absent (an unbound
        binary) or mismatched (a stale one), the record is disowned.
        Mutation: dropping harness_bound from the pinned conjunction
        fails exactly this test while the bound case still passes."""
        from ama_cryptography.pqc_backends import native_sha3_256

        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        digest = native_sha3_256(b"synthetic backend bytes").hex()
        loaded = {
            "path": "/opt/run/libama_cryptography.so",
            "sha3_256": digest,
            "method": "dladdr(ama_sha3_256); self-hash",
        }
        for recorded in ("00" * 32, None):
            payload: dict[str, object] = {"loaded_library": loaded, "results": []}
            if recorded is not None:
                payload["harness_source_sha3"] = recorded
            results = tmp_path / "multi_library_results.json"
            results.write_text(json.dumps(payload), encoding="utf-8")
            block = cb.stamp_c_harness_provenance(results)
            assert block["harness_source"]["binary_matches_tree"] is False
            assert block["attributable"] is False
            assert block["ama_commit"] == "unknown"
            assert any("harness binary" in r for r in block["unattributable_because"])
            # Byte identity is a separate fact: the library digests ARE
            # equal here, and a stale harness attestation must not make
            # the record claim otherwise (review finding on 5da5c6c).
            assert block["linked_library"]["byte_identical_to_loaded_backend"] is True

    def test_a_record_without_the_harness_block_is_disowned(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PIN (review finding on 8a26498, mutation-earned with the
        mismatch pin): a result file with no ``loaded_library`` block —
        an old harness binary, a non-dladdr platform, a static link that
        hashed nothing — cannot name the object its process resolved, so
        the stamp refuses the attribution outright."""
        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        results = tmp_path / "multi_library_results.json"
        results.write_text(json.dumps({"results": []}), encoding="utf-8")
        block = cb.stamp_c_harness_provenance(results)
        assert isinstance(block["linked_library"], str)
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("no loaded_library" in r for r in block["unattributable_because"])

    def test_an_unrecorded_build_configuration_disowns_the_commit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PIN (review finding on f0582cf, mutation-earned): a pinned
        artifact whose build no tree digest-matches carried
        ``native_build: "not recorded: ..."`` under ``attributable: true``,
        so the generator would publish figures without build flags —
        AGENTS.md section 8 item 7 forbids exactly that.  Mutation:
        removing the build_unrecorded arm of the demotion fails exactly
        this test while the pinned-build case above still passes."""
        import benchmarks.benchmark_runner as benchmark_runner

        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        monkeypatch.setattr(
            benchmark_runner,
            "_native_build_configuration",
            lambda: "not recorded: no build tree digest-matches the measured object",
        )
        block = cb._measurement_provenance()
        assert isinstance(block["native_artifact"], dict)
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("build flags" in r for r in block["unattributable_because"])

    def test_a_dirty_c_harness_disowns_the_commit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PIN (review finding on f0582cf, mutation-earned with the
        measured-path list): an uncommitted edit to
        ``multi_library_bench.cpp`` produces different rows under a clean
        HEAD, and the loaded-library digest proves only which AMA object
        ran, not which harness measured it.  The C harness is a measured
        build path.  Mutation: removing its entry from
        ``_MEASURED_BUILD_PATHS`` fails exactly this test."""
        _pinned_attestation(monkeypatch, tmp_path, b"synthetic backend bytes")
        _fake_git(
            monkeypatch,
            toplevel=str(REPO_ROOT),
            status=" M benchmarks/multi_library_bench.cpp\n",
        )
        block = cb._measurement_provenance()
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("multi_library_bench.cpp" in r for r in block["unattributable_because"])

    def test_an_unpinnable_artifact_disowns_the_commit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PIN (review finding on a3508b6, mutation-earned): the first form
        recorded an unpinnable artifact as 'unrecorded' but left the commit
        attribution standing, so on a loader without mapped-bytes evidence
        (or on any attestation failure) the generator would still publish
        the record under ``ama_commit``.  An unpinned artifact now clears
        the commit and marks the block unattributable with the reason.
        Mutation: removing the demotion block fails exactly this test."""
        import ama_cryptography._self_test as self_test

        _fake_git(monkeypatch, toplevel=str(REPO_ROOT))
        monkeypatch.setattr(self_test, "module_attestation", lambda: {})
        block = cb._measurement_provenance()
        assert isinstance(block["native_artifact"], str), block["native_artifact"]
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"
        assert any("could not be pinned" in r for r in block["unattributable_because"])
        # The macOS-lane shape specifically: a digest exists but is not of
        # the mapped bytes (the live loader semantics that failed the
        # first form of these tests on a3508b6).
        monkeypatch.setattr(
            self_test,
            "module_attestation",
            lambda: {
                "native_backend": {
                    "loaded": True,
                    "path": "/opt/libama_cryptography.dylib",
                    "preload_digest_hex": "ab" * 32,
                    "preload_digest_is_of_mapped_bytes": False,
                }
            },
        )
        block = cb._measurement_provenance()
        assert "not of the mapped bytes" in str(block["native_artifact"])
        assert block["attributable"] is False
        assert block["ama_commit"] == "unknown"


class TestProvenanceIsTakenBeforeMeasuring:
    def test_comparative_benchmark(self, monkeypatch: pytest.MonkeyPatch) -> None:
        order: list[str] = []
        block = {"attributable": True, "ama_commit": HEAD}

        def provenance() -> dict[str, Any]:
            order.append("provenance")
            return block

        monkeypatch.setattr(cb, "_measurement_provenance", provenance)
        for method in (
            "benchmark_ama_raw_c",
            "benchmark_ama_cryptography",
            "benchmark_libsodium_ed25519",
            "benchmark_cryptography_ed25519",
            "benchmark_aes_gcm_comparison",
        ):
            monkeypatch.setattr(
                cb.ComparativeBenchmark,
                method,
                lambda self, _m=method: order.append(_m),
            )
        saved: list[Any] = []

        def save_results(
            self: object, filename: str = "x", provenance: Any = None
        ) -> dict[str, Any]:
            saved.append(provenance)
            return {}

        monkeypatch.setattr(cb.ComparativeBenchmark, "save_results", save_results)
        cb.main()
        assert order[0] == "provenance", f"provenance was taken after measuring: {order}"
        assert saved == [block], "the block taken before the run is the one saved"

    # The harness imports PyCA `cryptography` at module level: it measures
    # against OpenSSL through it.  That is the interop oracle, installed by the
    # require-backends lanes and not by the [dev] extra, so without this a
    # contributor's `pytest tests/` (AGENTS.md section 9) errored here with
    # ModuleNotFoundError.  The marker escalates a skip back to a failure on
    # every lane that provides the oracle (INVARIANT-47).
    @pytest.mark.requires_interop_oracle
    def test_pqc_comparative_bench(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        pytest.importorskip("cryptography")
        spec = importlib.util.spec_from_file_location(
            "pqc_comparative_bench_under_test",
            REPO_ROOT / "benchmarks" / "pqc_comparative_bench.py",
        )
        assert spec is not None and spec.loader is not None
        mod: ModuleType = importlib.util.module_from_spec(spec)
        path_before = list(sys.path)
        try:
            spec.loader.exec_module(mod)
            order: list[str] = []
            block = {"attributable": True, "ama_commit": HEAD}

            def provenance() -> dict[str, Any]:
                order.append("provenance")
                return block

            monkeypatch.setattr(mod, "_harness_provenance", provenance, raising=False)
            monkeypatch.setattr(mod, "bench", lambda *a, **k: order.append("bench"))
            monkeypatch.chdir(tmp_path)
            mod.main()
            assert order and order[0] == "provenance", f"measured before provenance: {order}"
            written = json.loads((tmp_path / "pqc_results.json").read_text(encoding="utf-8"))
            assert written["provenance"] == block
        finally:
            sys.path[:] = path_before


class TestThePageRefusesAnUnattributableRun:
    @staticmethod
    def _load() -> ModuleType:
        spec = importlib.util.spec_from_file_location(
            "generate_competitive_under_test", REPO_ROOT / "benchmarks" / "generate_competitive.py"
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @staticmethod
    def _write(directory: Path, provenance: dict[str, Any]) -> None:
        for name in ("multi_library_results.json", "pqc_results.json"):
            (directory / name).write_text(json.dumps({"provenance": provenance}), encoding="utf-8")

    def test_two_unknown_commits_agree_but_are_still_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        gc = self._load()
        self._write(
            tmp_path,
            {
                "ama_commit": "unknown",
                "ama_version": "5.0.0",
                "attributable": False,
                "unattributable_because": ["git could not describe the checkout"],
            },
        )
        monkeypatch.setattr(gc, "BENCH", tmp_path)
        with pytest.raises(RuntimeError, match="unattributable"):
            gc._source_provenance()

    def test_an_attributed_pair_still_renders(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        gc = self._load()
        block = {"ama_commit": HEAD, "ama_version": "5.0.0", "attributable": True}
        self._write(tmp_path, block)
        monkeypatch.setattr(gc, "BENCH", tmp_path)
        assert gc._source_provenance() == block
