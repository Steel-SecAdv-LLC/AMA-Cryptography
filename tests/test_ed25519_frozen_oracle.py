# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Replay the frozen Ed25519 oracle against the loaded native library.

``tests/oracle/ed25519_frozen_oracle.txt`` records 2,022 Ed25519 inputs and
the answers the since-removed vendored x86-64 backend gave for them at commit
``e848740``, the last tree that carried it: keypairs and signatures, single
and batch verification verdicts (honest signatures, the ``S + L`` malleable
twin, boundary ``S`` values, bit flips in every field, non-canonical and
small-order ``R``), the compressed-point decode rules, and the 32 output
bytes of every group-arithmetic entry point over unreduced scalars and
small-order points.  With that backend gone this fixture and the RFC 8032
§7.1 vectors are the independent oracles for the in-house backend, so it runs on
every Python lane — including ``windows-latest``, whose MSVC build takes the
fe51 path — and its C twin (``tests/c/test_ed25519_frozen_oracle.c``) runs on
every ctest lane.

The reader is ``tools/freeze_ed25519_oracle.py``'s own, so the tool that
writes the fixture and the test that replays it cannot disagree on the format.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ama_cryptography import pqc_backends
from tools.freeze_ed25519_oracle import FIXTURE_PATH, Library, replay

#: The record count the fixture was frozen with.  Pinned so a truncated
#: fixture cannot pass by replaying fewer cases than were recorded.
FROZEN_RECORDS = 2022


def _loaded_library_path() -> Path:
    """The filesystem path of the library the suite is running against.

    Read from the discovery record, not from the CDLL's ``_name``: on Linux a
    pre-load-verified library is mapped through ``/proc/self/fd/N`` and that
    descriptor is closed once the mapping exists, so ``_name`` is a path that
    no longer resolves.  A replay opened by that name only worked because the
    loader matched the already-mapped object by string.
    """
    if pqc_backends._native_lib is None:  # pragma: no cover - INVARIANT-7
        pytest.skip("native library unavailable")
    recorded = pqc_backends._NATIVE_LIB_PATH
    if not isinstance(recorded, str):  # pragma: no cover - discovery always records it
        raise RuntimeError("the loaded native library has no recorded path")
    path = Path(recorded)
    assert path.is_file(), f"recorded native library path does not exist: {path}"
    return path


def test_fixture_is_present_and_complete() -> None:
    assert FIXTURE_PATH.is_file(), FIXTURE_PATH
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    records = [line for line in lines if line and not line.startswith("#")]
    assert len(records) == FROZEN_RECORDS
    header = [line for line in lines if line.startswith("#")]
    assert any(line.startswith("# source-backend: vendored-x86-64") for line in header)
    assert any(line.startswith("# source-commit: e848740") for line in header)
    # Every record kind the format defines is present, so a regeneration that
    # dropped a family cannot pass on the count alone.
    kinds = {line[0] for line in records}
    assert kinds == set("KVBDPMAJRS")


def test_native_backend_reproduces_every_frozen_answer() -> None:
    lib = Library(_loaded_library_path())
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    checked, mismatches = replay(lib, lines)
    assert checked == FROZEN_RECORDS
    assert not mismatches, "\n".join(mismatches[:20])


def test_replay_detects_a_changed_answer() -> None:
    """Negative control (INVARIANT-2): a replayed mismatch is reported."""
    lib = Library(_loaded_library_path())
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    first_v = next(i for i, line in enumerate(lines) if line.startswith("V "))
    fields = lines[first_v].split()
    fields[-1] = "0" if fields[-1] == "1" else "1"
    lines[first_v] = " ".join(fields)
    checked, mismatches = replay(lib, lines)
    assert checked == FROZEN_RECORDS
    assert len(mismatches) == 1 and "verify verdict" in mismatches[0]


class TestTheCommittedFixtureCannotBeReRecorded:
    """``--write`` must refuse the committed fixture.

    The fixture's value is that the vendored backend answered it; that backend
    is gone.  A ``--write`` onto it — which was the documented usage and the
    default path — would record the shipped backend's own answers, and the
    replay above would then compare that backend with itself.
    """

    class _FakeLibrary:
        """Stands in for the C library so ``--write`` can run without one."""

        def __init__(self, path: Path) -> None:
            self.path = path

        def backend(self) -> str:
            return "fake"

    def _patch(self, monkeypatch: pytest.MonkeyPatch, committed: Path) -> None:
        import tools.freeze_ed25519_oracle as tool

        monkeypatch.setattr(tool, "FIXTURE_PATH", committed)
        monkeypatch.setattr(tool, "Library", self._FakeLibrary)
        monkeypatch.setattr(tool, "render", lambda lib, commit: "# re-recorded\n")

    def test_write_onto_the_committed_fixture_is_refused(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import tools.freeze_ed25519_oracle as tool

        committed = tmp_path / "oracle" / "ed25519_frozen_oracle.txt"
        committed.parent.mkdir()
        committed.write_text("# the vendored backend's answers\n", encoding="utf-8")
        self._patch(monkeypatch, committed)

        # The default path, and a spelling of it that only resolves to it.
        spelled = tmp_path / "oracle" / ".." / "oracle" / "ed25519_frozen_oracle.txt"
        for extra in ([], ["--fixture", str(spelled)]):
            rc = tool.main(["--library", str(tmp_path / "lib.so"), "--write", *extra])
            assert rc == 2
            assert "REFUSED" in capsys.readouterr().err
            assert committed.read_text(encoding="utf-8") == "# the vendored backend's answers\n"

    def test_write_to_another_path_still_records(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import tools.freeze_ed25519_oracle as tool

        committed = tmp_path / "oracle" / "ed25519_frozen_oracle.txt"
        self._patch(monkeypatch, committed)
        scratch = tmp_path / "scratch.txt"
        rc = tool.main(
            ["--library", str(tmp_path / "lib.so"), "--write", "--fixture", str(scratch)]
        )
        capsys.readouterr()
        assert rc == 0
        assert scratch.read_text(encoding="utf-8") == "# re-recorded\n"
        assert not committed.exists()

    def test_the_real_default_is_the_committed_fixture(self) -> None:
        """The refusal compares against FIXTURE_PATH, so it must BE the fixture."""
        assert FIXTURE_PATH == Path(__file__).resolve().parent / "oracle" / (
            "ed25519_frozen_oracle.txt"
        )
