#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for ``tools/resign_wheel.py`` — the post-repair wheel re-signer.

The tool closes the pipeline-ordering hole the 5.0.0 release dry run exposed:
the integrity artefact is minted before cibuildwheel's repair step, so a
repair tool that rewrites the binding ELFs (as delocate did on macOS)
invalidates the signature on every wheel it touches.  On Linux the artefact is
now re-signed AFTER ``auditwheel repair``, and these tests pin the tool's pure
logic without cibuildwheel:

* wheel discovery and its fail-loud modes (empty ``{dest_dir}``, missing dir);
* the exactly-one-``ama_cryptography``-directory requirement;
* the signer subprocess contract (command line, cwd/PYTHONPATH pinned to the
  unpacked root, stale artefact deleted first, env scrubbed);
* the out-of-root native-library guard — the one silent-wrong-signing hazard,
  since the signer takes its native digest from import-path discovery rather
  than from ``--package-dir``;
* repack: original inventory replayed exactly (permissions included), RECORD
  regenerated over the re-signed bytes, stray files never ship;
* end-to-end over a fake wheel with a stubbed signer, cross-checked against
  the reference ``wheel`` CLI (which verifies RECORD hashes on unpack) when
  that package is available.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import os
import subprocess
import sys
import types
import zipfile
from pathlib import Path
from typing import Iterator

import pytest

from tools import resign_wheel as rw

# ---------------------------------------------------------------------------
# Fixture helpers: a minimal but structurally faithful repaired wheel.
# ---------------------------------------------------------------------------

WHEEL_NAME = "ama_cryptography-5.0.0-cp311-cp311-manylinux_2_28_x86_64.whl"
DIST_INFO = "ama_cryptography-5.0.0.dist-info"

#: Fake native-library bytes and the digest the artefact must carry for the
#: out-of-root guard to accept the tree.
NATIVE_BYTES = b"\x7fELF fake libama_cryptography.so for resign tests"
NATIVE_DIGEST_HEX = hashlib.sha3_256(NATIVE_BYTES).hexdigest()

BINDING_NAME = "dilithium_binding.cpython-311-x86_64-linux-gnu.so"


def _artefact_bytes(native_digest_hex: str) -> bytes:
    """A fake ``_integrity_signature.py`` with the fields the tool parses."""
    return (
        "# fake generated integrity artefact (test fixture)\n"
        f'INTEGRITY_DIGEST_HEX = "{"0" * 64}"\n'
        f'INTEGRITY_NATIVE_DIGEST_HEX = "{native_digest_hex}"\n'
        "INTEGRITY_BINDING_DIGESTS_HEX: dict[str, str] = {}\n"
        f'INTEGRITY_PUBKEY_HEX = "{"1" * 64}"\n'
        f'INTEGRITY_SIGNATURE_HEX = "{"2" * 128}"\n'
    ).encode()


def _default_files() -> dict[str, bytes]:
    return {
        "ama_cryptography/__init__.py": b"# fake package\n",
        "ama_cryptography/pqc_backends.py": b"# fake module\n",
        "ama_cryptography/_integrity_digest.txt": b"0" * 64 + b"\n",
        "ama_cryptography/_integrity_signature.py": _artefact_bytes("f" * 64),
        "ama_cryptography/libama_cryptography.so": NATIVE_BYTES,
        f"ama_cryptography/{BINDING_NAME}": b"\x7fELF fake binding extension",
        f"{DIST_INFO}/METADATA": b"Metadata-Version: 2.1\nName: ama-cryptography\n",
        f"{DIST_INFO}/WHEEL": b"Wheel-Version: 1.0\nTag: cp311-cp311-manylinux_2_28_x86_64\n",
    }


def _make_wheel(
    dest_dir: Path,
    files: dict[str, bytes] | None = None,
    name: str = WHEEL_NAME,
) -> Path:
    """Write a fake repaired wheel with a correct RECORD and exec-bit .so files."""
    contents = _default_files() if files is None else files
    record_name = f"{DIST_INFO}/RECORD"
    record_rows = []
    for arcname, data in contents.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        record_rows.append(f"{arcname},sha256={digest.decode('ascii')},{len(data)}")
    record_rows.append(f"{record_name},,")
    record_bytes = ("\r\n".join(record_rows) + "\r\n").encode("utf-8")

    dest_dir.mkdir(parents=True, exist_ok=True)
    whl = dest_dir / name
    with zipfile.ZipFile(whl, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname, data in {**contents, record_name: record_bytes}.items():
            info = zipfile.ZipInfo(arcname, date_time=(2026, 1, 2, 3, 4, 6))
            mode = 0o755 if arcname.endswith((".so", ".pyd", ".dylib")) else 0o644
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return whl


def _fake_signer(root: Path, pkg_dir: Path) -> None:
    """Stub for ``_run_signer``: emit an artefact binding the in-tree library."""
    (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes(NATIVE_DIGEST_HEX))


def _record_entries(whl: Path) -> dict[str, tuple[str, str]]:
    """``{path: (hash, size)}`` parsed from the wheel's RECORD."""
    with zipfile.ZipFile(whl) as archive:
        text = archive.read(f"{DIST_INFO}/RECORD").decode("utf-8")
    return {row[0]: (row[1], row[2]) for row in csv.reader(text.splitlines()) if row}


# ---------------------------------------------------------------------------
# Wheel discovery.
# ---------------------------------------------------------------------------


class TestWheelDiscovery:
    def test_empty_dest_dir_fails_loudly(self, tmp_path: Path) -> None:
        with pytest.raises(rw.ResignError, match="no \\*\\.whl found"):
            rw._find_wheels(tmp_path)

    def test_missing_dest_dir_fails_loudly(self, tmp_path: Path) -> None:
        with pytest.raises(rw.ResignError, match="does not exist"):
            rw._find_wheels(tmp_path / "absent")

    def test_main_exits_nonzero_on_empty_dest_dir(self, tmp_path: Path) -> None:
        assert rw.main([str(tmp_path)]) == 1

    def test_all_wheels_are_discovered_in_stable_order(self, tmp_path: Path) -> None:
        _make_wheel(tmp_path, name="b-1.0-py3-none-any.whl")
        _make_wheel(tmp_path, name="a-1.0-py3-none-any.whl")
        (tmp_path / "not-a-wheel.txt").write_bytes(b"ignored")
        assert [whl.name for whl in rw._find_wheels(tmp_path)] == [
            "a-1.0-py3-none-any.whl",
            "b-1.0-py3-none-any.whl",
        ]


# ---------------------------------------------------------------------------
# Package-directory location.
# ---------------------------------------------------------------------------


class TestPackageDirLocation:
    def test_more_than_one_package_dir_fails_loudly(self, tmp_path: Path) -> None:
        files = _default_files()
        files["vendor/ama_cryptography/shadow.py"] = b"# a second package tree\n"
        whl = _make_wheel(tmp_path, files=files)
        with pytest.raises(rw.ResignError, match="exactly one ama_cryptography"):
            rw.resign_wheel(whl)

    def test_no_package_dir_fails_loudly(self, tmp_path: Path) -> None:
        files = {f"{DIST_INFO}/METADATA": b"Metadata-Version: 2.1\n"}
        whl = _make_wheel(tmp_path, files=files)
        with pytest.raises(rw.ResignError, match="exactly one ama_cryptography"):
            rw.resign_wheel(whl)

    def test_wheel_without_artefact_fails_loudly(self, tmp_path: Path) -> None:
        files = _default_files()
        del files["ama_cryptography/_integrity_signature.py"]
        whl = _make_wheel(tmp_path, files=files)
        with pytest.raises(rw.ResignError, match=r"never\s+signed"):
            rw.resign_wheel(whl)


# ---------------------------------------------------------------------------
# Signer subprocess contract.
# ---------------------------------------------------------------------------


def _unpacked_tree(tmp_path: Path) -> tuple[Path, Path]:
    """A fake unpacked-wheel tree with a stale artefact, as ``_unpack`` leaves it."""
    root = tmp_path / "unpacked"
    pkg_dir = root / "ama_cryptography"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_bytes(b"# fake\n")
    (pkg_dir / "libama_cryptography.so").write_bytes(NATIVE_BYTES)
    (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes("f" * 64))
    return root, pkg_dir


class TestRunSigner:
    def test_signer_command_env_and_stale_artefact_deletion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root, pkg_dir = _unpacked_tree(tmp_path)
        monkeypatch.setenv("LD_LIBRARY_PATH", "/somewhere/stale")
        monkeypatch.setenv("PYTHONPATH", "/pre/existing")
        seen: dict[str, object] = {}

        def fake_run(command: list[str], cwd: Path, env: dict[str, str]) -> object:
            # The stale artefact must be gone BEFORE the signer process starts,
            # or the pre-import binding gate would refuse a repair-rewritten
            # tree against the stale digests.
            seen["stale_artefact_present"] = (pkg_dir / rw.ARTEFACT_NAME).exists()
            seen["command"] = command
            seen["cwd"] = cwd
            seen["env"] = env
            (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes(NATIVE_DIGEST_HEX))
            return types.SimpleNamespace(returncode=0)

        monkeypatch.setattr(rw, "subprocess", types.SimpleNamespace(run=fake_run))
        rw._run_signer(root, pkg_dir)

        assert seen["stale_artefact_present"] is False
        assert seen["command"] == [
            sys.executable,
            "-m",
            "ama_cryptography._build_sign",
            "--package-dir",
            str(pkg_dir),
            "--bind-extensions",
        ]
        assert seen["cwd"] == root
        env = seen["env"]
        assert isinstance(env, dict)
        # The unpacked root must be the FIRST import-path entry, so the signer
        # imports the wheel's own tree rather than a site-packages install.
        assert env["PYTHONPATH"].split(os.pathsep)[0] == str(root)
        assert env["PYTHONPATH"].split(os.pathsep)[1:] == ["/pre/existing"]
        assert env["AMA_BUILD_PIPELINE"] == "1"
        assert env["PYTHONDONTWRITEBYTECODE"] == "1"
        assert env["AMA_CRYPTO_LIB_PATH"] == str(pkg_dir)
        assert "LD_LIBRARY_PATH" not in env

    def test_signer_nonzero_exit_fails_loudly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root, pkg_dir = _unpacked_tree(tmp_path)
        fake = types.SimpleNamespace(
            run=lambda *a, **k: types.SimpleNamespace(returncode=3),
        )
        monkeypatch.setattr(rw, "subprocess", fake)
        with pytest.raises(rw.ResignError, match="signer exited 3"):
            rw._run_signer(root, pkg_dir)

    def test_signer_writing_no_artefact_fails_loudly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root, pkg_dir = _unpacked_tree(tmp_path)
        fake = types.SimpleNamespace(
            run=lambda *a, **k: types.SimpleNamespace(returncode=0),
        )
        monkeypatch.setattr(rw, "subprocess", fake)
        with pytest.raises(rw.ResignError, match="wrote no _integrity_signature"):
            rw._run_signer(root, pkg_dir)


# ---------------------------------------------------------------------------
# Out-of-root native-library guard.
# ---------------------------------------------------------------------------


class TestOutOfRootGuard:
    def test_in_tree_digest_is_accepted(self, tmp_path: Path) -> None:
        _root, pkg_dir = _unpacked_tree(tmp_path)
        (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes(NATIVE_DIGEST_HEX))
        bound = rw._assert_native_digest_bound_in_root(pkg_dir)
        assert bound == pkg_dir / "libama_cryptography.so"

    def test_out_of_root_digest_fails_loudly(self, tmp_path: Path) -> None:
        _root, pkg_dir = _unpacked_tree(tmp_path)
        elsewhere = hashlib.sha3_256(b"a library the wheel does not ship").hexdigest()
        (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes(elsewhere))
        with pytest.raises(rw.ResignError, match="OUTSIDE the unpacked wheel"):
            rw._assert_native_digest_bound_in_root(pkg_dir)

    def test_tree_without_native_library_fails_loudly(self, tmp_path: Path) -> None:
        _root, pkg_dir = _unpacked_tree(tmp_path)
        (pkg_dir / "libama_cryptography.so").unlink()
        (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes(NATIVE_DIGEST_HEX))
        with pytest.raises(rw.ResignError, match="no native library"):
            rw._assert_native_digest_bound_in_root(pkg_dir)

    def test_unparseable_artefact_fails_loudly(self, tmp_path: Path) -> None:
        _root, pkg_dir = _unpacked_tree(tmp_path)
        (pkg_dir / rw.ARTEFACT_NAME).write_bytes(b"# no digest field at all\n")
        with pytest.raises(rw.ResignError, match="no parseable INTEGRITY_NATIVE_DIGEST_HEX"):
            rw._assert_native_digest_bound_in_root(pkg_dir)


# ---------------------------------------------------------------------------
# Repack.
# ---------------------------------------------------------------------------


def _unpack_for_repack(whl: Path, tmp_path: Path) -> tuple[Path, list[zipfile.ZipInfo]]:
    return rw._unpack(whl, tmp_path)


class TestRepack:
    def test_repack_replays_inventory_and_regenerates_record(self, tmp_path: Path) -> None:
        whl = _make_wheel(tmp_path / "dest")
        with zipfile.ZipFile(whl) as archive:
            original_names = archive.namelist()
        root, infos = _unpack_for_repack(whl, tmp_path)

        # Simulate the signer: the artefact's bytes change, and the signer
        # subprocess leaves droppings the wheel must never ship.
        new_artefact = _artefact_bytes(NATIVE_DIGEST_HEX)
        (root / "ama_cryptography" / rw.ARTEFACT_NAME).write_bytes(new_artefact)
        pycache = root / "ama_cryptography" / "__pycache__"
        pycache.mkdir()
        (pycache / "_integrity_signature.cpython-311.pyc").write_bytes(b"bytecode")
        (root / "scratch.txt").write_bytes(b"stray")

        rw._repack(whl, root, infos)

        with zipfile.ZipFile(whl) as archive:
            assert archive.namelist() == original_names
            artefact_arcname = f"ama_cryptography/{rw.ARTEFACT_NAME}"
            assert archive.read(artefact_arcname) == new_artefact
            # Permissions replayed from the original archive: the extensions
            # keep their exec bits, or the installed wheel cannot dlopen them.
            so_info = archive.getinfo("ama_cryptography/libama_cryptography.so")
            assert (so_info.external_attr >> 16) & 0o111
            # RECORD describes the FINAL bytes of every shipped file.
            entries = _record_entries(whl)
            assert set(entries) == set(original_names)
            for arcname in original_names:
                if arcname == f"{DIST_INFO}/RECORD":
                    assert entries[arcname] == ("", "")
                    continue
                data = archive.read(arcname)
                digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
                assert entries[arcname] == (f"sha256={digest.decode('ascii')}", str(len(data)))

    def test_repack_refuses_missing_tree_file(self, tmp_path: Path) -> None:
        whl = _make_wheel(tmp_path / "dest")
        root, infos = _unpack_for_repack(whl, tmp_path)
        (root / "ama_cryptography" / "pqc_backends.py").unlink()
        with pytest.raises(rw.ResignError, match="missing from"):
            rw._repack(whl, root, infos)

    def test_repack_refuses_detached_record_signature(self, tmp_path: Path) -> None:
        files = _default_files()
        files[f"{DIST_INFO}/RECORD.jws"] = b"{}"
        whl = _make_wheel(tmp_path / "dest", files=files)
        root, infos = _unpack_for_repack(whl, tmp_path)
        with pytest.raises(rw.ResignError, match="detached RECORD signature"):
            rw._repack(whl, root, infos)

    def test_failed_repack_leaves_no_temp_archive(self, tmp_path: Path) -> None:
        whl = _make_wheel(tmp_path / "dest")
        root, infos = _unpack_for_repack(whl, tmp_path)
        (root / "ama_cryptography" / "pqc_backends.py").unlink()
        with pytest.raises(rw.ResignError):
            rw._repack(whl, root, infos)
        assert list((tmp_path / "dest").glob("*.resign-tmp")) == []


# ---------------------------------------------------------------------------
# End to end (signer stubbed — the real signer needs a built native library).
# ---------------------------------------------------------------------------


@pytest.fixture
def resigned_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    dest = tmp_path / "dest"
    whl = _make_wheel(dest)
    before = whl.read_bytes()
    monkeypatch.setattr(rw, "_run_signer", _fake_signer)
    assert rw.main([str(dest)]) == 0
    assert whl.read_bytes() != before
    yield whl


class TestEndToEnd:
    def test_wheel_is_resigned_in_place_with_consistent_record(self, resigned_wheel: Path) -> None:
        with zipfile.ZipFile(resigned_wheel) as archive:
            artefact = archive.read(f"ama_cryptography/{rw.ARTEFACT_NAME}")
            assert NATIVE_DIGEST_HEX.encode("ascii") in artefact
            entries = _record_entries(resigned_wheel)
            arcname = f"ama_cryptography/{rw.ARTEFACT_NAME}"
            digest = base64.urlsafe_b64encode(hashlib.sha256(artefact).digest()).rstrip(b"=")
            assert entries[arcname] == (
                f"sha256={digest.decode('ascii')}",
                str(len(artefact)),
            )

    def test_out_of_root_binding_fails_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = tmp_path / "dest"
        _make_wheel(dest)

        def bad_signer(root: Path, pkg_dir: Path) -> None:
            elsewhere = hashlib.sha3_256(b"library from /usr/local/lib").hexdigest()
            (pkg_dir / rw.ARTEFACT_NAME).write_bytes(_artefact_bytes(elsewhere))

        monkeypatch.setattr(rw, "_run_signer", bad_signer)
        assert rw.main([str(dest)]) == 1

    @pytest.mark.skipif(
        importlib.util.find_spec("wheel") is None,
        reason="the reference `wheel` package is not installed",
    )
    def test_reference_wheel_cli_verifies_the_resigned_wheel(
        self, resigned_wheel: Path, tmp_path: Path
    ) -> None:
        # `python -m wheel unpack` verifies every file against RECORD as it
        # extracts, so a clean exit pins this tool's RECORD regeneration
        # against the reference implementation.
        cli_dir = tmp_path / "wheel-cli"
        cli_dir.mkdir()
        completed = subprocess.run(
            [sys.executable, "-m", "wheel", "unpack", str(resigned_wheel)],
            cwd=cli_dir,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
