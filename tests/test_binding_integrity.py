#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for the v3 integrity artefact: binding extensions bound into the signature.

The six Cython binding extensions contain compiled kernels and execute at
import, before POST can examine them, and until v3 nothing covered their
bytes — SECURITY.md carried the gap as "the fix requires a release-pipeline
change" on the claim that ``auditwheel repair`` rewrites the binding ELFs
after signing.  Measured, that claim is false: the published v4.0.0 wheels
ship the bindings byte-identical to the build on every platform (no
``.libs``/``.dylibs`` graft, unmangled ``DT_NEEDED``, the native library
resolving in-package via ``$ORIGIN``/``@loader_path``; Windows repair is
disabled outright), and a local ``auditwheel repair`` of a freshly built
wheel changes only ``RECORD``/``WHEEL`` metadata.  So the digests survive
the pipeline and the artefact now binds them: SHA3-256 per binding file,
serialized into the v3 composite message under its own domain string.

Signer (``_build_sign``) and verifier (``_self_test``) deliberately do not
import each other (INVARIANT-1 build/runtime separation), so their mirrored
constructions are pinned equal here — same pattern as
``tests/test_native_integrity.py::TestSignerVerifierAgreement`` for v2.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ama_cryptography import _build_sign, _self_test

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"


class TestSignerVerifierAgreement:
    """The mirrored v3 constructions must be byte-identical."""

    def test_v3_domain_constants_are_identical(self) -> None:
        assert _self_test._INTEGRITY_SIG_DOMAIN_V3 == _build_sign._INTEGRITY_SIG_DOMAIN_V3
        # ...and distinct from v2, or the format versioning is decorative.
        assert _self_test._INTEGRITY_SIG_DOMAIN_V3 != _self_test._INTEGRITY_SIG_DOMAIN

    def test_enumeration_criteria_are_identical(self) -> None:
        assert _self_test._EXTENSION_SUFFIXES == _build_sign._EXTENSION_SUFFIXES
        assert _self_test._NATIVE_LIB_PREFIXES == _build_sign._NATIVE_LIB_PREFIXES

    def test_serializers_are_identical(self) -> None:
        sample = {
            "b_binding.so": b"\x02" * 32,
            "a_binding.so": b"\x01" * 32,
            "math_engine.pyd": b"\x03" * 32,
        }
        assert _self_test._serialize_binding_digests(sample) == (
            _build_sign._serialize_binding_digests(sample)
        )

    def test_composite_v3_is_identical(self) -> None:
        py, native = b"\x11" * 32, b"\x22" * 32
        sample = {"a_binding.so": b"\x01" * 32}
        assert _self_test._composite_integrity_message_v3(py, native, sample) == (
            _build_sign._composite_integrity_message_v3(py, native, sample)
        )

    def test_composite_v3_binds_every_component(self) -> None:
        py, native = b"\x11" * 32, b"\x22" * 32
        sample = {"a_binding.so": b"\x01" * 32}
        base = _self_test._composite_integrity_message_v3(py, native, sample)
        assert _self_test._composite_integrity_message_v3(b"\x00" * 32, native, sample) != base
        assert _self_test._composite_integrity_message_v3(py, b"\x00" * 32, sample) != base
        assert (
            _self_test._composite_integrity_message_v3(py, native, {"a_binding.so": b"\x02" * 32})
            != base
        )
        assert _self_test._composite_integrity_message_v3(py, native, {}) != base

    def test_serialization_is_order_independent_and_framed(self) -> None:
        a = {"x.so": b"\x01" * 32, "y.so": b"\x02" * 32}
        b = dict(reversed(list(a.items())))
        assert _self_test._serialize_binding_digests(a) == (
            _self_test._serialize_binding_digests(b)
        )
        # NUL framing: name boundaries cannot be shifted between entries.
        assert _self_test._serialize_binding_digests(
            {"ab.so": b"\x01" * 32}
        ) != _self_test._serialize_binding_digests({"a": b"b" + b".so\x00" + b"\x01" * 31})


class TestTreeArtefactSelfCheck:
    """The committed artefact must describe this tree's actual binding files."""

    def test_artefact_is_v3(self) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        assert getattr(sig_mod, "BUILD_PIPELINE_VERSION", None) == "3"
        assert isinstance(getattr(sig_mod, "INTEGRITY_BINDING_DIGESTS_HEX", None), dict)

    def test_artefact_matches_on_disk_bindings(self) -> None:
        from ama_cryptography import _integrity_signature as sig_mod

        on_disk = {p.name: p for p in _self_test._iter_extension_files(PKG_DIR)}
        signed = sig_mod.INTEGRITY_BINDING_DIGESTS_HEX
        assert set(signed) == set(on_disk), (
            "artefact and package directory disagree on the binding inventory — "
            "re-sign: AMA_BUILD_PIPELINE=1 python -m ama_cryptography.integrity --update --sign"
        )
        for name, path in on_disk.items():
            assert hashlib.sha3_256(path.read_bytes()).hexdigest() == signed[name], name

    def test_signer_and_verifier_enumerate_the_tree_identically(self) -> None:
        assert [p.name for p in _build_sign._iter_binding_files(PKG_DIR)] == [
            p.name for p in _self_test._iter_extension_files(PKG_DIR)
        ]


class TestParseEmbeddedBindingDigests:
    class _Artefact:
        def __init__(self, field: object) -> None:
            if field is not _ABSENT:
                self.INTEGRITY_BINDING_DIGESTS_HEX = field

    def test_absent_field_is_pre_v3_not_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(self._Artefact(_ABSENT))
        assert parsed is None and error is None

    def test_non_dict_is_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(self._Artefact(["x"]))
        assert parsed is None and error is not None

    def test_bad_hex_is_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(
            self._Artefact({"a.so": "not-hex"})
        )
        assert parsed is None and error is not None and "a.so" in error

    def test_wrong_length_is_error(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(
            self._Artefact({"a.so": "ab" * 16})
        )
        assert parsed is None and error is not None

    def test_valid_dict_parses(self) -> None:
        parsed, error = _self_test._parse_embedded_binding_digests(
            self._Artefact({"a.so": "ab" * 32})
        )
        assert error is None and parsed == {"a.so": bytes.fromhex("ab" * 32)}


_ABSENT = object()


class TestCheckBindingExtensions:
    """Each failure direction, driven on a scratch tree."""

    @pytest.fixture()
    def scratch(self, tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
        files: dict[str, bytes] = {}
        for name in ("ed25519_binding.cpython-311-x86_64-linux-gnu.so", "math_engine.pyd"):
            body = f"compiled {name}".encode()
            (tmp_path / name).write_bytes(body)
            files[name] = hashlib.sha3_256(body).digest()
        # The native library must be ignored by enumeration, not reported.
        (tmp_path / "libama_cryptography.so.4").write_bytes(b"native")
        return tmp_path, files

    def test_matching_tree_verifies(self, scratch: tuple[Path, dict[str, bytes]]) -> None:
        tree, files = scratch
        ok, note = _self_test._check_binding_extensions(files, pkg_dir=tree)
        assert ok and "2 binding extension(s) verified" in note

    def test_tampered_file_fails(self, scratch: tuple[Path, dict[str, bytes]]) -> None:
        tree, files = scratch
        (tree / "math_engine.pyd").write_bytes(b"different bytes")
        ok, note = _self_test._check_binding_extensions(files, pkg_dir=tree)
        assert not ok and "math_engine.pyd" in note and "MISMATCH" in note

    def test_missing_file_fails(self, scratch: tuple[Path, dict[str, bytes]]) -> None:
        tree, files = scratch
        (tree / "math_engine.pyd").unlink()
        ok, note = _self_test._check_binding_extensions(files, pkg_dir=tree)
        assert not ok and "missing on disk" in note

    def test_unlisted_file_fails(self, scratch: tuple[Path, dict[str, bytes]]) -> None:
        tree, files = scratch
        (tree / "planted.cpython-311-x86_64-linux-gnu.so").write_bytes(b"rogue")
        ok, note = _self_test._check_binding_extensions(files, pkg_dir=tree)
        assert not ok and "planted" in note and "not covered" in note

    def test_failure_note_carries_the_resign_hint(
        self, scratch: tuple[Path, dict[str, bytes]]
    ) -> None:
        tree, files = scratch
        (tree / "math_engine.pyd").write_bytes(b"different bytes")
        _ok, note = _self_test._check_binding_extensions(files, pkg_dir=tree)
        assert "integrity --update --sign" in note


class TestSignerInventoryFailClosed:
    def test_unknown_extension_refuses_to_sign(self, tmp_path: Path) -> None:
        (tmp_path / "mystery_module.cpython-311-x86_64-linux-gnu.so").write_bytes(b"?")
        with pytest.raises(RuntimeError, match="unknown compiled extension"):
            _build_sign._iter_binding_files(tmp_path)

    def test_native_library_files_are_not_bindings(self, tmp_path: Path) -> None:
        for name in (
            "libama_cryptography.so.4.0.0",
            "libama_cryptography.4.dylib",
            "ama_cryptography.dll",  # .dll is not an enumerated suffix, doubly ignored
            "ed25519_binding.cpython-311-darwin.so",
        ):
            (tmp_path / name).write_bytes(b"x")
        names = [p.name for p in _build_sign._iter_binding_files(tmp_path)]
        assert names == ["ed25519_binding.cpython-311-darwin.so"]
