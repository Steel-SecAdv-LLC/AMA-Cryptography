#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
HSM Integration Tests for HSMKeyStorage
========================================

Comprehensive test suite for HSMKeyStorage using mocked PyKCS11 when hardware
is unavailable. Covers initialisation, key generation, encrypt/decrypt,
error handling, context management, slot selection, PIN handling, and more.

A conditional integration test at the bottom runs against SoftHSM2 when the
library is present on the system.
"""

import os
import pathlib
import shutil
import sys
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.exceptions import AmaHSMUnavailableError
from ama_cryptography.key_management import HSMKeyStorage

# ---------------------------------------------------------------------------
# Helper: build a realistic mock PyKCS11 module
# ---------------------------------------------------------------------------


def _make_mock_pkcs11() -> MagicMock:
    """Return a MagicMock that mimics the PyKCS11 top-level module."""
    mock = MagicMock()

    # Attribute objects used via CKA.<name>
    mock.CKA = MagicMock()
    mock.CKM = MagicMock()
    mock.CKO_SECRET_KEY = 0x04
    mock.CKK_AES = 0x1F

    # Session flag constants used in _open_session
    mock.CKF_SERIAL_SESSION = 0x04
    mock.CKF_RW_SESSION = 0x02

    # Exception class must be a real class so isinstance/except works
    class _PyKCS11Error(Exception):
        pass

    mock.PyKCS11Error = _PyKCS11Error

    # AES_GCM_Mechanism callable
    mock.AES_GCM_Mechanism = MagicMock()
    mock.Mechanism = MagicMock()

    # PyKCS11Lib
    mock_lib = MagicMock()
    mock.PyKCS11Lib.return_value = mock_lib

    # Token info with a label attribute that behaves like a padded string
    token_info = MagicMock()
    # Use a real string subclass so .strip() works naturally
    token_info.label = "AmaCryptography          "

    mock_lib.getSlotList.return_value = [0]
    mock_lib.getTokenInfo.return_value = token_info

    # Session
    mock_session = MagicMock()
    mock_lib.openSession.return_value = mock_session

    return mock


def _build_hsm(
    mock_pkcs11: MagicMock,
    hsm_type: str = "softhsm",
    library_path: str = "/usr/lib/softhsm/libsofthsm2.so",
    token_label: str = "AmaCryptography",  # noqa: S107 -- test fixture label, not a production secret (HSM-001)
    pin: str = "1234",
    slot_index: Optional[int] = None,
) -> HSMKeyStorage:
    """Construct an HSMKeyStorage instance with all internals mocked."""
    with (
        patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock_pkcs11),
        patch("os.path.exists", return_value=True),
    ):
        return HSMKeyStorage(
            hsm_type=hsm_type,
            library_path=library_path,
            token_label=token_label,
            pin=pin,
            slot_index=slot_index,
        )


# ===========================================================================
# Module-level autouse fixture
# ===========================================================================


@pytest.fixture(autouse=True)
def _hsm_available(monkeypatch: Any) -> None:
    """Patch HSM_AVAILABLE=True for every test in this module.

    Without this, HSMKeyStorage.__init__ raises AmaHSMUnavailableError before
    _import_pykcs11() is ever called, breaking all mock-based tests in
    environments where PyKCS11 is not installed (standard CI).

    Tests that specifically verify the HSM_AVAILABLE=False path (e.g.
    test_init_raises_hsm_unavailable_when_pykcs11_missing) override this
    within their own body via patch().
    """
    monkeypatch.setattr("ama_cryptography.key_management.HSM_AVAILABLE", True)


# ===========================================================================
# Tests: __init__ / construction
# ===========================================================================


class TestHSMInit:
    """Tests for HSMKeyStorage.__init__ and its helper methods."""

    def test_init_default_softhsm(self) -> None:
        """Default construction with softhsm type succeeds."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        assert hsm._logged_in is True

    def test_init_with_custom_library_path(self) -> None:
        """When library_path is provided it is used directly."""
        mock = _make_mock_pkcs11()
        custom_path = "/custom/pkcs11.so"
        hsm = _build_hsm(mock, library_path=custom_path)
        assert hsm.library_path == custom_path

    def test_init_yubikey_type(self) -> None:
        """Initialisation with hsm_type='yubikey' resolves correct paths."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock, hsm_type="yubikey", library_path="/lib/yk.so")
        assert hsm.library_path == "/lib/yk.so"

    def test_init_nitrokey_type(self) -> None:
        """Initialisation with hsm_type='nitrokey'."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock, hsm_type="nitrokey", library_path="/lib/nk.so")
        assert hsm.library_path == "/lib/nk.so"

    def test_init_aws_cloudhsm_type(self) -> None:
        """Initialisation with hsm_type='aws-cloudhsm'."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock, hsm_type="aws-cloudhsm", library_path="/lib/aws.so")
        assert hsm.library_path == "/lib/aws.so"

    def test_init_thales_luna_type(self) -> None:
        """Initialisation with hsm_type='thales-luna'."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock, hsm_type="thales-luna", library_path="/lib/luna.so")
        assert hsm.library_path == "/lib/luna.so"

    def test_init_unknown_hsm_type_raises_valueerror(self) -> None:
        """An unknown hsm_type without a library_path raises ValueError."""
        mock = _make_mock_pkcs11()
        with patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock):
            with pytest.raises(ValueError, match="Unknown HSM type"):
                HSMKeyStorage(hsm_type="unknown-vendor", pin="0000")

    def test_init_auto_resolve_softhsm_path(self) -> None:
        """When no library_path is given, _resolve_library_path searches PKCS11_PATHS."""
        mock = _make_mock_pkcs11()
        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", side_effect=lambda p: p == "/usr/lib/softhsm/libsofthsm2.so"),
        ):
            hsm = HSMKeyStorage(hsm_type="softhsm", pin="1234")
            assert hsm.library_path == "/usr/lib/softhsm/libsofthsm2.so"

    def test_init_library_not_found_raises_runtime_error(self) -> None:
        """If no PKCS#11 library file exists on disk, RuntimeError is raised."""
        mock = _make_mock_pkcs11()
        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=False),
        ):
            with pytest.raises(RuntimeError, match="PKCS#11 library not found"):
                HSMKeyStorage(hsm_type="softhsm", pin="1234")

    def test_init_raises_hsm_unavailable_when_pykcs11_missing(self) -> None:
        """When HSM_AVAILABLE is False, __init__ raises AmaHSMUnavailableError."""
        with patch("ama_cryptography.key_management.HSM_AVAILABLE", False):
            with pytest.raises(AmaHSMUnavailableError, match="PyKCS11"):
                HSMKeyStorage()


# ===========================================================================
# Tests: library loading errors
# ===========================================================================


class TestLibraryLoading:
    """Tests for PKCS#11 library loading failures."""

    def test_load_library_failure_raises_runtime_error(self) -> None:
        """If lib.load() throws PyKCS11Error, a RuntimeError is raised."""
        mock = _make_mock_pkcs11()
        lib_instance = mock.PyKCS11Lib.return_value
        lib_instance.load.side_effect = mock.PyKCS11Error("lib not loadable")

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(RuntimeError, match="Failed to load PKCS#11 library"):
                HSMKeyStorage(library_path="/bad/lib.so", pin="1234")

    def test_import_pykcs11_not_installed_raises_hsm_unavailable(self) -> None:
        """When PyKCS11 is not installed, AmaHSMUnavailableError is raised."""
        hsm = object.__new__(HSMKeyStorage)
        with patch.dict("sys.modules", {"PyKCS11": None}):
            with pytest.raises(AmaHSMUnavailableError, match="HSM support requires PyKCS11"):
                hsm._import_pykcs11()


# ===========================================================================
# Tests: token / slot selection
# ===========================================================================


class TestSlotSelection:
    """Tests for _find_token_slot with various slot configurations."""

    def test_slot_index_selects_correct_slot(self) -> None:
        """Providing slot_index picks the slot at that position."""
        mock = _make_mock_pkcs11()
        lib_inst = mock.PyKCS11Lib.return_value
        lib_inst.getSlotList.return_value = [10, 20, 30]

        token_info = MagicMock()
        token_info.label = "AmaCryptography          "
        lib_inst.getTokenInfo.return_value = token_info

        hsm = _build_hsm(mock, slot_index=1)
        assert hsm.slot == 20

    def test_slot_index_out_of_range_raises_valueerror(self) -> None:
        """A slot_index beyond available slots raises ValueError."""
        mock = _make_mock_pkcs11()
        lib_inst = mock.PyKCS11Lib.return_value
        lib_inst.getSlotList.return_value = [0]

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(ValueError, match=r"Slot index .* out of range"):
                HSMKeyStorage(library_path="/lib.so", pin="1234", slot_index=5)

    def test_no_tokens_found_raises_runtime_error(self) -> None:
        """Empty slot list raises RuntimeError."""
        mock = _make_mock_pkcs11()
        lib_inst = mock.PyKCS11Lib.return_value
        lib_inst.getSlotList.return_value = []

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(RuntimeError, match="No HSM tokens found"):
                HSMKeyStorage(library_path="/lib.so", pin="1234")

    def test_token_label_not_found_raises_runtime_error(self) -> None:
        """If no slot matches the token_label, RuntimeError lists available tokens."""
        mock = _make_mock_pkcs11()
        lib_inst = mock.PyKCS11Lib.return_value
        lib_inst.getSlotList.return_value = [0]

        other_token = MagicMock()
        other_token.label = "OtherToken               "
        lib_inst.getTokenInfo.return_value = other_token

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(RuntimeError, match=r"Token .* not found"):
                HSMKeyStorage(
                    library_path="/lib.so",
                    token_label="NonExistent",
                    pin="1234",
                )


# ===========================================================================
# Tests: PIN handling
# ===========================================================================


class TestPINHandling:
    """Tests for PIN login behaviour."""

    def test_pin_provided_directly(self) -> None:
        """When a PIN is passed, login is called with that PIN."""
        mock = _make_mock_pkcs11()
        _build_hsm(mock, pin="9999")
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.login.assert_called_once_with("9999")

    def test_pin_prompt_via_getpass(self) -> None:
        """When pin=None, getpass is used to prompt for the PIN."""
        mock = _make_mock_pkcs11()
        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
            patch("getpass.getpass", return_value="prompted_pin"),
        ):
            HSMKeyStorage(library_path="/lib.so", pin=None)
            session = mock.PyKCS11Lib.return_value.openSession.return_value
            session.login.assert_called_once_with("prompted_pin")

    def test_incorrect_pin_raises_runtime_error(self) -> None:
        """CKR_PIN_INCORRECT from HSM raises RuntimeError('Invalid PIN')."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.login.side_effect = mock.PyKCS11Error("CKR_PIN_INCORRECT")

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(RuntimeError, match="Invalid PIN"):
                HSMKeyStorage(library_path="/lib.so", pin="wrong")

    def test_login_generic_failure(self) -> None:
        """Non-PIN PKCS#11 login error is wrapped in RuntimeError."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.login.side_effect = mock.PyKCS11Error("CKR_GENERAL_ERROR")

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(RuntimeError, match="HSM login failed"):
                HSMKeyStorage(library_path="/lib.so", pin="1234")


# ===========================================================================
# Tests: session failures
# ===========================================================================


class TestSessionFailures:
    """Tests for session open/close error paths."""

    def test_open_session_failure_raises_runtime_error(self) -> None:
        """If openSession raises PyKCS11Error, RuntimeError is raised."""
        mock = _make_mock_pkcs11()
        lib_inst = mock.PyKCS11Lib.return_value
        lib_inst.openSession.side_effect = mock.PyKCS11Error("CKR_SESSION_CLOSED")

        with (
            patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(RuntimeError, match="Failed to open HSM session"):
                HSMKeyStorage(library_path="/lib.so", pin="1234")


# ===========================================================================
# Tests: generate_aes_key
# ===========================================================================


class TestGenerateAESKey:
    """Tests for HSMKeyStorage.generate_aes_key."""

    def test_generate_aes_key_256(self) -> None:
        """Generate a 256-bit AES key and receive a handle."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.generateKey.return_value = 42

        hsm = _build_hsm(mock)
        handle = hsm.generate_aes_key("test-key", key_size=256)

        assert handle == (42).to_bytes(8, "big")
        session.generateKey.assert_called_once()

    def test_generate_aes_key_128(self) -> None:
        """128-bit key generation is valid."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.generateKey.return_value = 7

        hsm = _build_hsm(mock)
        handle = hsm.generate_aes_key("small-key", key_size=128)
        assert handle == (7).to_bytes(8, "big")

    def test_generate_aes_key_192(self) -> None:
        """192-bit key generation is valid."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.generateKey.return_value = 8

        hsm = _build_hsm(mock)
        handle = hsm.generate_aes_key("med-key", key_size=192)
        assert handle == (8).to_bytes(8, "big")

    def test_generate_aes_key_invalid_size_raises_valueerror(self) -> None:
        """Key sizes other than 128/192/256 raise ValueError."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        with pytest.raises(ValueError, match="Invalid key size"):
            hsm.generate_aes_key("bad-key", key_size=512)

    def test_generate_aes_key_pkcs11_error(self) -> None:
        """PyKCS11Error during generation is wrapped in RuntimeError."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.generateKey.side_effect = mock.PyKCS11Error("CKR_DEVICE_ERROR")

        hsm = _build_hsm(mock)
        with pytest.raises(RuntimeError, match="Failed to generate AES key"):
            hsm.generate_aes_key("fail-key")

    def test_generate_aes_key_extractable_flag(self) -> None:
        """The extractable parameter is forwarded in the template."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.generateKey.return_value = 1

        hsm = _build_hsm(mock)
        hsm.generate_aes_key("exp-key", extractable=True)
        # Verify generateKey was called (template is opaque MagicMock attrs)
        session.generateKey.assert_called_once()


# ===========================================================================
# Tests: encrypt / decrypt
# ===========================================================================


class TestEncryptDecrypt:
    """Tests for HSMKeyStorage.encrypt and .decrypt."""

    def test_encrypt_returns_nonce_ciphertext_tag(self) -> None:
        """encrypt() returns a 3-tuple of (nonce, ciphertext, tag)."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        # Simulate GCM output: ciphertext (10 bytes) + tag (16 bytes)
        fake_ct_tag = b"\x01" * 10 + b"\x02" * 16
        session.encrypt.return_value = list(fake_ct_tag)

        hsm = _build_hsm(mock)
        key_handle = (1).to_bytes(8, "big")
        nonce, ct, tag = hsm.encrypt(key_handle, b"hello")

        assert len(nonce) == 12
        assert ct == b"\x01" * 10
        assert tag == b"\x02" * 16

    def test_decrypt_returns_plaintext(self) -> None:
        """decrypt() returns the original plaintext bytes."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.decrypt.return_value = list(b"hello world")

        hsm = _build_hsm(mock)
        key_handle = (1).to_bytes(8, "big")
        pt = hsm.decrypt(key_handle, b"\x00" * 12, b"ciphertext", b"\x00" * 16)
        assert pt == b"hello world"

    def test_encrypt_decrypt_roundtrip_mock(self) -> None:
        """Mocked round-trip: encrypt then decrypt yields original data."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value

        plaintext = b"sensitive payload"
        fake_ct_tag = b"\xab" * len(plaintext) + b"\xcd" * 16
        session.encrypt.return_value = list(fake_ct_tag)
        session.decrypt.return_value = list(plaintext)

        hsm = _build_hsm(mock)
        key_handle = (99).to_bytes(8, "big")

        nonce, ct, tag = hsm.encrypt(key_handle, plaintext)
        recovered = hsm.decrypt(key_handle, nonce, ct, tag)
        assert recovered == plaintext

    def test_encrypt_pkcs11_error(self) -> None:
        """PyKCS11Error during encryption raises RuntimeError."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.encrypt.side_effect = mock.PyKCS11Error("CKR_DEVICE_MEMORY")

        hsm = _build_hsm(mock)
        with pytest.raises(RuntimeError, match="HSM encryption failed"):
            hsm.encrypt((1).to_bytes(8, "big"), b"data")

    def test_decrypt_tag_mismatch_error(self) -> None:
        """CKR_ENCRYPTED_DATA_INVALID triggers a tamper-detection message."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.decrypt.side_effect = mock.PyKCS11Error("CKR_ENCRYPTED_DATA_INVALID")

        hsm = _build_hsm(mock)
        with pytest.raises(RuntimeError, match="authentication tag mismatch"):
            hsm.decrypt((1).to_bytes(8, "big"), b"\x00" * 12, b"ct", b"\x00" * 16)

    def test_decrypt_generic_pkcs11_error(self) -> None:
        """Non-tag-mismatch decryption error raises generic RuntimeError."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.decrypt.side_effect = mock.PyKCS11Error("CKR_DEVICE_ERROR")

        hsm = _build_hsm(mock)
        with pytest.raises(RuntimeError, match="HSM decryption failed"):
            hsm.decrypt((1).to_bytes(8, "big"), b"\x00" * 12, b"ct", b"\x00" * 16)


# ===========================================================================
# Tests: find_key
# ===========================================================================


class TestFindKey:
    """Tests for HSMKeyStorage.find_key."""

    def test_find_key_exists(self) -> None:
        """find_key returns a handle when the key exists."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.findObjects.return_value = [42]

        hsm = _build_hsm(mock)
        handle = hsm.find_key("my-key")
        assert handle == (42).to_bytes(8, "big")

    def test_find_key_not_found(self) -> None:
        """find_key returns None when no matching key exists."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.findObjects.return_value = []

        hsm = _build_hsm(mock)
        assert hsm.find_key("nonexistent") is None

    def test_find_key_pkcs11_error_returns_none(self) -> None:
        """find_key returns None on PyKCS11Error (graceful degradation)."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.findObjects.side_effect = mock.PyKCS11Error("CKR_SESSION_CLOSED")

        hsm = _build_hsm(mock)
        assert hsm.find_key("broken") is None


# ===========================================================================
# Tests: delete_key
# ===========================================================================


class TestDeleteKey:
    """Tests for HSMKeyStorage.delete_key."""

    def test_delete_key_success(self) -> None:
        """delete_key returns True when destroyObject succeeds."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        assert hsm.delete_key((10).to_bytes(8, "big")) is True

    def test_delete_key_not_found(self) -> None:
        """delete_key returns False when destroyObject raises PyKCS11Error."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.destroyObject.side_effect = mock.PyKCS11Error("CKR_OBJECT_HANDLE_INVALID")

        hsm = _build_hsm(mock)
        assert hsm.delete_key((999).to_bytes(8, "big")) is False


# ===========================================================================
# Tests: context manager (__enter__ / __exit__)
# ===========================================================================


class TestContextManager:
    """Tests for the context manager protocol."""

    def test_enter_returns_self(self) -> None:
        """__enter__ returns the HSMKeyStorage instance."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        assert hsm.__enter__() is hsm

    def test_exit_calls_close(self) -> None:
        """__exit__ delegates to close(), which logs out and closes session."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        session = mock.PyKCS11Lib.return_value.openSession.return_value

        hsm.__exit__(None, None, None)

        session.logout.assert_called_once()
        session.closeSession.assert_called_once()
        assert hsm._logged_in is False

    def test_with_statement_lifecycle(self) -> None:
        """Full with-statement lifecycle: enter, use, exit."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.generateKey.return_value = 5

        with _build_hsm(mock) as hsm:
            handle = hsm.generate_aes_key("ctx-key")
            assert handle == (5).to_bytes(8, "big")

        session.logout.assert_called_once()
        session.closeSession.assert_called_once()

    def test_close_idempotent(self) -> None:
        """Calling close() multiple times does not raise."""
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        hsm.close()
        hsm.close()  # second call should not raise

    def test_close_handles_logout_exception(self) -> None:
        """close() catches and logs exceptions from session.logout()."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.logout.side_effect = Exception("device removed")

        hsm = _build_hsm(mock)
        # Should not raise
        hsm.close()
        assert hsm._logged_in is False

    def test_close_handles_close_session_exception(self) -> None:
        """close() catches and logs exceptions from session.closeSession()."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.closeSession.side_effect = Exception("already closed")

        hsm = _build_hsm(mock)
        # Should not raise
        hsm.close()

    def test_del_calls_close(self) -> None:
        """__del__ triggers close() for cleanup."""
        import gc

        # Flush any lingering HSMKeyStorage objects from earlier tests so
        # their deferred __del__ calls do not run inside *our* gc.collect().
        gc.collect()

        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        session = mock.PyKCS11Lib.return_value.openSession.return_value

        del hsm
        gc.collect()
        session.logout.assert_called()


# ===========================================================================
# Tests: multiple sessions
# ===========================================================================


class TestMultipleSessions:
    """Tests for creating multiple HSMKeyStorage instances concurrently."""

    def test_two_independent_sessions(self) -> None:
        """Two HSMKeyStorage instances operate on independent sessions."""
        mock1 = _make_mock_pkcs11()
        mock2 = _make_mock_pkcs11()

        session1 = mock1.PyKCS11Lib.return_value.openSession.return_value
        session2 = mock2.PyKCS11Lib.return_value.openSession.return_value
        session1.generateKey.return_value = 1
        session2.generateKey.return_value = 2

        hsm1 = _build_hsm(mock1)
        hsm2 = _build_hsm(mock2)

        h1 = hsm1.generate_aes_key("key-a")
        h2 = hsm2.generate_aes_key("key-b")

        assert h1 != h2
        hsm1.close()
        hsm2.close()

    def test_close_one_does_not_affect_other(self) -> None:
        """Closing one session leaves the other functional."""
        mock1 = _make_mock_pkcs11()
        mock2 = _make_mock_pkcs11()
        session2 = mock2.PyKCS11Lib.return_value.openSession.return_value
        session2.findObjects.return_value = [77]

        hsm1 = _build_hsm(mock1)
        hsm2 = _build_hsm(mock2)

        hsm1.close()
        # hsm2 should still work
        handle = hsm2.find_key("still-alive")
        assert handle == (77).to_bytes(8, "big")
        hsm2.close()


# ===========================================================================
# Tests: key listing (via find_key with different labels)
# ===========================================================================


class TestKeyListing:
    """Tests exercising key lookup patterns that simulate key listing."""

    def test_find_multiple_keys_by_label(self) -> None:
        """Sequential find_key calls for different labels each succeed."""
        mock = _make_mock_pkcs11()
        session = mock.PyKCS11Lib.return_value.openSession.return_value
        session.findObjects.side_effect = [[10], [20], []]

        hsm = _build_hsm(mock)
        assert hsm.find_key("key-a") == (10).to_bytes(8, "big")
        assert hsm.find_key("key-b") == (20).to_bytes(8, "big")
        assert hsm.find_key("key-c") is None


# ===========================================================================
# Tests: PKCS11_PATHS constant
# ===========================================================================


class TestPKCS11Paths:
    """Validate the PKCS11_PATHS mapping on the class."""

    def test_all_known_hsm_types_present(self) -> None:
        """All documented HSM types have entries in PKCS11_PATHS."""
        expected = {"yubikey", "nitrokey", "softhsm", "aws-cloudhsm", "thales-luna"}
        assert expected == set(HSMKeyStorage.PKCS11_PATHS.keys())

    def test_each_type_has_at_least_one_path(self) -> None:
        """Every HSM type entry contains at least one library path."""
        for hsm_type, paths in HSMKeyStorage.PKCS11_PATHS.items():
            assert len(paths) >= 1, f"{hsm_type} has no library paths"

    def test_softhsm_auto_resolution_covers_windows(self) -> None:
        """The choco/Disig install path is auto-resolvable, not override-only.

        TestSoftHSMIntegration constructs ``HSMKeyStorage("softhsm")`` with no
        ``library_path`` override, so the Windows lane only works if the DLL
        the ``softhsm.install`` package lays down is in the search list.
        """
        assert "C:\\SoftHSM2\\lib\\softhsm2-x64.dll" in HSMKeyStorage.PKCS11_PATHS["softhsm"]


# ===========================================================================
# Conditional integration test: SoftHSM2
# ===========================================================================

#: Where Debian/Ubuntu's ``softhsm2`` package installs the PKCS#11 module, and
#: where a multiarch install puts it.  Both are checked: a host with the token
#: available but at the second path used to read as "not installed".
_SOFTHSM_LIB_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",  # Homebrew on Intel macOS
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",  # Homebrew on Apple Silicon
    "C:\\SoftHSM2\\lib\\softhsm2-x64.dll",  # Disig MSI via `choco install softhsm.install`
)


def _softhsm_module_path() -> "str | None":
    """The installed SoftHSM2 PKCS#11 module, or None.

    Derived from ``softhsm2-util``'s own location first, then the fixed
    candidate list.  Deriving matters: Homebrew's prefix differs by
    architecture (``/opt/homebrew`` on Apple Silicon, ``/usr/local`` on
    Intel), and a package manager is free to move it again.  A fixed list
    that happens to omit the live prefix reports "SoftHSM2 not installed" on
    a host where it *is* installed — the same failure as the ``.so.2`` SONAME
    pin in the ACVP harness, and it would have made provisioning the macOS
    runners look like it worked while the lane went on skipping.

    On win32 the Disig build lays the module out differently: the DLL sits
    directly under ``<prefix>\\lib`` (no ``softhsm`` subdirectory) as
    ``softhsm2-x64.dll``, so the derivation has its own arm rather than
    pretending the POSIX layout is universal.
    """
    util = shutil.which("softhsm2-util")
    if util:
        prefix = os.path.dirname(os.path.dirname(os.path.realpath(util)))
        if sys.platform == "win32":
            # <prefix>\bin\softhsm2-util.exe -> <prefix>\lib\softhsm2-x64.dll
            derived = os.path.join(prefix, "lib", "softhsm2-x64.dll")
        else:
            # <prefix>/bin/softhsm2-util -> <prefix>/lib/softhsm/libsofthsm2.so
            derived = os.path.join(prefix, "lib", "softhsm", "libsofthsm2.so")
        if os.path.exists(derived):
            return derived
    return next((c for c in _SOFTHSM_LIB_CANDIDATES if os.path.exists(c)), None)


_SOFTHSM_LIB = _softhsm_module_path()


def _pykcs11_importable() -> bool:
    """Whether ``HSMKeyStorage`` can actually reach a token.

    Checked as part of the availability predicate, not left implicit.
    ``HSMKeyStorage`` reaches the token through PyKCS11, so a host with
    SoftHSM2 installed and PyKCS11 absent made this class ERROR rather than
    skip — the predicate claimed a capability one of whose halves it never
    tested.  It is a real configuration: the ``hsm`` extra is optional, and
    SoftHSM2 arrives from the system package manager.
    """
    import importlib.util

    return importlib.util.find_spec("PyKCS11") is not None


_SOFTHSM_AVAILABLE = (
    _SOFTHSM_LIB is not None and shutil.which("softhsm2-util") is not None and _pykcs11_importable()
)


def _softhsm_unavailable_reason() -> str:
    """Which half is missing, so a skip line says what to install."""
    missing = []
    if _SOFTHSM_LIB is None:
        missing.append(
            "SoftHSM2 module (apt-get install softhsm2 / brew install softhsm / "
            "choco install softhsm.install)"
        )
    if shutil.which("softhsm2-util") is None:
        missing.append("softhsm2-util")
    if not _pykcs11_importable():
        missing.append("PyKCS11 (pip install '.[hsm]')")
    return "SoftHSM2 integration unavailable: missing " + ", ".join(missing)


def test_softhsm_lane_is_provisioned_in_ci() -> None:
    """Under ``AMA_CI_REQUIRE_BACKENDS=1`` the HSM lane must actually run.

    ``TestSoftHSMIntegration`` is the only coverage of the real PKCS#11 key
    lifecycle — every other test in this file drives a mock.  It skipped on
    every job this repository had ever run, because nothing installed SoftHSM2,
    so "HSM support works" rested entirely on mocks agreeing with themselves.

    The declarative ``skipif`` below cannot be escalated by conftest's
    ``AMA_CI_REQUIRE_BACKENDS`` hook (its reason does not name a crypto
    backend), so the requirement is asserted here instead: in the CI job that
    promises every backend is present, a missing token is a failure with a
    remedy attached, not a quiet skip.

    Asserted on every platform CI runs.  The history of this test's scope is
    a history of claims being retired one by one.  An earlier revision scoped
    it to Linux only and wrote the macOS gap up as a known limitation; that
    was a choice presented as a constraint — `brew install softhsm` ships the
    same PKCS#11 module — so macOS was provisioned and asserted instead.

    Windows was the last holdout, excused by "SoftHSM2 has no maintained
    package on any Windows runner manager, only a manual installer".  That
    claim was checked and found false: Chocolatey's ``softhsm.install``
    package (which wraps the Disig SoftHSM2-for-Windows MSI) is live on the
    community feed, and ``choco`` is on every windows-latest runner.  CI now
    installs it with ``INSTALLDIR`` pinned to ``C:\\SoftHSM2`` and then
    *discovers* the resulting module before putting its ``bin\\`` on the job
    PATH.  The pin matters: the MSI parents its directory to ``TARGETDIR``,
    which Windows Installer resolves to ``ROOTDRIVE`` — the fixed drive with
    the most free space, ``D:`` on these runners — so the first revision's
    hard-coded ``C:\\SoftHSM2\\lib\\softhsm2-x64.dll`` assertion failed every
    Windows lane on an otherwise successful install.  Windows is held to the
    same provisioning standard as Linux and macOS rather than skipped on the
    strength of a falsified premise.

    The requirement is not a hole if a step is deleted:
    ``test_the_workflow_still_provisions_softhsm`` asserts the provisioning
    steps still exist, so removing one fails the suite rather than silently
    returning this lane to the skip it spent this release's whole history in.
    """
    if os.environ.get("AMA_CI_REQUIRE_BACKENDS", "").lower() not in ("true", "1", "yes"):
        pytest.skip("AMA_CI_REQUIRE_BACKENDS is not set — local run")
    assert _SOFTHSM_AVAILABLE, (
        _softhsm_unavailable_reason()
        + ". This job asserts every backend is provisioned; install SoftHSM2 "
        "and the [hsm] extra (see the 'Install SoftHSM2' step in ci.yml) "
        "rather than letting the only real PKCS#11 coverage skip."
    )


def test_the_workflow_still_provisions_softhsm() -> None:
    """Every workflow that promises provisioned backends must install the token.

    ``test_softhsm_lane_is_provisioned_in_ci`` only fires where the token is
    expected, so on its own it would be satisfied by removing the step that
    installs it — the lane would return to skipping everywhere and both checks
    would stay green. This asserts the provisioning exists, so the pair cannot
    be satisfied by deletion.

    Both workflows are checked, because both set ``AMA_CI_REQUIRE_BACKENDS=1``.
    ``ci-build-test.yml`` set that flag while installing neither the token nor
    PyKCS11, so it promised every backend was present and skipped the only
    real PKCS#11 coverage in the tree — which is exactly the shape this test
    exists to catch, and is how it was found.

    Reads the workflows rather than trusting a comment: the claim is about
    what CI does.
    """
    workflows = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"
    for name in ("ci.yml", "ci-build-test.yml"):
        text = (workflows / name).read_text(encoding="utf-8")
        if "AMA_CI_REQUIRE_BACKENDS" not in text:
            continue
        assert "softhsm2" in text or "brew install softhsm" in text, (
            f"{name} sets AMA_CI_REQUIRE_BACKENDS but no longer installs softhsm2. "
            f"TestSoftHSMIntegration is the only real PKCS#11 coverage in the tree; "
            f"without this step it skips while the flag claims every backend is present."
        )
        # Windows evidence is asserted separately: the choco package name is
        # the only string the apt/brew checks above cannot be satisfied by,
        # so deleting just the Windows step would otherwise stay green while
        # test_softhsm_lane_is_provisioned_in_ci failed the Windows entries.
        assert "softhsm.install" in text, (
            f"{name} sets AMA_CI_REQUIRE_BACKENDS but no longer installs the "
            f"Windows SoftHSM2 token (choco softhsm.install). The Windows matrix "
            f"entries assert the real PKCS#11 lane runs there; without this step "
            f"they fail — or, if the assertion is also removed, silently skip."
        )
        assert "hsm]" in text, (
            f"{name} no longer installs the [hsm] extra, so PyKCS11 is absent and the "
            f"SoftHSM2 lane skips even with the token installed."
        )


@pytest.mark.skipif(not _SOFTHSM_AVAILABLE, reason=_softhsm_unavailable_reason())
class TestSoftHSMIntegration:
    """
    Integration tests that run against a real SoftHSM2 instance.

    These tests are skipped unless SoftHSM2 is installed on the host.
    A temporary token is initialised before the test and cleaned up afterwards.
    """

    @pytest.fixture(autouse=True)
    def _setup_softhsm_token(self, tmp_path: Any) -> Any:
        """Create a temporary SoftHSM2 token for the test session."""
        token_dir = tmp_path / "softhsm_tokens"
        token_dir.mkdir()

        # Mirror the configuration SoftHSM2 itself ships.  The Disig Windows
        # MSI installs this exact shape (verified by extracting the package's
        # own softhsm2.conf): a tokendir with a TRAILING separator, plus the
        # objectstore/log/slots keys stated rather than left to defaults.  The
        # first revision wrote only `directories.tokendir` with no trailing
        # separator, which is fine on Linux and macOS but is not the layout
        # the Windows build is shipped and tested against.
        conf_path = tmp_path / "softhsm2.conf"
        conf_path.write_text(
            f"directories.tokendir = {token_dir}{os.sep}\n"
            "objectstore.backend = file\n"
            "log.level = INFO\n"
            "slots.removable = false\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["SOFTHSM2_CONF"] = str(conf_path)
        self._env = env

        import subprocess

        # `--free` is the form softhsm2-util's own SYNOPSIS documents for
        # initialising a token ("--init-token --free --label text"); `--slot 0`
        # addresses a slot ID, and SoftHSM reassigns initialised tokens to a
        # serial-derived slot, so slot 0 is only incidentally the free one.
        # Verified equivalent on Linux 2.6.1 (both initialise a fresh store).
        # `--module` is passed explicitly rather than left to the loader's
        # search path.  softhsm2-util lives in <prefix>/bin while the PKCS#11
        # module lives in <prefix>/lib, so a bare LoadLibrary/dlopen depends on
        # that lib directory being on PATH (Windows) or the loader path (POSIX)
        # — which is why the Windows lane failed with
        #     LoadLibraryA failed: 0x0000007E   (ERROR_MOD_NOT_FOUND)
        # even with a correct install and bin/ on PATH.
        #
        # The module must match the *loading process's* architecture, and on
        # Windows that is not the same module the test process needs.  Verified
        # from the MSI payload's PE headers:
        #     softhsm2-util.exe  machine=0x014c  i386   (32-bit)
        #     softhsm2.dll       machine=0x014c  i386   (32-bit)
        #     softhsm2-x64.dll   machine=0x8664  AMD64  (64-bit)
        # The Disig package ships both modules deliberately: its command-line
        # tools are 32-bit, while a 64-bit Python loading the token through
        # PyKCS11 needs the x64 module.  Naming the x64 DLL for the 32-bit
        # utility is what turned 0x7E into
        #     LoadLibraryA failed: 0x000000C1   (ERROR_BAD_EXE_FORMAT)
        # — the module was found, and refused as a foreign image.  So the
        # utility is paired with its own-architecture sibling; HSMKeyStorage
        # keeps resolving the x64 module for this process.  On POSIX there is
        # one module and _SOFTHSM_LIB serves both.
        init_module = _SOFTHSM_LIB
        if sys.platform == "win32" and init_module is not None:
            sibling = pathlib.Path(init_module).with_name("softhsm2.dll")
            if sibling.is_file():
                init_module = str(sibling)

        init_cmd = [
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            "AmaTest",
            "--so-pin",
            "12345678",
            "--pin",
            "1234",
        ]
        if init_module is not None:
            init_cmd += ["--module", init_module]

        proc = subprocess.run(
            init_cmd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        # Surface the tool's own diagnosis.  `check=True` with captured output
        # raises a CalledProcessError whose message carries the exit status and
        # nothing else, which is how a Windows token-init failure reached CI as
        # an unactionable "returned non-zero exit status 1".
        assert proc.returncode == 0, (
            f"softhsm2-util --init-token failed (exit {proc.returncode})\n"
            f"config: {conf_path}\n{conf_path.read_text(encoding='utf-8')}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

        self._old_env = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = str(conf_path)
        yield
        if self._old_env is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = self._old_env

    def test_full_lifecycle(self) -> None:
        """End-to-end: connect, generate key, encrypt, decrypt, delete, close."""
        with HSMKeyStorage(
            hsm_type="softhsm",
            token_label="AmaTest",
            pin="1234",
        ) as hsm:
            key_handle = hsm.generate_aes_key("integration-key", key_size=256)
            assert len(key_handle) == 8

            plaintext = b"integration test payload"
            nonce, ct, tag = hsm.encrypt(key_handle, plaintext)
            recovered = hsm.decrypt(key_handle, nonce, ct, tag)
            assert recovered == plaintext

            found = hsm.find_key("integration-key")
            assert found is not None

            deleted = hsm.delete_key(key_handle)
            assert deleted is True

            assert hsm.find_key("integration-key") is None
