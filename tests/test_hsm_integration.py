#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
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
import shutil
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

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
    token_label: str = "AmaCryptography",  # noqa: S107
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

    def test_import_pykcs11_not_installed_raises_import_error(self) -> None:
        """When PyKCS11 is not installed, ImportError with helpful message is raised."""
        hsm = object.__new__(HSMKeyStorage)
        with patch.dict("sys.modules", {"PyKCS11": None}):
            with pytest.raises(ImportError, match="HSM support requires PyKCS11"):
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
        mock = _make_mock_pkcs11()
        hsm = _build_hsm(mock)
        session = mock.PyKCS11Lib.return_value.openSession.return_value

        hsm.__del__()
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


# ===========================================================================
# Conditional integration test: SoftHSM2
# ===========================================================================

_SOFTHSM_LIB = "/usr/lib/softhsm/libsofthsm2.so"
_SOFTHSM_AVAILABLE = os.path.exists(_SOFTHSM_LIB) and shutil.which("softhsm2-util") is not None


@pytest.mark.skipif(not _SOFTHSM_AVAILABLE, reason="SoftHSM2 is not installed")
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

        conf_path = tmp_path / "softhsm2.conf"
        conf_path.write_text(f"directories.tokendir = {token_dir}\n")

        env = os.environ.copy()
        env["SOFTHSM2_CONF"] = str(conf_path)
        self._env = env

        import subprocess

        subprocess.run(
            [
                "softhsm2-util",
                "--init-token",
                "--slot",
                "0",
                "--label",
                "AmaTest",
                "--so-pin",
                "12345678",
                "--pin",
                "1234",
            ],
            env=env,
            check=True,
            capture_output=True,
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
