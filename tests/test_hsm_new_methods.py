#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Tests for new HSMKeyStorage methods and HSM_AVAILABLE flag.

Covers:
- HSM_AVAILABLE module flag existence and type
- AmaHSMUnavailableError exists and is a RuntimeError subclass
- generate_ec_keypair()
- sign() / verify()
- destroy_key() alias for delete_key()
- list_keys()
- Constructor raises AmaHSMUnavailableError when PyKCS11 is absent
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Guard for tests that require key_management.py (needs native C library)
try:
    from ama_cryptography.pqc_backends import _native_lib

    NATIVE_AVAILABLE = _native_lib is not None
except ImportError:
    NATIVE_AVAILABLE = False

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE,
    reason="Native C library not available (build with cmake)",
)


# ---------------------------------------------------------------------------
# HSM_AVAILABLE and AmaHSMUnavailableError
# These tests use exceptions.py / __init__.py so they don't need native lib.
# ---------------------------------------------------------------------------


class TestHSMAvailableFlag:
    def test_hsm_available_is_bool(self):
        """HSM_AVAILABLE is exported from ama_cryptography and is a bool."""
        import ama_cryptography

        hsm_avail = getattr(ama_cryptography, "HSM_AVAILABLE", None)
        # When native lib is absent __init__.py sets HSM_AVAILABLE=False explicitly.
        assert isinstance(hsm_avail, bool)

    def test_ama_hsm_unavailable_error_is_runtime_error(self):
        """AmaHSMUnavailableError (from exceptions.py) is a RuntimeError subclass."""
        from ama_cryptography.exceptions import AmaHSMUnavailableError

        assert issubclass(AmaHSMUnavailableError, RuntimeError)

    @skip_no_native
    def test_init_raises_when_hsm_unavailable(self):
        """HSMKeyStorage.__init__ raises AmaHSMUnavailableError when HSM_AVAILABLE=False."""
        from ama_cryptography.key_management import AmaHSMUnavailableError, HSMKeyStorage

        with patch("ama_cryptography.key_management.HSM_AVAILABLE", False):
            with pytest.raises(AmaHSMUnavailableError, match="PyKCS11"):
                HSMKeyStorage(pin="1234")


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _build_mock_pkcs11() -> MagicMock:
    """Return a mock PyKCS11 module with all constants needed by HSMKeyStorage."""
    m = MagicMock()

    class _Err(Exception):
        pass

    m.PyKCS11Error = _Err

    # Constants
    m.CKF_SERIAL_SESSION = 0x04
    m.CKF_RW_SESSION = 0x02
    m.CKO_SECRET_KEY = 0x04
    m.CKO_PUBLIC_KEY = 0x02
    m.CKO_PRIVATE_KEY = 0x03
    m.CKK_AES = 0x1F
    m.CKK_EC = 0x03
    m.CKK_RSA = 0x00
    m.CKA_CLASS = 0
    m.CKA_KEY_TYPE = 1
    m.CKA_LABEL = 3
    m.CKA_TOKEN = 0x102
    m.CKA_PRIVATE = 0x103
    m.CKA_SENSITIVE = 0x103
    m.CKA_EXTRACTABLE = 0x162
    m.CKA_ENCRYPT = 0x104
    m.CKA_DECRYPT = 0x105
    m.CKA_WRAP = 0x106
    m.CKA_UNWRAP = 0x107
    m.CKA_SIGN = 0x108
    m.CKA_VERIFY = 0x10A
    m.CKA_VALUE_LEN = 0x161
    m.CKA_EC_PARAMS = 0x180
    m.CKM_AES_KEY_GEN = 0x1080
    m.CKM_EC_KEY_PAIR_GEN = 0x1040
    m.CKM_ECDSA_SHA256 = 0x1044
    m.AES_GCM_Mechanism = MagicMock()
    m.Mechanism = MagicMock()

    # Library
    lib = MagicMock()
    m.PyKCS11Lib.return_value = lib

    # Slot / token
    lib.getSlotList.return_value = [0]
    ti = MagicMock()

    class _Label(str):
        def strip(self):
            return "AmaCryptography"

    ti.label = _Label("AmaCryptography")
    lib.getTokenInfo.return_value = ti
    lib.openSession.return_value = MagicMock()

    return m


def _make_hsm(mock_pkcs11: MagicMock) -> Any:
    """Instantiate an HSMKeyStorage against a mock PyKCS11 module."""
    from ama_cryptography.key_management import HSMKeyStorage

    with (
        patch("ama_cryptography.key_management.HSM_AVAILABLE", True),
        patch.object(HSMKeyStorage, "_import_pykcs11", return_value=mock_pkcs11),
        patch.object(
            HSMKeyStorage,
            "_resolve_library_path",
            return_value="/fake/libsofthsm2.so",
        ),
        patch.object(HSMKeyStorage, "_load_pkcs11_library", return_value=mock_pkcs11.PyKCS11Lib()),
        patch.object(HSMKeyStorage, "_find_token_slot", return_value=0),
        patch.object(HSMKeyStorage, "_open_session", return_value=mock_pkcs11.PyKCS11Lib()),
        patch.object(HSMKeyStorage, "_login", return_value=None),
    ):
        hsm = HSMKeyStorage.__new__(HSMKeyStorage)
        hsm.pkcs11 = mock_pkcs11
        hsm.session = mock_pkcs11.PyKCS11Lib()
        hsm._handle_map = {}
        hsm._logged_in = True
        return hsm


# ---------------------------------------------------------------------------
# generate_ec_keypair
# ---------------------------------------------------------------------------


@skip_no_native
class TestHSMGenerateEcKeypair:
    def test_returns_two_handles(self):
        """generate_ec_keypair() returns (pub_handle, prv_handle) both 8 bytes."""
        pk = _build_mock_pkcs11()

        pub_obj = MagicMock()
        pub_obj.value.return_value = 101
        prv_obj = MagicMock()
        prv_obj.value.return_value = 102

        pk.PyKCS11Lib().generateKeyPair.return_value = (pub_obj, prv_obj)

        hsm = _make_hsm(pk)
        pub_h, prv_h = hsm.generate_ec_keypair("test-ec")
        assert len(pub_h) == 8
        assert len(prv_h) == 8

    def test_invalid_curve_raises(self):
        """Unsupported curve name raises ValueError."""
        pk = _build_mock_pkcs11()
        hsm = _make_hsm(pk)
        with pytest.raises(ValueError, match="Unsupported curve"):
            hsm.generate_ec_keypair("bad", curve="secp999k1")

    def test_p384_accepted(self):
        """P-384 curve is accepted without error."""
        pk = _build_mock_pkcs11()
        pub_obj = MagicMock()
        pub_obj.value.return_value = 200
        prv_obj = MagicMock()
        prv_obj.value.return_value = 201
        pk.PyKCS11Lib().generateKeyPair.return_value = (pub_obj, prv_obj)
        hsm = _make_hsm(pk)
        pub_h, prv_h = hsm.generate_ec_keypair("p384-key", curve="P-384")
        assert len(pub_h) == 8


# ---------------------------------------------------------------------------
# sign / verify
# ---------------------------------------------------------------------------


@skip_no_native
class TestHSMSignVerify:
    def test_sign_returns_bytes(self):
        """sign() returns bytes from HSM session.sign."""
        pk = _build_mock_pkcs11()
        fake_sig = b"\xde\xad\xbe\xef" * 16
        pk.PyKCS11Lib().sign.return_value = list(fake_sig)
        hsm = _make_hsm(pk)

        handle = (99).to_bytes(8, "big")
        hsm._handle_map[handle] = 99

        sig = hsm.sign(handle, b"data to sign")
        assert sig == fake_sig

    def test_verify_returns_true_on_success(self):
        """verify() returns True when session.verify does not raise."""
        pk = _build_mock_pkcs11()
        pk.PyKCS11Lib().verify.return_value = None  # no exception = valid
        hsm = _make_hsm(pk)

        handle = (88).to_bytes(8, "big")
        hsm._handle_map[handle] = 88

        result = hsm.verify(handle, b"data", b"\x00" * 64)
        assert result is True

    def test_verify_returns_false_on_pykcs11_error(self):
        """verify() returns False when PyKCS11Error is raised."""
        pk = _build_mock_pkcs11()
        pk.PyKCS11Lib().verify.side_effect = pk.PyKCS11Error("invalid")
        hsm = _make_hsm(pk)

        handle = (77).to_bytes(8, "big")
        hsm._handle_map[handle] = 77

        result = hsm.verify(handle, b"data", b"\x00" * 64)
        assert result is False


# ---------------------------------------------------------------------------
# destroy_key (alias for delete_key)
# ---------------------------------------------------------------------------


@skip_no_native
class TestHSMDestroyKey:
    def test_destroy_key_delegates_to_delete_key(self):
        """destroy_key() calls destroyObject and returns True on success."""
        pk = _build_mock_pkcs11()
        pk.PyKCS11Lib().destroyObject.return_value = None
        hsm = _make_hsm(pk)

        handle = (55).to_bytes(8, "big")
        obj = MagicMock()
        obj.value.return_value = 55
        hsm._handle_map[handle] = obj

        result = hsm.destroy_key(handle)
        assert result is True

    def test_destroy_key_returns_false_on_error(self):
        """destroy_key() returns False when PyKCS11Error is raised."""
        pk = _build_mock_pkcs11()
        pk.PyKCS11Lib().destroyObject.side_effect = pk.PyKCS11Error("fail")
        hsm = _make_hsm(pk)

        handle = (44).to_bytes(8, "big")
        result = hsm.destroy_key(handle)
        assert result is False


# ---------------------------------------------------------------------------
# list_keys
# ---------------------------------------------------------------------------


@skip_no_native
class TestHSMListKeys:
    def test_list_keys_returns_list(self):
        """list_keys() returns a list."""
        pk = _build_mock_pkcs11()
        pk.PyKCS11Lib().findObjects.return_value = []
        hsm = _make_hsm(pk)
        result = hsm.list_keys()
        assert isinstance(result, list)

    def test_list_keys_with_objects(self):
        """list_keys() maps found objects to dicts with expected keys."""
        pk = _build_mock_pkcs11()

        obj1 = MagicMock()
        obj1.value.return_value = 1001
        pk.PyKCS11Lib().findObjects.return_value = [obj1]
        pk.PyKCS11Lib().getAttributeValue.return_value = [
            pk.CKO_SECRET_KEY,  # CKA_CLASS
            pk.CKK_AES,  # CKA_KEY_TYPE
            list(b"my-key\x00"),  # CKA_LABEL as bytes
        ]

        hsm = _make_hsm(pk)
        result = hsm.list_keys()
        assert len(result) == 1
        assert "label" in result[0]
        assert "class" in result[0]
        assert "key_type" in result[0]
        assert "handle" in result[0]
