# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Known answers for the HD derivation tree, and a gate on the BIP32 claim.

KM-HD-001.  ``tests/test_hd_key_derivation_vectors.py`` is named for vectors
and contains none: every assertion there is a structural or self-consistency
property (lengths, determinism, uniqueness), so the file passes unchanged
when ``k_i = (parse256(I_L) + k_par) mod n`` is mutated to an XOR, and when
the master key and chain code are swapped.  Structure without a fixed answer
does not test arithmetic.

No BIP32 vector can serve here, because the master key is derived with the
HMAC key ``b"AMA Cryptography Master Key"`` where BIP32 specifies
``b"Bitcoin seed"``: the tree is BIP32-shaped but rooted elsewhere.  So the
answers below are AMA-specific, generated from the shipped implementation and
frozen.  Their value is exactly that they are fixed: any change to the
derivation is a change to somebody's derived keys, and must be a deliberate,
visible one.

The last class keeps the documentation honest, because the original defect
was as much the claim as the code.
"""

from __future__ import annotations

import pathlib

import pytest

from ama_cryptography.key_management import HDKeyDerivation

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A fixed 64-byte seed: bytes 0x00..0x3f.
SEED = bytes(range(64))

MASTER_KEY = "7cdab45b22f214c96a3f862ce69c425505203843e309d04a919e0fc86767f535"
MASTER_CHAIN = "f21e83e5d47808054f9275c9b8ba9db332b1565742bdd35f521372eeaebf80c1"

#: path -> (private key hex, chain code hex).  Hardened throughout, so the
#: native secp256k1 public-key function is not required to replay them.
PATH_VECTORS: dict[str, tuple[str, str]] = {
    "m/0'": (
        "8960cf9e818d13566e9334bfaa1c123937d29e3c288af90881cd39d42517a3d4",
        "e066e84b2545b9c9098ca333b07b0c83f9561ac1635aa0ad00f01328d8c70114",
    ),
    "m/44'": (
        "86930008e2840cf9eec78ad440b7b6b5493c5631d8f6862e7601d42fc9a66b83",
        "fd09ebdaf107978babadfb70db62d62a62b50c3bedffbf452dd188aa0c5aca00",
    ),
    "m/44'/0'": (
        "ef263b3b01a8ceb0405a50b32031003fbd32ee3c8805d1913fe60943487db7d3",
        "01ead454775001940aef7c47d23e3c2855642df5ced743c95f0e4c25f10804fa",
    ),
    "m/44'/0'/0'": (
        "20ef2979e7973a06ddd4e02814aca73778207d5062c6b5f810baad833a8dad37",
        "074d650af08a2e8463f7e9cf540a83f8e8099109cba1dd78f6ffadd251bc1176",
    ),
    "m/44'/0'/0'/0'": (
        "ec1469d83c1867e5200e6630af12a143e41a8b2f834c3753c065b7531c3aa00a",
        "a716f2de0eaf29619eba636ef646817eff5a51e7994e32cd4b0cdd295b475c98",
    ),
    # The largest hardened index, exercising ser32(i) at its boundary.
    "m/2147483647'": (
        "c0dda8618502d1cc5d0a6d1a336bb2aef832891e781e05b0d13da03d21151fb6",
        "99901ea37f088d4a39d1a18f7444cb995832f7044df4c7d8c63a351619d589c3",
    ),
}


@pytest.fixture(scope="module")
def hd() -> HDKeyDerivation:
    return HDKeyDerivation(seed=SEED)


class TestTheRootIsPinned:
    def test_master_key_matches_the_frozen_answer(self, hd: HDKeyDerivation) -> None:
        assert hd.master_key.hex() == MASTER_KEY

    def test_master_chain_code_matches_the_frozen_answer(self, hd: HDKeyDerivation) -> None:
        assert hd.master_chain_code.hex() == MASTER_CHAIN

    def test_the_key_and_the_chain_code_are_not_interchangeable(self, hd: HDKeyDerivation) -> None:
        """A swapped split is the mutation the structural tests cannot see."""
        assert hd.master_key.hex() != MASTER_CHAIN
        assert hd.master_chain_code.hex() != MASTER_KEY

    def test_the_root_is_the_ama_one_not_bip32s(self) -> None:
        """Guards the documented non-interoperability in the other direction.

        If someone "fixes" the root to BIP32's ``b"Bitcoin seed"``, every
        derived key in every existing deployment moves.  This is the test
        that makes that a deliberate act.
        """
        from ama_cryptography.key_management import _hmac_sha512

        bip32_root = _hmac_sha512(b"Bitcoin seed", SEED)
        assert bip32_root[:32].hex() != MASTER_KEY, (
            "the master key now matches BIP32's root: this silently re-derives "
            "every key any existing tree has produced. If it is intended, it is "
            "a breaking change with a migration, not a docstring edit."
        )


class TestEveryPathIsPinned:
    @pytest.mark.parametrize("path", sorted(PATH_VECTORS))
    def test_path_matches_the_frozen_answer(self, hd: HDKeyDerivation, path: str) -> None:
        expected_key, expected_chain = PATH_VECTORS[path]
        key, chain = hd.derive_path(path)
        assert key.hex() == expected_key, f"{path}: derived private key moved"
        assert chain.hex() == expected_chain, f"{path}: derived chain code moved"

    def test_the_vectors_are_all_distinct(self) -> None:
        # Non-vacuity: identical answers would let one correct path carry them all.
        keys = {k for k, _ in PATH_VECTORS.values()}
        assert len(keys) == len(PATH_VECTORS)


class TestModularAdditionIsTheOperation:
    """The XOR mutation the previous file could not detect."""

    def test_a_child_key_is_the_modular_sum_not_the_xor(self, hd: HDKeyDerivation) -> None:
        from ama_cryptography.key_management import _hmac_sha512

        index = HDKeyDerivation.HARDENED_OFFSET  # 0'
        data = b"\x00" + hd.master_key + index.to_bytes(4, "big")
        i_l = _hmac_sha512(hd.master_chain_code, data)[:32]

        modular = (
            int.from_bytes(i_l, "big") + int.from_bytes(hd.master_key, "big")
        ) % HDKeyDerivation.SECP256K1_N
        xored = int.from_bytes(bytes(a ^ b for a, b in zip(i_l, hd.master_key)), "big")

        derived, _ = hd.derive_path("m/0'")
        assert int.from_bytes(derived, "big") == modular
        assert modular != xored, "seed chosen badly: the two operations coincide here"
        assert int.from_bytes(derived, "big") != xored


class TestTheDocumentationDoesNotClaimBip32Compliance:
    """The claim was the other half of the defect."""

    DOCS = (
        "ama_cryptography/key_management.py",
        "ENHANCED_FEATURES.md",
        "CRYPTOGRAPHY.md",
        "tests/test_key_management_comprehensive.py",
        "tests/test_hd_key_derivation_vectors.py",
    )

    @pytest.mark.parametrize("relative", DOCS)
    def test_no_file_claims_bip32_compliance(self, relative: str) -> None:
        path = REPO_ROOT / relative
        if not path.is_file():  # pragma: no cover - file removed
            pytest.skip(f"{relative} is not present")
        text = path.read_text(encoding="utf-8").lower()
        for claim in ("bip32-compliant", "bip32 compliant"):
            assert claim not in text, (
                f"{relative} claims {claim!r}. The master key is derived with "
                f"b'AMA Cryptography Master Key', not BIP32's b'Bitcoin seed', "
                f"so no BIP32 wallet derives these keys."
            )

    def test_the_class_docstring_states_the_non_interoperability(self) -> None:
        doc = (HDKeyDerivation.__doc__ or "").lower()
        assert "not bip32" in doc or "not interoperable" in doc, (
            "the class docstring must say plainly that this tree is not "
            "BIP32-interoperable; a reader who skims takes 'BIP32' as a promise"
        )
