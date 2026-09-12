# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The trust store names the key that actually signs this project's releases.

Why this file exists
--------------------
``tools/check_release_tag.py`` checks a release tag's *shape* and says so: it
does not verify the signature, because verifying one needs a trust store — a
list binding a public key to a name.  Until now this repository shipped no such
list, and INVARIANT-10's addendum recorded that as a deliberate refusal:

    publishing an ``allowed_signers`` file would assert a key binding only the
    account owner can establish

The reasoning was about authority and it was sound.  The conclusion was not,
because the premise had already been satisfied: the maintainer had registered
the signing key on the account, and v4.0.0 — tagged twenty-eight minutes after
that sentence was committed — was signed with it.  "I cannot establish this
binding" had been written down as "this binding must not be published."

So the file now ships, and this module is the reason a reader may believe it.
An ``allowed_signers`` line is an assertion; on its own it is worth exactly as
much as the repository that carries it.  What makes it evidence is that the key
it names is demonstrably the key that signed a release: not a fingerprint
copied from a settings page into a document, but a signature checked against
the bytes it covers.

What is checked
---------------
The v4.0.0 tag object is embedded below verbatim (466 bytes, base64).  It is
embedded rather than read through ``git`` because ``actions/checkout`` does not
fetch tags at its default depth, and a check that silently skips on the runners
that matter is not a check.  Embedding is safe in a way a copied fingerprint is
not: a tag object that has been altered by so much as one byte fails
verification, which is the point of the exercise.

1. The key in ``.github/allowed_signers`` is byte-identical to the key carried
   inside the v4.0.0 signature.
2. That signature verifies over the tag payload.
3. The principal in the trust store is the tag's own tagger identity, and the
   entry is scoped ``namespaces="git"``.
4. Negative controls, because a verifier nobody has watched fail is a verifier
   nobody has watched: a one-byte-tampered payload must fail, a different key
   must fail, and a malformed signature must fail.
5. The verifier itself is checked against RFC 8032 §7.1 TEST 1 — a published
   known-answer, so a self-consistent-but-wrong implementation cannot pass.

The Ed25519 verifier is written here in the standard library alone.  ``git
verify-tag`` is the command a *consumer* runs (README documents it); it needs
``ssh-keygen``, which not every environment running this suite has, and
INVARIANT-1's refusal of external cryptographic dependencies is a poor thing to
honour everywhere except in the test that checks the release key.  Roughly
sixty lines of modular arithmetic is the cheaper answer, and its correctness is
pinned by the known-answer test rather than assumed.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_SIGNERS = REPO_ROOT / ".github" / "allowed_signers"

# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032), standard library only.
# ---------------------------------------------------------------------------

_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _point_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    """Twisted-Edwards addition on -x^2 + y^2 = 1 + d x^2 y^2 (affine)."""
    x1, y1 = p
    x2, y2 = q
    k = (_D * x1 * x2 * y1 * y2) % _P
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + k, _P - 2, _P)) % _P
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - k, _P - 2, _P)) % _P
    return (x3, y3)


def _scalar_mult(p: tuple[int, int], e: int) -> tuple[int, int]:
    """Double-and-add.  Not constant time; nothing secret is multiplied here."""
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        e >>= 1
    return q


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    xx = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    if xx == 0:
        return 0 if sign == 0 else None
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if (x * x - xx) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BASE_Y = (4 * pow(5, _P - 2, _P)) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
assert _BASE_X is not None
_BASE = (_BASE_X, _BASE_Y)


def _decode_point(raw: bytes) -> tuple[int, int] | None:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature over `message`."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decode_point(public_key)
    r = _decode_point(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    digest = hashlib.sha512(signature[:32] + public_key + message).digest()
    h = int.from_bytes(digest, "little") % _L
    return _scalar_mult(_BASE, s) == _point_add(r, _scalar_mult(a, h))


# ---------------------------------------------------------------------------
# The v4.0.0 tag object, verbatim.  `git cat-file tag v4.0.0 | base64`.
# ---------------------------------------------------------------------------

V4_TAG_OBJECT_B64 = (
    "b2JqZWN0IDRjYmU0NjVjOTRkZjEzMGY3NzlhMTc1YjVlOGE4ZDFhYjcyMDQxYjAKdHlwZSBjb21t"
    "aXQKdGFnIHY0LjAuMAp0YWdnZXIgU3RlZWwgU2VjdXJpdHkgQWR2aXNvcnMgTExDIDxzdGVlbC5z"
    "YS5sbGNAZ21haWwuY29tPiAxNzg1NjQyODgyICswMDAwCgphbWEtY3J5cHRvZ3JhcGh5IDQuMC4w"
    "Ci0tLS0tQkVHSU4gU1NIIFNJR05BVFVSRS0tLS0tClUxTklVMGxIQUFBQUFRQUFBRE1BQUFBTGMz"
    "Tm9MV1ZrTWpVMU1Ua0FBQUFnMlRGNmZ5ekdwRVRxU3JSa2lQYzl5Y0g5WnMKRlNxa2t5YUQ2bDFa"
    "ZFBHVU1BQUFBRFoybDBBQUFBQUFBQUFBWnphR0UxTVRJQUFBQlRBQUFBQzNOemFDMWxaREkxTlRF"
    "NQpBQUFBUUZBV2NNU0hFM211dTJJV1NkMUc0QksvT0hRNG42bndqcnU3cG0rNU5lcTdQTEI4SVdw"
    "OXVPSmkwVHZwQm8zTjIvCkxydlBvRVh4dWFKZWNvdmZnQ3RBYz0KLS0tLS1FTkQgU1NIIFNJR05B"
    "VFVSRS0tLS0tCg=="
)

_SSH_SIG_BEGIN = b"-----BEGIN SSH SIGNATURE-----\n"
_SSH_SIG_END = b"-----END SSH SIGNATURE-----\n"


def _read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", buf[off : off + 4])
    start = off + 4
    return buf[start : start + length], start + length


class _Sshsig:
    """A parsed SSHSIG blob (PROTOCOL.sshsig)."""

    def __init__(self, armored: bytes) -> None:
        blob = base64.b64decode(b"".join(armored.split()))
        if blob[:6] != b"SSHSIG":
            raise ValueError("not an SSHSIG blob")
        off = 6
        (self.version,) = struct.unpack(">I", blob[off : off + 4])
        off += 4
        self.public_key_blob, off = _read_string(blob, off)
        self.namespace, off = _read_string(blob, off)
        self.reserved, off = _read_string(blob, off)
        self.hash_algorithm, off = _read_string(blob, off)
        signature_blob, _ = _read_string(blob, off)

        key_type, pos = _read_string(self.public_key_blob, 0)
        self.key_type = key_type
        self.public_key, _ = _read_string(self.public_key_blob, pos)
        sig_type, pos = _read_string(signature_blob, 0)
        self.signature_type = sig_type
        self.signature, _ = _read_string(signature_blob, pos)

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.public_key_blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    def signed_data(self, message: bytes) -> bytes:
        """The bytes an SSHSIG signature actually covers."""
        message_hash = hashlib.new(self.hash_algorithm.decode(), message).digest()

        def s(field: bytes) -> bytes:
            return struct.pack(">I", len(field)) + field

        return (
            b"SSHSIG"
            + s(self.namespace)
            + s(self.reserved)
            + s(self.hash_algorithm)
            + s(message_hash)
        )

    def verify(self, message: bytes) -> bool:
        return ed25519_verify(self.public_key, self.signed_data(message), self.signature)


def _split_tag(tag_object: bytes) -> tuple[bytes, bytes]:
    """Return (signed payload, armored signature) for an SSH-signed tag."""
    begin = tag_object.index(_SSH_SIG_BEGIN)
    return (
        tag_object[:begin],
        tag_object[begin + len(_SSH_SIG_BEGIN) : tag_object.index(_SSH_SIG_END)],
    )


def _parse_allowed_signers(text: str) -> list[dict[str, str]]:
    """Parse the ssh-keygen ALLOWED SIGNERS format we actually use.

    Deliberately strict: the entries this repository ships are
    ``<principal> namespaces="git" <keytype> <base64>`` and nothing else, so a
    line that does not have that shape is a parse failure rather than a
    silently ignored one.
    """
    entries: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 4:
            raise ValueError(f"unexpected allowed_signers line shape: {line!r}")
        principal, options, key_type, key_b64 = parts
        entries.append(
            {
                "principal": principal,
                "options": options,
                "key_type": key_type,
                "key_b64": key_b64,
            }
        )
    return entries


@pytest.fixture(scope="module")
def tag_object() -> bytes:
    return base64.b64decode(V4_TAG_OBJECT_B64)


@pytest.fixture(scope="module")
def signature(tag_object: bytes) -> _Sshsig:
    return _Sshsig(_split_tag(tag_object)[1])


@pytest.fixture(scope="module")
def entries() -> list[dict[str, str]]:
    return _parse_allowed_signers(ALLOWED_SIGNERS.read_text(encoding="utf-8"))


class TestTheVerifierItself:
    """A known-answer test, so the checks below rest on something published."""

    # RFC 8032 section 7.1, TEST 1.
    PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    SIGNATURE = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )

    def test_the_rfc_8032_vector_verifies(self) -> None:
        assert ed25519_verify(self.PUBLIC, b"", self.SIGNATURE) is True

    def test_a_flipped_signature_bit_does_not(self) -> None:
        broken = bytearray(self.SIGNATURE)
        broken[0] ^= 0x01
        assert ed25519_verify(self.PUBLIC, b"", bytes(broken)) is False

    def test_a_non_empty_message_does_not(self) -> None:
        assert ed25519_verify(self.PUBLIC, b"x", self.SIGNATURE) is False

    def test_wrong_lengths_are_refused_rather_than_crashing(self) -> None:
        assert ed25519_verify(self.PUBLIC[:31], b"", self.SIGNATURE) is False
        assert ed25519_verify(self.PUBLIC, b"", self.SIGNATURE[:63]) is False


class TestTheTrustStore:
    """`.github/allowed_signers` against the release it claims to describe."""

    def test_the_file_exists_and_holds_exactly_one_entry(self) -> None:
        # Deliberately not via the `entries` fixture: a deleted trust store
        # must report itself as a deleted trust store, not as a fixture error.
        assert ALLOWED_SIGNERS.is_file(), (
            f"{ALLOWED_SIGNERS.relative_to(REPO_ROOT)} is missing — without it "
            "`git verify-tag` cannot check a release tag at all"
        )
        entries = _parse_allowed_signers(ALLOWED_SIGNERS.read_text(encoding="utf-8"))
        assert len(entries) == 1, (
            "one maintainer signs releases; more than one entry means a key was "
            "added without this test being told why"
        )

    def test_the_entry_is_scoped_to_the_git_namespace(self, entries: list[dict[str, str]]) -> None:
        # Unscoped, the same key would be trusted for every SSHSIG namespace
        # (file signing, and anything else added later).
        assert entries[0]["options"] == 'namespaces="git"'

    def test_the_published_key_is_the_key_inside_the_signature(
        self, entries: list[dict[str, str]], signature: _Sshsig
    ) -> None:
        published = base64.b64decode(entries[0]["key_b64"])
        assert entries[0]["key_type"] == "ssh-ed25519"
        assert signature.key_type == b"ssh-ed25519"
        assert published == signature.public_key_blob, (
            "the key in .github/allowed_signers is not the key that signed "
            "v4.0.0 — the trust store names someone else"
        )

    def test_the_principal_is_the_tagger(
        self, entries: list[dict[str, str]], tag_object: bytes
    ) -> None:
        lines = tag_object.decode().splitlines()
        tagger = next(line for line in lines if line.startswith("tagger "))
        email = tagger.split("<", 1)[1].split(">", 1)[0]
        assert entries[0]["principal"] == email, (
            "git matches an allowed_signers entry by the tagger's identity; a "
            "principal that is not the tagger email verifies nothing"
        )

    def test_the_v4_signature_verifies(self, tag_object: bytes, signature: _Sshsig) -> None:
        payload, _ = _split_tag(tag_object)
        assert signature.namespace == b"git"
        assert (
            signature.verify(payload) is True
        ), "the embedded v4.0.0 tag does not verify under its own key"


class TestTheNegativeControls:
    """Each asserts the check above can fail — otherwise it proves nothing."""

    def test_a_single_tampered_payload_byte_breaks_verification(
        self, tag_object: bytes, signature: _Sshsig
    ) -> None:
        payload, _ = _split_tag(tag_object)
        tampered = bytearray(payload)
        tampered[-2] ^= 0x01
        assert signature.verify(bytes(tampered)) is False

    def test_a_different_key_does_not_verify_the_same_signature(
        self, tag_object: bytes, signature: _Sshsig
    ) -> None:
        payload, _ = _split_tag(tag_object)
        # A valid curve point that is not the signer: the RFC 8032 TEST 1 key.
        other = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        assert ed25519_verify(other, signature.signed_data(payload), signature.signature) is False

    def test_a_truncated_signature_does_not_verify(
        self, tag_object: bytes, signature: _Sshsig
    ) -> None:
        payload, _ = _split_tag(tag_object)
        assert (
            ed25519_verify(
                signature.public_key, signature.signed_data(payload), signature.signature[:-1]
            )
            is False
        )

    def test_the_namespace_is_part_of_what_is_signed(
        self, tag_object: bytes, signature: _Sshsig
    ) -> None:
        # A "git" signature must not verify as some other namespace's, or the
        # namespaces="git" scoping above would be decoration.
        payload, _ = _split_tag(tag_object)
        signature.namespace = b"file"
        try:
            assert signature.verify(payload) is False
        finally:
            signature.namespace = b"git"


class TestTheEmbeddedFixtureMatchesTheRepository:
    """When the tag is present locally, the embedded copy must be it.

    CI checkouts do not fetch tags at the default depth, so this cannot be a
    hard requirement; every check above runs regardless.  Where the tag *is*
    reachable — a maintainer's clone, any lane with ``fetch-depth: 0`` — a
    divergence between the object store and the embedded bytes is caught.
    """

    def test_embedded_bytes_equal_the_real_tag_object(self, tag_object: bytes) -> None:
        probe = subprocess.run(
            ["git", "cat-file", "-t", "v4.0.0"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0 or probe.stdout.strip() != "tag":
            pytest.skip("v4.0.0 is not present in this checkout (tags not fetched)")
        real = subprocess.run(
            ["git", "cat-file", "tag", "v4.0.0"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        ).stdout
        assert real == tag_object
