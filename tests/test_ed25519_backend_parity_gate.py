# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_ed25519_backend_parity.py``.

The gate compares the vendored donna backend against the in-tree fe51 one and
is required in CI, and it had no test of its own — the gap INVARIANT-2 names:
*"a gate with no negative control has not been shown to be a gate at all."*

This particular gate has already been caught reporting coverage it did not
have. It claimed to show that "both backends accept exactly the same set of
encodings after the `y` change" while its corpus contained no non-canonical
`y` at all — public-key bitflips essentially never land in `[p, 2^255)`, so the
claim could not have been tested by the cases that existed. The decode stage
and the ``decode_asserted`` / ``must_verify_seen`` guards were added in
response. Those guards are themselves untested code in the path that decides
whether a green run means anything, which is what this module fixes.

Driving the real thing needs two differently-configured shared libraries, so
the harness is driven against stub backends instead. That is the right seam:
what is under test here is the *verdict logic* — does divergence fail, does a
vacuous corpus refuse to pass, does correctness get distinguished from mere
agreement — not the Ed25519 maths, which the C and Python suites already pin.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_ed25519_backend_parity.py"

#: 2^255 - 19, the field prime.
P = 2**255 - 19
#: The Ed25519 group order.  The arithmetic family compares OUTPUT BYTES, so
#: the stub needs an actual group to produce them; see _StubBackend's
#: "pseudo-group" note.
L = 2**252 + 27742317777372353535851937790883648493


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_ed25519_backend_parity", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _StubBackend:
    """A backend whose verdicts are supplied rather than computed.

    ``verify`` accepts every signature this stub itself produced and rejects
    everything else, which is the behaviour a correct backend has on the
    generated corpus. ``decode_ok`` decides the compressed-point rule, so a
    backend can be made to enforce the canonical-`y` check or not.
    """

    def __init__(
        self,
        name: str,
        *,
        canonical_y: bool = True,
        x_sign_rule: bool = True,
        batch_r_rule: bool = True,
        scalar_reduction: bool = True,
        joint_arithmetic: bool = True,
        verify_override: Optional[Callable[[bytes, bytes, bytes], bool]] = None,
        backend_name: Optional[str] = None,
        report_no_backend: bool = False,
        issued: Optional[set[tuple[bytes, bytes, bytes]]] = None,
    ) -> None:
        self.name = name
        self.path = Path(f"/stub/{name}.so")
        self.canonical_y = canonical_y
        #: Whether this stub applies RFC 8032 §5.1.3.  Switchable so a test can
        #: build the one-sided backend pair the gate exists to catch.
        self.x_sign_rule = x_sign_rule
        #: Whether this stub applies the canonical-R rule on its BATCH path.
        #: Independent of the single path on purpose — that split is the
        #: defect the batch family exists to catch.
        self.batch_r_rule = batch_r_rule
        #: Whether this stub's scalar mults depend on the scalar only through
        #: `s mod L`.  False reproduces fe51's dropped wNAF carry.
        self.scalar_reduction = scalar_reduction
        #: Whether the joint double-scalar mult agrees with the split
        #: composition of its halves.  False reproduces donna's stale
        #: extended-t coordinate.
        self.joint_arithmetic = joint_arithmetic
        self._verify_override = verify_override
        #: M14: which backend this stub reports from active_backend().  Defaults
        #: to self.name, so a donna/fe51 pair differs and the identity guard
        #: passes; a test can force them equal or absent.
        self._backend_name = backend_name
        self._report_no_backend = report_no_backend
        # Shared across the pair: the harness signs with each backend in turn
        # and cross-verifies every case with BOTH, so a signature minted by
        # one must verify under the other. A per-instance registry would make
        # two correct backends look like a total divergence.
        self._issued: set[tuple[bytes, bytes, bytes]] = set() if issued is None else issued
        #: Signatures whose group equation holds even though their R encoding
        #: is inadmissible — see non_canonical_r_signature.
        self._equation_holds: set[bytes] = set()
        self._counter = 0

    def active_backend(self) -> Optional[str]:
        # M14: the real Backend reports which backend the .so selected; the
        # differential refuses to run unless the two libraries differ.
        if self._report_no_backend:
            return None
        return self._backend_name if self._backend_name is not None else self.name

    def keypair(self) -> tuple[bytes, bytes]:
        self._counter += 1
        seed = self._counter.to_bytes(4, "little")
        return (b"pk" + seed).ljust(32, b"\x00"), (b"sk" + seed).ljust(64, b"\x00")

    def sign(self, message: bytes, secret: bytes) -> bytes:
        # S must stay well below L so `_with_s(s + L)` remains representable,
        # otherwise build_cases would skip the malleability case entirely and
        # the corpus would quietly shrink.
        signature = (b"R" + secret[2:6] + message[:8]).ljust(32, b"\x01") + (1).to_bytes(
            32, "little"
        )
        public = (b"pk" + secret[2:6]).ljust(32, b"\x00")
        self._issued.add((message, signature, public))
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if self._verify_override is not None:
            return self._verify_override(message, signature, public_key)
        return (message, signature, public_key) in self._issued

    #: R = `01 00..00 | 0x80`, the identity's sign-bit-set encoding: the one
    #: input that discriminated the batch path from the single path.
    NON_CANONICAL_R = bytes([0x01]) + bytes(30) + bytes([0x80])

    def non_canonical_r_signature(self, message: bytes, secret: bytes) -> bytes:
        """A signature whose R half is a non-canonical point encoding.

        The real backend derives S so the group equation holds; this stub does
        not need to, because ``batch_verify`` below decides by the same
        registry ``verify`` uses.  What must be modelled is the SHAPE — an R
        that RFC 8032 §5.1.3 requires a decoder to refuse — so a stub can be
        built that enforces the rule on one path and not the other, which is
        the pair the batch family exists to catch.
        """
        signature = self.NON_CANONICAL_R + (2).to_bytes(32, "little")
        # The real S makes [S]B - [h]A equal the identity R decodes to, so the
        # GROUP EQUATION holds while the ENCODING is inadmissible.  That split
        # is the whole mechanism: donna's batch routine checks the equation
        # over a decoded R and never re-encodes, so it accepted this; the
        # single verifiers re-encode and could not match it.  Recording the
        # signature here lets batch_verify below model "the equation holds"
        # without doing curve arithmetic, while verify() keeps rejecting it —
        # exactly the two behaviours.
        self._equation_holds.add(signature)
        return signature

    def small_order_r_signature(
        self,
        message: bytes,
        public: bytes,
        secret: bytes,
        torsion_enc: bytes,
        seed: int = 0,
    ) -> bytes:
        """A stand-in for the torsion discriminator (audit B1).

        The stub's pseudo-group (Z/L, prime order) has no small-order element, so
        it cannot reproduce the real torsion divergence; it models only the SHAPE
        the torsion family needs: an invalid signature with a CANONICAL R that
        this backend rejects on both the single and batch paths (``verify()``
        rejects anything it did not issue).  A correct pair rejects it everywhere
        and the family passes; the real divergence is exercised against the
        built ``.so``, not here.
        """
        r_half = (bytes([0x02, torsion_enc[0]]) + seed.to_bytes(4, "little")).ljust(32, b"\x05")
        return r_half + (3).to_bytes(32, "little")

    def batch_verify(self, entries: list[tuple[bytes, bytes, bytes]]) -> list[bool]:
        """Per-entry verdicts, modelling the R rule independently of ``verify``.

        ``batch_r_rule`` is switchable for the same reason ``x_sign_rule`` is:
        the defect this family was added for was a backend that applied the
        canonical-R rule on its single-signature path and not on its batch
        path, and a stub that cannot express that cannot test for it.
        """
        verdicts: list[bool] = []
        for message, signature, public_key in entries:
            if not self._r_is_canonical(signature):
                # Rejected iff this backend applies the rule on THIS path.
                # Without the rule the aggregate equation decides, and it
                # holds — which is how a signature the single verifier
                # rejects came to be reported valid.
                verdicts.append((not self.batch_r_rule) and signature in self._equation_holds)
                continue
            verdicts.append(self.verify(message, signature, public_key))
        return verdicts

    def _r_is_canonical(self, signature: bytes) -> bool:
        return signature[:32] != self.NON_CANONICAL_R

    def _decodes(self, encoding: bytes) -> bool:
        """Model the two decode rules the shipped backends apply.

        An earlier version of this stub returned ``y != P - 1``, on the belief
        that ``y = p - 1`` was off-curve.  It is not: ``y = -1`` gives
        ``x^2 = (y^2 - 1)/(d y^2 + 1) = 0``, so it is the order-2 point and both
        real backends decode it (verified against
        ``build/lib/libama_cryptography.so`` through ``ama_ed25519_point_add``).
        Modelling it as a reject is what let DECODE_CASES carry ``None`` — no
        absolute expectation — for one of the only two encodings the RFC 8032
        §5.1.3 x-sign rule discriminates.
        """
        y = int.from_bytes(encoding, "little") & ((1 << 255) - 1)
        x_sign = encoding[31] >> 7
        if self.canonical_y and y >= P:
            return False
        # RFC 8032 §5.1.3: "if x = 0, and x_0 = 1, decoding fails".  x = 0 for
        # exactly two y values, y = 1 and y = p - 1.
        if x_sign and (y == 1 or y == P - 1) and self.x_sign_rule:
            return False
        return True

    def point_add(self, p_enc: bytes, q_enc: bytes) -> bool:
        return self._decodes(p_enc) and self._decodes(q_enc)

    def scalarmult_public(self, scalar: bytes, p_enc: bytes) -> bool:
        return self._decodes(p_enc)

    # ---- the byte-exact arithmetic surface --------------------------------
    #
    # The four wrappers above answer "did it decode".  The gate's fifth family
    # compares the 32 OUTPUT BYTES, because a backend that succeeds and returns
    # the wrong group element is invisible to a verdict comparison — and both
    # shipped backends did exactly that (donna summed two partial points with a
    # stale extended-t; fe51 dropped the wNAF carry out of bit 255).
    #
    # Modelling that needs an actual group, so this stub uses a pseudo-group:
    # a point IS its discrete logarithm base B, little-endian in the low 255
    # bits, and the group law is addition mod L.  Every identity the family
    # asserts — [s]P == [s mod L]P, and joint == point_add of the split halves
    # — holds exactly in it, so a correct pair passes, while the two switches
    # below reproduce the two real defects.

    @staticmethod
    def _dlog(encoding: bytes) -> int:
        return (int.from_bytes(encoding, "little") & ((1 << 255) - 1)) % L

    @staticmethod
    def _encode(dlog: int) -> bytes:
        return (dlog % L).to_bytes(32, "little")

    def reduce32(self, scalar: bytes) -> bytes:
        return (int.from_bytes(scalar, "little") % L).to_bytes(32, "little")

    def point_from_scalar_bytes(self, scalar: bytes) -> Optional[bytes]:
        return self._encode(int.from_bytes(scalar, "little"))

    def point_add_bytes(self, p_enc: bytes, q_enc: bytes) -> Optional[bytes]:
        if not self._decodes(p_enc) or not self._decodes(q_enc):
            return None
        return self._encode(self._dlog(p_enc) + self._dlog(q_enc))

    def scalarmult_public_bytes(self, scalar: bytes, p_enc: bytes) -> Optional[bytes]:
        if not self._decodes(p_enc):
            return None
        # ``scalar_reduction=False`` is fe51's dropped-carry defect: the scalar
        # is consumed as a raw 256-bit integer minus 2**256 rather than reduced,
        # so [s]P and [s mod L]P differ for every s that sets the top bits.
        raw = int.from_bytes(scalar, "little")
        if not self.scalar_reduction and raw >= L:
            raw -= 1 << 256
        return self._encode(raw * self._dlog(p_enc))

    def double_scalarmult_public_bytes(
        self, s1: bytes, p1_enc: bytes, s2: bytes, p2_enc: bytes
    ) -> Optional[bytes]:
        if not self._decodes(p1_enc) or not self._decodes(p2_enc):
            return None
        left = self.scalarmult_public_bytes(s1, p1_enc)
        right = self.scalarmult_public_bytes(s2, p2_enc)
        if left is None or right is None:
            return None
        total = self._dlog(left) + self._dlog(right)
        # ``joint_arithmetic=False`` is donna's stale extended-t defect: the
        # joint routine returns AMA_SUCCESS with an arbitrary point, so it
        # disagrees with the split composition of its own two halves.
        if not self.joint_arithmetic:
            total += 1
        return self._encode(total)


def _pair(**kwargs: Any) -> tuple[_StubBackend, _StubBackend]:
    """A donna/fe51 pair sharing one signature registry.

    ``kwargs`` prefixed ``donna_`` / ``fe51_`` go to that backend only; any
    other keyword goes to both.
    """
    shared: set[tuple[bytes, bytes, bytes]] = set()
    donna_kw = {k[6:]: v for k, v in kwargs.items() if k.startswith("donna_")}
    fe51_kw = {k[5:]: v for k, v in kwargs.items() if k.startswith("fe51_")}
    common = {k: v for k, v in kwargs.items() if not k.startswith(("donna_", "fe51_"))}
    return (
        _StubBackend("donna", issued=shared, **{**common, **donna_kw}),
        _StubBackend("fe51", issued=shared, **{**common, **fe51_kw}),
    )


def _run(
    tool: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    donna: _StubBackend,
    fe51: _StubBackend,
) -> int:
    backends = iter((donna, fe51))
    monkeypatch.setattr(tool, "Backend", lambda _name, _path: next(backends))
    return int(tool.main(["--donna", "/stub/donna.so", "--fe51", "/stub/fe51.so"]))


class TestBackendIdentityGuard:
    """M14: the differential must refuse to compare a library with itself.

    Before this guard, handing the gate one library twice -- or two builds that
    both fell back to fe51 -- compared a build with itself and passed vacuously:
    the torsion, count-sweep and canonical corpora all agree when both objects
    ARE the same object.
    """

    def test_same_backend_reported_twice_is_inconclusive(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shared: set[tuple[bytes, bytes, bytes]] = set()
        donna = _StubBackend("donna", backend_name="donna", issued=shared)
        fe51 = _StubBackend("fe51", backend_name="donna", issued=shared)  # same backend!
        assert _run(tool, monkeypatch, donna, fe51) == 2

    def test_a_library_without_the_backend_probe_is_inconclusive(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shared: set[tuple[bytes, bytes, bytes]] = set()
        donna = _StubBackend("donna", report_no_backend=True, issued=shared)
        fe51 = _StubBackend("fe51", issued=shared)
        assert _run(tool, monkeypatch, donna, fe51) == 2


class TestAgreeingBackendsPass:
    def test_two_correct_backends_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-vacuity for everything below: the harness can return 0."""
        assert _run(tool, monkeypatch, *_pair()) == 0


class TestDivergenceIsCaught:
    def test_one_backend_missing_the_canonical_y_rule_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The INVARIANT-38 regression this gate exists for.

        donna enforces `y < p`, fe51 does not, so the two accept different sets
        of compressed encodings — the exact state the tree was in before the
        batch path was fixed.
        """
        rc = _run(tool, monkeypatch, *_pair(donna_canonical_y=True, fe51_canonical_y=False))
        assert rc == 1

    def test_one_backend_missing_the_x_sign_rule_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RFC 8032 §5.1.3 applied to one backend only must be a disagreement.

        This is the rule the branch added to BOTH backends independently, and
        the corpus could not see it: with the x-sign cases absent, deleting the
        rule from the fe51 sources, rebuilding, and running the real gate over
        the two real libraries printed "both backends agree on every case" and
        exited 0.  A gate whose whole purpose is catching a one-sided fix must
        fail here, so this is the control that keeps the discriminating
        encodings in DECODE_CASES.
        """
        rc = _run(tool, monkeypatch, *_pair(donna_x_sign_rule=True, fe51_x_sign_rule=False))
        assert rc == 1

    def test_a_backend_that_accepts_everything_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A verifier that never rejects diverges on the malleability cases."""
        rc = _run(tool, monkeypatch, *_pair(fe51_verify_override=lambda *_a: True))
        assert rc == 1


class TestAgreementIsNotCorrectness:
    def test_two_backends_that_reject_every_signature_do_not_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both wrong in the same way is perfect agreement and total breakage.

        This is why ``must_verify`` is carried on each case: without an
        absolute assertion, a differential harness reports success for a pair
        of libraries that verify nothing at all.
        """
        rc = _run(tool, monkeypatch, *_pair(verify_override=lambda *_a: False))
        assert rc == 1


class TestVacuousRunsAreInconclusive:
    def test_a_corpus_with_no_genuine_signature_cannot_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Strip the must-verify cases and the run must refuse to report success."""
        real_build = tool.build_cases
        monkeypatch.setattr(
            tool,
            "build_cases",
            lambda signer: [c for c in real_build(signer) if not c.must_verify],
        )
        rc = _run(tool, monkeypatch, *_pair())
        assert rc == 2

    def test_a_decode_stage_that_asserts_nothing_cannot_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every decode case with expectation None is the historical corpus.

        Before the y=0 / y=p pair was added, that is exactly what the decode
        stage was, and the gate reported the canonical-y claim as verified.
        """
        monkeypatch.setattr(
            tool,
            "DECODE_CASES",
            tuple((label, enc, None) for label, enc, _ in tool.DECODE_CASES),
        )
        rc = _run(tool, monkeypatch, *_pair())
        assert rc == 2

    def test_an_unloadable_library_is_inconclusive_not_a_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(_name: str, _path: Path) -> Any:
            raise OSError("cannot open shared object file")

        monkeypatch.setattr(tool, "Backend", _boom)
        rc = int(tool.main(["--donna", "/nope.so", "--fe51", "/nope.so"]))
        assert rc == 2


class TestDivergenceOutranksVacuity:
    def test_total_decode_divergence_reports_divergence_not_an_empty_corpus(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``decode_asserted`` only advances on cases where the backends AGREED.

        So a pair that disagrees on every decode case leaves it at zero. With
        the vacuity guard checked first, the worst possible outcome — total
        divergence — was announced as "the decode stage asserted nothing",
        naming a corpus problem for a library problem. Both exits are
        non-zero, so nothing was ever let through; what was wrong was the
        message the reader had to act on.
        """
        rc = _run(tool, monkeypatch, *_pair(donna_canonical_y=True, fe51_canonical_y=False))
        captured = capsys.readouterr()
        assert rc == 1
        assert "DIFFERENTIAL FAILED" in captured.err
        assert "asserted nothing" not in captured.err


class TestCorpusShape:
    def test_decode_cases_contain_a_canonical_non_canonical_twin_pair(
        self, tool: ModuleType
    ) -> None:
        """The discriminating pair, and the reason the stage is not vacuous.

        `y = 0` is a genuine curve point (`x^2 = -1`, and `-1` is a square mod
        p) and `y = p` reduces to it. A backend that reduces accepts both; one
        that rejects non-canonical `y` accepts only the first. Nothing else in
        the corpus separates the two behaviours, so losing this pair would
        return the gate to the state where it reported an untested claim.
        """
        expectations = {label: expected for label, _enc, expected in tool.DECODE_CASES}
        assert any("y=0" in label and expected is True for label, expected in expectations.items())
        assert any("y=p" in label and expected is False for label, expected in expectations.items())

    def test_decode_cases_discriminate_the_x_sign_rule(self, tool: ModuleType) -> None:
        """The x = 0 encodings, in both parities, with absolute expectations.

        RFC 8032 §5.1.3 ("if x = 0, and x_0 = 1, decoding fails") is decided by
        exactly two encodings, because x = 0 holds for exactly two y values:
        y = 1 and y = p - 1.  Both must appear with the sign bit SET and an
        expectation of False, and both must appear with it CLEAR and an
        expectation of True — the paired accept is what stops a backend
        satisfying the rejects by refusing every set sign bit.  y = 0 with the
        sign bit set must be accepted for the same reason: x != 0 there, so the
        rule does not apply to it.
        """
        one = bytes([0x01] + [0x00] * 31)
        one_signed = bytes([0x01] + [0x00] * 30 + [0x80])
        pm1 = bytes([0xEC] + [0xFF] * 30 + [0x7F])
        pm1_signed = bytes([0xEC] + [0xFF] * 30 + [0xFF])
        zero_signed = bytes(31) + bytes([0x80])

        by_encoding = {enc: expected for _label, enc, expected in tool.DECODE_CASES}
        assert by_encoding.get(one_signed) is False, "y=1 with x-sign set must be refused"
        assert by_encoding.get(pm1_signed) is False, "y=p-1 with x-sign set must be refused"
        assert by_encoding.get(one) is True, "y=1 must decode (the paired accept)"
        assert by_encoding.get(pm1) is True, "y=p-1 is the order-2 point and must decode"
        assert by_encoding.get(zero_signed) is True, "y=0 has x != 0; the rule must not apply"

    def test_decode_cases_include_an_ordinary_point_in_both_parities(
        self, tool: ModuleType
    ) -> None:
        """An over-rejecting backend must be caught, not only an under-rejecting one.

        Every other decode case is a special point.  2G is an ordinary one, and
        both sign parities of it are legal, so a backend that started refusing
        set sign bits wholesale fails here.
        """
        two_g = bytes.fromhex("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022")
        two_g_flipped = two_g[:31] + bytes([two_g[31] ^ 0x80])
        by_encoding = {enc: expected for _label, enc, expected in tool.DECODE_CASES}
        assert by_encoding.get(two_g) is True
        assert by_encoding.get(two_g_flipped) is True

    def test_with_s_rejects_an_oversized_scalar(self, tool: ModuleType) -> None:
        """A silent reduction mod 2^256 would change the case under test."""
        with pytest.raises(ValueError):
            tool._with_s(b"\x00" * 64, 2**256)

    def test_build_cases_includes_the_s_plus_l_malleability_case(self, tool: ModuleType) -> None:
        labels = [c.label for c in tool.build_cases(_StubBackend("signer"))]
        assert any(label.startswith("malleable S+L") for label in labels)
        assert any(label.startswith("honest") for label in labels)

    def test_must_verify_is_a_field_not_inferred_from_the_label(self, tool: ModuleType) -> None:
        """Renaming a label must not silently switch an assertion off."""
        case = tool.Case("renamed-by-someone", b"m", b"s", b"p", must_verify=True)
        assert case.must_verify is True


class TestTheArithmeticFamilyIsNotVacuous:
    """The family that was missing when two wrong-answer defects shipped.

    Families 1-4 compare VERDICTS: did both backends accept, did both reject,
    did both decode.  None of that can see a backend that returns
    ``AMA_SUCCESS`` with the wrong group element, and both shipped backends
    did:

    * donna's ``ama_ed25519_double_scalarmult_public`` summed two PARTIAL
      points with ``ge25519_add_p1p1``, whose third product is
      ``p->t * q->t``, and neither ``t`` had been written — ``[7]B + [3]B``
      returned ``906ebcd3…`` instead of ``[10]B``.
    * fe51's ``sc25519_to_wnaf`` emitted 256 digits from eight 32-bit limbs and
      discarded the carry out of bit 255, so it represented ``s - 2^256`` for
      about 17% of uniform 32-byte scalars — ``[ff..ff]B`` returned ``-B``.

    Neither was reachable from this gate: it compared ``rc == 0`` booleans, its
    only scalar was ``2`` (smaller than either defect), and
    ``double_scalarmult_public`` had no ctypes binding at all.  Run against the
    real libraries before the fix, the extended gate reports 350
    disagreements and exits 1; after, 3783 cases and exit 0.

    These tests pin the family with stubs, so the property survives without a
    build of both backends.
    """

    def test_a_correct_pair_passes(self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        """The control: correct arithmetic must not be reported as divergence."""
        donna, fe51 = _pair()
        assert _run(tool, monkeypatch, donna, fe51) == 0

    def test_one_backend_that_does_not_reduce_the_scalar_is_caught(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fe51's dropped wNAF carry, as a divergence between the two."""
        donna, fe51 = _pair(fe51_scalar_reduction=False)
        assert _run(tool, monkeypatch, donna, fe51) == 1, (
            "a backend whose scalar mult depends on more than the scalar mod L "
            "was reported as agreeing with one that reduces"
        )

    def test_both_backends_failing_to_reduce_is_still_caught(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Agreement is not correctness, in this family as in the others.

        Two backends that BOTH consume the raw 256-bit scalar agree with each
        other on every case, so a pure differential passes them.  The
        reduction contract is asserted per backend, so it does not.
        """
        donna, fe51 = _pair(scalar_reduction=False)
        assert _run(tool, monkeypatch, donna, fe51) == 1, (
            "both backends violated [s]P == [s mod L]P and the gate reported " "agreement"
        )

    def test_one_backend_with_a_wrong_joint_mult_is_caught(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """donna's stale extended-t, as a divergence between the two."""
        donna, fe51 = _pair(donna_joint_arithmetic=False)
        assert _run(tool, monkeypatch, donna, fe51) == 1

    def test_both_backends_with_a_wrong_joint_mult_are_still_caught(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The split-composition identity, asserted per backend."""
        donna, fe51 = _pair(joint_arithmetic=False)
        assert _run(tool, monkeypatch, donna, fe51) == 1, (
            "both backends' joint mult disagreed with their own split "
            "composition and the gate reported agreement"
        )

    def test_a_pair_that_produces_no_output_bytes_is_inconclusive(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The vacuity guard: refusing everything is not agreeing.

        Every comparison in the family tolerates ``None`` (a refusal), so a
        pair that refused every input would agree on every case.  ``exit 2``,
        not ``exit 0``.
        """
        donna, fe51 = _pair()
        for backend in (donna, fe51):
            monkeypatch.setattr(backend, "point_from_scalar_bytes", lambda _s: None)
            monkeypatch.setattr(backend, "point_add_bytes", lambda _p, _q: None)
            monkeypatch.setattr(backend, "scalarmult_public_bytes", lambda _s, _p: None)
            monkeypatch.setattr(
                backend, "double_scalarmult_public_bytes", lambda _a, _b, _c, _d: None
            )
        assert _run(tool, monkeypatch, donna, fe51) == 2, (
            "a pair that produced no output bytes at all was reported as "
            "agreeing rather than as inconclusive"
        )


class TestTheBatchFamilyIsNotVacuous:
    """The family that was missing when a real divergence shipped.

    Families 1-3 drive ``ama_ed25519_verify`` only.  The library exposes a
    SECOND verifier, ``ama_ed25519_batch_verify``, whose two backends are
    entirely different code: fe51's is a loop over the single verifier,
    donna's is ``ed25519-donna-batchverify.h``'s multi-scalar routine, which
    DECODES R rather than re-encoding and comparing it.  Nothing in this gate
    ever put a signature to it, while the module docstring says it asserts the
    backends "return the same verdict for every signature put to them".

    Run against the real libraries with the canonical-R predicate neutered —
    the code as it stood — the extended gate reports:

        ED25519 BACKEND DIFFERENTIAL FAILED — 6 disagreement(s):
          batch   signed-by=donna case=non-canonical R
              batch and single disagree within one build:
              donna single=False batch=True
              fe51  single=False batch=False

    These tests pin the family with stubs, so the property survives without a
    build of both backends.
    """

    def test_a_backend_that_skips_the_r_rule_on_its_batch_path_is_caught(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exact shape of the shipped defect: one path enforces, one does not."""
        donna, fe51 = _pair(donna_batch_r_rule=False)
        assert _run(tool, monkeypatch, donna, fe51) == 1, (
            "a backend applying the canonical-R rule on its single path but not "
            "on its batch path was reported as agreeing with one that applies it "
            "on both — which is the divergence that shipped"
        )

    def test_both_backends_skipping_it_is_still_caught(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Agreement is not correctness — the same rule families 1-3 follow.

        Two backends that both report a non-canonical R valid AGREE, and are
        both wrong.  A differential that only compared them would pass.
        """
        donna, fe51 = _pair(batch_r_rule=False)
        assert _run(tool, monkeypatch, donna, fe51) == 1, (
            "both backends accepted a non-canonical R in batch verify and the "
            "gate passed; agreement alone is not correctness"
        )

    def test_a_correct_pair_passes(self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        """The over-rejection guard: the family must not fail a correct pair."""
        donna, fe51 = _pair()
        assert _run(tool, monkeypatch, donna, fe51) == 0
