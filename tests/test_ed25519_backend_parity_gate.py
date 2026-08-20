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
        verify_override: Optional[Callable[[bytes, bytes, bytes], bool]] = None,
        issued: Optional[set[tuple[bytes, bytes, bytes]]] = None,
    ) -> None:
        self.name = name
        self.path = Path(f"/stub/{name}.so")
        self.canonical_y = canonical_y
        #: Whether this stub applies RFC 8032 §5.1.3.  Switchable so a test can
        #: build the one-sided backend pair the gate exists to catch.
        self.x_sign_rule = x_sign_rule
        self._verify_override = verify_override
        # Shared across the pair: the harness signs with each backend in turn
        # and cross-verifies every case with BOTH, so a signature minted by
        # one must verify under the other. A per-instance registry would make
        # two correct backends look like a total divergence.
        self._issued: set[tuple[bytes, bytes, bytes]] = set() if issued is None else issued
        self._counter = 0

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
