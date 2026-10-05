#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AvaDescent: the math layer's convergent descent mode.

Labels follow AGENTS.md section 6.4 and were earned by mutation on
2026-10-05 (each named mutant rebuilt and the test observed failing):

* PIN  test_descent_reaches_the_target_without_equity_bias — fails when
  ``step`` is mutated to the additive-equity form
  (``gradient + equity_gain``), which settles 1.15 per component short.
* PIN  test_the_measured_decay_rate_holds — fails under the same mutant
  and when the equity gain is dropped from the step entirely.
* PIN  test_the_contraction_bound_is_enforced — fails when the
  ``alpha * equity_gain < 2`` constructor bound is deleted.
* RANGE — the validation tests exercise each refusal's domain and were
  not mutation-tested beyond the bound above.
"""

import math

import pytest

from ama_cryptography._numeric import asvec, zeros
from ama_cryptography.double_helix_engine import AvaDescent

TARGET = asvec([1.0, -0.5, 2.0, 0.25, -1.5, 0.75, 1.25, -0.25])
DIM = len(TARGET)


class TestConvergence:
    def test_descent_reaches_the_target_without_equity_bias(self) -> None:
        """PIN. The additive-equity mutant settles at exactly
        ``equity_gain`` per component (distance 1.15 * sqrt(8) ~ 3.25);
        the multiplicative form must land on the target itself."""
        _, history = AvaDescent().descend(TARGET, zeros(DIM), max_steps=200)
        distance = math.sqrt(history[-1])
        assert distance < 1e-6
        # The bias the mutant produces, explicitly excluded:
        assert abs(distance - 1.15 * math.sqrt(DIM)) > 1.0

    def test_the_measured_decay_rate_holds(self) -> None:
        """PIN. At the default gains the per-step error factor is
        ``(1 - 0.618 * 1.15)^2 ~ 0.0837``, so twelve steps contract V to
        ``0.0837^12 ~ 1.2e-13 * V0`` — 16x below this floor. Dropping the
        equity gain leaves ``0.146^12 ~ 9.2e-11 * V0``, 46x above it; the
        additive mutant never falls below ``V0`` at all. The arithmetic is
        exact and deterministic, so the margins cannot drift."""
        _, history = AvaDescent().descend(TARGET, zeros(DIM), max_steps=12, tolerance=0.0)
        v0 = sum(t * t for t in TARGET.tolist())
        assert history[-1] < v0 * 2e-12

    @pytest.mark.parametrize("mode", ["equity", "variance", "momentum", "catalan", "adaptive"])
    def test_every_mode_converges_on_the_benchmark(self, mode: str) -> None:
        final, history = AvaDescent().descend(TARGET, zeros(DIM), max_steps=2000, mode=mode)
        assert math.sqrt(history[-1]) < 1e-6
        assert final.tolist() == pytest.approx(TARGET.tolist(), abs=1e-6)

    def test_histories_are_lyapunov_values_of_the_walked_states(self) -> None:
        final, history = AvaDescent().descend(TARGET, zeros(DIM), max_steps=5, tolerance=0.0)
        assert len(history) == 5
        v_final = sum((a - b) ** 2 for a, b in zip(final.tolist(), TARGET.tolist()))
        assert history[-1] == pytest.approx(v_final)


class TestOperatorContracts:
    def test_step_is_the_multiplicative_equity_form(self) -> None:
        d = AvaDescent(alpha=0.5, equity_gain=1.2)
        out = d.step([1.0, 2.0], [0.5, -0.5])
        assert out.tolist() == pytest.approx([1.0 + 0.3, 2.0 - 0.3])

    def test_variance_damping_follows_the_family_law(self) -> None:
        d = AvaDescent(alpha=0.6, equity_gain=1.0)
        state = [0.0, 2.0]  # mean 1, variance 1
        out = d.variance_adapted_step(state, [1.0, 1.0])
        assert out.tolist() == pytest.approx([0.0 + 0.3, 2.0 + 0.3])

    def test_momentum_velocity_law_is_exact(self) -> None:
        d = AvaDescent(alpha=0.5)
        nxt, vel = d.momentum_step([0.0], [1.0], [2.0], beta=0.9)
        assert vel.tolist() == pytest.approx([0.9 * 2.0 + 0.1 * 1.0])
        assert nxt.tolist() == pytest.approx([0.5 * (0.9 * 2.0 + 0.1 * 1.0)])

    def test_catalan_step_keeps_the_family_formula(self) -> None:
        d = AvaDescent(alpha=1.0, equity_gain=1.15)
        out = d.catalan_step([0.0], [1.0])
        expected = AvaDescent.CATALAN_CONSTANT * math.sqrt(2.0) * 1.15 * 0.40
        assert out.tolist() == pytest.approx([expected])

    def test_select_alpha_covers_the_selection_table(self) -> None:
        d = AvaDescent()
        small_g, large_g = [0.1], [5.0]
        assert d.select_alpha(small_g, 0.0, 0.92) == d.ALPHA_MODES["high_reliability"]
        assert d.select_alpha(small_g, 0.9, 0.99) == d.ALPHA_MODES["balanced"]
        assert d.select_alpha(large_g, 0.0, 0.99) == d.ALPHA_MODES["balanced"]
        assert d.select_alpha(small_g, 0.0, 0.99) == d.ALPHA_MODES["golden_ratio"]


class TestRefusals:
    def test_the_contraction_bound_is_enforced(self) -> None:
        """PIN. Without the bound, alpha * equity_gain >= 2 constructs an
        operator whose per-step factor |1 - a*k| >= 1 never contracts."""
        with pytest.raises(ValueError, match=r"below 2\.0"):
            AvaDescent(alpha=1.8, equity_gain=1.15)
        # The boundary itself is excluded; just inside is accepted.
        assert AvaDescent(alpha=1.73, equity_gain=1.15).alpha == 1.73

    @pytest.mark.parametrize("alpha", [0.0, -0.1, math.inf, math.nan])
    def test_degenerate_alpha_is_refused(self, alpha: float) -> None:
        with pytest.raises(ValueError):
            AvaDescent(alpha=alpha)

    def test_mismatched_lengths_are_refused(self) -> None:
        with pytest.raises(ValueError, match="components"):
            AvaDescent().step([1.0, 2.0], [1.0])

    def test_non_finite_components_are_refused(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            AvaDescent().step([1.0], [math.nan])

    def test_unknown_mode_and_bad_budgets_are_refused(self) -> None:
        d = AvaDescent()
        with pytest.raises(ValueError, match="unknown mode"):
            d.descend(TARGET, zeros(DIM), mode="exponential")
        with pytest.raises(ValueError, match="max_steps"):
            d.descend(TARGET, zeros(DIM), max_steps=-1)
        with pytest.raises(ValueError, match="tolerance"):
            d.descend(TARGET, zeros(DIM), tolerance=-1.0)

    def test_bad_beta_and_bad_selector_domains_are_refused(self) -> None:
        d = AvaDescent()
        with pytest.raises(ValueError, match="beta"):
            d.momentum_step([0.0], [1.0], [0.0], beta=1.0)
        with pytest.raises(ValueError, match="ethical_score"):
            d.select_alpha([0.1], 0.0, 1.5)
        with pytest.raises(ValueError, match="variance"):
            d.select_alpha([0.1], -0.5, 0.99)


class TestPackageSurface:
    def test_ava_descent_is_a_package_export(self) -> None:
        import ama_cryptography

        assert ama_cryptography.AvaDescent is AvaDescent
        assert "AvaDescent" in ama_cryptography.__all__
