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


class TestEngineWiring:
    """``AmaEquationEngine.converge(method="descent")`` — the descent mode
    wired into the engine's public convergence API.

    PIN test_descent_method_reaches_the_engines_own_target — fails when the
    delegation is removed (the helix walk reaches this target on 0 of 5
    seeds, measured 2026-10-05). PIN test_the_default_method_is_untouched —
    fails if the default path changes behaviour."""

    def test_descent_method_reaches_the_engines_own_target(self) -> None:
        from ama_cryptography.double_helix_engine import AmaEquationEngine

        eng = AmaEquationEngine(state_dim=DIM, random_seed=42)
        final, history = eng.converge(zeros(DIM), max_steps=200, tolerance=1e-10, method="descent")
        distance = math.sqrt(
            sum((a - b) ** 2 for a, b in zip(final.tolist(), eng.target_state.tolist()))
        )
        assert distance < 1e-6
        assert history[-1] == pytest.approx(distance**2, abs=1e-12)

    def test_the_default_method_is_untouched(self) -> None:
        """Two same-seed engines, one called with the explicit default:
        byte-identical walks, so the new parameter changed nothing."""
        from ama_cryptography.double_helix_engine import AmaEquationEngine

        a = AmaEquationEngine(state_dim=DIM, random_seed=42)
        fa, ha = a.converge(zeros(DIM), max_steps=20)
        b = AmaEquationEngine(state_dim=DIM, random_seed=42)
        fb, hb = b.converge(zeros(DIM), max_steps=20, method="helix")
        assert fa.tolist() == fb.tolist()
        assert ha == hb

    def test_an_unknown_method_is_refused(self) -> None:
        from ama_cryptography.double_helix_engine import AmaEquationEngine

        with pytest.raises(ValueError, match="unknown method"):
            AmaEquationEngine(state_dim=DIM, random_seed=42).converge(
                zeros(DIM), method="exponential"
            )


class TestReviewHardening:
    """Validation holes closed in the 2026-10-06 review round, each pinned."""

    def test_empty_vectors_are_refused(self) -> None:
        d = AvaDescent()
        with pytest.raises(ValueError, match="empty"):
            d.step([], [])
        with pytest.raises(ValueError, match="empty"):
            d.descend([], [], mode="variance")

    def test_non_finite_velocity_is_refused(self) -> None:
        with pytest.raises(ValueError, match="velocity"):
            AvaDescent().momentum_step([0.0], [1.0], [math.nan])

    def test_select_alpha_refuses_nan_measurements(self) -> None:
        """NaN fails every comparison, so unvalidated it would fall through
        to the most aggressive row of the table."""
        d = AvaDescent()
        with pytest.raises(ValueError, match="variance"):
            d.select_alpha([0.1], math.nan, 0.99)
        with pytest.raises(ValueError, match="non-finite"):
            d.select_alpha([math.nan], 0.0, 0.99)

    def test_non_finite_tolerance_is_refused(self) -> None:
        d = AvaDescent()
        for bad in (math.inf, math.nan):
            with pytest.raises(ValueError, match="tolerance"):
                d.descend(TARGET, zeros(DIM), tolerance=bad)

    def test_select_alpha_reaches_exactly_three_modes(self) -> None:
        """'aggressive' is a constructor mode, never a selector outcome —
        the documented contract, asserted over the full branch structure."""
        d = AvaDescent()
        outcomes = {
            d.select_alpha([0.1], 0.0, 0.92),
            d.select_alpha([0.1], 0.9, 0.99),
            d.select_alpha([5.0], 0.0, 0.99),
            d.select_alpha([0.1], 0.0, 0.99),
        }
        assert outcomes == {
            d.ALPHA_MODES["high_reliability"],
            d.ALPHA_MODES["balanced"],
            d.ALPHA_MODES["golden_ratio"],
        }
        assert d.ALPHA_MODES["aggressive"] not in outcomes

    def test_overflow_at_the_float_extremes_is_refused_not_published(self) -> None:
        """PIN (review finding): finite operands are not closed under
        floating-point subtraction — descend([1e308], [-1e308]) passed
        entry validation and returned ([inf], [inf]).  The per-step
        Lyapunov value now refuses the overflow."""
        with pytest.raises(ValueError, match="overflow"):
            AvaDescent().descend([1e308], [-1e308], max_steps=5)

    def test_a_non_finite_forcing_scalar_is_refused(self) -> None:
        d = AvaDescent()
        for bad in (math.inf, math.nan):
            with pytest.raises(ValueError, match="omni_scalar"):
                d.catalan_step([0.0], [1.0], omni_scalar=bad)

    def test_an_int_outside_float_range_is_refused_not_leaked(self) -> None:
        """PIN (review finding, 2026-10-07): ``math.isfinite(10**1000)`` and
        ``float(10**1000)`` raise ``OverflowError``, so an int too large to
        convert to float escaped every documented ``ValueError`` refusal —
        through the constructor's finiteness check, ``descend``'s tolerance
        check, and the ``asvec`` coercion of every vector argument.  Each
        site now refuses it as the non-finite value it is in these
        operators' float domain.  Mutation: restoring bare ``math.isfinite``
        at the scalar sites, or unwrapping any ``asvec`` coercion, leaks
        ``OverflowError`` and fails exactly the matching case here."""
        huge = 10**1000
        d = AvaDescent()
        with pytest.raises(ValueError, match="finite positive"):
            AvaDescent(alpha=huge)
        with pytest.raises(ValueError, match="finite positive"):
            AvaDescent(equity_gain=huge)
        with pytest.raises(ValueError, match="tolerance"):
            d.descend(TARGET, zeros(DIM), tolerance=huge)
        with pytest.raises(ValueError, match="float range"):
            d.descend([huge], [1.0])
        with pytest.raises(ValueError, match="float range"):
            d.descend([1.0], [huge])
        with pytest.raises(ValueError, match="velocity"):
            d.momentum_step([1.0], [1.0], [huge])
        with pytest.raises(ValueError, match="variance"):
            d.select_alpha([0.5], huge, 0.99)
        with pytest.raises(ValueError, match="float range"):
            d.select_alpha([huge], 0.1, 0.99)
        with pytest.raises(ValueError, match="omni_scalar"):
            d.catalan_step([0.0], [1.0], omni_scalar=huge)
        from ama_cryptography.double_helix_engine import AmaEquationEngine

        engine = AmaEquationEngine(state_dim=DIM, random_seed=42)
        with pytest.raises(ValueError, match="float range"):
            engine.converge([huge] + [0.1] * (DIM - 1), max_steps=2)
        with pytest.raises(ValueError, match="tolerance"):
            engine.converge(zeros(DIM), max_steps=2, tolerance=huge)

    def test_momentum_stability_agrees_between_operator_and_loop(self) -> None:
        """PIN (review finding, 2026-10-07): the loop-entry check in
        ``descend(mode="momentum")`` pre-evaluated the Jury bound at
        beta = 0.9 as ``alpha * 0.1 >= 3.8``, which is NOT the expression
        ``momentum_step`` evaluates — ``1.0 - 0.9`` is not exactly ``0.1``,
        so ``alpha = 38.0`` was accepted by the operator and refused by the
        loop.  Both paths now call the one ``_momentum_unstable`` expression.
        Mutation: restoring the pre-evaluated form fails exactly the
        boundary acceptance below."""
        d = AvaDescent(alpha=38.0, equity_gain=0.01)
        # Boundary configuration: 38 * (1.0 - 0.9) = 3.799... < 3.8 — both
        # paths accept.
        d.momentum_step([0.0], [0.1], [0.0])
        d.descend([0.5], [0.0], max_steps=1, mode="momentum")
        # One step past the bound: both paths refuse.
        unstable = AvaDescent(alpha=39.0, equity_gain=0.01)
        with pytest.raises(ValueError, match="momentum stability"):
            unstable.momentum_step([0.0], [0.1], [0.0])
        with pytest.raises(ValueError, match="momentum stability"):
            unstable.descend([0.5], [0.0], max_steps=1, mode="momentum")

    def test_zero_step_momentum_keeps_its_documented_contract(self) -> None:
        """PIN (review finding, 2026-10-08): the Jury bound is an
        operational property of the iteration (its fixed beta = 0.9), but
        it was validated before the ``max_steps=0`` path, so a
        constructible operator like ``alpha=100, equity_gain=0.01`` raised
        where the docstring promises the initial state and an empty
        history.  The bound now binds only when a step will run.
        Mutation: dropping the ``max_steps > 0`` condition fails exactly
        the zero-step case while the one-step refusal holds."""
        d = AvaDescent(alpha=100.0, equity_gain=0.01)
        state, history = d.descend([0.0, 0.0], [1.0, 2.0], max_steps=0, mode="momentum")
        assert state.tolist() == [1.0, 2.0]
        assert history == []
        # The operational refusal is untouched the moment a step would run.
        with pytest.raises(ValueError, match="momentum stability"):
            d.descend([0.0, 0.0], [1.0, 2.0], max_steps=1, mode="momentum")
        # And max_steps=0 still validates its own arguments: a negative
        # count refuses ahead of the zero-step return.
        with pytest.raises(ValueError, match="max_steps"):
            d.descend([0.0], [1.0], max_steps=-1, mode="momentum")

    def test_converge_tolerance_contract_is_method_independent(self) -> None:
        """PIN (review finding, 2026-10-07): the ``descent`` branch refused
        NaN/inf tolerance in ``AvaDescent.descend`` while the ``helix``
        branch interpreted them (NaN never stops, inf stops after one
        step), so one documented contract validated method-dependently.
        ``converge`` now refuses non-finite tolerance before dispatch.
        Mutation: dropping the pre-dispatch check reverts the helix rows
        here to silent acceptance and fails exactly this test."""
        from ama_cryptography.double_helix_engine import AmaEquationEngine

        engine = AmaEquationEngine(state_dim=DIM, random_seed=42)
        for bad in (math.nan, math.inf):
            for method in ("helix", "descent"):
                with pytest.raises(ValueError, match="tolerance"):
                    engine.converge(zeros(DIM), max_steps=2, tolerance=bad, method=method)

    def test_a_subnormal_contraction_factor_is_refused(self) -> None:
        """PIN (review finding): operand positivity does not survive floating
        point — alpha = equity_gain = 1e-308 underflows the product to 0,
        and a product below ~1.1e-16 rounds 1 - gain back to exactly 1, so
        every step is a no-op that "converges" wherever it started.  The
        representable contraction factor is validated."""
        with pytest.raises(ValueError, match="resolution"):
            AvaDescent(alpha=1e-308, equity_gain=1e-308)
        with pytest.raises(ValueError, match="resolution"):
            AvaDescent(alpha=1e-308, equity_gain=1.0)
        assert AvaDescent(alpha=1e-6, equity_gain=1.0).alpha == 1e-6

    def test_variance_overflow_is_a_defined_refusal(self) -> None:
        """PIN (review finding): [1e200, -1e200] leaked an incidental
        OverflowError from the squared deviation ahead of every defined
        refusal; it is now a named ValueError.  Its variance, 1e400, is
        genuinely non-representable, so the refusal survives the 2026-10-08
        scale-before-sum correction below."""
        d = AvaDescent()
        with pytest.raises(ValueError, match="variance overflowed"):
            d.variance_adapted_step([1e200, -1e200], [0.0, 0.0])
        with pytest.raises(ValueError, match="variance overflowed"):
            d.descend([0.0, 0.0], [1e200, -1e200], mode="variance")

    def test_a_representable_variance_is_computed_not_refused(self) -> None:
        """PIN (review finding, 2026-10-08): the accumulation summed raw
        squared deviations, so [1e154, -1e154] overflowed the running sum
        and was refused although its variance, 1e308, is a representable
        float.  The deviation is now divided by n before the multiply, so
        only a genuinely non-representable variance refuses.  Mutation:
        restoring the raw d*d accumulation fails exactly this test's
        finite case while the [1e200, -1e200] refusal above still passes."""
        out = AvaDescent().variance_adapted_step([1e154, -1e154], [0.0, 0.0])
        assert all(math.isfinite(x) for x in out.tolist()), out.tolist()
        # The damping actually used the huge variance: a unit gradient is
        # attenuated by 1/(1 + 1e308), i.e. to zero at float resolution.
        moved = AvaDescent().variance_adapted_step([1e154, -1e154], [1.0, 1.0])
        assert moved.tolist() == [1e154, -1e154], moved.tolist()

    def test_catalan_combines_scalar_gains_before_the_gradient(self) -> None:
        """PIN (review finding): alpha * gradient first overflowed for a
        huge alpha whose product with the tiny equity gain was fine; the
        scalar coefficient now multiplies first, so the constructor-approved
        combined gain is what touches the gradient."""
        d = AvaDescent(alpha=1e308, equity_gain=1e-308)
        out = d.catalan_step([0.0], [2.0])
        assert all(math.isfinite(x) for x in out.tolist()), out.tolist()

    def test_an_overflowing_result_is_refused_on_every_public_operator(self) -> None:
        """PIN (review finding): input finiteness does not survive the
        arithmetic — step([1e308], [1e308]) overflowed to inf from finite,
        validated operands.  Every public operator validates its result."""
        d = AvaDescent(alpha=1.7, equity_gain=1.0)
        with pytest.raises(ValueError, match="overflowed the finite"):
            d.step([1e308], [1e308])
        with pytest.raises(ValueError, match="overflowed the finite"):
            d.catalan_step([1e308], [1e308])
        with pytest.raises(ValueError, match="overflowed the finite"):
            AvaDescent().momentum_step([1.7e308], [1.7e308], [1.7e308], beta=0.0)

    def test_a_mean_of_representable_inputs_never_refuses(self) -> None:
        """PIN (review findings, 2026-10-06 and 2026-10-08): _numeric.mean
        sums with math.fsum, which raises 'intermediate overflow' for
        [1e308, 1e308] although the mean, 1e308, and the variance, exactly
        zero, are both representable.  The 2026-10-06 pass turned that leak
        into a refusal; this one removes the false refusal by summing the
        mean from terms scaled by n, like the variance accumulation.
        Mutation: restoring the `mean(v)` call fails exactly this test
        with the leaked OverflowError it used to raise."""
        d = AvaDescent(alpha=1e-10, equity_gain=1.0)
        # Variance is exactly zero, so the step is undamped: the update is
        # alpha * gain * gradient on top of the state, and it is finite.
        out = d.variance_adapted_step([1e308, 1e308], [1.0, 1.0])
        assert out.tolist() == [1e308, 1e308], out.tolist()

    def test_lyapunov_square_overflow_in_descend_is_the_named_refusal(self) -> None:
        """PIN (review finding): Vec.__pow__ raises past the float range
        (1e200 ** 2) instead of yielding inf, bypassing descend's guard;
        the square's overflow now feeds the same named refusal."""
        with pytest.raises(ValueError, match="descend overflowed"):
            AvaDescent().descend([0.0], [1e200], max_steps=3, mode="equity")

    def test_exact_stagnation_is_refused_not_reported_as_convergence(self) -> None:
        """PIN (review finding): variance mode from [1e150, -1e150] toward
        the origin computes a variance near 1e300, the effective update
        rounds away below the state's ulp, and the loop returned
        "converged" after one no-op iteration at V ~ 2e300.  A zero move
        with target error remaining is now a named refusal."""
        with pytest.raises(ValueError, match="stagnated"):
            AvaDescent().descend([0.0, 0.0], [1e150, -1e150], mode="variance")

    def test_momentum_outside_its_stability_bound_is_refused(self) -> None:
        """PIN (review finding): the constructor bounds alpha * equity_gain,
        but momentum applies alpha alone — alpha=100 with equity_gain=0.01
        passes construction and diverges (0 -> 10 -> -71 on the unit
        quadratic).  The EMA-momentum bound alpha*(1-beta) < 2*(1+beta) is
        enforced at the call."""
        d = AvaDescent(alpha=100.0, equity_gain=0.01)
        with pytest.raises(ValueError, match="momentum stability"):
            d.momentum_step([1.0], [0.0], [0.0])
        with pytest.raises(ValueError, match="stability bound"):
            d.descend([0.0], [1.0], mode="momentum")
        # Just inside the bound for beta=0.9 (alpha < 38): accepted and
        # convergent on the benchmark.
        close = AvaDescent(alpha=37.0, equity_gain=0.01)
        _, history = close.descend(TARGET, zeros(DIM), max_steps=2000, mode="momentum")
        assert math.sqrt(history[-1]) < 1e-6

    def test_catalan_omni_scalar_is_a_forcing_term_with_the_documented_offset(self) -> None:
        """A nonzero omni offsets the settle point by omni / CATALAN_CONSTANT
        per component — measured here, documented in the method."""
        d = AvaDescent()
        omni = 0.25
        state = zeros(DIM)
        for _ in range(500):
            state = d.catalan_step(state, TARGET - state, omni_scalar=omni)
        expected = omni / AvaDescent.CATALAN_CONSTANT
        offsets = [s - t for s, t in zip(state.tolist(), TARGET.tolist())]
        assert offsets == pytest.approx([expected] * DIM, abs=1e-9)


class TestPackageSurface:
    def test_ava_descent_is_a_package_export(self) -> None:
        import ama_cryptography

        assert ama_cryptography.AvaDescent is AvaDescent
        assert "AvaDescent" in ama_cryptography.__all__
