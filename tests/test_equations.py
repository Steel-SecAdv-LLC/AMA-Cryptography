#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography: Mathematical Equations Test Suite
========================================================

Comprehensive tests for 5 mathematical frameworks:
1. Helical Geometric Invariants
2. Lyapunov Stability Theory
3. Golden Ratio Harmonics
4. Quadratic Form Constraints
5. Integration utilities

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-17
Version: 3.0.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import math
import sys
import unittest
from pathlib import Path
from typing import ClassVar

# Derive repo root relative to this file for portability
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ama_cryptography._numeric import (
    Vec,
    allclose,
    eigvals,
    eye,
    ones,
)
from ama_cryptography.equations import (
    PHI,
    PHI_CUBED,
    calculate_sigma_quadratic,
    convergence_time,
    enforce_sigma_quadratic_threshold,
    fibonacci_sequence,
    golden_ratio_convergence_proof,
    helix_curvature,
    helix_torsion,
    initialize_ethical_matrix,
    lyapunov_derivative,
    lyapunov_function,
    lyapunov_stability_proof,
    verify_all_codes,
    verify_fundamental_relation,
    verify_mathematical_foundations,
)


class TestHelicalGeometricInvariants(unittest.TestCase):
    """Test helical geometric invariant calculations."""

    def test_helix_curvature(self) -> None:
        """Test curvature calculation κ = r/(r² + c²)."""
        r, c = 20.0, 0.7
        kappa = helix_curvature(r, c)
        expected = r / (r**2 + c**2)
        self.assertAlmostEqual(kappa, expected, places=10)

    def test_helix_torsion(self) -> None:
        """Test torsion calculation τ = c/(r² + c²)."""
        r, c = 20.0, 0.7
        tau = helix_torsion(r, c)
        expected = c / (r**2 + c**2)
        self.assertAlmostEqual(tau, expected, places=10)

    def test_fundamental_relation(self) -> None:
        """Test κ² + τ² = 1/(r² + c²) with machine precision."""
        r, c = 20.0, 0.7
        error = verify_fundamental_relation(r, c)
        self.assertLess(error, 1e-10, "Fundamental relation error too large")

    def test_all_codes(self) -> None:
        """Test all 7 Omni-Codes verify κ² + τ² = 1/(r²+c²)."""
        results = verify_all_codes()
        self.assertEqual(len(results), 7, "Should verify all 7 Omni-Codes")

        for code, data in results.items():
            with self.subTest(code=code):
                self.assertLess(
                    data["fundamental_error"],
                    1e-10,
                    f"{code} fundamental relation error too large",
                )
                self.assertTrue(data["valid"], f"{code} failed validation")


class TestLyapunovStability(unittest.TestCase):
    """Test Lyapunov stability theory implementation."""

    def test_lyapunov_function_positive_definite(self) -> None:
        """Test V(x) > 0 for x ≠ x*."""
        state = Vec([0.5, 0.3, 0.2])
        target = ones(3)
        V = lyapunov_function(state, target)
        self.assertGreater(V, 0, "Lyapunov function must be positive")

    def test_lyapunov_function_zero_at_equilibrium(self) -> None:
        """Test V(x*) = 0 at equilibrium."""
        target = ones(3)
        V = lyapunov_function(target, target)
        self.assertAlmostEqual(V, 0.0, places=10, msg="V should be 0 at equilibrium")

    def test_lyapunov_derivative_negative(self) -> None:
        """Test V̇(x) ≤ 0 (negative semi-definite)."""
        V = 1.5
        V_dot = lyapunov_derivative(V)
        self.assertLessEqual(V_dot, 0, "V̇(x) must be non-positive")

    def test_convergence_time_calculation(self) -> None:
        """Test convergence time estimates."""
        V0 = 100.0
        t_99 = convergence_time(V0, 0.01)
        t_999 = convergence_time(V0, 0.001)
        self.assertGreater(t_999, t_99, "99.9% convergence takes longer than 99%")
        self.assertGreater(t_99, 0, "Convergence time must be positive")

    def test_lyapunov_stability_proof(self) -> None:
        """Test complete Lyapunov stability proof."""
        state = Vec([0.5, 0.3, 0.2])
        target = ones(3)
        stable, V, proof = lyapunov_stability_proof(state, target)

        self.assertTrue(stable, "System should be Lyapunov stable")
        self.assertGreater(V, 0, "V(x) must be positive")
        self.assertLessEqual(proof["V_dot"], 0, "V̇(x) must be non-positive")
        self.assertIn("time_to_99", proof)
        self.assertIn("half_life", proof)


class TestGoldenRatioHarmonics(unittest.TestCase):
    """Test golden ratio and Fibonacci convergence."""

    def test_fibonacci_sequence_generation(self) -> None:
        """Test Fibonacci sequence generation."""
        fib = fibonacci_sequence(10)
        expected = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
        self.assertEqual(fib, expected, "Fibonacci sequence incorrect")

    def test_fibonacci_ratio_convergence(self) -> None:
        """Test F_{n+1}/F_n → φ convergence."""
        converged, ratio, proof = golden_ratio_convergence_proof(30)
        self.assertTrue(converged, "Fibonacci ratio should converge")
        self.assertAlmostEqual(ratio, PHI, places=8, msg="Ratio should equal φ")
        self.assertLess(proof["error"], 1e-8, "Convergence error too large")

    def test_phi_value(self) -> None:
        """Test φ = (1 + √5)/2 ≈ 1.618034."""
        expected = (1 + math.sqrt(5)) / 2
        self.assertAlmostEqual(PHI, expected, places=15)

    def test_phi_cubed_value(self) -> None:
        """Test φ³ ≈ 4.236068."""
        expected = PHI**3
        self.assertAlmostEqual(PHI_CUBED, expected, places=15)


class TestQuadraticFormConstraints(unittest.TestCase):
    """Test σ_quadratic constraint enforcement."""

    def test_calculate_sigma_quadratic(self) -> None:
        """Test σ_quadratic = x^T·E·x / ||x||² calculation."""
        state = Vec([1.0, 1.0, 1.0])
        E = eye(3) * 2.0  # Simple diagonal matrix
        sigma = calculate_sigma_quadratic(state, E)
        expected = 2.0  # For normalized vector and diagonal E=2I
        self.assertAlmostEqual(sigma, expected, places=6)

    def test_sigma_quadratic_enforcement_valid(self) -> None:
        """Test enforcement when σ_quadratic already meets threshold."""
        state = Vec([1.0, 1.0, 1.0])
        E = eye(3) * 2.0
        valid, corrected = enforce_sigma_quadratic_threshold(state, E, threshold=0.96)
        self.assertTrue(valid, "State should be valid")
        self.assertTrue(allclose(corrected, state))

    def test_sigma_quadratic_enforcement_correction(self) -> None:
        """A violated threshold is actually corrected, to the threshold.

        σ is a Rayleigh quotient, so ``σ(kx) == σ(x)``: scaling cannot change
        it, and the correction has to rotate the state toward E's dominant
        eigenvector.  This asserts the property the function advertises —
        σ_corrected >= threshold — rather than "σ did not decrease", which a
        no-op satisfies (and which is how a scale-only "correction" went
        unnoticed through 4.0).
        """
        # E's dominant eigenvalue is 1.0, so a 0.9 threshold is reachable;
        # the state starts aligned with the weak (0.2) directions.
        E = eye(4) * 0.2
        E[0][0] = 1.0
        state = Vec([0.0, 1.0, 1.0, 1.0])

        sigma_original = calculate_sigma_quadratic(state, E)
        self.assertLess(sigma_original, 0.9, "Original should be below threshold")

        valid, corrected = enforce_sigma_quadratic_threshold(state, E, threshold=0.9)
        self.assertFalse(valid, "Original state should be reported invalid")

        sigma_corrected = calculate_sigma_quadratic(corrected, E)
        self.assertGreaterEqual(
            sigma_corrected,
            0.9 - 1e-9,
            f"Correction must reach the threshold, got {sigma_corrected}",
        )

        # The correction preserves the state's magnitude: σ does not depend on
        # it, but the downstream helix dynamics do.
        norm_before = math.sqrt(sum(v * v for v in state))
        norm_after = math.sqrt(sum(v * v for v in corrected))
        self.assertAlmostEqual(norm_before, norm_after, places=9)

    def test_sigma_quadratic_enforcement_unreachable_threshold(self) -> None:
        """An unreachable threshold is reported, not faked.

        ``max_x σ(x) == λ_max``, so with E = 0.5·I no state whatsoever can
        reach 0.96.  The honest result is "invalid, unchanged" — perturbing the
        state would return something that still fails the constraint while
        looking corrected.
        """
        state = Vec([1.0, 1.0, 1.0])
        E = eye(3) * 0.5

        valid, corrected = enforce_sigma_quadratic_threshold(state, E, threshold=0.96)

        self.assertFalse(valid, "0.96 is unreachable for λ_max = 0.5")
        self.assertTrue(allclose(corrected, state), "Unreachable → state unchanged")
        self.assertAlmostEqual(calculate_sigma_quadratic(corrected, E), 0.5, places=12)

    def test_initialize_ethical_matrix_positive_definite(self) -> None:
        """Test ethical matrix is positive-definite."""
        E = initialize_ethical_matrix(10)
        eigs = eigvals(E)
        self.assertTrue(all(e > 0 for e in eigs), "All eigenvalues must be positive")

    def test_initialize_ethical_matrix_dimension(self) -> None:
        """Test ethical matrix has correct dimensions."""
        dim = 15
        E = initialize_ethical_matrix(dim)
        self.assertEqual(E.shape, (dim, dim), "Matrix dimension incorrect")


class TestIntegration(unittest.TestCase):
    """Test integration utilities and overall verification."""

    def test_verify_mathematical_foundations(self) -> None:
        """Test comprehensive verification of all frameworks."""
        results = verify_mathematical_foundations()

        self.assertIn("helical_invariants", results)
        self.assertIn("lyapunov_stability", results)
        self.assertIn("golden_ratio", results)
        self.assertIn("sigma_quadratic", results)
        self.assertIn("frameworks_ready", results)

        # All frameworks should pass
        self.assertTrue(results["helical_invariants"], "Helical invariants failed")
        self.assertTrue(results["lyapunov_stability"], "Lyapunov stability failed")
        self.assertTrue(results["golden_ratio"], "Golden ratio failed")
        self.assertTrue(results["sigma_quadratic"], "σ_quadratic failed")
        self.assertTrue(results["frameworks_ready"], "Overall frameworks not ready")


class TestSigmaEnforcementOnAnIndefiniteMatrix(unittest.TestCase):
    """``max_x sigma(x)`` is the largest ALGEBRAIC eigenvalue, not the largest
    by magnitude — and power iteration finds the second one.

    ``_dominant_eigenvector`` is plain power iteration, so it converges to the
    eigenvector of the largest-magnitude eigenvalue.  Its docstring asserted
    that this equals ``max_x sigma_quadratic(x)``, which holds only for a
    positive semi-definite matrix; ``enforce_sigma_quadratic_threshold`` then
    used it as an unreachability oracle ("lambda_max < threshold: no state
    satisfies the constraint").  Nothing on the public boundary validates
    definiteness — both functions take an arbitrary caller-supplied array — and
    the iteration itself already carried explicit handling for a negative
    dominant eigenvalue, so the indefinite case was reachable, not excluded.

    Measured before the fix on ``E = diag(-5, 1)``: the direction came back as
    ``[1, 0]`` where sigma = -5, and a threshold of 0.5 — which the state
    ``[0, 1]`` meets with sigma = 1.0 — was reported unreachable and the state
    returned uncorrected.
    """

    #: Eigenvalues -5 and +1: largest by magnitude is -5, largest
    #: algebraically is +1, and they have different eigenvectors.
    INDEFINITE: ClassVar[list[list[float]]] = [[-5.0, 0.0], [0.0, 1.0]]

    def test_a_reachable_threshold_is_reached(self) -> None:
        met, corrected = enforce_sigma_quadratic_threshold(
            Vec([1.0, 0.0]), self.INDEFINITE, threshold=0.5
        )
        self.assertFalse(met, "the input state violated the threshold")
        sigma = calculate_sigma_quadratic(corrected, self.INDEFINITE)
        self.assertGreaterEqual(sigma + 1e-9, 0.5, f"correction left sigma at {sigma}")

    def test_the_corrected_state_keeps_the_callers_norm(self) -> None:
        state = Vec([3.0, 0.0])
        _met, corrected = enforce_sigma_quadratic_threshold(state, self.INDEFINITE, threshold=0.5)
        self.assertAlmostEqual(math.sqrt(corrected @ corrected), 3.0, places=9)

    def test_a_genuinely_unreachable_threshold_is_still_refused(self) -> None:
        """Non-vacuity: the fix must not be "always correct something".

        2.0 is above this matrix's true lambda_max of 1.0, so no state meets
        it and the state must come back untouched.
        """
        state = Vec([1.0, 0.0])
        met, corrected = enforce_sigma_quadratic_threshold(state, self.INDEFINITE, threshold=2.0)
        self.assertFalse(met)
        self.assertEqual(list(corrected), list(state))

    def test_the_direction_maximises_sigma_over_the_whole_matrix(self) -> None:
        """Stated as the property, checked against a dense sweep."""
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _dominant_eigenvector

        for data in (
            self.INDEFINITE,
            [[-1.0, 2.0], [2.0, -1.0]],  # eigenvalues -3 and +1
            [[0.0, 1.0], [1.0, 0.0]],  # eigenvalues -1 and +1
            [[2.0, 0.0], [0.0, 3.0]],  # already positive definite
        ):
            matrix = asmat(data)
            direction = _dominant_eigenvector(matrix)
            assert direction is not None
            best = calculate_sigma_quadratic(direction, matrix)
            for step in range(721):
                angle = math.pi * step / 720.0
                probe = Vec([math.cos(angle), math.sin(angle)])
                self.assertLessEqual(
                    calculate_sigma_quadratic(probe, matrix),
                    best + 1e-9,
                    f"{data}: a swept direction beat the reported maximiser",
                )

    def test_a_positive_definite_matrix_is_unaffected(self) -> None:
        """The shift is zero whenever Gershgorin already bounds below at >= 0."""
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _gershgorin_lower_bound

        matrix = initialize_ethical_matrix(6)
        self.assertGreaterEqual(_gershgorin_lower_bound(asmat(matrix)), 0.0)

    def test_gershgorin_is_a_bound_not_the_spectrum(self) -> None:
        """A positive-definite matrix can still have a negative bound.

        The docstring once said "for a matrix that was already PSD the bound
        is >= 0, c is 0, and the iteration is bit-identical".  That is false
        for almost every PSD matrix with off-diagonal mass: ``[[1, 2], [2, 5]]``
        has eigenvalues ~5.83 and ~0.17 — positive definite — and a Gershgorin
        lower bound of -1, so a shift IS applied.  Harmless, because shifting
        preserves eigenvectors exactly, but the claim of bit-identity was not.
        This test exists so that claim cannot come back.
        """
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _gershgorin_lower_bound

        psd = asmat([[1.0, 2.0], [2.0, 5.0]])
        # Positive definite by Sylvester's criterion — derived from the
        # MATRIX, not restated as literals: `assertGreater(1.0, 0.0)` was a
        # compile-time truth that kept passing however `psd` was edited,
        # leaving the load-bearing Gershgorin assertion attached to a
        # premise nothing checked.
        self.assertGreater(psd[0][0], 0.0)
        self.assertGreater(psd[0][0] * psd[1][1] - psd[0][1] * psd[1][0], 0.0)
        self.assertLess(_gershgorin_lower_bound(psd), 0.0)


class TestSigmaIsBlindToTheSkewPart(unittest.TestCase):
    """``argmax_x sigma(x)`` is an eigenproblem on ``(E + E^T)/2``, not on ``E``.

    ``sigma(x) = x^T E x / x^T x`` and ``x^T E x`` is a scalar, so it equals
    ``x^T E^T x``; averaging gives ``x^T E x = x^T ((E + E^T)/2) x`` for every
    ``x``.  The skew part contributes exactly nothing.

    The first version of the indefinite-matrix fix shifted and iterated ``E``
    itself, which is the right operator only when ``E`` is symmetric.  Measured
    on ``E = [[0, 4], [0, 1]]``: it returned ``[0.970, 0.243]`` where
    ``sigma = 1.000``, against a true maximum of ``2.562`` at
    ``[0.615, 0.788]`` — the same class of failure the shift was added to
    remove, reached through a different input.
    """

    NON_SYMMETRIC = (
        [[0.0, 4.0], [0.0, 1.0]],
        [[3.0, -7.0], [2.0, 3.0]],
        [[1.0, 10.0], [-2.0, 1.0]],
        [[-5.0, 6.0], [0.0, -1.0]],
    )

    def test_the_symmetric_part_is_what_sigma_sees(self) -> None:
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _symmetric_part

        for data in self.NON_SYMMETRIC:
            matrix = asmat(data)
            sym = _symmetric_part(matrix)
            for step in range(181):
                angle = math.pi * step / 180.0
                probe = Vec([math.cos(angle), math.sin(angle)])
                self.assertAlmostEqual(
                    calculate_sigma_quadratic(probe, matrix),
                    calculate_sigma_quadratic(probe, sym),
                    places=12,
                    msg=f"{data}: sigma differs between E and its symmetric part",
                )

    def test_the_direction_maximises_sigma_for_non_symmetric_input(self) -> None:
        """The property, swept densely — this is what caught the defect."""
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _dominant_eigenvector

        for data in self.NON_SYMMETRIC:
            matrix = asmat(data)
            direction = _dominant_eigenvector(matrix)
            self.assertIsNotNone(direction, f"{data}: no direction returned")
            assert direction is not None
            best = calculate_sigma_quadratic(direction, matrix)
            for step in range(2881):
                angle = math.pi * step / 2880.0
                probe = Vec([math.cos(angle), math.sin(angle)])
                self.assertLessEqual(
                    calculate_sigma_quadratic(probe, matrix),
                    best + 1e-9,
                    f"{data}: a swept direction beat the reported maximiser",
                )

    def test_a_purely_skew_matrix_has_no_maximiser(self) -> None:
        """sigma is identically zero there, so "no direction" is the answer.

        Returning some arbitrary unit vector would be worse than None: the
        caller blends toward it to raise sigma, and no blend can.
        """
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _dominant_eigenvector

        skew = asmat([[0.0, 1.0], [-1.0, 0.0]])
        for step in range(181):
            angle = math.pi * step / 180.0
            probe = Vec([math.cos(angle), math.sin(angle)])
            self.assertAlmostEqual(calculate_sigma_quadratic(probe, skew), 0.0, places=12)
        self.assertIsNone(_dominant_eigenvector(skew))

    def test_symmetric_input_is_untouched_by_the_symmetrisation(self) -> None:
        """The documented case must be an exact identity, not an approximation."""
        from ama_cryptography._numeric import asmat
        from ama_cryptography.equations import _symmetric_part

        for data in ([[2.0, 0.0], [0.0, 3.0]], [[-1.0, 2.0], [2.0, -1.0]]):
            matrix = asmat(data)
            sym = _symmetric_part(matrix)
            for i in range(2):
                for j in range(2):
                    self.assertEqual(float(sym[i][j]), float(matrix[i][j]), f"{data} [{i}][{j}]")


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
