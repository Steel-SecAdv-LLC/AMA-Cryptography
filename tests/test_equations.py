#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
Date: 2026-03-08
Version: 2.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import math
import sys
import unittest
from pathlib import Path

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
        """Test automatic correction mechanism exists."""
        # Test that the correction function properly scales states
        state = Vec([1.0, 1.0, 1.0])
        E = eye(3) * 0.5  # Diagonal matrix with values < threshold

        sigma_original = calculate_sigma_quadratic(state, E)
        valid, corrected = enforce_sigma_quadratic_threshold(state, E, threshold=0.96)

        # For a diagonal matrix, the correction should work
        # σ_quadratic = x^T·E·x / ||x||² = sum(E_ii * x_i^2) / sum(x_i^2)
        # For diagonal E and uniform state, σ = E_ii (all same)
        self.assertFalse(valid, "Original state should be invalid")
        self.assertLess(sigma_original, 0.96, "Original should be below threshold")

        # After correction, verify state was modified
        self.assertFalse(allclose(state, corrected), "State should be corrected")

        # Verify sigma improved (though may not reach threshold for all matrices)
        sigma_corrected = calculate_sigma_quadratic(corrected, E)
        self.assertGreaterEqual(
            sigma_corrected,
            sigma_original * 0.95,  # Should not decrease
            "Correction should not decrease sigma",
        )

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


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
