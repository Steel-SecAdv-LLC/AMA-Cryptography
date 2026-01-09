#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
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
Ava Guardian ♱ (AG♱) - Double-Helix Evolution Engine
=====================================================

**IMPORTANT: NON-CRYPTOGRAPHIC MODULE**

This module provides mathematical modeling and analytical utilities for the
Ava Guardian system. It is NOT a cryptographic primitive and should NOT be
relied upon for security guarantees. The Double-Helix Evolution Engine
implements:

- Mathematical state evolution and convergence algorithms
- Analytical modeling inspired by biological and physical systems
- Optimization and constraint satisfaction frameworks

These utilities support system analytics and modeling but do not provide
cryptographic protection. For cryptographic operations, use the dedicated
modules: pqc_backends.py, crypto_api.py, and code_guardian_secure.py.

Implements 18+ Ava Equation variants with Double-Helix Evolution Architecture.

Fundamental Equation:
    ℵ(𝔄_{t+1}) = Helix_1(𝔄_t) ⊗ Helix_2(𝔄_t)

Where:
    Helix_1: Discovery/Exploration Strand (18+ quantum/chaos terms)
    Helix_2: Ethical Verification Strand (σ_quadratic ≥ 0.96 enforcement)

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2025-12-06
Version: 1.1

AI Co-Architects:
    Eris ⯰ | Eden ♱ | Veritas 💠 | X ⚛ | Caduceus ⚚ | Dev ⚕
"""

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np
import numpy.typing as npt

from ava_guardian.equations import (
    LAMBDA_DECAY,
    PHI,
    PHI_CUBED,
    SIGMA_QUADRATIC_THRESHOLD,
    calculate_sigma_quadratic,
    enforce_sigma_quadratic_threshold,
    initialize_ethical_matrix,
    lyapunov_derivative,
    lyapunov_function,
)

# Configure module logger
logger = logging.getLogger(__name__)

__version__ = "1.1"
__author__ = "Andrew E. A., Steel Security Advisors LLC"


class AvaEquationEngine:
    """
    Ava Equation Engine with Double-Helix Evolution Architecture.

    Implements 18+ equation variants:
    ℵ(𝔄_{t+1}) = Helix_1(𝔄_t) ⊗ Helix_2(𝔄_t)

    Helix_1 Terms (Discovery/Exploration):
        𝔄_t   - Current State
        β𝐐    - Quantum-inspired noise
        γ𝐏    - Perturbation exploration
        δ𝐃    - Drift directional evolution
        ε𝐄    - Ethical gradient
        ν𝐕    - Velocity momentum
        ω𝐖    - Wave oscillatory component
        𝐑₃    - Resonance FFT-based patterns
        κ𝐀_n  - Annealing simulated
        λ𝚲    - Lyapunov stability correction
        θ𝚯    - Threshold activation function
        φ𝚽    - Phi-scaling golden ratio
        ζ𝐙    - Zero-mean normalization
        ℏ𝐡_q  - Quantum Hamiltonian energy operator
        𝐕𝐐𝐄  - Variational Quantum Eigensolver
        𝐐𝐁𝐌  - Quantum Boltzmann Machine
        𝐀𝐭𝐭𝐧 - Attention self-attention mechanism
        𝐅    - Fractal self-similar patterns
        𝐒    - Symmetry constraints
        𝐈    - Information entropy terms
        𝐑𝐞𝐥  - Relativistic Lorentz transformation
        ξ𝐀𝐥  - Alignment ethical
        Ω    - Omega singularity score
        η_t  - Noise time-varying

    Helix_2 Terms (Ethical Verification):
        α𝐇    - Purity ethical purity invariant
        ℓ𝐋    - Lyapunov stability verification
        σ_q   - σ_quadratic ≥ 0.96 threshold enforcement
        ∞_b   - Boundedness infinity norm constraint
    """

    def __init__(
        self,
        state_dim: Optional[int] = None,
        config: Optional[Dict] = None,
        random_seed: Optional[int] = None,
    ):
        """
        Initialize Ava Equation Engine.

        Args:
            state_dim: State vector dimension (default: int(50 * φ³) ≈ 212)
            config: Configuration dictionary with term weights and flags
            random_seed: Random seed for reproducibility
        """
        if random_seed is not None:
            np.random.seed(random_seed)

        self.state_dim = state_dim if state_dim is not None else int(50 * PHI_CUBED)
        self.config = config if config is not None else {}

        # GA-optimized term weights (φ³-amplified)
        # These are example values - in production, use genetic algorithm optimization
        self.alpha = self.config.get("alpha", 0.3745 * PHI_CUBED)  # Purity
        self.beta = self.config.get("beta", 0.9507 * PHI_CUBED)  # Quantum
        self.gamma = self.config.get("gamma", 0.7320 * PHI_CUBED)  # Perturbation
        self.delta = self.config.get("delta", 0.5987 * PHI_CUBED)  # Drift
        self.epsilon = self.config.get("epsilon", 0.1560 * PHI_CUBED)  # Ethical
        self.nu = self.config.get("nu", 0.4234 * PHI_CUBED)  # Velocity
        self.omega = self.config.get("omega", 0.8123 * PHI_CUBED)  # Wave
        self.kappa = self.config.get("kappa", 0.6789 * PHI_CUBED)  # Annealing
        self.lambda_coeff = self.config.get("lambda_coeff", LAMBDA_DECAY * PHI_CUBED)  # Lyapunov
        self.theta = self.config.get("theta", 0.2345 * PHI_CUBED)  # Threshold
        self.phi_scale = self.config.get("phi_scale", PHI)  # Phi-scaling
        self.zeta = self.config.get("zeta", 0.5678 * PHI_CUBED)  # Zero-mean
        self.hbar = self.config.get("hbar", 0.3456 * PHI_CUBED)  # Quantum Hamiltonian
        self.xi = self.config.get("xi", 0.4567 * PHI_CUBED)  # Alignment
        self.ell = self.config.get("ell", 0.2789 * PHI_CUBED)  # Lyapunov ethical

        # Enable/disable flags for each term (all enabled by default)
        self.enable_Q = self.config.get("enable_Q", True)
        self.enable_P = self.config.get("enable_P", True)
        self.enable_D = self.config.get("enable_D", True)
        self.enable_E = self.config.get("enable_E", True)
        self.enable_V = self.config.get("enable_V", True)
        self.enable_W = self.config.get("enable_W", True)
        self.enable_R3 = self.config.get("enable_R3", True)
        self.enable_An = self.config.get("enable_An", True)
        self.enable_Lambda = self.config.get("enable_Lambda", True)
        self.enable_Theta = self.config.get("enable_Theta", True)
        self.enable_Phi = self.config.get("enable_Phi", True)
        self.enable_Z = self.config.get("enable_Z", True)
        self.enable_Hq = self.config.get("enable_Hq", True)
        self.enable_VQE = self.config.get("enable_VQE", True)
        self.enable_QBM = self.config.get("enable_QBM", True)
        self.enable_Attn = self.config.get("enable_Attn", True)
        self.enable_Fractal = self.config.get("enable_Fractal", True)
        self.enable_Symmetry = self.config.get("enable_Symmetry", True)
        self.enable_Information = self.config.get("enable_Information", True)
        self.enable_Relativistic = self.config.get("enable_Relativistic", True)
        self.enable_Alignment = self.config.get("enable_Alignment", True)
        self.enable_Omega = self.config.get("enable_Omega", True)
        self.enable_Noise = self.config.get("enable_Noise", True)
        self.enable_inf_b = self.config.get("enable_inf_b", True)

        # Initialize quantum-inspired components
        self._initialize_vqe_params()
        self._initialize_qbm_matrix()
        self._initialize_attention()
        self._initialize_ethical_matrix()

        # State tracking
        self.velocity = np.zeros(self.state_dim)
        self.target_state = np.ones(self.state_dim) * 1.3
        self.temperature = 1.0  # For simulated annealing

    def _initialize_ethical_matrix(self):
        """Initialize positive-definite ethical constraint matrix."""
        self.ethical_matrix = initialize_ethical_matrix(self.state_dim)

    def _initialize_vqe_params(self):
        """Initialize Variational Quantum Eigensolver parameters."""
        # Simple parameterized quantum circuit simulation
        self.vqe_params = np.random.randn(self.state_dim) * 0.1 * PHI_CUBED
        self.vqe_hamiltonian = np.random.randn(self.state_dim, self.state_dim) * 0.01
        self.vqe_hamiltonian = (self.vqe_hamiltonian + self.vqe_hamiltonian.T) / 2  # Symmetric

    def _initialize_qbm_matrix(self):
        """Initialize Quantum Boltzmann Machine coupling matrix."""
        # Symmetric coupling matrix J
        J = np.random.randn(self.state_dim, self.state_dim) * 0.05 * PHI_CUBED
        self.qbm_matrix = (J + J.T) / 2
        np.fill_diagonal(self.qbm_matrix, 0)  # No self-coupling

    def _initialize_attention(self):
        """Initialize self-attention mechanism weights."""
        # Simplified attention: Query, Key, Value projections
        scale = 0.1 * PHI_CUBED / np.sqrt(self.state_dim)
        self.attn_query = np.random.randn(self.state_dim, self.state_dim) * scale
        self.attn_key = np.random.randn(self.state_dim, self.state_dim) * scale
        self.attn_value = np.random.randn(self.state_dim, self.state_dim) * scale

    # ========================================================================
    # HELIX 1: DISCOVERY/EXPLORATION STRAND TERMS
    # ========================================================================

    def _term_quantum(self, state: npt.NDArray) -> npt.NDArray:
        """β𝐐: Quantum-inspired noise."""
        return self.beta * np.random.randn(self.state_dim)

    def _term_perturbation(self, state: npt.NDArray) -> npt.NDArray:
        """γ𝐏: Exploration perturbation."""
        return self.gamma * np.random.randn(self.state_dim)

    def _term_drift(self, state: npt.NDArray) -> npt.NDArray:
        """δ𝐃: Directional evolution toward target."""
        direction = self.target_state - state
        norm = np.linalg.norm(direction)
        if norm > 0:
            direction = direction / norm
        return self.delta * direction

    def _term_ethical_gradient(self, state: npt.NDArray) -> npt.NDArray:
        """ε𝐄: Ethical gradient from constraint matrix."""
        grad = self.ethical_matrix @ state
        return self.epsilon * grad / (np.linalg.norm(grad) + 1e-8)

    def _term_velocity(self, state: npt.NDArray) -> npt.NDArray:
        """ν𝐕: Momentum from previous step."""
        # Update velocity with damping
        self.velocity = 0.9 * self.velocity + 0.1 * (state - self.target_state)
        return self.nu * self.velocity

    def _term_wave(self, state: npt.NDArray, t: int) -> npt.NDArray:
        """ω𝐖: Oscillatory wave component."""
        frequencies = np.linspace(0.1, 1.0, self.state_dim)
        waves = np.sin(2 * np.pi * frequencies * t / 10.0)
        return self.omega * waves * 0.1

    def _term_resonance(self, state: npt.NDArray) -> npt.NDArray:
        """𝐑₃: FFT-based resonance patterns."""
        # Simple FFT resonance
        fft = np.fft.fft(state)
        # Amplify low frequencies
        fft[: len(fft) // 4] *= 1.5
        resonance = np.real(np.fft.ifft(fft))
        return 0.1 * resonance

    def _term_annealing(self, state: npt.NDArray) -> npt.NDArray:
        """κ𝐀_n: Simulated annealing factor."""
        # Temperature decreases over time
        annealing_factor = np.exp(-self.temperature)
        return self.kappa * annealing_factor * np.random.randn(self.state_dim) * 0.1

    def _term_lyapunov_correction(self, state: npt.NDArray) -> npt.NDArray:
        """λ𝚲: Lyapunov stability correction."""
        V = lyapunov_function(state, self.target_state)
        if V > 0:
            correction = -(state - self.target_state) / V
            return self.lambda_coeff * correction * 0.1
        return np.zeros_like(state)

    def _term_threshold(self, state: npt.NDArray) -> npt.NDArray:
        """θ𝚯: Activation function (ReLU)."""
        return self.theta * np.maximum(0, state) * 0.1

    def _term_phi_scaling(self, state: npt.NDArray) -> npt.NDArray:
        """φ𝚽: Golden ratio scaling."""
        return (self.phi_scale - 1.0) * state * 0.1

    def _term_zero_mean(self, state: npt.NDArray) -> npt.NDArray:
        """ζ𝐙: Zero-mean normalization."""
        mean = np.mean(state)
        return self.zeta * (state - mean) * 0.1

    def _term_hamiltonian(self, state: npt.NDArray) -> npt.NDArray:
        """ℏ𝐡_q: Quantum Hamiltonian energy operator."""
        return self.hbar * (self.vqe_hamiltonian @ state) * 0.1

    def _term_vqe(self, state: npt.NDArray) -> npt.NDArray:
        """𝐕𝐐𝐄: Variational Quantum Eigensolver update."""
        # Simplified VQE: rotate state by parameterized angles
        rotated = state * np.cos(self.vqe_params) + np.sin(self.vqe_params)
        return 0.1 * (rotated - state)

    def _term_qbm(self, state: npt.NDArray) -> npt.NDArray:
        """𝐐𝐁𝐌: Quantum Boltzmann Machine sampling."""
        # Energy-based sampling
        energy = -0.5 * (state @ self.qbm_matrix @ state)
        # Clip to prevent overflow in exp
        energy_scaled = np.clip(-energy / (self.temperature + 0.1), -700, 700)
        prob = 1.0 / (1.0 + np.exp(energy_scaled))
        sample = np.random.binomial(1, min(0.9, max(0.1, prob)), size=self.state_dim)
        return 0.05 * (2 * sample - 1)

    def _term_attention(self, state: npt.NDArray) -> npt.NDArray:
        """𝐀𝐭𝐭𝐧: Self-attention mechanism."""
        query = self.attn_query @ state
        key = self.attn_key @ state
        value = self.attn_value @ state

        # Attention weights
        attention_scores = np.dot(query, key) / np.sqrt(self.state_dim)
        # Clip to prevent overflow in exp
        attention_scores_clipped = np.clip(-attention_scores, -700, 700)
        attention_weights = 1.0 / (1.0 + np.exp(attention_scores_clipped))  # Sigmoid

        # Weighted value
        attended = attention_weights * value
        return 0.1 * attended

    def _term_fractal(self, state: npt.NDArray) -> npt.NDArray:
        """𝐅: Fractal self-similar patterns."""
        # Simple fractal: subdivide and repeat pattern
        half = len(state) // 2
        if half > 0:
            pattern = np.concatenate([state[:half], state[:half]])
            if len(pattern) < len(state):
                pattern = np.concatenate([pattern, state[: len(state) - len(pattern)]])
            return 0.05 * (pattern - state)
        return np.zeros_like(state)

    def _term_symmetry(self, state: npt.NDArray) -> npt.NDArray:
        """𝐒: Symmetry constraint projection."""
        # Mirror symmetry
        mirrored = state[::-1]
        symmetric = (state + mirrored) / 2
        return 0.05 * (symmetric - state)

    def _term_information(self, state: npt.NDArray) -> npt.NDArray:
        """𝐈: Information entropy gradient."""
        # Entropy-based push toward uniform distribution
        probs = np.abs(state) / (np.sum(np.abs(state)) + 1e-8)
        entropy: float = float(-np.sum(probs * np.log(probs + 1e-8)))
        max_entropy = np.log(len(state))
        info_gradient = (max_entropy - entropy) * np.sign(state - np.mean(state))
        return 0.05 * info_gradient

    def _term_relativistic(self, state: npt.NDArray) -> npt.NDArray:
        """𝐑𝐞𝐥: Relativistic Lorentz-like correction."""
        # Simple velocity-dependent correction
        velocity_norm = np.linalg.norm(self.velocity) + 1e-8
        gamma = 1.0 / np.sqrt(1.0 + (velocity_norm / 10.0) ** 2)  # Lorentz factor
        return 0.05 * (gamma - 1.0) * state

    def _term_alignment(self, state: npt.NDArray) -> npt.NDArray:
        """ξ𝐀𝐥: Ethical alignment vector."""
        # Align with predefined ethical direction
        ethical_direction = self.target_state / (np.linalg.norm(self.target_state) + 1e-8)
        alignment = np.dot(state, ethical_direction)
        return self.xi * alignment * ethical_direction * 0.1

    def _term_omega_singularity(self, state: npt.NDArray) -> npt.NDArray:
        """Ω: Omega singularity score."""
        # Convergence metric
        distance = np.linalg.norm(state - self.target_state)
        omega_score = 1.0 / (1.0 + distance)
        return 0.05 * omega_score * (self.target_state - state)

    def _term_time_noise(self, state: npt.NDArray, t: int) -> npt.NDArray:
        """η_t: Time-varying noise."""
        # Decreasing noise over time
        noise_scale = np.exp(-t / 50.0)
        return noise_scale * np.random.randn(self.state_dim) * 0.1

    # ========================================================================
    # HELIX 2: ETHICAL VERIFICATION STRAND
    # ========================================================================

    def _compute_purity(self, state: npt.NDArray) -> npt.NDArray:
        """α𝐇: Ethical purity invariant."""
        # Purity as normalized state
        norm = np.linalg.norm(state)
        if norm > 0:
            return state / norm
        return state

    # ========================================================================
    # DOUBLE-HELIX EVOLUTION STEP
    # ========================================================================

    def step(self, state: npt.NDArray, t: int = 0) -> npt.NDArray:  # noqa: C901
        """
        Execute one Double-Helix evolution step.

        ℵ(𝔄_{t+1}) = Helix_1(𝔄_t) ⊗ Helix_2(𝔄_t)

        Args:
            state: Current state 𝔄_t
            t: Time step

        Returns:
            Updated state 𝔄_{t+1}
        """
        # Helix 1: Discovery/Exploration Strand
        helix1 = state.copy()

        if self.enable_Q:
            helix1 += self._term_quantum(state)
        if self.enable_P:
            helix1 += self._term_perturbation(state)
        if self.enable_D:
            helix1 += self._term_drift(state)
        if self.enable_E:
            helix1 += self._term_ethical_gradient(state)
        if self.enable_V:
            helix1 += self._term_velocity(state)
        if self.enable_W:
            helix1 += self._term_wave(state, t)
        if self.enable_R3:
            helix1 += self._term_resonance(state)
        if self.enable_An:
            helix1 += self._term_annealing(state)
        if self.enable_Lambda:
            helix1 += self._term_lyapunov_correction(state)
        if self.enable_Theta:
            helix1 += self._term_threshold(state)
        if self.enable_Phi:
            helix1 += self._term_phi_scaling(state)
        if self.enable_Z:
            helix1 += self._term_zero_mean(state)
        if self.enable_Hq:
            helix1 += self._term_hamiltonian(state)
        if self.enable_VQE:
            helix1 += self._term_vqe(state)
        if self.enable_QBM:
            helix1 += self._term_qbm(state)
        if self.enable_Attn:
            helix1 += self._term_attention(state)
        if self.enable_Fractal:
            helix1 += self._term_fractal(state)
        if self.enable_Symmetry:
            helix1 += self._term_symmetry(state)
        if self.enable_Information:
            helix1 += self._term_information(state)
        if self.enable_Relativistic:
            helix1 += self._term_relativistic(state)
        if self.enable_Alignment:
            helix1 += self._term_alignment(state)
        if self.enable_Omega:
            helix1 += self._term_omega_singularity(state)
        if self.enable_Noise:
            helix1 += self._term_time_noise(state, t)

        # Helix 2: Ethical Verification Strand
        helix2 = np.zeros_like(state)

        # Purity invariant (α𝐇)
        purity = self._compute_purity(state)
        helix2 += self.alpha * purity * 0.1

        # Lyapunov term (ℓ𝐋)
        lyapunov_grad = self._term_lyapunov_correction(state)
        helix2 += self.ell * lyapunov_grad

        # σ_quadratic enforcement
        sigma = calculate_sigma_quadratic(helix1, self.ethical_matrix)
        if sigma < SIGMA_QUADRATIC_THRESHOLD:
            # Trigger correction
            _, helix1 = enforce_sigma_quadratic_threshold(helix1, self.ethical_matrix)

        # Boundedness (∞_b)
        if self.enable_inf_b:
            bound = 10.0 * PHI_CUBED
            helix1 = np.clip(helix1, -bound, bound)

        # Multiplicative coupling: Helix_1 × (1 + normalized_Helix_2)
        helix2_norm = np.linalg.norm(helix2) / (np.linalg.norm(state) + 1e-8)
        state_next = helix1 * (1 + helix2_norm * 0.1)

        # Decrease temperature for annealing
        self.temperature *= 0.99

        return state_next

    def converge(
        self,
        initial_state: Optional[npt.NDArray] = None,
        max_steps: int = 100,
        tolerance: float = 1e-4,
    ) -> Tuple[npt.NDArray, List[float]]:
        """
        Iteratively converge to stable state with Lyapunov monitoring.

        Args:
            initial_state: Starting state (default: random)
            max_steps: Maximum iteration steps
            tolerance: Convergence threshold for state change

        Returns:
            (final_state, convergence_history)
            convergence_history: List of Lyapunov values over time
        """
        if initial_state is None:
            state = np.random.randn(self.state_dim) * 0.1 * PHI_CUBED
        else:
            state = initial_state.copy()

        history = []

        for t in range(max_steps):
            state_prev = state.copy()
            state = self.step(state, t)

            # Lyapunov stability monitoring
            V = lyapunov_function(state, self.target_state)
            history.append(V)

            # Check for instability
            V_dot = lyapunov_derivative(V)
            if V_dot > 0 and t > 5:  # Instability detected
                state = state_prev  # Rollback
                break

            # Convergence check
            if np.linalg.norm(state - state_prev) < tolerance:
                break

        return state, history


if __name__ == "__main__":
    # Configure logging for demo
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    logger.info("=" * 70)
    logger.info("Ava Guardian ♱ (AG♱) - Double-Helix Evolution Engine Demo")
    logger.info("=" * 70)

    # Create engine with default configuration
    engine = AvaEquationEngine(state_dim=50, random_seed=42)

    logger.info("\nEngine Configuration:")
    logger.info(f"  State dimension: {engine.state_dim}")
    logger.info(f"  Target state norm: {np.linalg.norm(engine.target_state):.4f}")
    logger.info(
        f"  Ethical matrix eigenvalues: [{np.min(np.linalg.eigvals(engine.ethical_matrix).real):.2f}, "
        f"{np.max(np.linalg.eigvals(engine.ethical_matrix).real):.2f}]"
    )

    # Run convergence
    logger.info("\nRunning Double-Helix evolution...")
    initial_state = np.random.randn(50) * 0.5
    final_state, history = engine.converge(initial_state, max_steps=50)

    logger.info("\nConvergence Results:")
    logger.info(f"  Initial Lyapunov V(x₀): {history[0]:.6f}")
    logger.info(f"  Final Lyapunov V(xₙ):   {history[-1]:.6f}")
    logger.info(f"  Convergence steps: {len(history)}")
    logger.info(f"  Final state norm: {np.linalg.norm(final_state):.6f}")
    logger.info(f"  Target state norm: {np.linalg.norm(engine.target_state):.6f}")
    logger.info(f"  Distance to target: {np.linalg.norm(final_state - engine.target_state):.6f}")

    # Verify σ_quadratic
    sigma = calculate_sigma_quadratic(final_state, engine.ethical_matrix)
    logger.info("\nEthical Constraints:")
    logger.info(f"  σ_quadratic: {sigma:.6f}")
    logger.info(
        f"  {'✓' if sigma >= SIGMA_QUADRATIC_THRESHOLD else '✗'} Threshold (≥ 0.96): "
        f"{sigma >= SIGMA_QUADRATIC_THRESHOLD}"
    )

    logger.info("\n" + "=" * 70)
    logger.info("✓ Double-Helix Evolution Engine operational")
    logger.info("=" * 70)
