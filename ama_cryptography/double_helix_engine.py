#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography - Double-Helix Evolution Engine
=====================================================

**IMPORTANT: NON-CRYPTOGRAPHIC MODULE**

This module provides mathematical modeling and analytical utilities for the
AMA Cryptography system. It is NOT a cryptographic primitive and should NOT be
relied upon for security guarantees. The Double-Helix Evolution Engine
implements:

- Mathematical state evolution and convergence algorithms
- Analytical modeling inspired by biological and physical systems
- Optimization and constraint satisfaction frameworks

These utilities support system analytics and modeling but do not provide
cryptographic protection. For cryptographic operations, use the dedicated
modules: pqc_backends.py and crypto_api.py.

Implements 18+ AMA Equation variants with Double-Helix Evolution Architecture.

Fundamental Equation:
    ℵ(𝔄_{t+1}) = Helix_1(𝔄_t) ⊗ Helix_2(𝔄_t)

Where:
    Helix_1: Discovery/Exploration Strand (18+ quantum/chaos terms)
    Helix_2: Ethical Verification Strand (σ_quadratic ≥ 0.96 enforcement)

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-17
Version: 5.0.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import logging
import math
from typing import Dict, List, Optional, Tuple

from ama_cryptography._numeric import (
    Vec,
    abs_,
    asvec,
    clip,
    concatenate,
    cos,
    dot,
    eigvals,
    fft,
    fill_diagonal,
    ifft,
    linspace,
    log,
    maximum,
    mean,
    norm,
    ones,
    random,
    real,
    sign,
    sin,
    sum_,
    zeros,
    zeros_like,
)
from ama_cryptography.equations import (
    LAMBDA_DECAY,
    PHI,
    PHI_CUBED,
    SIGMA_QUADRATIC_THRESHOLD,
    calculate_sigma_quadratic,
    enforce_sigma_quadratic_threshold,
    initialize_ethical_matrix,
    lyapunov_function,
)

# Configure module logger
logger = logging.getLogger(__name__)

__version__ = "5.0.0"
__author__ = "Andrew E. A., Steel Security Advisors LLC"


class AmaEquationEngine:
    """
    AMA Equation Engine with Double-Helix Evolution Architecture.

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
        config: Optional[Dict[str, float]] = None,
        random_seed: Optional[int] = None,
    ) -> None:
        """
        Initialize AMA Equation Engine.

        Args:
            state_dim: State vector dimension (default: int(50 * φ³) ≈ 212)
            config: Configuration dictionary with term weights and flags
            random_seed: Random seed for reproducibility
        """
        if random_seed is not None:
            random.seed(random_seed)

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
        self.velocity = zeros(self.state_dim)
        self.target_state = ones(self.state_dim) * 1.3
        self.temperature = 1.0  # For simulated annealing

    def _initialize_ethical_matrix(self) -> None:
        """Initialize positive-definite ethical constraint matrix."""
        self.ethical_matrix = initialize_ethical_matrix(self.state_dim)

    # ========================================================================
    # INPUT COERCION
    # ========================================================================

    def _coerce_state(self, state: object, argument: str) -> Vec:
        """Normalise a caller-supplied state to a :class:`Vec` of the right size.

        This engine's arithmetic runs on ``ama_cryptography._numeric``, but its
        callers do not all have a ``Vec`` in hand — the shipped
        ``examples/python/complete_demo.py`` builds its initial state with
        ``numpy.random.randn``, and so will anyone who already has an array.

        Mixing the two types used to fail deep inside numpy rather than here.
        ``Mat`` had no ``__len__``, so ``numpy`` treated ``self.ethical_matrix``
        as a 0-dimensional object scalar and ``self.ethical_matrix @ state``
        raised::

            ValueError: matmul: Input operand 0 does not have enough
            dimensions (has 0, gufunc core with signature
            (n?,k),(k,m?)->(n?,m?) requires 1)

        — from ``_term_ethical_gradient``, four frames below the public call,
        naming neither the engine, the argument, nor numpy's involvement. The
        conversion therefore happens once, at the boundary, where the error can
        say which argument was wrong and why.

        This is analytics, not cryptography (see the module docstring): the
        right property here is that the numbers are correct and the failure
        mode is legible, and no constant-time or secret-handling constraint
        applies to any of it.

        Args:
            state: ``Vec``, ``numpy.ndarray``, list, tuple, or any 1-D
                array-like of real numbers.
            argument: Parameter name to quote in an error message.

        Returns:
            A ``Vec`` of length ``self.state_dim``.  A ``Vec`` input is passed
            through without copying — no method on this class mutates the state
            it is given — so the conversion costs nothing on the internal path.

        Raises:
            TypeError: ``state`` is not array-like, or holds non-numbers.
            ValueError: ``state`` is not 1-D, or its length is not
                ``state_dim``.
        """
        try:
            vec = asvec(state, copy=False)
        except (TypeError, ValueError) as exc:
            raise type(exc)(f"{argument}: {exc}") from None
        if len(vec) != self.state_dim:
            raise ValueError(
                f"{argument}: state has {len(vec)} elements but this engine "
                f"was built for state_dim={self.state_dim}. Construct the "
                f"engine with AmaEquationEngine(state_dim={len(vec)}) or "
                f"resize the state."
            )
        return vec

    def _initialize_vqe_params(self) -> None:
        """Initialize Variational Quantum Eigensolver parameters."""
        # Simple parameterized quantum circuit simulation
        self.vqe_params = random.randn(self.state_dim) * (0.1 * PHI_CUBED)
        self.vqe_hamiltonian = random.randn(self.state_dim, self.state_dim) * 0.01
        self.vqe_hamiltonian = (self.vqe_hamiltonian + self.vqe_hamiltonian.T) * 0.5  # Symmetric

    def _initialize_qbm_matrix(self) -> None:
        """Initialize Quantum Boltzmann Machine coupling matrix."""
        # Symmetric coupling matrix J
        J = random.randn(self.state_dim, self.state_dim) * (0.05 * PHI_CUBED)
        self.qbm_matrix = (J + J.T) * 0.5
        fill_diagonal(self.qbm_matrix, 0)  # No self-coupling

    def _initialize_attention(self) -> None:
        """Initialize self-attention mechanism weights."""
        # Simplified attention: Query, Key, Value projections
        scale = 0.1 * PHI_CUBED / math.sqrt(self.state_dim)
        self.attn_query = random.randn(self.state_dim, self.state_dim) * scale
        self.attn_key = random.randn(self.state_dim, self.state_dim) * scale
        self.attn_value = random.randn(self.state_dim, self.state_dim) * scale

    # ========================================================================
    # HELIX 1: DISCOVERY/EXPLORATION STRAND TERMS
    # ========================================================================

    def _term_quantum(self, state: Vec) -> Vec:
        """β𝐐: Quantum-inspired noise."""
        return random.randn(self.state_dim) * self.beta

    def _term_perturbation(self, state: Vec) -> Vec:
        """γ𝐏: Exploration perturbation."""
        return random.randn(self.state_dim) * self.gamma

    def _term_drift(self, state: Vec) -> Vec:
        """δ𝐃: Directional evolution toward target."""
        direction = self.target_state - state
        n = norm(direction)
        if n > 0:
            direction = direction * (1.0 / n)
        return direction * self.delta

    def _term_ethical_gradient(self, state: Vec) -> Vec:
        """ε𝐄: Ethical gradient from constraint matrix."""
        grad = self.ethical_matrix @ state
        return grad * (self.epsilon / (norm(grad) + 1e-8))

    def _term_velocity(self, state: Vec) -> Vec:
        """ν𝐕: Momentum from previous step."""
        # Update velocity with damping
        self.velocity = self.velocity * 0.9 + (state - self.target_state) * 0.1
        return self.velocity * self.nu

    def _term_wave(self, state: Vec, t: int) -> Vec:
        """ω𝐖: Oscillatory wave component."""
        frequencies = linspace(0.1, 1.0, self.state_dim)
        waves = sin(frequencies * (2 * math.pi * t / 10.0))
        return waves * (self.omega * 0.1)

    def _term_resonance(self, state: Vec) -> Vec:
        """𝐑₃: FFT-based resonance patterns."""
        # Simple FFT resonance
        f = fft(state)
        # Amplify low frequencies
        quarter = len(f) // 4
        for i in range(quarter):
            f._data[i] = f._data[i] * 1.5
        resonance = real(ifft(f))
        return resonance * 0.1

    def _term_annealing(self, state: Vec) -> Vec:
        """κ𝐀_n: Simulated annealing factor."""
        # Temperature decreases over time
        annealing_factor = math.exp(-self.temperature)
        return random.randn(self.state_dim) * (self.kappa * annealing_factor * 0.1)

    def _term_lyapunov_correction(self, state: Vec) -> Vec:
        """λ𝚲: Lyapunov stability correction."""
        V = lyapunov_function(state, self.target_state)
        if V > 0:
            correction = (state - self.target_state) * (-1.0 / V)
            return correction * (self.lambda_coeff * 0.1)
        return zeros_like(state)

    def _term_threshold(self, state: Vec) -> Vec:
        """θ𝚯: Activation function (ReLU)."""
        return maximum(0, state) * (self.theta * 0.1)

    def _term_phi_scaling(self, state: Vec) -> Vec:
        """φ𝚽: Golden ratio scaling."""
        return state * ((self.phi_scale - 1.0) * 0.1)

    def _term_zero_mean(self, state: Vec) -> Vec:
        """ζ𝐙: Zero-mean normalization."""
        m = mean(state)
        return (state - m) * (self.zeta * 0.1)

    def _term_hamiltonian(self, state: Vec) -> Vec:
        """ℏ𝐡_q: Quantum Hamiltonian energy operator."""
        return (self.vqe_hamiltonian @ state) * (self.hbar * 0.1)

    def _term_vqe(self, state: Vec) -> Vec:
        """𝐕𝐐𝐄: Variational Quantum Eigensolver update."""
        # Simplified VQE: rotate state by parameterized angles
        rotated = state * cos(self.vqe_params) + sin(self.vqe_params)
        return (rotated - state) * 0.1

    def _term_qbm(self, state: Vec) -> Vec:
        """𝐐𝐁𝐌: Quantum Boltzmann Machine sampling."""
        # Energy-based sampling
        energy = -0.5 * (state @ (self.qbm_matrix @ state))
        # Clip to prevent overflow in exp
        energy_scaled = max(-700.0, min(700.0, -energy / (self.temperature + 0.1)))
        prob = 1.0 / (1.0 + math.exp(energy_scaled))
        sample = random.binomial(1, min(0.9, max(0.1, prob)), size=self.state_dim)
        return (sample * 2 - 1.0) * 0.05  # map {0,1} -> {-1,1} and apply 0.05 scale factor

    def _term_attention(self, state: Vec) -> Vec:
        """𝐀𝐭𝐭𝐧: Self-attention mechanism."""
        query = self.attn_query @ state
        key = self.attn_key @ state
        value = self.attn_value @ state

        # Attention weights
        attention_scores = dot(query, key) / math.sqrt(self.state_dim)
        # Clip to prevent overflow in exp
        attention_scores_clipped = max(-700.0, min(700.0, -attention_scores))
        attention_weights = 1.0 / (1.0 + math.exp(attention_scores_clipped))  # Sigmoid

        # Weighted value
        attended = value * attention_weights
        return attended * 0.1

    def _term_fractal(self, state: Vec) -> Vec:
        """𝐅: Fractal self-similar patterns."""
        # Simple fractal: subdivide and repeat pattern
        half = len(state) // 2
        if half > 0:
            pattern = concatenate([state[:half], state[:half]])
            if len(pattern) < len(state):
                pattern = concatenate([pattern, state[: len(state) - len(pattern)]])
            return (pattern - state) * 0.05
        return zeros_like(state)

    def _term_symmetry(self, state: Vec) -> Vec:
        """𝐒: Symmetry constraint projection."""
        # Mirror symmetry
        mirrored = Vec._wrap(state._data[::-1])
        symmetric = (state + mirrored) * 0.5
        return (symmetric - state) * 0.05

    def _term_information(self, state: Vec) -> Vec:
        """𝐈: Information entropy gradient."""
        # Entropy-based push toward uniform distribution
        abs_state = abs_(state)
        total = sum_(abs_state) + 1e-8
        probs = abs_state * (1.0 / total)
        entropy: float = -sum_(probs * log(probs + 1e-8))
        max_entropy = math.log(len(state))
        info_gradient = sign(state - mean(state)) * (max_entropy - entropy)
        return info_gradient * 0.05

    def _term_relativistic(self, state: Vec) -> Vec:
        """𝐑𝐞𝐥: Relativistic Lorentz-like correction."""
        # Simple velocity-dependent correction
        velocity_norm = norm(self.velocity) + 1e-8
        gamma = 1.0 / math.sqrt(1.0 + (velocity_norm / 10.0) ** 2)  # Lorentz factor
        return state * (0.05 * (gamma - 1.0))

    def _term_alignment(self, state: Vec) -> Vec:
        """ξ𝐀𝐥: Ethical alignment vector."""
        # Align with predefined ethical direction
        ethical_direction = self.target_state * (1.0 / (norm(self.target_state) + 1e-8))
        alignment = dot(state, ethical_direction)
        return ethical_direction * (self.xi * alignment * 0.1)

    def _term_omega_singularity(self, state: Vec) -> Vec:
        """Ω: Omega singularity score."""
        # Convergence metric
        distance = norm(state - self.target_state)
        omega_score = 1.0 / (1.0 + distance)
        return (self.target_state - state) * (0.05 * omega_score)

    def _term_time_noise(self, state: Vec, t: int) -> Vec:
        """η_t: Time-varying noise."""
        # Decreasing noise over time
        noise_scale = math.exp(-t / 50.0)
        return random.randn(self.state_dim) * (noise_scale * 0.1)

    # ========================================================================
    # HELIX 2: ETHICAL VERIFICATION STRAND
    # ========================================================================

    def _compute_purity(self, state: Vec) -> Vec:
        """α𝐇: Ethical purity invariant."""
        # Purity as normalized state
        n = norm(state)
        if n > 0:
            return state * (1.0 / n)
        return state

    # ========================================================================
    # DOUBLE-HELIX EVOLUTION STEP
    # ========================================================================

    def step(self, state: object, t: int = 0) -> Vec:  # fmt: skip  # noqa: C901 -- McCabe complexity unavoidable in double-helix evolution step (DHE-001)
        """
        Execute one Double-Helix evolution step.

        ℵ(𝔄_{t+1}) = Helix_1(𝔄_t) ⊗ Helix_2(𝔄_t)

        Args:
            state: Current state 𝔄_t.  A ``Vec``, a ``numpy.ndarray``, or any
                1-D array-like of ``state_dim`` real numbers; converted once at
                entry by :meth:`_coerce_state`.
            t: Time step

        Returns:
            Updated state 𝔄_{t+1}, always a ``Vec`` regardless of the input
            type.  ``numpy.asarray(result)`` converts it back to an ndarray.

        Raises:
            TypeError: ``state`` is not array-like, or holds non-numbers.
            ValueError: ``state`` is not 1-D, or its length is not
                ``state_dim``.
        """
        vec: Vec = self._coerce_state(state, "step(state=...)")

        # Helix 1: Discovery/Exploration Strand
        helix1 = vec.copy()

        if self.enable_Q:
            helix1 += self._term_quantum(vec)
        if self.enable_P:
            helix1 += self._term_perturbation(vec)
        if self.enable_D:
            helix1 += self._term_drift(vec)
        if self.enable_E:
            helix1 += self._term_ethical_gradient(vec)
        if self.enable_V:
            helix1 += self._term_velocity(vec)
        if self.enable_W:
            helix1 += self._term_wave(vec, t)
        if self.enable_R3:
            helix1 += self._term_resonance(vec)
        if self.enable_An:
            helix1 += self._term_annealing(vec)
        if self.enable_Lambda:
            helix1 += self._term_lyapunov_correction(vec)
        if self.enable_Theta:
            helix1 += self._term_threshold(vec)
        if self.enable_Phi:
            helix1 += self._term_phi_scaling(vec)
        if self.enable_Z:
            helix1 += self._term_zero_mean(vec)
        if self.enable_Hq:
            helix1 += self._term_hamiltonian(vec)
        if self.enable_VQE:
            helix1 += self._term_vqe(vec)
        if self.enable_QBM:
            helix1 += self._term_qbm(vec)
        if self.enable_Attn:
            helix1 += self._term_attention(vec)
        if self.enable_Fractal:
            helix1 += self._term_fractal(vec)
        if self.enable_Symmetry:
            helix1 += self._term_symmetry(vec)
        if self.enable_Information:
            helix1 += self._term_information(vec)
        if self.enable_Relativistic:
            helix1 += self._term_relativistic(vec)
        if self.enable_Alignment:
            helix1 += self._term_alignment(vec)
        if self.enable_Omega:
            helix1 += self._term_omega_singularity(vec)
        if self.enable_Noise:
            helix1 += self._term_time_noise(vec, t)

        # Helix 2: Ethical Verification Strand
        helix2 = zeros_like(vec)

        # Purity invariant (α𝐇)
        purity = self._compute_purity(vec)
        helix2 += purity * (self.alpha * 0.1)

        # Lyapunov term (ℓ𝐋)
        lyapunov_grad = self._term_lyapunov_correction(vec)
        helix2 += lyapunov_grad * self.ell

        # σ_quadratic enforcement
        sigma = calculate_sigma_quadratic(helix1, self.ethical_matrix)
        if sigma < SIGMA_QUADRATIC_THRESHOLD:
            # Trigger correction
            _, helix1 = enforce_sigma_quadratic_threshold(helix1, self.ethical_matrix)

        # Boundedness (∞_b)
        if self.enable_inf_b:
            bound = 10.0 * PHI_CUBED
            helix1 = clip(helix1, -bound, bound)

        # Multiplicative coupling: Helix_1 × (1 + normalized_Helix_2)
        helix2_norm = norm(helix2) / (norm(vec) + 1e-8)
        state_next = helix1 * (1 + helix2_norm * 0.1)

        # Decrease temperature for annealing
        self.temperature *= 0.99

        return state_next

    def converge(
        self,
        initial_state: object = None,
        max_steps: int = 100,
        tolerance: float = 1e-4,
    ) -> Tuple[Vec, List[float]]:
        """
        Iteratively converge to stable state with Lyapunov monitoring.

        Args:
            initial_state: Starting state.  Accepts a ``Vec``, a
                ``numpy.ndarray``, or any 1-D array-like of ``state_dim`` real
                numbers — a list, a tuple, or another library's array type.
                ``None`` draws a random start.  Whatever is passed is copied,
                so the caller's object is never modified.
            max_steps: Maximum iteration steps.  Must be >= 0; 0 returns the
                initial state with an empty history.
            tolerance: Convergence threshold for state change.  Must be >= 0.

        Returns:
            ``(final_state, convergence_history)``.

            ``final_state`` is always a ``Vec``, regardless of what was passed
            in — the engine's arithmetic is defined over
            ``ama_cryptography._numeric``, and returning the input's type would
            mean re-importing whichever library it came from.  Convert back
            with ``numpy.asarray(final_state)``, or read
            ``final_state.tolist()``.

            ``convergence_history`` is the list of Lyapunov values, one per
            *retained* step, so ``convergence_history[-1]`` is always
            ``V(final_state)``.

        Stopping conditions, in the order they are tested each step:

        1. **Instability** — the Lyapunov value rose relative to the previous
           step, after a five-step warm-up. The step is rolled back and its
           value dropped from the history, so the returned state is the last
           one that did not increase V.
        2. **Convergence** — the state moved less than ``tolerance``.
        3. ``max_steps`` steps have run.

        Note that with the default GA-optimised weights the exploration terms
        dominate and V *rises*; condition 1 is the one that normally fires, and
        a rising history is the engine reporting that this configuration does
        not converge rather than a fault in the caller's input.

        Raises:
            TypeError: ``initial_state`` is not array-like, or holds
                non-numbers.
            ValueError: ``initial_state`` is not 1-D, its length is not
                ``state_dim``, or ``max_steps`` / ``tolerance`` is negative.

        Example:
            >>> engine = AmaEquationEngine(state_dim=8, random_seed=42)
            >>> final, history = engine.converge([0.1] * 8, max_steps=5)
            >>> len(final) == 8 and len(history) <= 5
            True

            The same call with numpy, which is what
            ``examples/python/complete_demo.py`` does::

                import numpy as np
                final, history = engine.converge(np.random.randn(8) * 0.5)
                final_array = np.asarray(final)

        .. versionchanged:: 4.0
           ``numpy.ndarray`` and other 1-D array-likes are accepted. Through
           3.x only a ``Vec`` worked: anything else reached
           ``self.ethical_matrix @ state`` as a mixed-type ``matmul`` and
           raised ``ValueError: matmul: Input operand 0 does not have enough
           dimensions`` from inside numpy, four frames below this call.

        .. versionchanged:: 4.0
           The instability rollback now fires. Through 3.x it tested
           ``lyapunov_derivative(V) > 0``, which is ``-2λV > 0`` and therefore
           false for every reachable value of ``V``, so the branch was dead and
           ``converge`` ran to ``max_steps`` or to the boundedness clip in
           every case. Callers relying on the old behaviour — a state
           saturated at ``±10·φ³`` reported as converged — should pass
           ``max_steps`` explicitly and read the history.
        """
        if max_steps < 0:
            raise ValueError(f"max_steps must be >= 0, got {max_steps}")
        if tolerance < 0:
            raise ValueError(f"tolerance must be >= 0, got {tolerance}")

        if initial_state is None:
            state = random.randn(self.state_dim) * (0.1 * PHI_CUBED)
        else:
            state = self._coerce_state(initial_state, "converge(initial_state=...)").copy()

        history: List[float] = []
        V_previous: Optional[float] = None

        for t in range(max_steps):
            state_prev = state.copy()
            state = self.step(state, t)

            # Lyapunov stability monitoring
            V = lyapunov_function(state, self.target_state)
            history.append(V)

            # Instability: V̇ > 0, measured on the trajectory this loop is
            # actually walking.
            #
            # This test used to read `lyapunov_derivative(V) > 0`, and it could
            # never be true. `lyapunov_derivative` returns the *analytic model*
            # V̇ = -2λV of the reference exponential decay — with λ = 0.18 > 0
            # and V = ||x - x*||² >= 0 by construction, its value is <= 0 for
            # every input the function can be given. The branch, its rollback
            # and its comment were therefore unreachable from the day they were
            # written, and no test caught it because the only test that named
            # the mechanism asserted merely that `converge` returns something.
            #
            # V̇ on a discrete trajectory is the step-to-step difference, so
            # that is what is compared. `lyapunov_derivative` keeps its
            # analytic role in `lyapunov_stability_proof` / `convergence_time`,
            # where a model value is what is wanted; it was the wrong
            # instrument here, not a wrong function.
            #
            # The `t > 5` warm-up is unchanged: the first steps are dominated
            # by the exploration terms, and a transient rise there is expected
            # rather than a failure to converge.
            if V_previous is not None and t > 5 and V > V_previous:
                state = state_prev  # Rollback to the last non-increasing state
                # ...and drop the rejected value, so `history[-1]` is the
                # Lyapunov value *of the state being returned*. With the branch
                # dead this mismatch could not be observed; with it live, a
                # caller plotting `history` against `final_state` would have
                # been reading one step past the answer.
                history.pop()
                break
            V_previous = V

            # Convergence check
            if norm(state - state_prev) < tolerance:
                break

        return state, history


if __name__ == "__main__":
    # Configure logging for demo
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    logger.info("=" * 70)
    logger.info("AMA Cryptography - Double-Helix Evolution Engine Demo")
    logger.info("=" * 70)

    # Create engine with default configuration
    engine = AmaEquationEngine(state_dim=50, random_seed=42)

    logger.info("\nEngine Configuration:")
    logger.info(f"  State dimension: {engine.state_dim}")
    logger.info(f"  Target state norm: {norm(engine.target_state):.4f}")
    eigs = eigvals(engine.ethical_matrix)
    logger.info(f"  Ethical matrix eigenvalues: [{min(eigs):.2f}, {max(eigs):.2f}]")

    # Run convergence
    logger.info("\nRunning Double-Helix evolution...")
    initial_state = random.randn(50) * 0.5
    final_state, history = engine.converge(initial_state, max_steps=50)

    logger.info("\nConvergence Results:")
    logger.info(f"  Initial Lyapunov V(x0): {history[0]:.6f}")
    logger.info(f"  Final Lyapunov V(xn):   {history[-1]:.6f}")
    logger.info(f"  Convergence steps: {len(history)}")
    logger.info(f"  Final state norm: {norm(final_state):.6f}")
    logger.info(f"  Target state norm: {norm(engine.target_state):.6f}")
    logger.info(f"  Distance to target: {norm(final_state - engine.target_state):.6f}")

    # Verify σ_quadratic
    sigma = calculate_sigma_quadratic(final_state, engine.ethical_matrix)
    logger.info("\nEthical Constraints:")
    logger.info(f"  sigma_quadratic: {sigma:.6f}")
    logger.info(
        f"  {'[OK]' if sigma >= SIGMA_QUADRATIC_THRESHOLD else '[FAIL]'} Threshold (>= 0.96): "
        f"{sigma >= SIGMA_QUADRATIC_THRESHOLD}"
    )

    logger.info("\n" + "=" * 70)
    logger.info("[OK] Double-Helix Evolution Engine operational")
    logger.info("=" * 70)
