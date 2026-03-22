AMA Cryptography Documentation
============================

Welcome to the AMA Cryptography documentation. This system provides quantum-resistant
cryptographic protection with a multi-language architecture optimized for both
security and performance.

.. note::

   Comprehensive documentation is available in the repository root as Markdown files:

   * `README.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/README.md>`_ - Quick start and overview
   * `ARCHITECTURE.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/ARCHITECTURE.md>`_ - System architecture
   * `IMPLEMENTATION_GUIDE.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/IMPLEMENTATION_GUIDE.md>`_ - Deployment guide
   * `SECURITY.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/SECURITY.md>`_ - Security analysis
   * `CRYPTOGRAPHY.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/CRYPTOGRAPHY.md>`_ - Cryptographic details
   * `CONTRIBUTING.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/CONTRIBUTING.md>`_ - Contribution guidelines

Quick Links
-----------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Overview
--------

AMA Cryptography is a secure post-quantum cryptographic (PQC)
system featuring:

- **Multi-Algorithm Support**: ML-DSA-65, Kyber-1024, SPHINCS+-256f
- **Hybrid Architecture**: C core with Python/Cython optimizations
- **Constant-Time Operations**: Timing-attack resistant implementations
- **High Performance**: 18-37x speedup via Cython mathematical engine (vs pure Python baseline)
- **Cross-Platform**: Linux, macOS, Windows, ARM support
- **Security Hardened**: HSM/TPM integration, key rotation, TLS support

Key Features
------------

Mathematical Foundation
~~~~~~~~~~~~~~~~~~~~~~~

- 5 proven mathematical frameworks with machine precision
- Lyapunov stability theory (exponential convergence O(e^{-0.18t}))
- Golden ratio harmonics (φ³-amplification)
- Double-helix evolution engine (18+ equation variants)
- Quadratic form constraints (σ_quadratic ≥ 0.96)

Security
~~~~~~~~

- NIST PQC Round 3 algorithms
- Constant-time cryptographic operations
- Memory scrubbing for sensitive data
- Side-channel resistance
- Timing attack protection

Performance
~~~~~~~~~~~

- Cython mathematical engine (18-37x vs pure Python mathematical baseline)
- AVX2/SIMD optimizations
- NTT-based polynomial multiplication (O(n log n))
- Cache-friendly memory layouts
- Link-time optimization

Getting Started
---------------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   # Install from source
   git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
   cd AMA-Cryptography
   make all
   sudo make install

   # Or with pip (when available)
   pip install ama-cryptography

Quick Example
~~~~~~~~~~~~~

.. code-block:: python

   from ama_cryptography import AmaEquationEngine
   import numpy as np

   # Initialize engine
   engine = AmaEquationEngine(state_dim=100, random_seed=42)

   # Run evolution
   initial_state = np.random.randn(100) * 0.5
   final_state, history = engine.converge(initial_state, max_steps=100)

   print(f"Converged in {len(history)} steps")
   print(f"Final Lyapunov value: {history[-1]:.6f}")

C API Example
~~~~~~~~~~~~~

.. code-block:: c

   #include "ama_cryptography.h"

   int main(void) {
       ama_context_t* ctx = ama_context_init(AMA_ALG_ML_DSA_65);

       uint8_t public_key[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
       uint8_t secret_key[AMA_ML_DSA_65_SECRET_KEY_BYTES];

       ama_error_t err = ama_keypair_generate(
           ctx, public_key, sizeof(public_key),
           secret_key, sizeof(secret_key)
       );

       ama_secure_memzero(secret_key, sizeof(secret_key));
       ama_context_free(ctx);
       return 0;
   }

License
-------

Copyright 2025-2026 Steel Security Advisors LLC

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

Contact
-------

- Email: steel.sa.llc@gmail.com
- GitHub: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography
- Issues: https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
