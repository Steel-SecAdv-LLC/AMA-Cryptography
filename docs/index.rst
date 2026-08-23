AMA Cryptography Documentation
==============================

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
   * `docs/compliance/ACVP_SELF_ATTESTATION.md <https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/blob/main/docs/compliance/ACVP_SELF_ATTESTATION.md>`_ - NIST ACVP self-attestation (NOT CAVP)

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/index

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

- NIST-standardized PQC algorithms (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA)
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

Install from a git tag — the primary channel, reproducible and index-free:

.. note::

   ``v5.0.0`` **is not tagged yet.**  ``CHANGELOG.md`` heads its section
   ``[5.0.0] - Unreleased``, and the newest published tag is ``v4.0.0``.  The
   command below resolves only for tags that exist, so until the release is
   tagged, substitute the newest published tag, ``v4.0.0``, or install from a
   source checkout as shown underneath.  (Written without the ``@`` on
   purpose: ``tools/check_version_consistency.py`` requires every ``@vX.Y.Z``
   git-tag pin in an ``.rst`` under ``docs/`` to name the canonical version,
   and a prose substitution spelled as a pin is indistinguishable from the
   stale-pin defect that gate exists to catch.)  ``README.md`` carries this
   same warning above its identical
   command; this page did not, which is how the two entry-point documents came
   to disagree about whether the release exists.

.. code-block:: bash

   pip install "git+https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git@v5.0.0"

Or build and install the C library from a source checkout:

.. code-block:: bash

   git clone https://github.com/Steel-SecAdv-LLC/AMA-Cryptography.git
   cd AMA-Cryptography
   make all
   sudo make install

.. warning::

   ``pip install ama-cryptography`` does **not** install this library. The
   project is not published on PyPI and the name is unregistered, so a package
   appearing under it is not ours. Use a git tag or a signed wheel from a
   GitHub Release — see the README section *Distribution Channels* for the
   verification steps.

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
