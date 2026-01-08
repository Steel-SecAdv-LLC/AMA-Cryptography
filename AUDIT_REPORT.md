# Ava Guardian ♱ – Repository Audit (Validity, Functionality, Usability, Capabilities)

**Date:** 2026-01-08  
**Scope:** Repository-level audit based on documentation and code inspection. No third-party audit was performed. Runtime tests were attempted but not executed because `pytest` is not installed in the current environment.

## Methodology
- Reviewed primary documentation (README, SECURITY_ANALYSIS, ARCHITECTURE, MONITORING, BENCHMARKS, IMPLEMENTATION_GUIDE).
- Reviewed key Python modules (`ava_guardian/crypto_api.py`, PQC backends, monitoring utilities).
- Executed `python -m pytest` (failed: missing dependency `pytest`).
- Focused on validity of claims, functional coverage, usability, and alignment between stated and actual capabilities.

## Findings

### Validity and Transparency
- Claims are largely standards-based (SHA3/HKDF/Ed25519/ML-DSA/Kyber/SPHINCS+) with clear self-disclosure that the project is **experimental and not externally audited**.
- PQC features rely on `liboqs-python`; without it, PQC calls are stubbed or fallback to non-constant-time pure Python implementations with warnings. This matches documented caveats.
- 3R monitoring is positioned as anomaly surfacing, **not** a guarantee against timing/side-channel attacks; documentation is consistent with implementation.

### Functionality
- Python API provides hybrid signature/KEM flows, key management, RFC3161 timestamping hooks, and monitoring integration. Algorithm selection is explicit; missing backends raise or warn.
- C/Cython layers exist for acceleration and constant-time primitives; some PQC code paths are gated behind `AVA_USE_LIBOQS` or marked experimental.
- Error handling is explicit via typed exceptions; secret material is flagged for cleanup best-effort.

### Usability
- Excellent narrative documentation and Makefile targets for build/lint/test; Docker images and platform notes included.
- Setup is non-trivial: requires liboqs, compiler toolchain, and optional OpenSSL for TSA. Users without `pytest`/dev deps will see failed tests (as observed).
- Default behavior is permissive: PQC falls back to slower/non-constant-time code unless `AVA_REQUIRE_CONSTANT_TIME` is set—users must opt in to stricter posture.

### Capabilities vs. Claims
- Core capabilities (hybrid signing/verification, PQC KEM/signatures, monitoring, key lifecycle) are present in code and aligned with documentation, subject to backend availability.
- Performance and security claims are backed by benchmarks and self-assessments; no independent verification is provided.
- Ethical binding and bio-inspired constructs are documented conceptual overlays; functional impact is limited to domain-separated HKDF/context handling.

## Risks and Gaps
- No independent cryptographic audit; AI-generated code may contain subtle side-channel or correctness issues.
- PQC availability is optional; environments without `liboqs` degrade to non-constant-time or stubbed behavior.
- Test suite cannot be confirmed in this environment (missing `pytest`); CI status should be consulted for actual coverage.

## Recommendations
1. Make `liboqs` + `pytest` installation explicit in quick-start steps for users who expect PQC features and test execution.
2. When PQC is requested but unavailable, raise an error instead of proceeding with a non-constant-time fallback.
3. Run CI/constant-time checks on target hardware; publish results or third-party review to strengthen validity.
4. Provide a minimal “sanity check” script that asserts backend availability and runs a sample hybrid sign/verify path.

## Conclusion
Ava Guardian presents a well-documented experimental PQC/hybrid cryptography framework with runtime monitoring and multi-language layers. Functionality matches claims within documented constraints, but production deployment still requires third-party audit, strict constant-time configuration, and verified PQC backends. Usability is strong for experienced practitioners. Dependency setup remains the primary barrier for new users.
