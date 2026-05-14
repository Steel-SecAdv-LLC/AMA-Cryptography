# `# nosec` disposition audit

Scope audited: `ama_cryptography/`, `tools/`, `benchmarks/`, `examples/`, plus the single additional repo-wide `# nosec` occurrence in `tests/` to satisfy the one-row-per-occurrence acceptance criterion.

No `# nosec` suppressions were removed while preparing this table. Remediation is intentionally deferred until this disposition is reviewed, then each affected file can be landed in its own PR.

| Location | Classification | Rationale | Action taken |
|---|---|---|---|
| ama_cryptography/_finalizer_health.py:57 | JUSTIFIED | B110/S110 broad exception suppression is constrained to finalizer-health shutdown handling; the module records observable finalizer state before the shutdown-only fallback can fail. | Kept suppression pending table review; no code change. |
| ama_cryptography/_numeric.py:863 | JUSTIFIED | B311 is a false positive for this numpy-compatible numeric shim: stdlib Random is used only for reproducible non-cryptographic math samples, not keys, nonces, or secrets. | Kept suppression pending table review; no code change. |
| ama_cryptography/key_management.py:1014 | JUSTIFIED | B107 is a false positive: default is None, and any HSM PIN is caller-provided at runtime rather than hardcoded. | Kept suppression pending table review; no code change. |
| ama_cryptography/key_management.py:1378 | REMOVABLE | B106 flags a demo-only hardcoded password in a __main__ example block; the demo can derive/read an ephemeral value without embedding a password literal. | Removed the hardcoded demo password; the demo now generates an ephemeral URL-safe password at runtime. |
| ama_cryptography/legacy_compat.py:52 | JUSTIFIED | B404 import is isolated to the permitted legacy compatibility module and only supports trusted external tools for RFC 3161/OpenSSL compatibility. | Kept suppression pending table review; no code change. |
| ama_cryptography/legacy_compat.py:471 | JUSTIFIED | B603 is constrained to a hardcoded argv list, shell=False default, stdin-only data, capture_output, and a timeout for openssl ts -query. | Kept suppression pending table review; no code change. |
| ama_cryptography/legacy_compat.py:487 | DEFECT | B310 was suppressed while allowing http URLs; the comment said HTTPS was enforced, but the code accepted both http and https. | Fixed by enforcing HTTPS-only TSA URLs and removing the B310 suppression while preserving the Optional[bytes] return contract for invalid schemes. |
| ama_cryptography/legacy_compat.py:553 | JUSTIFIED | B603 is constrained to a hardcoded argv list plus validated temp-file paths, shell=False default, capture_output, and a timeout for openssl ts -verify. | Kept suppression pending table review; no code change. |
| tests/conftest.py:134 | JUSTIFIED | B105 is a test fixture password used only inside the test suite, not a production secret or shipped runtime credential. | Kept suppression pending table review; no code change. |
