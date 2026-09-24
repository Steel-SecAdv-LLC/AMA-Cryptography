# Secure Memory

Documentation for the secure memory operations module (`ama_cryptography/secure_memory.py`), covering `SecureBuffer`, memory zeroing, memory locking, and constant-time comparisons.

---

## Overview

Cryptographic key material must be handled with care:
- **Zeroed** when no longer needed (prevent exposure via heap dumps, core files, swap)
- **Locked** in RAM (prevent exposure via swap/hibernate)
- **Compared** in constant time (prevent timing side-channel attacks)

The `secure_memory` module provides these capabilities using only the standard library, with optional acceleration via the AMA native C backend.

---

## `SecureBuffer`

A context manager for automatic, guaranteed memory zeroing:

<!-- example: python-run -->
```python
from ama_cryptography.secure_memory import SecureBuffer
import os

# Allocate a 32-byte secure buffer
with SecureBuffer(32) as buf:
    # buf is a bytearray, initially zeroed
    buf[:] = os.urandom(32)   # Load key material

    # Use buf for cryptographic operations...
    key = bytes(buf)

# On context manager __exit__, buf is automatically zeroed by the native
# kernel: one pass of volatile stores followed by a compiler barrier.
print("buffer zeroed on exit")
```

### Internal Design

`SecureBuffer.__enter__()` returns a `bytearray` (not `bytes`) because `bytearray` supports in-place modification, allowing the buffer to be zeroed without creating new memory allocations. `bytes` objects in Python are immutable and cannot be zeroed in place.

---

## `secure_memzero()`

Barrier-backed memory zeroing for sensitive data:

<!-- example: python-run -->
```python
import os

from ama_cryptography.pqc_backends import native_hmac_sha3_256
from ama_cryptography.secure_memory import secure_memzero

# Load sensitive data
secret_key = bytearray(os.urandom(32))

# Use the key...
tag = native_hmac_sha3_256(bytes(secret_key), b"message")

# Zero immediately after use
secure_memzero(secret_key)
assert bytes(secret_key) == bytes(32)   # secret_key is now all zeros
```

> **Important:** Always pass a `bytearray` or a contiguous `memoryview`, not
> `bytes`. `bytes` objects are immutable and cannot be zeroed.

### Implementation

`secure_memzero()` writes zeros **once**, through `volatile` 64-bit stores, and
then issues a compiler barrier (`src/c/ama_consttime.c`,
`ama_secure_memzero()`). The barrier — not a repeat count — is what stops
dead-store elimination: it tells the compiler the memory may be observed, so
the stores cannot be proved dead and removed.

A three-pass 0x00 / 0xFF / 0x00 description belonged to the **opt-in
pure-Python fallback** (`AMA_ALLOW_PYTHON_MEMZERO=1`), which loops in the
interpreter because it has no barrier to reach for. It was never what the
shipped native kernel does, and on a normal build that fallback is refused
outright rather than used (`SecureMemoryError` — see INVARIANT-7).

---

## `secure_mlock()` and `secure_munlock()`

Lock memory pages to prevent swapping to disk:

<!-- example: python-run -->
```python
import os

from ama_cryptography.secure_memory import secure_mlock, secure_munlock

secret = bytearray(os.urandom(32))

# Lock the memory page containing `secret` into RAM
# Raises NotImplementedError if native C or POSIX mlock unavailable
secure_mlock(secret)
print("Memory locked in RAM (will not swap)")

# ... use secret ...

# Unlock when done (allow the OS to swap it again)
secure_munlock(secret)

# Zero the memory
from ama_cryptography.secure_memory import secure_memzero
secure_memzero(secret)
```

> **Return value.** `secure_mlock()` and `secure_munlock()` return `None`. They
> signal failure by raising (`SecureMemoryError`, `NotImplementedError`,
> `OSError`), not by returning a boolean — `if secure_mlock(buf):` takes the
> false branch on every *successful* lock.

### Platform Notes

| Platform | API | Notes |
|----------|-----|-------|
| Linux | `mlock()` | Requires `CAP_IPC_LOCK` or `ulimit -l` ≥ buffer size |
| macOS | `mlock()` | Requires entitlements in sandboxed environments |
| Windows | `VirtualLock()` | Standard user processes have limits |

> **Native C backend:** If the AMA native C library is available, `secure_mlock()` delegates to `ama_secure_mlock()`. Otherwise falls back to POSIX `mlock()`.

---

## `constant_time_compare()`

Timing-safe byte comparison:

<!-- example: python-run -->
```python
import os

from ama_cryptography.pqc_backends import native_hmac_sha3_256
from ama_cryptography.secure_memory import constant_time_compare

key = os.urandom(32)
message = b"payload"

# Timing-safe comparison (always runs in O(n) time regardless of where mismatch occurs)
hmac_expected = native_hmac_sha3_256(key, message)
hmac_received = native_hmac_sha3_256(key, message)

# Safe: does not leak position of first mismatch
if constant_time_compare(hmac_expected, hmac_received):
    print("HMAC valid")
else:
    print("HMAC invalid")
```

### Why Constant-Time Matters

A naive comparison (`expected == received`) returns `False` as soon as it finds the first differing byte. An attacker making many requests can measure small timing differences to determine byte-by-byte what the correct HMAC tag is (a timing oracle attack).

`constant_time_compare()` never short-circuits on the first differing byte, preventing this.

### Implementation

Uses `ama_consttime_memcmp()` from AMA's native C library, and **refuses to
operate without it** — there is no pure-Python fallback. Earlier releases fell
back to an XOR accumulator and documented it as constant-time; INVARIANT-7
forbids exactly that substitution for a secret-dependent operation, and the
loop was constant-time only in shape (`ljust` allocates, `zip` builds tuples,
and CPython's small-int cache makes `result |= x ^ y` data-dependent). A
fallback documented as constant-time that is not is worse than no fallback.

Cost is bounded by the **shorter** operand: `min(len(a), len(b))` bytes are
compared in place, and any length difference is OR-ed into the verdict rather
than short-circuiting the scan. Lengths are public metadata here (tags, public
keys and KEM shared secrets each have one published size). The previous
implementation padded both operands to `max(len(a), len(b))`, which let an
unauthenticated package declaring an 8 MiB tag force 16 MiB of allocation to
reject a 32-byte value. Use `lengths_match()` for an explicit, deliberately
non-constant-time length pre-check.

---

## `SecureKeyStorage`

Encrypted storage with automatic memory management:

<!-- example: python-run -->
```python
import os
import tempfile
from pathlib import Path

from ama_cryptography.key_management import SecureKeyStorage

# The constructor takes a storage DIRECTORY and an optional master password —
# not a raw encryption key. The AES-256 key is derived from the password
# with Argon2id (there is no PBKDF2 fallback: a library without Argon2id
# refuses to create the store) and held internally as a bytearray so it can
# be zeroed in place.
with SecureKeyStorage(
    storage_path=Path(tempfile.mkdtemp()),
    master_password="example-passphrase",
) as storage:
    # Store key material (sealed with AES-256-GCM; the methods are
    # store_key / retrieve_key, not store / retrieve)
    material = os.urandom(32)
    storage.store_key("signing-key-v1", material)

    # Retrieve key material (decrypted on access)
    key = storage.retrieve_key("signing-key-v1")
    assert key == material

# The derived encryption key is zeroed by __exit__ via secure_memzero().
```

---

## Best Practices

### Do: Use `bytearray` for Key Material

<!-- example: python-run -->
```python
import os

from ama_cryptography.secure_memory import secure_memzero

# ✓ Correct: bytearray can be zeroed
key = bytearray(os.urandom(32))
# ... use key ...
secure_memzero(key)
assert bytes(key) == bytes(32)
```

<!-- example: python-run -->
```python
import os

from ama_cryptography.secure_memory import secure_memzero

# ✗ Incorrect: bytes cannot be zeroed in-place
key = os.urandom(32)   # bytes object
try:
    secure_memzero(key)
except TypeError as exc:
    print("refused, as it must be:", exc)
```

### Do: Use `SecureBuffer` Context Manager

<!-- example: python-run -->
```python
import os

from ama_cryptography.crypto_api import AESGCMProvider
from ama_cryptography.secure_memory import SecureBuffer

plaintext = b"payload"

# ✓ Automatic zeroing even on exception
with SecureBuffer(32) as buf:
    buf[:] = os.urandom(32)             # in production: your HSM / KDF
    result = AESGCMProvider().encrypt(plaintext, bytes(buf))
# buf is zeroed here, even if encrypt() raised
print("ciphertext bytes:", len(result["ciphertext"]))
```

### Do: Lock Sensitive Buffers in RAM

<!-- example: python-run -->
```python
import os

from ama_cryptography.secure_memory import (
    secure_memzero,
    secure_mlock,
    secure_munlock,
)

# ✓ Prevent swap exposure for long-lived keys.
# secure_mlock returns None and raises on failure — do not branch on it.
master_key = bytearray(os.urandom(32))
secure_mlock(master_key)
try:
    pass  # ... use master_key for the session ...
finally:
    secure_memzero(master_key)   # wipe while the pages are still pinned
    secure_munlock(master_key)
```

### Do: Use Constant-Time Comparisons for MACs and Secrets

<!-- example: python-run -->
```python
import os

from ama_cryptography.pqc_backends import native_hmac_sha3_256
from ama_cryptography.secure_memory import constant_time_compare

key = os.urandom(32)
expected_mac = native_hmac_sha3_256(key, b"payload")
received_mac = native_hmac_sha3_256(key, b"payload")

# ✓ Constant-time comparison for HMAC tags
if constant_time_compare(expected_mac, received_mac):
    print("MAC accepted")
```

<!-- example: pseudocode: shows the anti-pattern this page tells you not to write -->
```python
# ✗ Timing-vulnerable comparison
if expected_mac == received_mac:   # DO NOT USE for secrets
    proceed()
```

---

## Native C Backend

When the AMA native C library is available (built via CMake), the secure memory module uses it for:
- `secure_mlock()` / `secure_munlock()` via `ama_secure_mlock()` / `ama_secure_munlock()`
- `constant_time_compare()` via `ama_consttime_memcmp()`

Without the native C library, `secure_mlock()`/`secure_munlock()` fall back to
POSIX `mlock()`/`munlock()` via ctypes (and raise on non-POSIX hosts).
`constant_time_compare()` has **no fallback** — it refuses to operate without
the native library, for the reasons in the Implementation section above: the
old pure-Python XOR accumulator was constant-time only in shape, and a
fallback documented as constant-time that is not is worse than no fallback.

---

*See [Key Management](Key-Management) for how `SecureBuffer` is used in key storage, or [Architecture](Architecture) for the security architecture overview.*
