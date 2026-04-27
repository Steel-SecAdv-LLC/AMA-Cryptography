/* Public domain — single-translation-unit aggregator for ed25519-donna.
 *
 * This header exists solely to contain donna's single-file compilation
 * pattern (`#include "ed25519.c"`) inside the vendor tree, so that
 * static analyzers which flag `cpp/include-non-header` see the
 * non-header include in vendor code (path-ignored) rather than in the
 * AMA shim. The macros that select donna's reference SHA-512 and
 * custom-randombytes glue, plus the `ed25519_randombytes_unsafe`
 * definition, MUST be in scope at the point this header is included.
 * See src/c/ed25519_donna_shim.c.
 */
#ifndef AMA_VENDOR_ED25519_DONNA_UNIT_H
#define AMA_VENDOR_ED25519_DONNA_UNIT_H

#include "ed25519.c"

#endif /* AMA_VENDOR_ED25519_DONNA_UNIT_H */
