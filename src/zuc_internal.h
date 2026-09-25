/* zucrypt: declarations shared between the adapter's translation units.
 * Never installed, never part of any ABI.
 *
 * Everything that includes this header is R-free and goes into
 * libzucrypt.a, which a consumer links into its own shared object.
 * Including R.h anywhere below this line would put R glue in that archive,
 * where it is a duplicate symbol at best.
 *
 * The public surface is inst/include/zucrypt.h. This header adds only what
 * the adapter needs to talk to the backend, and it is the one place where
 * PSA vocabulary and zuc_ vocabulary meet.
 */

#ifndef ZUC_INTERNAL_H
#define ZUC_INTERNAL_H

#include <psa/crypto.h>

#include "zucrypt.h"

/* Map a backend status onto the public enum. Every unrecognised failure
 * becomes ZUC_ERR_BACKEND: the upstream code is meaningful only against a
 * specific release and configuration, so publishing it would make a caller's
 * error handling depend on our build. */
zuc_status zuc_int_from_psa(psa_status_t status);

/* The backend algorithm for a digest, or 0 if `alg` is not a digest this
 * build knows. Does not say whether it is *available*; zuc_alg_available()
 * does that. */
psa_algorithm_t zuc_int_psa_hash(zuc_alg alg);

/* Do these two buffers overlap in a way that would corrupt the result?
 *
 * Returns 0 for disjoint buffers and for the exactly-equal case, which the
 * backend supports in place and which this package tests. Returns 1 for
 * every partial overlap, which is what ZUC_ERR_OVERLAP reports. */
int zuc_int_overlaps(const void *in, const void *out, size_t len);

/* The name of the compile-time random source, from src/zuc_random.c. */
const char *zuc_int_random_backend(void);

/* Non-zero once zuc_init() has succeeded and before the last
 * zuc_shutdown(). Every entry point that touches the backend checks it, so
 * that calling into a library that was never started is ZUC_ERR_NOT_READY
 * rather than undefined behaviour inside the backend. */
int zuc_int_ready(void);

#endif /* ZUC_INTERNAL_H */
