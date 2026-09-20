/* zucrypt: declarations shared inside the package. Never installed.
 *
 * The zuc_int_ prefix is the family's "internal only" layer (design.md
 * section 3). Nothing here is part of any ABI: the public C surface is
 * inst/include/zucrypt.h, which Stage 2 of .agents/roadmap.md writes.
 *
 * This header is R-free on purpose. Everything below it in the build --
 * src/zuc_*.c and src/vendor/ -- is what will become inst/lib/libzucrypt.a,
 * which a consumer links into its own shared object, where R glue would be a
 * duplicate symbol. R headers appear only in src/zucrypt_r.c.
 */

#ifndef ZUC_INTERNAL_H
#define ZUC_INTERNAL_H

/* Brings up the PSA backend. Returns 0 on success, and the upstream status
 * code otherwise. Idempotent: psa_crypto_init() is documented as safe to call
 * more than once. Reference counting and an ordered shutdown belong to the
 * adapter in Stage 2, not here. */
int zuc_int_backend_init(void);

/* The version of the compiled-in backend, e.g. "1.1.1".
 *
 * Reported from the library rather than read from tools/vendor/manifest.tsv:
 * the manifest is maintainer tooling and is not installed, so it cannot say
 * anything about the binary a user actually has. design.md section 3. */
const char *zuc_int_backend_version(void);

/* The name of the operating-system random source selected at compile time by
 * src/zuc_random.c, e.g. "arc4random_buf". */
const char *zuc_int_random_backend(void);

#endif /* ZUC_INTERNAL_H */
