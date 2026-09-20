/* zucrypt: the TF-PSA-Crypto build configuration.
 *
 * This file replaces upstream's psa/crypto_config.h wholesale --
 * src/Makevars passes -DTF_PSA_CRYPTO_CONFIG_FILE pointing here -- so the
 * enabled feature set is exactly what is written below and nothing else.
 * Disabling through upstream configuration rather than by editing upstream
 * internals is a requirement of design.md section 4; src/vendor/ is never
 * edited in place.
 *
 * Every entry is also listed in the `defines` column of
 * tools/vendor/manifest.tsv, and tools/vendor/verify fails if the two
 * disagree. Adding a line here without adding it there is the way a feature
 * silently joins the supported profile.
 *
 * Scope is design.md section 6: hashes, HMAC, and unauthenticated AES. No
 * public-key cryptography, no AEAD, no key derivation, no X.509, no TLS.
 * SHA-1 and ECB are present for Office compatibility only and are never a
 * default for a new format.
 */

#ifndef ZUC_CRYPTO_CONFIG_H
#define ZUC_CRYPTO_CONFIG_H

/* Digests. SHA-224 is deliberately absent: nothing in scope uses it, and
 * sha256.c carries it either way, so leaving it out costs nothing and keeps
 * crypt_hash()'s algorithm list equal to what the backend can actually do. */
#define PSA_WANT_ALG_SHA_1               1
#define PSA_WANT_ALG_SHA_256             1
#define PSA_WANT_ALG_SHA_384             1
#define PSA_WANT_ALG_SHA_512             1

#define PSA_WANT_ALG_HMAC                1
#define PSA_WANT_KEY_TYPE_HMAC           1

/* AES with no padding, in the two modes the Office formats need. PKCS#7
 * padding is not enabled: design.md section 7 makes padding the caller's
 * business, and a padding mode the wrappers never select is a code path the
 * tests would never reach. */
#define PSA_WANT_ALG_CBC_NO_PADDING      1
#define PSA_WANT_ALG_ECB_NO_PADDING      1
#define PSA_WANT_KEY_TYPE_AES            1

#define MBEDTLS_PSA_CRYPTO_C             1

/* MBEDTLS_PSA_CRYPTO_C requires an RNG: CTR-DRBG, HMAC-DRBG, or an external
 * one (core/tf_psa_crypto_check_config.h). External is the smallest of the
 * three and the only one that pulls in no entropy module, no DRBG and no
 * NV-seed storage. src/zuc_random.c supplies the one function it asks for,
 * from the operating system.
 *
 * The spike measured what this costs: psa_crypto_init() succeeds without
 * drawing a single byte, even when the external RNG is wired to fail. No
 * operation in the profile above consumes randomness -- CBC takes the IV from
 * the caller -- so the RNG is a link-time requirement, not a runtime one.
 * Hardware acceleration is off everywhere for the same reason it is not
 * configured: MBEDTLS_HAVE_ASM, MBEDTLS_AESNI_C and MBEDTLS_AESCE_C are set
 * only by upstream's default config, which this file replaces, so every
 * platform runs the same C and produces the same bytes. */
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG  1

#endif /* ZUC_CRYPTO_CONFIG_H */
