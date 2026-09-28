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
 * Scope is design.md section 6: hashes, HMAC, and unauthenticated AES-CBC,
 * in hardware where the CPU allows (below).
 * No public-key cryptography, no AEAD, no key derivation, no X.509, no TLS.
 * SHA-1 is present for Office compatibility only and is never a default for
 * a new format. ECB was here too, for Office Standard encryption; it left in
 * design revision 3 (#29) when that format left zuxlsx's scope.
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

/* AES-CBC with no padding, the mode Office agile encryption uses. PKCS#7
 * padding is not enabled: design.md section 7 makes padding the caller's
 * business, and a padding mode the wrappers never select is a code path the
 * tests would never reach. */
#define PSA_WANT_ALG_CBC_NO_PADDING      1
#define PSA_WANT_KEY_TYPE_AES            1

#define MBEDTLS_PSA_CRYPTO_C             1

/* A key store that grows. Without this, upstream's static store has 32 slots
 * (MBEDTLS_PSA_KEY_SLOT_COUNT), shared by every live zuc_aes and zuc_hmac in
 * the process -- including, in zucrypt.so, every table consumer's -- and the
 * 33rd key failed as PSA_ERROR_INSUFFICIENT_MEMORY, which reached the caller
 * as ZUC_ERR_MEMORY although no allocation had failed (#30). The dynamic
 * store keeps volatile keys in slices that double in size, up to about
 * 6.7e7 keys, so running out of it really is running out of memory. */
#define MBEDTLS_PSA_KEY_STORE_DYNAMIC    1

/* AES in hardware where the CPU has it, chosen at run time.
 *
 * Upstream's security policy for this release (SECURITY.md, "Block
 * ciphers") is explicit: the software AES uses lookup tables indexed by
 * secret-dependent values, which leaks through cache timing -- locally, and
 * depending on latency even remotely -- and the attacks can recover the key.
 * Its recommended workaround is hardware acceleration. Until #51 this file
 * left it off everywhere, reasoning that every platform should run the same
 * C; but AES is deterministic, so hardware and software produce the same
 * bytes, and the published vectors check that on every platform CI reaches.
 *
 *   MBEDTLS_AESNI_C   x86-64 and x86 (AES-NI). On x86-64 without -maes --
 *                     which R's portable build cannot pass -- upstream uses
 *                     inline assembly, hence MBEDTLS_HAVE_ASM; on 32-bit x86
 *                     it uses intrinsics under its own `#pragma GCC target`.
 *   MBEDTLS_AESCE_C   ARMv8-A (the Cryptography Extension), for Apple
 *                     silicon and 64-bit Arm Linux.
 *
 * Both detect the instructions at run time and fall back to the software
 * tables on a CPU without them: MBEDTLS_AES_USE_HARDWARE_ONLY is not set, so
 * AES keeps working on every CPU, and crypt_info()$build_flags reports which
 * path this machine uses. On the fallback the timing exposure above still
 * applies, and the package documents that rather than refusing to run
 * (design.md section 4, #51). On other architectures both options compile
 * to nothing and the software path is the only one.
 *
 * MBEDTLS_HAVE_ASM also lets constant_time_impl.h put its optimisation
 * barriers in inline assembly rather than relying on `volatile` alone.
 *
 * ZUC_AES_SOFTWARE_ONLY is for testing the fallback, never for a release
 * build: aes-paths.yaml installs with it, through ZUCRYPT_TEST_CPPFLAGS in
 * src/Makevars, so that the software path keeps being exercised on machines
 * that would never otherwise reach it. */
#if !defined(ZUC_AES_SOFTWARE_ONLY)
#define MBEDTLS_HAVE_ASM                 1
#define MBEDTLS_AESNI_C                  1
#define MBEDTLS_AESCE_C                  1
#endif

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
 * Hardware AES is configured above, not here. */
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG  1

#endif /* ZUC_CRYPTO_CONFIG_H */
