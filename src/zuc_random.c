/* zucrypt: the one random source the backend asks for.
 *
 * MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG (src/zuc_crypto_config.h) makes the backend
 * call out for randomness instead of compiling in an entropy module, a DRBG
 * and NV-seed storage. This file is that call-out.
 *
 * Nothing in the v0.1 profile consumes randomness: hashes and HMAC take none,
 * and CBC takes its IV from the caller. The symbol is still referenced by
 * psa_cipher_encrypt() and psa_generate_key() inside psa_crypto.c, so it has
 * to link -- which is why this is a real operating-system source rather than
 * a stub returning an error. A stub would be a correct description of today
 * and a trap the first time anything here needs a random byte.
 *
 * Backend selection happens in the preprocessor, the way zuxml selects
 * Expat's (src/zux_expat_random.c): a portable Makevars has no conditional
 * with which to choose a source file, and there is no configure script to
 * probe with. The order is most-specific first, with /dev/urandom as the
 * POSIX fallback that needs no feature test at all.
 *
 * design.md: randomness comes from platform entropy, never from R's RNG.
 * R's generator is seeded from the R session, reproducible on purpose, and
 * shared with whatever else the user is doing.
 */

#if defined(_WIN32)
/* Must precede <stdlib.h>: rand_s is only declared when this is set. */
#  define _CRT_RAND_S
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <psa/crypto.h>

#if defined(_WIN32)
#  include <stdlib.h>
#  define ZUC_RANDOM_BACKEND "rand_s"
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
      defined(__NetBSD__) || defined(__DragonFly__)
#  include <stdlib.h>
#  define ZUC_RANDOM_ARC4RANDOM 1
#  define ZUC_RANDOM_BACKEND "arc4random_buf"
#elif defined(__GLIBC__) && \
      (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#  include <sys/random.h>
#  define ZUC_RANDOM_GETRANDOM 1
#  define ZUC_RANDOM_BACKEND "getrandom"
#else
#  include <stdio.h>
#  define ZUC_RANDOM_DEV_URANDOM 1
#  define ZUC_RANDOM_BACKEND "/dev/urandom"
#endif

const char *zuc_int_random_backend(void)
{
    return ZUC_RANDOM_BACKEND;
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) context;
    *output_length = 0;

#if defined(_WIN32)
    while (output_size > 0) {
        unsigned int v;
        size_t n = output_size < sizeof v ? output_size : sizeof v;
        if (rand_s(&v) != 0) {
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        memcpy(output, &v, n);
        output += n;
        output_size -= n;
        *output_length += n;
    }
    return PSA_SUCCESS;

#elif defined(ZUC_RANDOM_ARC4RANDOM)
    arc4random_buf(output, output_size);
    *output_length = output_size;
    return PSA_SUCCESS;

#elif defined(ZUC_RANDOM_GETRANDOM)
    /* getrandom() may return short, and returns EINTR on a signal. */
    while (output_size > 0) {
        ssize_t n = getrandom(output, output_size, 0);
        if (n < 0) {
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        output += n;
        output_size -= (size_t) n;
        *output_length += (size_t) n;
    }
    return PSA_SUCCESS;

#else
    {
        FILE *f = fopen("/dev/urandom", "rb");
        size_t n;

        if (f == NULL) {
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        n = fread(output, 1, output_size, f);
        fclose(f);
        if (n != output_size) {
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        *output_length = output_size;
        return PSA_SUCCESS;
    }
#endif
}
