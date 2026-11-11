/* zucrypt: the operating system's random source.
 *
 * Two callers draw from it. MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 * (src/zuc_crypto_config.h) makes the backend call out for randomness
 * instead of compiling in an entropy module, a DRBG and NV-seed storage;
 * mbedtls_psa_external_get_random() below is that call-out. And
 * zuc_random_bytes(), the public entry point behind crypt_rand_bytes()
 * (#9), draws from the same source directly.
 *
 * Directly, not through psa_generate_random(): with an external RNG that
 * function is this same call-out, wrapped in a heap copy of the output
 * buffer. Going straight to the operating system skips an allocation and
 * leaves no copy of the bytes in freed memory.
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

#include "zuc_internal.h"

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
#  include <errno.h>
#  include <stdio.h>
#  include <sys/random.h>
#  define ZUC_RANDOM_GETRANDOM 1
#  define ZUC_RANDOM_BACKEND "getrandom"
#else
#  include <stdio.h>
#  define ZUC_RANDOM_DEV_URANDOM 1
#  define ZUC_RANDOM_BACKEND "/dev/urandom"
#endif

/* Set once getrandom() has been refused by the kernel (ENOSYS: glibc 2.25
 * or later on a kernel before 3.17) or by a seccomp filter (EPERM): every
 * draw after that reads /dev/urandom instead (#144). */
#if defined(ZUC_RANDOM_GETRANDOM)
static int zuc_random_fallback = 0;
#endif

const char *zuc_int_random_backend(void)
{
#if defined(ZUC_RANDOM_GETRANDOM)
    if (zuc_random_fallback) {
        return "/dev/urandom (getrandom() unavailable)";
    }
#endif
    return ZUC_RANDOM_BACKEND;
}

/* The test harness's switch: while set, the source reports failure without
 * reading anything, so the suite can prove that a failure becomes
 * ZUC_ERR_ENTROPY and zucrypt_entropy_error rather than bytes. Not atomic,
 * for the same reason as the refcount: the library is main-thread only. */
static int zuc_random_failing = 0;

void zuc_int_random_fail(int on)
{
    zuc_random_failing = on != 0;
}

/* The harness's other switch: while set, getrandom() is treated as having
 * failed with ENOSYS, so the suite exercises the fallback on any glibc
 * build. Switching it off forgets the fallback too. Returns whether this
 * build draws from getrandom() at all. */
#if defined(ZUC_RANDOM_GETRANDOM)
static int zuc_random_enosys = 0;
#endif

int zuc_int_random_enosys(int on)
{
#if defined(ZUC_RANDOM_GETRANDOM)
    zuc_random_enosys = on != 0;
    if (!on) {
        zuc_random_fallback = 0;
    }
    return 1;
#else
    (void) on;
    return 0;
#endif
}

#if defined(ZUC_RANDOM_GETRANDOM) || defined(ZUC_RANDOM_DEV_URANDOM)
/* Fill all of `out` from /dev/urandom, or fail. Returns 0 on success. */
static int urandom_read(uint8_t *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t n;

    if (f == NULL) {
        return 1;
    }
    n = fread(out, 1, len, f);
    fclose(f);
    return n != len;
}
#endif

/* Fill all of `out`, or fail. Returns 0 on success. Never returns a short
 * read as success: every branch below either loops until `len` bytes have
 * arrived or reports failure. */
static int os_random(uint8_t *out, size_t len)
{
    if (zuc_random_failing) {
        return 1;
    }

#if defined(_WIN32)
    while (len > 0) {
        unsigned int v;
        size_t n = len < sizeof v ? len : sizeof v;
        if (rand_s(&v) != 0) {
            return 1;
        }
        memcpy(out, &v, n);
        out += n;
        len -= n;
    }
    return 0;

#elif defined(ZUC_RANDOM_ARC4RANDOM)
    arc4random_buf(out, len);
    return 0;

#elif defined(ZUC_RANDOM_GETRANDOM)
    /* getrandom() may return short, and a request over 256 bytes may be
     * interrupted by a signal, which R sessions receive routinely. Both
     * mean "ask again", not "the source failed". */
    if (zuc_random_fallback) {
        return urandom_read(out, len);
    }
    while (len > 0) {
        ssize_t n = zuc_random_enosys ? (errno = ENOSYS, -1)
                                      : getrandom(out, len, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            /* The kernel or a seccomp filter refuses the call itself, not
             * the request: read the device instead, from now on. */
            if (errno == ENOSYS || errno == EPERM) {
                zuc_random_fallback = 1;
                return urandom_read(out, len);
            }
            return 1;
        }
        out += n;
        len -= (size_t) n;
    }
    return 0;

#else
    return urandom_read(out, len);
#endif
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) context;
    *output_length = 0;
    if (os_random(output, output_size) != 0) {
        zuc_int_random_failed();
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    *output_length = output_size;
    return PSA_SUCCESS;
}

zuc_status zuc_random_bytes(uint8_t *out, size_t len)
{
    if (len == 0) {
        return ZUC_OK;
    }
    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* Nothing below needs the backend, but the header promises that every
     * function that would is refused outside an initialised window, and a
     * consumer should not have to know which ones those are. */
    if (!zuc_int_ready()) {
        zuc_secure_zero(out, len);
        return ZUC_ERR_NOT_READY;
    }
    if (os_random(out, len) != 0) {
        zuc_secure_zero(out, len);
        return ZUC_ERR_ENTROPY;
    }
    return ZUC_OK;
}
