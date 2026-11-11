/* zucrypt: the two utilities that are easy to get wrong by hand. */

#include <stdint.h>
#include <string.h>

#include <mbedtls/constant_time.h>
#include <mbedtls/platform_util.h>

#include <stdlib.h>

#include "zuc_internal.h"

int zuc_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (len == 0) {
        /* Two empty buffers are equal, and neither pointer is dereferenced,
         * so NULL is acceptable here and only here. */
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    /* The backend's constant-time compare rather than a local loop: the
     * naive version is correct C and the compiler is free to turn it into an
     * early exit, which is the entire bug this function exists to avoid. */
    return mbedtls_ct_memcmp(a, b, len) == 0 ? 1 : 0;
}

void zuc_secure_zero(void *buffer, size_t len)
{
    if (buffer == NULL || len == 0) {
        return;
    }
    /* Not memset: a memset over storage that is about to die is removable
     * under the as-if rule, and compilers remove it. */
    mbedtls_platform_zeroize(buffer, len);
}

/* Whether [a, a + an) and [b, b + bn) share a byte. Unlike
 * zuc_int_overlaps() an exact match counts: this is for buffers that may
 * not share memory at all. NULL or empty never overlaps. */
int zuc_int_spans_overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t pa, pb;

    if (a == NULL || b == NULL || an == 0 || bn == 0) {
        return 0;
    }
    pa = (uintptr_t) a;
    pb = (uintptr_t) b;
    return pa < pb ? pa + an > pb : pb + bn > pa;
}

int zuc_int_overlaps(const void *in, const void *out, size_t len)
{
    const unsigned char *a = (const unsigned char *) in;
    const unsigned char *b = (const unsigned char *) out;

    if (a == NULL || b == NULL || len == 0) {
        return 0;
    }
    if (a == b) {
        /* Exact in-place. Supported, and covered by a test rather than by
         * assumption -- see test-kat.R. */
        return 0;
    }
    /* Comparing pointers into different objects is not strictly defined in
     * C, which is why this goes through uintptr_t: the question being asked
     * is about addresses, and on every platform this package targets that is
     * what these values are. The alternative is to accept partial overlap
     * silently, which corrupts output instead of reporting it. */
    {
        uintptr_t pa = (uintptr_t) a;
        uintptr_t pb = (uintptr_t) b;
        uintptr_t n  = (uintptr_t) len;

        if (pa < pb) {
            return pa + n > pb;
        }
        return pb + n > pa;
    }
}

/* The backend's allocator (zuc_crypto_config.h): calloc(), remembering a
 * failure until zuc_int_watch() clears it. Main thread only, as the
 * whole library is. A zero-sized request may legitimately return NULL and
 * is not a failure. */
static int alloc_failed = 0;

/* See zuc_live.h: the countdown to an injected failure, 0 when off. */
static long alloc_fail_in = 0;

void zuc_int_alloc_fail_at(long n)
{
    alloc_fail_in = n > 0 ? n : 0;
}

long zuc_int_alloc_fail_pending(void)
{
    return alloc_fail_in;
}

void *zuc_int_calloc(size_t n, size_t size)
{
    void *p;

    if (alloc_fail_in > 0 && --alloc_fail_in == 0) {
        p = NULL;
    } else {
        p = calloc(n, size);
    }
    if (p == NULL && n != 0 && size != 0) {
        alloc_failed = 1;
    }
    return p;
}

/* The random source's half of the watch (#140). */
static int random_failed = 0;

void zuc_int_random_failed(void)
{
    random_failed = 1;
}

void zuc_int_watch(void)
{
    alloc_failed = 0;
    random_failed = 0;
}

zuc_status zuc_int_watched_or(zuc_status st)
{
    if (st == ZUC_OK) return st;
    if (alloc_failed) return ZUC_ERR_MEMORY;
    if (random_failed) return ZUC_ERR_ENTROPY;
    return st;
}
