/* zucrypt: the two utilities that are easy to get wrong by hand. */

#include <stdint.h>
#include <string.h>

#include <mbedtls/constant_time.h>
#include <mbedtls/platform_util.h>

#include <stdlib.h>

#include "zuc_internal.h"
#include "zuc_live.h"

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
 * failure until zuc_int_alloc_watch() clears it. Main thread only, as the
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

/* See zuc_live.h: the residue scan's state, all zero when disarmed. */
#define ZUC_RESIDUE_SLOTS 4096
static struct {
    void *p;
    size_t n;
} residue_slot[ZUC_RESIDUE_SLOTS];
static size_t residue_used = 0;
static const unsigned char *residue_needle = NULL;
static size_t residue_len = 0;
static int residue_armed = 0;
static int residue_overflow = 0;
static long residue_hits = 0;

void zuc_int_residue_arm(const unsigned char *needle, size_t len)
{
    residue_used = 0;
    residue_needle = needle;
    residue_len = len;
    residue_overflow = 0;
    residue_hits = 0;
    residue_armed = 1;
}

long zuc_int_residue_disarm(void)
{
    residue_armed = 0;
    residue_needle = NULL;
    residue_len = 0;
    residue_used = 0;
    return residue_overflow ? -1 : residue_hits;
}

static int residue_contains(const unsigned char *hay, size_t n)
{
    size_t i;

    if (residue_len == 0 || n < residue_len) {
        return 0;
    }
    for (i = 0; i + residue_len <= n; i++) {
        if (hay[i] == residue_needle[0] &&
            memcmp(hay + i, residue_needle, residue_len) == 0) {
            return 1;
        }
    }
    return 0;
}

long zuc_int_residue_control(void)
{
    static const unsigned char needle[] = "zucrypt residue control";
    unsigned char *p;
    long kept, wiped;

    zuc_int_residue_arm(needle, sizeof needle - 1);
    p = zuc_int_calloc(1, 64);
    if (p != NULL) {
        memcpy(p + 7, needle, sizeof needle - 1);
        zuc_int_free(p);
    }
    kept = zuc_int_residue_disarm();
    zuc_int_residue_arm(needle, sizeof needle - 1);
    p = zuc_int_calloc(1, 64);
    if (p != NULL) {
        memcpy(p + 7, needle, sizeof needle - 1);
        mbedtls_platform_zeroize(p, 64);
        zuc_int_free(p);
    }
    wiped = zuc_int_residue_disarm();
    return kept + 10 * wiped;
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
    if (residue_armed && p != NULL) {
        if (residue_used < ZUC_RESIDUE_SLOTS) {
            residue_slot[residue_used].p = p;
            residue_slot[residue_used].n = n * size;   /* calloc checked it */
            residue_used++;
        } else {
            residue_overflow = 1;
        }
    }
    return p;
}

void zuc_int_free(void *p)
{
    size_t i;

    if (residue_armed && p != NULL) {
        for (i = residue_used; i-- > 0;) {
            if (residue_slot[i].p == p) {
                if (residue_contains(p, residue_slot[i].n)) {
                    residue_hits++;
                }
                residue_slot[i] = residue_slot[--residue_used];
                break;
            }
        }
    }
    free(p);
}

void zuc_int_alloc_watch(void)
{
    alloc_failed = 0;
}

zuc_status zuc_int_memory_or(zuc_status st)
{
    return (st != ZUC_OK && alloc_failed) ? ZUC_ERR_MEMORY : st;
}
