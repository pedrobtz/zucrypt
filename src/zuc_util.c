/* zucrypt: the two utilities that are easy to get wrong by hand. */

#include <stdint.h>
#include <string.h>

#include <mbedtls/constant_time.h>
#include <mbedtls/platform_util.h>

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
