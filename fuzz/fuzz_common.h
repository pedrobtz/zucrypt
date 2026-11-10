/* What the fuzz harnesses share (#94).
 *
 * Every harness carries an oracle: a property of the output that must hold
 * for every input, checked with REQUIRE(), which prints what failed and
 * aborts. libFuzzer reports an abort as a crash, and the replay driver
 * dies on it, so a wrong answer is a finding exactly as a memory error is.
 * "It did not crash" is never the check.
 */
#ifndef ZUC_FUZZ_COMMON_H
#define ZUC_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zucrypt.h"
#include "zuc_live.h"

#define REQUIRE(cond, ...)                                                  \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "ORACLE %s:%d: ", __FILE__, __LINE__);           \
            fprintf(stderr, __VA_ARGS__);                                   \
            fputc('\n', stderr);                                            \
            abort();                                                        \
        }                                                                   \
    } while (0)

/* The backend, brought up once for the process. */
static void fuzz_init(void)
{
    static int up = 0;
    if (!up) {
        REQUIRE(zuc_init() == ZUC_OK, "zuc_init");
        up = 1;
    }
}

static int fuzz_all(const uint8_t *p, size_t n, uint8_t v)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

/* Hex to bytes, into a buffer of `cap`; returns the length. */
static size_t fuzz_unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = strlen(h) / 2, i;
    REQUIRE(n <= cap, "hex too long");
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t) v;
    }
    return n;
}

/* No handle may outlive the input that made it. */
#define REQUIRE_NO_LEAK()                                                   \
    REQUIRE(zuc_int_live_contexts() == 0, "%ld handles live after an input", \
            zuc_int_live_contexts())

#endif
