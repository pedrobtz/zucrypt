/* zucrypt: a standalone C driver for the adapter (#96).
 *
 * Links src/zuc_*.c and the vendored backend, and no R. It exists for two
 * reasons. Mutation testing (mutation.yaml, under Mull) needs a test binary
 * that is the adapter plus its tests and nothing else. And every check here
 * compares an output with something that knows the answer, because a
 * mutant the suite merely runs is a mutant that survives:
 *
 *   - the known-answer fixtures in tests/testthat/fixtures, each of which
 *     tools/make-kat.R and its siblings check against openssl, Python or
 *     the RFC it came from;
 *   - equivalences the specification states: one-shot equals incremental
 *     at every split, a reset handle equals a fresh one, a shorter PBKDF2
 *     output is a prefix of a longer one;
 *   - the states and statuses zucrypt.h promises, including what a buffer
 *     holds after a failure;
 *   - an in-process allocation-failure sweep: every backend allocation of
 *     each operation is failed in turn, and the operation must then either
 *     report ZUC_ERR_MEMORY with no handle left live, or succeed with the
 *     right answer.
 *
 *   ./zuc_ctest [fixture-directory]     (default tests/testthat/fixtures)
 *
 * Exits 0 when every check passes, 1 otherwise, printing each failure.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zucrypt.h"
#include "zuc_live.h"

/* ------------------------------------------------------------------ *
 * Checks
 * ------------------------------------------------------------------ */

static long checks = 0, failures = 0;
static const char *context = "";

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            fprintf(stderr, "FAIL %s:%d [%s] ", __FILE__, __LINE__,          \
                    context);                                               \
            fprintf(stderr, __VA_ARGS__);                                   \
            fputc('\n', stderr);                                            \
        }                                                                   \
    } while (0)

#define ST(expr, want)                                                      \
    do {                                                                    \
        zuc_status st_ = (expr), want_ = (want);                            \
        CHECK(st_ == want_, "%s -> %s, want %s", #expr,                     \
              zuc_status_name(st_), zuc_status_name(want_));                \
    } while (0)

#define SAME(a, b, n) CHECK(memcmp((a), (b), (n)) == 0, "bytes differ")

static int all_bytes(const uint8_t *p, size_t n, uint8_t v)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ *
 * Fixtures: tab-separated, a header row, hex cells
 * ------------------------------------------------------------------ */

typedef struct {
    char  *text;
    char **cell;     /* nrow * ncol, row-major; row 0 is the header */
    int    nrow, ncol;
} table;

static const char *fixture_dir = "tests/testthat/fixtures";

static table read_table(const char *name)
{
    table t = {0};
    char path[1024];
    FILE *f;
    long size;
    char *p;
    int r, c, cap = 64;

    snprintf(path, sizeof path, "%s/%s", fixture_dir, name);
    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    t.text = malloc((size_t) size + 1);
    if (t.text == NULL || fread(t.text, 1, (size_t) size, f) != (size_t) size) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(2);
    }
    t.text[size] = '\0';
    fclose(f);

    for (p = t.text, t.ncol = 1; *p && *p != '\n'; p++) {
        if (*p == '\t') t.ncol++;
    }
    t.cell = malloc(sizeof(char *) * (size_t) cap * (size_t) t.ncol);
    for (p = t.text, r = 0; *p; r++) {
        if (r == cap) {
            cap *= 2;
            t.cell = realloc(t.cell, sizeof(char *) * (size_t) cap *
                                     (size_t) t.ncol);
        }
        for (c = 0; c < t.ncol; c++) {
            t.cell[r * t.ncol + c] = p;
            while (*p && *p != '\t' && *p != '\n' && *p != '\r') p++;
            if (*p == '\r') *p++ = '\0';
            if (*p == '\t' || *p == '\n') *p++ = '\0';
        }
    }
    t.nrow = r;
    return t;
}

static const char *get(const table *t, int row, const char *col)
{
    int c;
    for (c = 0; c < t->ncol; c++) {
        if (strcmp(t->cell[c], col) == 0) return t->cell[row * t->ncol + c];
    }
    fprintf(stderr, "no column %s\n", col);
    exit(2);
}

static int find_row(const table *t, const char *id)
{
    int r;
    for (r = 1; r < t->nrow; r++) {
        if (strcmp(get(t, r, "id"), id) == 0) return r;
    }
    fprintf(stderr, "no row %s\n", id);
    exit(2);
}

/* Hex, or "xx*N" for N copies of one byte (tests/testthat/helper-kat.R). */
static uint8_t *unhex(const char *h, size_t *len)
{
    size_t n = strlen(h), i;
    const char *star = strchr(h, '*');
    uint8_t *out;

    if (star != NULL) {
        unsigned v;
        *len = (size_t) strtoul(star + 1, NULL, 10);
        sscanf(h, "%2x", &v);
        out = malloc(*len ? *len : 1);
        memset(out, (int) v, *len);
        return out;
    }
    *len = n / 2;
    out = malloc(*len ? *len : 1);
    for (i = 0; i < *len; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t) v;
    }
    return out;
}

/* ------------------------------------------------------------------ *
 * Names and statuses
 * ------------------------------------------------------------------ */

static void test_names(void)
{
    static const char *digests[] = {"sha1", "sha256", "sha384", "sha512"};
    static const size_t sizes[] = {20, 32, 48, 64};
    int i;

    context = "names";
    for (i = ZUC_OK; i <= ZUC_ERR_AUTH; i++) {
        const char *name = zuc_status_name((zuc_status) i);
        const char *text = zuc_status_string((zuc_status) i);
        CHECK(name != NULL && strncmp(name, i ? "ZUC_ERR_" : "ZUC_OK", 6) == 0,
              "status %d has name %s", i, name ? name : "NULL");
        CHECK(text != NULL && text[0] != '\0', "status %d has no text", i);
    }
    CHECK(strcmp(zuc_status_name(ZUC_ERR_MEMORY), "ZUC_ERR_MEMORY") == 0,
          "memory name");
    CHECK(strcmp(zuc_status_name(ZUC_ERR_AUTH), "ZUC_ERR_AUTH") == 0,
          "auth name");
    for (i = 0; i < 4; i++) {
        zuc_alg a = zuc_alg_by_name(digests[i]);
        CHECK(a == (zuc_alg) (ZUC_ALG_SHA1 + i), "%s", digests[i]);
        CHECK(zuc_alg_size(a) == sizes[i], "size of %s", digests[i]);
        CHECK(zuc_alg_available(a), "%s available", digests[i]);
    }
    CHECK(zuc_alg_by_name("sha") == ZUC_ALG_NONE, "partial match");
    CHECK(zuc_alg_by_name("SHA256") == ZUC_ALG_NONE, "case");
    CHECK(zuc_alg_by_name("") == ZUC_ALG_NONE, "empty name");
    CHECK(zuc_alg_size(ZUC_ALG_NONE) == 0, "size of none");
    CHECK(!zuc_alg_available(ZUC_ALG_NONE), "none available");
}

/* ------------------------------------------------------------------ *
 * Digests and HMAC: the vectors, at every split, through a reset
 * ------------------------------------------------------------------ */

static void digest_vectors(const table *kat, int hmac)
{
    int r;
    for (r = 1; r < kat->nrow; r++) {
        uint8_t *in, *key = NULL, *want, out[ZUC_MAX_DIGEST_SIZE];
        size_t in_len, key_len = 0, want_len, out_len, k;
        zuc_alg alg;

        if (strcmp(get(kat, r, "family"), hmac ? "hmac" : "hash") != 0) continue;
        context = get(kat, r, "id");
        alg = zuc_alg_by_name(get(kat, r, "algorithm"));
        in = unhex(get(kat, r, "input"), &in_len);
        want = unhex(get(kat, r, "output"), &want_len);
        if (hmac) key = unhex(get(kat, r, "key"), &key_len);

        memset(out, 0, sizeof out);
        ST(hmac ? zuc_hmac_compute(alg, key, key_len, in, in_len, out,
                                   sizeof out, &out_len)
                : zuc_hash_compute(alg, in, in_len, out, sizeof out, &out_len),
           ZUC_OK);
        CHECK(out_len == want_len, "length %zu", out_len);
        SAME(out, want, want_len);

        /* Every split point of a short input, a few of a long one, each
         * through one handle that is reset between splits. */
        {
            zuc_hash *h = NULL;
            zuc_hmac *m = NULL;
            size_t step = in_len > 300 ? in_len / 7 + 1 : 1;
            ST(hmac ? zuc_hmac_new(alg, key, key_len, &m)
                    : zuc_hash_new(alg, &h), ZUC_OK);
            for (k = 0; k <= in_len; k += step) {
                memset(out, 0, sizeof out);
                ST(hmac ? zuc_hmac_update(m, in, k) : zuc_hash_update(h, in, k),
                   ZUC_OK);
                ST(hmac ? zuc_hmac_update(m, in + k, in_len - k)
                        : zuc_hash_update(h, in + k, in_len - k), ZUC_OK);
                ST(hmac ? zuc_hmac_finish(m, out, sizeof out, &out_len)
                        : zuc_hash_finish(h, out, sizeof out, &out_len),
                   ZUC_OK);
                CHECK(out_len == want_len, "split %zu length", k);
                SAME(out, want, want_len);
                /* Finished: no more input until reset. */
                ST(hmac ? zuc_hmac_update(m, in, 1) : zuc_hash_update(h, in, 1),
                   ZUC_ERR_INVALID_ARGUMENT);
                ST(hmac ? zuc_hmac_finish(m, out, sizeof out, &out_len)
                        : zuc_hash_finish(h, out, sizeof out, &out_len),
                   ZUC_ERR_INVALID_ARGUMENT);
                ST(hmac ? zuc_hmac_reset(m) : zuc_hash_reset(h), ZUC_OK);
            }
            /* A reset in mid-message discards what came before it. */
            ST(hmac ? zuc_hmac_update(m, (const uint8_t *) "junk", 4)
                    : zuc_hash_update(h, (const uint8_t *) "junk", 4), ZUC_OK);
            ST(hmac ? zuc_hmac_reset(m) : zuc_hash_reset(h), ZUC_OK);
            ST(hmac ? zuc_hmac_update(m, in, in_len)
                    : zuc_hash_update(h, in, in_len), ZUC_OK);
            /* A buffer one byte short is refused before anything is used. */
            ST(hmac ? zuc_hmac_finish(m, out, want_len - 1, &out_len)
                    : zuc_hash_finish(h, out, want_len - 1, &out_len),
               ZUC_ERR_BAD_LENGTH);
            ST(hmac ? zuc_hmac_finish(m, out, want_len, &out_len)
                    : zuc_hash_finish(h, out, want_len, &out_len), ZUC_OK);
            SAME(out, want, want_len);
            zuc_hash_free(h);
            zuc_hmac_free(m);
        }
        free(in);
        free(want);
        free(key);
    }
}

static void test_digests(void)
{
    table kat = read_table("kat.tsv");
    uint8_t out[ZUC_MAX_DIGEST_SIZE];
    size_t len;
    zuc_hash *h = NULL;
    zuc_hmac *m = NULL;

    digest_vectors(&kat, 0);
    digest_vectors(&kat, 1);

    context = "digest arguments";
    ST(zuc_hash_compute(ZUC_ALG_NONE, NULL, 0, out, sizeof out, &len),
       ZUC_ERR_UNSUPPORTED);
    ST(zuc_hash_compute(ZUC_ALG_AES_GCM, NULL, 0, out, sizeof out, &len),
       ZUC_ERR_UNSUPPORTED);
    ST(zuc_hash_compute(ZUC_ALG_SHA256, NULL, 1, out, sizeof out, &len),
       ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_compute(ZUC_ALG_SHA256, NULL, 0, NULL, sizeof out, &len),
       ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_compute(ZUC_ALG_SHA256, NULL, 0, out, 31, &len),
       ZUC_ERR_BAD_LENGTH);
    ST(zuc_hash_new(ZUC_ALG_SHA256, NULL), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_new(ZUC_ALG_NONE, &h), ZUC_ERR_UNSUPPORTED);
    CHECK(h == NULL, "no handle on failure");
    ST(zuc_hash_update(NULL, NULL, 0), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_reset(NULL), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hmac_new(ZUC_ALG_SHA256, NULL, 1, &m), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hmac_new(ZUC_ALG_AES_GCM, NULL, 0, &m), ZUC_ERR_UNSUPPORTED);
    CHECK(m == NULL, "no handle on failure");
    ST(zuc_hmac_compute(ZUC_ALG_SHA1, NULL, 0, NULL, 0, out, 19, &len),
       ZUC_ERR_BAD_LENGTH);
    ST(zuc_hash_new(ZUC_ALG_SHA1, &h), ZUC_OK);
    ST(zuc_hash_update(h, NULL, 1), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_update(h, NULL, 0), ZUC_OK);
    ST(zuc_hash_finish(h, NULL, sizeof out, &len), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_finish(h, out, sizeof out, NULL), ZUC_ERR_INVALID_ARGUMENT);
    zuc_hash_free(h);
    zuc_hash_free(NULL);
    zuc_hmac_free(NULL);
}

/* ------------------------------------------------------------------ *
 * AES-CBC
 * ------------------------------------------------------------------ */

static void test_aes(void)
{
    table kat = read_table("kat.tsv");
    uint8_t buf[256], state[16];
    int r;
    zuc_aes *a = NULL;

    for (r = 1; r < kat.nrow; r++) {
        uint8_t *key, *iv, *in, *want, *out;
        size_t key_len, iv_len, in_len, want_len, k;

        if (strcmp(get(&kat, r, "family"), "aes-cbc") != 0) continue;
        context = get(&kat, r, "id");
        key = unhex(get(&kat, r, "key"), &key_len);
        iv = unhex(get(&kat, r, "iv"), &iv_len);
        in = unhex(get(&kat, r, "input"), &in_len);
        want = unhex(get(&kat, r, "output"), &want_len);
        out = malloc(in_len);

        ST(zuc_aes_new(key, key_len, &a), ZUC_OK);
        /* Block by block, chaining through the handle, both ways. */
        ST(zuc_aes_cbc_set_state(a, iv), ZUC_OK);
        for (k = 0; k < in_len; k += 16) {
            ST(zuc_aes_cbc_encrypt(a, in + k, 16, out + k), ZUC_OK);
        }
        SAME(out, want, want_len);
        ST(zuc_aes_cbc_get_state(a, state), ZUC_OK);
        SAME(state, want + want_len - 16, 16);
        ST(zuc_aes_cbc_set_state(a, iv), ZUC_OK);
        ST(zuc_aes_cbc_decrypt(a, want, 32, out), ZUC_OK);
        ST(zuc_aes_cbc_decrypt(a, want + 32, want_len - 32, out + 32), ZUC_OK);
        SAME(out, in, in_len);
        ST(zuc_aes_cbc_get_state(a, state), ZUC_OK);
        SAME(state, want + want_len - 16, 16);
        /* In place, exactly. */
        memcpy(out, in, in_len);
        ST(zuc_aes_cbc_set_state(a, iv), ZUC_OK);
        ST(zuc_aes_cbc_encrypt(a, out, in_len, out), ZUC_OK);
        SAME(out, want, want_len);
        /* Lengths and overlaps are refused before anything is written. */
        memset(buf, 0xee, sizeof buf);
        ST(zuc_aes_cbc_encrypt(a, in, 15, buf), ZUC_ERR_BAD_LENGTH);
        ST(zuc_aes_cbc_encrypt(a, in, 17, buf), ZUC_ERR_BAD_LENGTH);
        CHECK(all_bytes(buf, sizeof buf, 0xee), "refused call wrote");
        memcpy(buf, in, 64);
        ST(zuc_aes_cbc_encrypt(a, buf, 32, buf + 8), ZUC_ERR_OVERLAP);
        ST(zuc_aes_cbc_decrypt(a, buf + 8, 32, buf), ZUC_ERR_OVERLAP);
        ST(zuc_aes_cbc_encrypt(a, NULL, 16, buf), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_aes_cbc_encrypt(a, in, 16, NULL), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_aes_cbc_encrypt(a, NULL, 0, NULL), ZUC_OK);
        ST(zuc_aes_cbc_encrypt(NULL, in, 16, buf), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_aes_cbc_set_state(a, NULL), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_aes_cbc_get_state(a, NULL), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_aes_cbc_set_state(NULL, iv), ZUC_ERR_INVALID_ARGUMENT);
        zuc_aes_free(a);
        a = NULL;
        free(key);
        free(iv);
        free(in);
        free(want);
        free(out);
    }
    context = "aes keys";
    for (r = 0; r <= 40; r++) {
        int ok = r == 16 || r == 24 || r == 32;
        memset(buf, 1, sizeof buf);
        ST(zuc_aes_new(buf, (size_t) r, &a), ok ? ZUC_OK : ZUC_ERR_BAD_LENGTH);
        CHECK((a != NULL) == ok, "handle for a %d-byte key", r);
        zuc_aes_free(a);
        a = NULL;
    }
    ST(zuc_aes_new(NULL, 16, &a), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_aes_new(buf, 16, NULL), ZUC_ERR_INVALID_ARGUMENT);
    zuc_aes_free(NULL);
}

/* ------------------------------------------------------------------ *
 * AES-GCM
 * ------------------------------------------------------------------ */

static void test_aead(void)
{
    table t = read_table("aead.tsv");
    int r;

    for (r = 1; r < t.nrow; r++) {
        uint8_t *key, *iv, *aad, *in, *want, *tag, *out, got_tag[16];
        size_t key_len, iv_len, aad_len, in_len, want_len, tag_len, i;
        const uint8_t *a;

        context = get(&t, r, "id");
        key = unhex(get(&t, r, "key"), &key_len);
        iv = unhex(get(&t, r, "iv"), &iv_len);
        aad = unhex(get(&t, r, "aad"), &aad_len);
        in = unhex(get(&t, r, "input"), &in_len);
        want = unhex(get(&t, r, "output"), &want_len);
        tag = unhex(get(&t, r, "tag"), &tag_len);
        out = malloc(in_len + 1);
        a = aad_len ? aad : NULL;
        if (iv_len != 12) {
            /* Only the 12-byte nonce is supported; the vectors with another
             * length are the backend's to refuse, and are. */
            ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                                aad_len, in_len ? in : NULL, in_len,
                                in_len ? out : NULL, got_tag, 16),
               ZUC_ERR_BAD_LENGTH);
            goto next;
        }

        ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                            aad_len, in_len ? in : NULL, in_len,
                            in_len ? out : NULL, got_tag, sizeof got_tag),
           ZUC_OK);
        SAME(out, want, want_len);
        SAME(got_tag, tag, 16);
        memset(out, 0xee, in_len + 1);
        ST(zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                            aad_len, in_len ? want : NULL, in_len, tag, 16,
                            in_len ? out : NULL), ZUC_OK);
        SAME(out, in, in_len);
        CHECK(out[in_len] == 0xee, "wrote past the plaintext");

        /* Every bit of the tag, and the first and last byte of each other
         * input: authentication fails, and the output is all zeros. */
        for (i = 0; i < 16 * 8; i++) {
            tag[i / 8] ^= (uint8_t) (1u << (i % 8));
            memset(out, 0xee, in_len);
            ST(zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                                aad_len, in_len ? want : NULL, in_len, tag, 16,
                                in_len ? out : NULL), ZUC_ERR_AUTH);
            CHECK(all_bytes(out, in_len, 0), "plaintext after a bad tag");
            tag[i / 8] ^= (uint8_t) (1u << (i % 8));
        }
#define TAMPER(buf, n, idx)                                                  \
        if ((n) > 0) {                                                       \
            (buf)[idx] ^= 0x80;                                              \
            memset(out, 0xee, in_len);                                       \
            ST(zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len,   \
                                a, aad_len, in_len ? want : NULL, in_len,    \
                                tag, 16, in_len ? out : NULL), ZUC_ERR_AUTH); \
            CHECK(all_bytes(out, in_len, 0), "plaintext after tampering");   \
            (buf)[idx] ^= 0x80;                                              \
        }
        TAMPER(want, in_len, 0)
        TAMPER(want, in_len, in_len - 1)
        TAMPER(aad, aad_len, 0)
        TAMPER(aad, aad_len, aad_len - 1)
        TAMPER(iv, iv_len, 0)
        TAMPER(iv, iv_len, iv_len - 1)
        TAMPER(key, key_len, 0)
        TAMPER(key, key_len, key_len - 1)
#undef TAMPER
        /* Another tag length cannot match; another nonce length is not
         * GCM as this interface offers it. */
        ST(zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                            aad_len, in_len ? want : NULL, in_len, tag, 15,
                            in_len ? out : NULL), ZUC_ERR_AUTH);
        ST(zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                            aad_len, in_len ? want : NULL, in_len, tag, 0,
                            in_len ? out : NULL), ZUC_ERR_AUTH);
        ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                            aad_len, in_len ? in : NULL, in_len,
                            in_len ? out : NULL, got_tag, 15),
           ZUC_ERR_BAD_LENGTH);
        ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, iv, 11, a, aad_len,
                            in_len ? in : NULL, in_len, in_len ? out : NULL,
                            got_tag, 16), ZUC_ERR_BAD_LENGTH);
        ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, 15, iv, iv_len, a, aad_len,
                            in_len ? in : NULL, in_len, in_len ? out : NULL,
                            got_tag, 16), ZUC_ERR_BAD_LENGTH);
        ST(zuc_aead_encrypt(ZUC_ALG_SHA256, key, key_len, iv, iv_len, a,
                            aad_len, in_len ? in : NULL, in_len,
                            in_len ? out : NULL, got_tag, 16),
           ZUC_ERR_UNSUPPORTED);
        if (in_len >= 16) {
            /* In place is allowed; a partial overlap is not. */
            memcpy(out, in, in_len);
            ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                                aad_len, out, in_len, out, got_tag, 16),
               ZUC_OK);
            SAME(out, want, in_len);
            ST(zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, iv, iv_len, a,
                                aad_len, out, in_len - 1, out + 1, got_tag, 16),
               ZUC_ERR_OVERLAP);
        }
    next:
        free(key);
        free(iv);
        free(aad);
        free(in);
        free(want);
        free(tag);
        free(out);
    }
}

/* ------------------------------------------------------------------ *
 * PBKDF2
 * ------------------------------------------------------------------ */

static void test_kdf(void)
{
    table t = read_table("kdf.tsv");
    uint8_t out[128];
    int r;

    for (r = 1; r < t.nrow; r++) {
        uint8_t *pw, *salt, *want;
        size_t pw_len, salt_len, want_len, n;
        uint32_t iter;
        zuc_alg alg;

        context = get(&t, r, "id");
        alg = zuc_alg_by_name(get(&t, r, "algorithm"));
        pw = unhex(get(&t, r, "password"), &pw_len);
        salt = unhex(get(&t, r, "salt"), &salt_len);
        want = unhex(get(&t, r, "output"), &want_len);
        iter = (uint32_t) strtoul(get(&t, r, "iterations"), NULL, 10);
        if (iter > 100000) {
            /* RFC 6070's 16,777,216 iterations: not in a mutation run. */
            goto next;
        }
        /* Prefixes at 1 and one byte short, and the whole: a shorter output
         * is a prefix of a longer one. The costly vectors run once. */
        for (n = iter > 4096 ? want_len : 1; n <= want_len;
             n = n == 1 ? want_len - 1 : n + 1) {
            memset(out, 0xee, sizeof out);
            ST(zuc_pbkdf2_hmac(alg, pw_len ? pw : NULL, pw_len,
                               salt_len ? salt : NULL, salt_len, iter, out, n),
               ZUC_OK);
            SAME(out, want, n);
            CHECK(out[n] == 0xee, "wrote past %zu bytes", n);
        }
    next:
        free(pw);
        free(salt);
        free(want);
    }
    context = "pbkdf2 arguments";
    memset(out, 0xee, sizeof out);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, out, 1, out, 1, 0, out, 16),
       ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, (const uint8_t *) "p", 1,
                       (const uint8_t *) "s", 1, 1, out, 0), ZUC_ERR_BAD_LENGTH);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, NULL, 1, NULL, 0, 1, out, 16),
       ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, NULL, 0, NULL, 1, 1, out, 16),
       ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, NULL, 0, NULL, 0, 1, NULL, 16),
       ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_AES_GCM, NULL, 0, NULL, 0, 1, out, 16),
       ZUC_ERR_UNSUPPORTED);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, NULL, 0, NULL, 0, 1, out, 16), ZUC_OK);
}

/* ------------------------------------------------------------------ *
 * Comparison, wiping, randomness
 * ------------------------------------------------------------------ */

static void test_util(void)
{
    uint8_t a[64], b[64], c[64];
    int i;

    context = "equal";
    for (i = 0; i < 64; i++) a[i] = b[i] = (uint8_t) (i * 7 + 1);
    CHECK(zuc_equal(a, b, 64) == 1, "equal");
    CHECK(zuc_equal(a, b, 0) == 1, "empty");
    for (i = 0; i < 64; i++) {
        b[i] ^= 0x01;
        CHECK(zuc_equal(a, b, 64) == 0, "differ at %d", i);
        b[i] ^= 0x81;
        CHECK(zuc_equal(a, b, 64) == 0, "differ at %d, top bit", i);
        b[i] ^= 0x80;
    }
    CHECK(zuc_equal(a, b, 64) == 1, "equal again");

    context = "secure_zero";
    memset(c, 0x5a, sizeof c);
    zuc_secure_zero(c + 1, 62);
    CHECK(c[0] == 0x5a && c[63] == 0x5a && all_bytes(c + 1, 62, 0),
          "wiped exactly the range");
    zuc_secure_zero(NULL, 0);

    context = "random";
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    ST(zuc_random_bytes(a, sizeof a), ZUC_OK);
    ST(zuc_random_bytes(b, sizeof b), ZUC_OK);
    CHECK(!all_bytes(a, sizeof a, 0), "random bytes are not all zero");
    CHECK(memcmp(a, b, sizeof a) != 0, "two draws differ");
    ST(zuc_random_bytes(NULL, 0), ZUC_OK);
    ST(zuc_random_bytes(NULL, 1), ZUC_ERR_INVALID_ARGUMENT);
    zuc_int_random_fail(1);
    memset(a, 0x5a, sizeof a);
    ST(zuc_random_bytes(a, sizeof a), ZUC_ERR_ENTROPY);
    CHECK(all_bytes(a, sizeof a, 0), "a failed draw is wiped");
    zuc_int_random_fail(0);
    ST(zuc_random_bytes(a, sizeof a), ZUC_OK);
}

/* ------------------------------------------------------------------ *
 * zuc_get_info(): what it writes, and what it must leave alone (#114)
 * ------------------------------------------------------------------ */

static void test_info(void)
{
    struct {
        zuc_info info;
        unsigned char guard[64];
    } box;
    const size_t req = ZUC_INFO_REQUIRED_SIZE;
    const size_t hw_end = offsetof(zuc_info, hardware_acceleration) +
                          sizeof(int);
    const size_t aes_end = offsetof(zuc_info, aes_implementation) +
                           sizeof(const char *);
    size_t sizes[8];
    size_t n = 0, i, b;

    sizes[n++] = 0;
    sizes[n++] = req - 1;
    sizes[n++] = req;
    sizes[n++] = hw_end - 1;
    sizes[n++] = hw_end;
    sizes[n++] = aes_end - 1;
    sizes[n++] = aes_end;
    sizes[n++] = sizeof(zuc_info);

    context = "info";
    ST(zuc_get_info(NULL), ZUC_ERR_INVALID_ARGUMENT);
    for (i = 0; i < n; i++) {
        size_t s = sizes[i];
        const unsigned char *p = (const unsigned char *) &box;
        zuc_status st;

        memset(&box, 0xa5, sizeof box);
        box.info.struct_size = (uint32_t) s;
        st = zuc_get_info(&box.info);
        CHECK(st == (s < req ? ZUC_ERR_ABI : ZUC_OK), "size %zu: %s", s,
              zuc_status_name(st));
        /* Nothing at or past the caller's size, and nothing at all on a
         * refusal, other than the size it was given. */
        for (b = s < req ? sizeof(uint32_t) : s; b < sizeof box; b++) {
            if (p[b] != 0xa5) break;
        }
        CHECK(b == sizeof box, "size %zu: byte %zu was written", s, b);
        if (st != ZUC_OK) continue;
        CHECK(box.info.abi_version == ZUCRYPT_ABI_VERSION, "abi version");
        CHECK(strcmp(box.info.backend_name, "TF-PSA-Crypto") == 0, "backend");
        CHECK(box.info.backend_version != NULL &&
              box.info.backend_version[0] != '\0', "backend version");
        CHECK(box.info.random_backend != NULL &&
              box.info.random_backend[0] != '\0', "random backend");
        if (s >= hw_end) {
            CHECK(box.info.hardware_acceleration == 0 ||
                  box.info.hardware_acceleration == 1, "hardware flag");
        }
        if (s >= aes_end) {
            const char *imp = box.info.aes_implementation;
            CHECK(strcmp(imp, "aesni") == 0 || strcmp(imp, "aesce") == 0 ||
                  strcmp(imp, "software") == 0, "aes implementation %s", imp);
            CHECK(box.info.hardware_acceleration ==
                  (strcmp(imp, "software") != 0), "flag agrees with path");
        }
    }
}

/* ------------------------------------------------------------------ *
 * Lifetime: the reference count, the not-ready window, and handles kept
 * across a teardown (#92)
 * ------------------------------------------------------------------ */

/* The zuc_status functions zucrypt.h declares whose first parameter is a
 * zuc_aes, zuc_hash or zuc_hmac handle, read from the header itself. */
static int handle_functions(char names[][64], int max)
{
    char path[1024], line[512];
    FILE *f;
    int n = 0;

    snprintf(path, sizeof path, "%s/../../../inst/include/zucrypt.h",
             fixture_dir);
    f = fopen(path, "r");
    if (f == NULL) {
        CHECK(0, "cannot read %s", path);
        return 0;
    }
    while (fgets(line, sizeof line, f) != NULL && n < max) {
        const char *name = line + strlen("zuc_status "), *paren, *param;
        size_t len;
        if (strncmp(line, "zuc_status zuc_", 15) != 0) continue;
        paren = strchr(name, '(');
        if (paren == NULL) continue;
        param = paren + 1;
        if (strncmp(param, "const ", 6) == 0) param += 6;
        if (strncmp(param, "zuc_aes *", 9) != 0 &&
            strncmp(param, "zuc_hash *", 10) != 0 &&
            strncmp(param, "zuc_hmac *", 10) != 0) continue;
        len = (size_t) (paren - name);
        if (len >= 64) continue;
        memcpy(names[n], name, len);
        names[n][len] = 0;
        n++;
    }
    fclose(f);
    return n;
}

static void test_lifetime(void)
{
    uint8_t k1[16], k2[16], zero[16] = {0}, out[64], c_new[16], m_new[32];
    size_t len;
    zuc_aes *a_old = NULL, *a_new = NULL;
    zuc_hmac *m_old = NULL, *m_new_h = NULL;
    zuc_hash *h_old = NULL;
    zuc_pkey *pk = NULL;

    context = "refcount";
    CHECK(zuc_int_live_contexts() == 0, "live at start: %ld",
          zuc_int_live_contexts());
    ST(zuc_init(), ZUC_OK);           /* a second reference */
    ST(zuc_shutdown(), ZUC_OK);       /* still up */
    ST(zuc_hash_compute(ZUC_ALG_SHA256, NULL, 0, out, sizeof out, &len),
       ZUC_OK);

    memset(k1, 1, sizeof k1);
    memset(k2, 2, sizeof k2);
    ST(zuc_aes_new(k1, 16, &a_old), ZUC_OK);
    ST(zuc_hmac_new(ZUC_ALG_SHA256, k1, 16, &m_old), ZUC_OK);
    ST(zuc_hash_new(ZUC_ALG_SHA256, &h_old), ZUC_OK);
    ST(zuc_pkey_import(ZUC_ALG_X25519, 1, k1, 16, &pk),
       ZUC_ERR_INVALID_ARGUMENT);

    context = "not ready";
    ST(zuc_shutdown(), ZUC_OK);       /* the last reference: torn down */
    ST(zuc_shutdown(), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_hash_compute(ZUC_ALG_SHA256, NULL, 0, out, sizeof out, &len),
       ZUC_ERR_NOT_READY);
    ST(zuc_hmac_compute(ZUC_ALG_SHA256, k1, 16, NULL, 0, out, sizeof out, &len),
       ZUC_ERR_NOT_READY);
    ST(zuc_aes_new(k1, 16, &a_new), ZUC_ERR_NOT_READY);
    ST(zuc_aes_cbc_encrypt(a_old, zero, 16, out), ZUC_ERR_NOT_READY);
    ST(zuc_hash_update(h_old, zero, 1), ZUC_ERR_NOT_READY);
    ST(zuc_random_bytes(out, 1), ZUC_ERR_NOT_READY);
    ST(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, NULL, 0, NULL, 0, 1, out, 16),
       ZUC_ERR_NOT_READY);
    ST(zuc_pkey_generate(ZUC_ALG_X25519, 0, &pk), ZUC_ERR_NOT_READY);
    CHECK(pk == NULL, "no key while down");

    /* zucrypt.h: on a handle that outlived the backend "every operation on
     * it returns ZUC_ERR_NOT_READY". Every function the header declares on
     * a zuc_aes, zuc_hash or zuc_hmac is called here, and the header is
     * read to prove none was left out (#142: the CBC state pair was). */
    context = "stale handles";
    ST(zuc_init(), ZUC_OK);
    ST(zuc_aes_new(k2, 16, &a_new), ZUC_OK);
    ST(zuc_hmac_new(ZUC_ALG_SHA256, k2, 16, &m_new_h), ZUC_OK);
    {
        const char *tested[32];
        int n_tested = 0, n_header, i, j;
        char header[32][64];
        uint8_t state[16];
#define STALE(name, call)                                                   \
        do {                                                                \
            tested[n_tested++] = name;                                      \
            ST(call, ZUC_ERR_NOT_READY);                                    \
        } while (0)
        memset(state, 0x5a, sizeof state);
        STALE("zuc_aes_cbc_set_state", zuc_aes_cbc_set_state(a_old, zero));
        STALE("zuc_aes_cbc_get_state", zuc_aes_cbc_get_state(a_old, state));
        CHECK(all_bytes(state, sizeof state, 0x5a),
              "a stale handle wrote its state");
        STALE("zuc_aes_cbc_encrypt", zuc_aes_cbc_encrypt(a_old, zero, 16, out));
        STALE("zuc_aes_cbc_decrypt", zuc_aes_cbc_decrypt(a_old, zero, 16, out));
        STALE("zuc_hmac_update", zuc_hmac_update(m_old, zero, 1));
        STALE("zuc_hmac_finish", zuc_hmac_finish(m_old, out, sizeof out, &len));
        STALE("zuc_hmac_reset", zuc_hmac_reset(m_old));
        STALE("zuc_hash_update", zuc_hash_update(h_old, zero, 1));
        STALE("zuc_hash_finish", zuc_hash_finish(h_old, out, sizeof out, &len));
        STALE("zuc_hash_reset", zuc_hash_reset(h_old));
#undef STALE
        n_header = handle_functions(header, 32);
        CHECK(n_header >= 10, "read %d handle functions from zucrypt.h",
              n_header);
        for (i = 0; i < n_header; i++) {
            int found = 0;
            for (j = 0; j < n_tested; j++) {
                if (strcmp(header[i], tested[j]) == 0) found = 1;
            }
            CHECK(found, "%s is not tested on a stale handle", header[i]);
        }
    }
    zuc_aes_free(a_old);
    zuc_hmac_free(m_old);
    zuc_hash_free(h_old);
    /* The new handles still hold their own keys. */
    {
        zuc_aes *ref = NULL;
        uint8_t c_ref[16], m_ref[32];
        ST(zuc_aes_cbc_set_state(a_new, zero), ZUC_OK);
        ST(zuc_aes_cbc_encrypt(a_new, zero, 16, c_new), ZUC_OK);
        ST(zuc_aes_new(k2, 16, &ref), ZUC_OK);
        ST(zuc_aes_cbc_set_state(ref, zero), ZUC_OK);
        ST(zuc_aes_cbc_encrypt(ref, zero, 16, c_ref), ZUC_OK);
        zuc_aes_free(ref);
        SAME(c_new, c_ref, 16);
        ST(zuc_hmac_update(m_new_h, (const uint8_t *) "abc", 3), ZUC_OK);
        ST(zuc_hmac_finish(m_new_h, m_new, sizeof m_new, &len), ZUC_OK);
        ST(zuc_hmac_compute(ZUC_ALG_SHA256, k2, 16, (const uint8_t *) "abc",
                            3, m_ref, sizeof m_ref, &len), ZUC_OK);
        SAME(m_new, m_ref, 32);
    }
    zuc_aes_free(a_new);
    zuc_hmac_free(m_new_h);
    CHECK(zuc_int_live_contexts() == 0, "live at end: %ld",
          zuc_int_live_contexts());
}

/* ------------------------------------------------------------------ *
 * Public keys: the RSA and EC vectors
 * ------------------------------------------------------------------ */

/* Minimal DER for RSAPrivateKey (RFC 8017 A.1.2) from the fixture's
 * integers, so the driver needs no PEM. */
static size_t der_len(uint8_t *p, size_t n)
{
    if (n < 128) { if (p) p[0] = (uint8_t) n; return 1; }
    if (n < 256) { if (p) { p[0] = 0x81; p[1] = (uint8_t) n; } return 2; }
    if (p) { p[0] = 0x82; p[1] = (uint8_t) (n >> 8); p[2] = (uint8_t) n; }
    return 3;
}

static size_t der_int(uint8_t *p, const uint8_t *v, size_t n)
{
    size_t pad, h;
    while (n > 1 && v[0] == 0) { v++; n--; }
    pad = (v[0] & 0x80) ? 1 : 0;
    if (p) p[0] = 0x02;
    h = 1 + der_len(p ? p + 1 : NULL, n + pad);
    if (p) {
        if (pad) p[h] = 0;
        memcpy(p + h + pad, v, n);
    }
    return h + pad + n;
}

static uint8_t *rsa_der(const table *keys, const char *id, size_t *out_len)
{
    static const char *cols[] = {"n", "e", "d", "p", "q", "dp", "dq", "qi"};
    uint8_t *part[9], *der;
    size_t plen[9], body = 0, h, off, i;
    int row = find_row(keys, id);
    static uint8_t zero = 0;

    part[0] = &zero;
    plen[0] = 1;
    for (i = 0; i < 8; i++) part[i + 1] = unhex(get(keys, row, cols[i]), &plen[i + 1]);
    for (i = 0; i < 9; i++) body += der_int(NULL, part[i], plen[i]);
    h = 1 + der_len(NULL, body);
    der = malloc(h + body);
    der[0] = 0x30;
    der_len(der + 1, body);
    for (i = 0, off = h; i < 9; i++) off += der_int(der + off, part[i], plen[i]);
    for (i = 1; i < 9; i++) free(part[i]);
    *out_len = h + body;
    return der;
}

static zuc_alg digest_of(const char *name)
{
    return name[0] ? zuc_alg_by_name(name) : ZUC_ALG_NONE;
}

static void test_rsa(void)
{
    table keys = read_table("rsa-keys.tsv"), t = read_table("rsa.tsv");
    uint8_t out[ZUC_PKEY_MAX_WRITE_SIZE], digest[64];
    size_t len, dlen;
    int r;

    for (r = 1; r < t.nrow; r++) {
        const char *op = get(&t, r, "operation"), *scheme = get(&t, r, "scheme");
        zuc_alg hash = digest_of(get(&t, r, "hash"));
        zuc_alg sch;
        uint8_t *der, *in, *want;
        size_t der_n, in_len, want_len;
        zuc_pkey *key = NULL, *pub = NULL;

        context = get(&t, r, "id");
        der = rsa_der(&keys, get(&t, r, "key"), &der_n);
        in = unhex(get(&t, r, "input"), &in_len);
        want = unhex(get(&t, r, "output"), &want_len);
        ST(zuc_pkey_parse(der, der_n, 1, &key), ZUC_OK);
        if (key == NULL) goto next;
        CHECK(zuc_pkey_type(key) == ZUC_ALG_RSA, "type");
        CHECK(zuc_pkey_is_private(key), "private");
        CHECK(zuc_pkey_bits(key) == 2048, "bits %zu", zuc_pkey_bits(key));
        /* It writes back the DER it was read from. */
        ST(zuc_pkey_write(key, ZUC_PKEY_PKCS1_DER, 0, out, sizeof out, &len),
           ZUC_OK);
        CHECK(len == der_n && memcmp(out, der, len) == 0, "PKCS#1 round trip");
        ST(zuc_pkey_write(key, ZUC_PKEY_PKCS1_DER, 0, out, len - 1, &len),
           ZUC_ERR_BAD_LENGTH);
        ST(zuc_pkey_public(key, &pub), ZUC_OK);
        CHECK(pub != NULL && !zuc_pkey_is_private(pub), "public half");

        if (strcmp(op, "decrypt") == 0) {
            /* `output` is the published ciphertext, `input` its plaintext. */
            sch = strcmp(scheme, "oaep") == 0 ? ZUC_ALG_RSA_OAEP
                                              : ZUC_ALG_RSA_PKCS1V15_CRYPT;
            if (sch == ZUC_ALG_RSA_OAEP && hash == ZUC_ALG_NONE) {
                hash = ZUC_ALG_SHA1;
            }
            memset(out, 0xee, sizeof out);
            ST(zuc_pkey_decrypt(key, sch, hash, want, want_len, out,
                                sizeof out, &len), ZUC_OK);
            CHECK(len == in_len && memcmp(out, in, len) == 0, "plaintext");
            want[want_len / 2] ^= 1;
            ST(zuc_pkey_decrypt(key, sch, hash, want, want_len, out,
                                sizeof out, &len), ZUC_ERR_AUTH);
            want[want_len / 2] ^= 1;
            ST(zuc_pkey_decrypt(pub, sch, hash, want, want_len, out,
                                sizeof out, &len), ZUC_ERR_INVALID_ARGUMENT);
            /* What it encrypts, it decrypts. */
            {
                uint8_t ct[1024], pt[1024];
                size_t ct_len, pt_len;
                ST(zuc_pkey_encrypt(pub, sch, hash, in, in_len, ct,
                                    sizeof ct, &ct_len), ZUC_OK);
                CHECK(ct_len == want_len, "ciphertext length");
                CHECK(memcmp(ct, want, want_len) != 0, "encryption is random");
                ST(zuc_pkey_decrypt(key, sch, hash, ct, ct_len, pt, sizeof pt,
                                    &pt_len), ZUC_OK);
                CHECK(pt_len == in_len && memcmp(pt, in, pt_len) == 0,
                      "round trip");
            }
        } else {
            sch = strcmp(scheme, "pss") == 0 ? ZUC_ALG_RSA_PSS
                                             : ZUC_ALG_RSA_PKCS1V15_SIGN;
            ST(zuc_hash_compute(hash, in, in_len, digest, sizeof digest, &dlen),
               ZUC_OK);
            if (strcmp(op, "sign") == 0) {
                ST(zuc_pkey_sign_hash(key, sch, hash, digest, dlen, out,
                                      sizeof out, &len), ZUC_OK);
                CHECK(len == want_len && memcmp(out, want, len) == 0,
                      "signature");
                ST(zuc_pkey_sign_hash(pub, sch, hash, digest, dlen, out,
                                      sizeof out, &len),
                   ZUC_ERR_INVALID_ARGUMENT);
            }
            ST(zuc_pkey_verify_hash(pub, sch, hash, digest, dlen, want,
                                    want_len), ZUC_OK);
            ST(zuc_pkey_verify_hash(key, sch, hash, digest, dlen, want,
                                    want_len), ZUC_OK);
            want[want_len - 1] ^= 1;
            ST(zuc_pkey_verify_hash(pub, sch, hash, digest, dlen, want,
                                    want_len), ZUC_ERR_AUTH);
            want[want_len - 1] ^= 1;
            digest[0] ^= 1;
            ST(zuc_pkey_verify_hash(pub, sch, hash, digest, dlen, want,
                                    want_len), ZUC_ERR_AUTH);
            ST(zuc_pkey_verify_hash(pub, sch, hash, digest, dlen - 1, want,
                                    want_len), ZUC_ERR_BAD_LENGTH);
        }
    next:
        zuc_pkey_free(key);
        zuc_pkey_free(pub);
        free(der);
        free(in);
        free(want);
    }
    context = "rsa parse";
    {
        uint8_t junk[64];
        zuc_pkey *key = NULL;
        memset(junk, 0x30, sizeof junk);
        ST(zuc_pkey_parse(junk, sizeof junk, 1, &key), ZUC_ERR_INVALID_ARGUMENT);
        CHECK(key == NULL, "no key from junk");
        ST(zuc_pkey_parse(NULL, 0, 1, &key), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_pkey_parse(junk, sizeof junk, 1, NULL), ZUC_ERR_INVALID_ARGUMENT);
    }
}

static zuc_alg curve_of(const char *name)
{
    if (strcmp(name, "P-256") == 0) return ZUC_ALG_EC_P256;
    if (strcmp(name, "P-384") == 0) return ZUC_ALG_EC_P384;
    if (strcmp(name, "P-521") == 0) return ZUC_ALG_EC_P521;
    if (strcmp(name, "X25519") == 0) return ZUC_ALG_X25519;
    return ZUC_ALG_NONE;
}

/* The fixture key `id` as a handle: private from d when it has one and
 * `want_private`, else public from x (X25519) or 04 || x || y. */
static zuc_pkey *ec_key(const table *keys, const char *id, int want_private)
{
    int row = find_row(keys, id);
    zuc_alg type = curve_of(get(keys, row, "curve"));
    const char *d = get(keys, row, "d");
    zuc_pkey *key = NULL;
    uint8_t *b, *x, *y, pt[1 + 2 * 66];
    size_t n, xn, yn;

    if (want_private && d[0]) {
        b = unhex(d, &n);
        ST(zuc_pkey_import(type, 1, b, n, &key), ZUC_OK);
        free(b);
        return key;
    }
    x = unhex(get(keys, row, "x"), &xn);
    if (type == ZUC_ALG_X25519) {
        ST(zuc_pkey_import(type, 0, x, xn, &key), ZUC_OK);
    } else {
        y = unhex(get(keys, row, "y"), &yn);
        pt[0] = 0x04;
        memcpy(pt + 1, x, xn);
        memcpy(pt + 1 + xn, y, yn);
        ST(zuc_pkey_import(type, 0, pt, 1 + xn + yn, &key), ZUC_OK);
        free(y);
    }
    free(x);
    return key;
}

static void test_ec(void)
{
    table keys = read_table("ec-keys.tsv"), t = read_table("ec.tsv");
    uint8_t out[ZUC_PKEY_MAX_WRITE_SIZE], digest[64];
    size_t len, dlen;
    int r, first;
    const char *last_key = "";

    for (r = 1; r < t.nrow; r++) {
        const char *op = get(&t, r, "operation");
        uint8_t *in, *want;
        size_t in_len, want_len;
        zuc_pkey *key, *pub;

        context = get(&t, r, "id");
        /* The vector itself on every row; the costlier extra checks on the
         * first row of each key only. */
        first = strcmp(get(&t, r, "key"), last_key) != 0;
        last_key = get(&t, r, "key");
        in = unhex(get(&t, r, "input"), &in_len);
        want = unhex(get(&t, r, "output"), &want_len);
        key = ec_key(&keys, get(&t, r, "key"), 1);
        pub = ec_key(&keys, get(&t, r, "key"), 0);
        if (key == NULL || pub == NULL) goto next;

        if (strcmp(op, "agree") == 0) {
            zuc_pkey *peer = ec_key(&keys, get(&t, r, "peer"), 0);
            ST(zuc_pkey_agree(key, peer, out, sizeof out, &len), ZUC_OK);
            CHECK(len == want_len && memcmp(out, want, len) == 0, "secret");
            ST(zuc_pkey_agree(pub, peer, out, sizeof out, &len),
               ZUC_ERR_INVALID_ARGUMENT);
            ST(zuc_pkey_agree(key, peer, out, want_len - 1, &len),
               ZUC_ERR_BAD_LENGTH);
            zuc_pkey_free(peer);
        } else {
            zuc_alg hash = digest_of(get(&t, r, "hash"));
            ST(zuc_hash_compute(hash, in, in_len, digest, sizeof digest, &dlen),
               ZUC_OK);
            if (strcmp(op, "sign-deterministic") == 0) {
                ST(zuc_pkey_sign_hash(key, ZUC_ALG_ECDSA_DETERMINISTIC, hash,
                                      digest, dlen, out, sizeof out, &len),
                   ZUC_OK);
                CHECK(len == want_len && memcmp(out, want, len) == 0,
                      "signature");
                /* Randomised signing gives another signature that verifies. */
                if (first) {
                    ST(zuc_pkey_sign_hash(key, ZUC_ALG_ECDSA, hash, digest,
                                          dlen, out, sizeof out, &len), ZUC_OK);
                    CHECK(len == want_len && memcmp(out, want, len) != 0,
                          "randomised signature");
                    ST(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA, hash, digest,
                                            dlen, out, len), ZUC_OK);
                }
            }
            ST(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA, hash, digest, dlen,
                                    want, want_len), ZUC_OK);
            if (!first) goto next;
            want[0] ^= 1;
            ST(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA, hash, digest, dlen,
                                    want, want_len), ZUC_ERR_AUTH);
            want[0] ^= 1;
            want[want_len - 1] ^= 1;
            ST(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA, hash, digest, dlen,
                                    want, want_len), ZUC_ERR_AUTH);
            want[want_len - 1] ^= 1;
            ST(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA, hash, digest, dlen,
                                    want, want_len - 1), ZUC_ERR_AUTH);
        }
        if (!first) goto next;
        /* Raw key material round-trips through export. */
        ST(zuc_pkey_export(pub, 0, out, sizeof out, &len), ZUC_OK);
        {
            zuc_pkey *again = NULL;
            uint8_t out2[ZUC_PKEY_MAX_WRITE_SIZE];
            size_t len2;
            ST(zuc_pkey_import(zuc_pkey_type(pub), 0, out, len, &again), ZUC_OK);
            ST(zuc_pkey_export(again, 0, out2, sizeof out2, &len2), ZUC_OK);
            CHECK(len2 == len && memcmp(out, out2, len) == 0, "export round trip");
            zuc_pkey_free(again);
        }
    next:
        zuc_pkey_free(key);
        zuc_pkey_free(pub);
        free(in);
        free(want);
    }
    context = "ec arguments";
    {
        uint8_t pt[65];
        zuc_pkey *key = NULL;
        memset(pt, 0, sizeof pt);
        pt[0] = 0x04;
        pt[64] = 1;
        ST(zuc_pkey_import(ZUC_ALG_EC_P256, 0, pt, sizeof pt, &key),
           ZUC_ERR_INVALID_ARGUMENT);
        CHECK(key == NULL, "no key off the curve");
        ST(zuc_pkey_import(ZUC_ALG_EC_P256, 1, pt, 31, &key),
           ZUC_ERR_INVALID_ARGUMENT);
    }
}

/* ------------------------------------------------------------------ *
 * The RSA size rule: 1024 to 4096 bits, whole bytes (#93, #141)
 * ------------------------------------------------------------------ */

static int rsa_size_ok(size_t bits)
{
    return bits >= 1024 && bits <= 4096 && bits % 8 == 0;
}

static void test_rsa_limits(void)
{
    table t = read_table("rsa-limit.tsv");
    static const size_t gen_ok[] = {1024, 1032};
    static const size_t gen_bad[] = {0, 512, 1016, 1023, 1025, 1026, 1028,
                                     4097, 4104, 8192};
    zuc_pkey *key;
    size_t i;
    int r, want_private;

    for (r = 1; r < t.nrow; r++) {
        const char *enc = get(&t, r, "encoding");
        size_t bits = (size_t) strtoul(get(&t, r, "bits"), NULL, 10), n;
        uint8_t *der = unhex(get(&t, r, "data"), &n);
        int is_private = strncmp(enc, "private", 7) == 0;

        context = get(&t, r, "id");
        for (want_private = 0; want_private <= is_private; want_private++) {
            key = NULL;
            if (rsa_size_ok(bits)) {
                ST(zuc_pkey_parse(der, n, want_private, &key), ZUC_OK);
                CHECK(zuc_pkey_bits(key) == bits, "read at %zu bits, not %zu",
                      zuc_pkey_bits(key), bits);
            } else {
                ST(zuc_pkey_parse(der, n, want_private, &key),
                   ZUC_ERR_UNSUPPORTED);
                CHECK(key == NULL, "no handle for a refused key");
            }
            zuc_pkey_free(key);
        }
        /* The raw form is PKCS#1 DER: the same rule through import. */
        if (strstr(enc, "pkcs1_der") != NULL) {
            key = NULL;
            ST(zuc_pkey_import(ZUC_ALG_RSA, is_private, der, n, &key),
               rsa_size_ok(bits) ? ZUC_OK : ZUC_ERR_UNSUPPORTED);
            zuc_pkey_free(key);
        }
        free(der);
    }

    context = "rsa generate";
    for (i = 0; i < sizeof gen_ok / sizeof gen_ok[0]; i++) {
        key = NULL;
        ST(zuc_pkey_generate(ZUC_ALG_RSA, gen_ok[i], &key), ZUC_OK);
        CHECK(zuc_pkey_bits(key) == gen_ok[i], "generated %zu bits, not %zu",
              zuc_pkey_bits(key), gen_ok[i]);
        zuc_pkey_free(key);
    }
    for (i = 0; i < sizeof gen_bad / sizeof gen_bad[0]; i++) {
        key = NULL;
        ST(zuc_pkey_generate(ZUC_ALG_RSA, gen_bad[i], &key), ZUC_ERR_BAD_LENGTH);
        CHECK(key == NULL, "no handle for %zu bits", gen_bad[i]);
    }
}

/* ------------------------------------------------------------------ *
 * Output-buffer contracts of zuc_pkey_write, _decrypt and _agree (#142)
 * ------------------------------------------------------------------ */

static void test_pkey_outputs(void)
{
    table rk = read_table("rsa-keys.tsv"), ek = read_table("ec-keys.tsv");
    static uint8_t want[ZUC_PKEY_MAX_WRITE_SIZE], got[ZUC_PKEY_MAX_WRITE_SIZE + 1];
    uint8_t *der, ct[512];
    size_t der_n, need, len, ct_len, size;
    zuc_pkey *keys[3] = {NULL, NULL, NULL}, *peer = NULL, *pub = NULL;
    int k, f, p;

    der = rsa_der(&rk, "rfc7515-a2", &der_n);
    ST(zuc_pkey_parse(der, der_n, 1, &keys[0]), ZUC_OK);
    free(der);
    keys[1] = ec_key(&ek, "rfc5903-p256-i", 1);
    keys[2] = ec_key(&ek, "rfc7748-alice", 1);
    peer = ec_key(&ek, "rfc5903-p256-r", 0);
    if (!keys[0] || !keys[1] || !keys[2] || !peer) return;

    /* Every encoding at exactly its length, a byte under and a byte over:
     * the exact size is enough, a byte under is BAD_LENGTH with the buffer
     * zeroed, and nothing is written past the length reported (PEM has no
     * terminating NUL). */
    context = "write straddle";
    for (k = 0; k < 3; k++) {
        for (f = ZUC_PKEY_PKCS1_DER; f <= ZUC_PKEY_INFO_PEM; f++) {
            for (p = 0; p <= 1; p++) {
                if (zuc_pkey_write(keys[k], (zuc_pkey_format) f, p, want,
                                   sizeof want, &need) != ZUC_OK) {
                    continue;
                }
                for (size = need - 1; size <= need + 1; size++) {
                    memset(got, 0x5a, sizeof got);
                    ST(zuc_pkey_write(keys[k], (zuc_pkey_format) f, p, got,
                                      size, &len),
                       size < need ? ZUC_ERR_BAD_LENGTH : ZUC_OK);
                    if (size < need) {
                        CHECK(len == 0 && all_bytes(got, size, 0),
                              "key %d format %d: a refusal is wiped", k, f);
                        CHECK(got[size] == 0x5a, "wrote past the buffer");
                    } else {
                        CHECK(len == need && memcmp(got, want, need) == 0,
                              "key %d format %d public %d at %zu bytes", k, f,
                              p, size);
                        CHECK(size == need || got[need] == 0x5a,
                              "key %d format %d wrote past its length", k, f);
                    }
                }
            }
        }
    }

    /* "On any failure the whole output buffer is zeroed", early refusals
     * included. */
    context = "decrypt refusals";
    ST(zuc_pkey_public(keys[0], &pub), ZUC_OK);
    ST(zuc_pkey_encrypt(keys[0], ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256,
                        (const uint8_t *) "abc", 3, ct, sizeof ct, &ct_len),
       ZUC_OK);
#define REFUSED(call, status)                                               \
    do {                                                                    \
        memset(got, 0x5a, 300);                                             \
        len = 99;                                                           \
        ST(call, status);                                                   \
        CHECK(len == 0 && all_bytes(got, 256, 0) && got[256] == 0x5a,       \
              "%s left its output", #call);                                 \
    } while (0)
    REFUSED(zuc_pkey_decrypt(pub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, ct,
                             ct_len, got, 256, &len),
            ZUC_ERR_INVALID_ARGUMENT);
    REFUSED(zuc_pkey_decrypt(keys[0], ZUC_ALG_RSA_OAEP, ZUC_ALG_NONE, ct,
                             ct_len, got, 256, &len), ZUC_ERR_UNSUPPORTED);
    REFUSED(zuc_pkey_decrypt(keys[1], ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, ct,
                             ct_len, got, 256, &len), ZUC_ERR_UNSUPPORTED);
    REFUSED(zuc_pkey_decrypt(keys[0], ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, NULL,
                             ct_len, got, 256, &len),
            ZUC_ERR_INVALID_ARGUMENT);
    REFUSED(zuc_pkey_decrypt(keys[0], ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, ct,
                             ct_len - 1, got, 256, &len), ZUC_ERR_AUTH);
    context = "agree refusals";
    REFUSED(zuc_pkey_agree(keys[0], peer, got, 256, &len), ZUC_ERR_UNSUPPORTED);
    REFUSED(zuc_pkey_agree(pub, peer, got, 256, &len), ZUC_ERR_UNSUPPORTED);
    REFUSED(zuc_pkey_agree(keys[2], peer, got, 256, &len),
            ZUC_ERR_INVALID_ARGUMENT);
    REFUSED(zuc_pkey_agree(keys[1], NULL, got, 256, &len),
            ZUC_ERR_INVALID_ARGUMENT);
    {
        zuc_pkey *ppub = NULL;
        ST(zuc_pkey_public(keys[1], &ppub), ZUC_OK);
        REFUSED(zuc_pkey_agree(ppub, peer, got, 256, &len),
                ZUC_ERR_INVALID_ARGUMENT);
        zuc_pkey_free(ppub);
    }
    memset(got, 0x5a, 300);
    ST(zuc_pkey_agree(keys[1], peer, got, 31, &len), ZUC_ERR_BAD_LENGTH);
    CHECK(len == 0 && all_bytes(got, 31, 0) && got[31] == 0x5a,
          "a short agreement buffer is wiped, and only it");
#undef REFUSED
    for (k = 0; k < 3; k++) zuc_pkey_free(keys[k]);
    zuc_pkey_free(peer);
    zuc_pkey_free(pub);
}

/* ------------------------------------------------------------------ *
 * A failing entropy source is reported as ZUC_ERR_ENTROPY (#140)
 * ------------------------------------------------------------------ */

static void test_entropy(void)
{
    table rk = read_table("rsa-keys.tsv"), ek = read_table("ec-keys.tsv");
    static uint8_t want[ZUC_PKEY_MAX_WRITE_SIZE], got[ZUC_PKEY_MAX_WRITE_SIZE];
    uint8_t *der, ct[512], msg[3] = {'a', 'b', 'c'};
    size_t der_n, want_len, got_len, ct_len;
    zuc_pkey *keys[3] = {NULL, NULL, NULL}, *peer = NULL, *bob = NULL;
    zuc_status ws, gs;
    long entropy = 0;
    int k, f, pub;

    der = rsa_der(&rk, "rfc7515-a2", &der_n);
    ST(zuc_pkey_parse(der, der_n, 1, &keys[0]), ZUC_OK);
    free(der);
    keys[1] = ec_key(&ek, "rfc5903-p256-i", 1);
    keys[2] = ec_key(&ek, "rfc7748-alice", 1);
    peer = ec_key(&ek, "rfc5903-p256-r", 0);
    bob = ec_key(&ek, "rfc7748-bob", 0);
    if (!keys[0] || !keys[1] || !keys[2] || !peer || !bob) return;

    /* Every encoding: the answer a working source gives, or ENTROPY. */
    for (k = 0; k < 3; k++) {
        for (f = ZUC_PKEY_PKCS1_DER; f <= ZUC_PKEY_INFO_PEM; f++) {
            for (pub = 0; pub <= 1; pub++) {
                context = "entropy write";
                ws = zuc_pkey_write(keys[k], (zuc_pkey_format) f, pub, want,
                                    sizeof want, &want_len);
                zuc_int_random_fail(1);
                gs = zuc_pkey_write(keys[k], (zuc_pkey_format) f, pub, got,
                                    sizeof got, &got_len);
                zuc_int_random_fail(0);
                if (gs == ZUC_ERR_ENTROPY) {
                    entropy++;
                    continue;
                }
                CHECK(gs == ws && (ws != ZUC_OK || (got_len == want_len &&
                      memcmp(got, want, want_len) == 0)),
                      "key %d format %d public %d: %s, working source %s",
                      k, f, pub, zuc_status_name(gs), zuc_status_name(ws));
            }
        }
    }
    /* The case the issue names: SubjectPublicKeyInfo from a private P-256
     * key derives the public point, with blinding. */
    context = "entropy spki";
    zuc_int_random_fail(1);
    ST(zuc_pkey_write(keys[1], ZUC_PKEY_INFO_DER, 1, got, sizeof got,
                      &got_len), ZUC_ERR_ENTROPY);
    zuc_int_random_fail(0);

    /* Decryption is blinded and agreement draws a blinding scalar, so a
     * failing source is ENTROPY, never AUTH ("forged") or INVALID_ARGUMENT
     * ("bad peer"). */
    context = "entropy decrypt";
    ST(zuc_pkey_encrypt(keys[0], ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, msg, 3,
                        ct, sizeof ct, &ct_len), ZUC_OK);
    zuc_int_random_fail(1);
    memset(got, 0x5a, sizeof got);
    ST(zuc_pkey_decrypt(keys[0], ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, ct, ct_len,
                        got, sizeof got, &got_len), ZUC_ERR_ENTROPY);
    CHECK(got_len == 0 && all_bytes(got, sizeof got, 0),
          "a failed decryption is wiped");
    zuc_int_random_fail(0);
    ST(zuc_pkey_encrypt(keys[0], ZUC_ALG_RSA_PKCS1V15_CRYPT, ZUC_ALG_NONE,
                        msg, 3, ct, sizeof ct, &ct_len), ZUC_OK);
    zuc_int_random_fail(1);
    ST(zuc_pkey_decrypt(keys[0], ZUC_ALG_RSA_PKCS1V15_CRYPT, ZUC_ALG_NONE, ct,
                        ct_len, got, sizeof got, &got_len), ZUC_ERR_ENTROPY);
    zuc_int_random_fail(0);
    context = "entropy agree";
    zuc_int_random_fail(1);
    ST(zuc_pkey_agree(keys[1], peer, got, sizeof got, &got_len),
       ZUC_ERR_ENTROPY);
    ST(zuc_pkey_agree(keys[2], bob, got, sizeof got, &got_len),
       ZUC_ERR_ENTROPY);
    zuc_int_random_fail(0);
    /* And the control: the backend works once the source does. */
    ST(zuc_pkey_agree(keys[1], peer, got, sizeof got, &got_len), ZUC_OK);
    CHECK(entropy > 0, "no write drew on the source");
    for (k = 0; k < 3; k++) zuc_pkey_free(keys[k]);
    zuc_pkey_free(peer);
    zuc_pkey_free(bob);
}

/* ------------------------------------------------------------------ *
 * DER and PEM, built by hand for the reader tests
 * ------------------------------------------------------------------ */

/* DER helpers for building inputs: a TLV around `v`, into a fresh buffer. */
static uint8_t *tlv_wrap(uint8_t tag, const uint8_t *v, size_t n,
                         size_t *out_len)
{
    size_t h = 1 + der_len(NULL, n);
    uint8_t *p = malloc(h + n);
    p[0] = tag;
    der_len(p + 1, n);
    memcpy(p + h, v, n);
    *out_len = h + n;
    return p;
}

static uint8_t *concat(const uint8_t *a, size_t an, const uint8_t *b,
                       size_t bn, size_t *out_len)
{
    uint8_t *p = malloc(an + bn);
    memcpy(p, a, an);
    memcpy(p + an, b, bn);
    *out_len = an + bn;
    return p;
}

/* PEM around `der` with `label`, NUL-free, lines of 64. */
static char *pem_wrap(const char *label, const uint8_t *der, size_t n,
                      size_t *out_len)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *p = malloc(4 * n / 3 + n / 48 + 200), *q = p;
    size_t i, col = 0;

    q += sprintf(q, "-----BEGIN %s-----\n", label);
    for (i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t) der[i] << 16;
        if (i + 1 < n) v |= (uint32_t) der[i + 1] << 8;
        if (i + 2 < n) v |= der[i + 2];
        *q++ = b64[(v >> 18) & 63];
        *q++ = b64[(v >> 12) & 63];
        *q++ = i + 1 < n ? b64[(v >> 6) & 63] : '=';
        *q++ = i + 2 < n ? b64[v & 63] : '=';
        if ((col += 4) == 64) {
            *q++ = '\n';
            col = 0;
        }
    }
    if (col) *q++ = '\n';
    q += sprintf(q, "-----END %s-----\n", label);
    *out_len = (size_t) (q - p);
    return p;
}

static const uint8_t RSA_ALG_ID[] = {
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00
};

static uint8_t *limit_row(const table *t, const char *id, size_t *n)
{
    return unhex(get(t, find_row(t, id), "data"), n);
}

/* ------------------------------------------------------------------ *
 * EC and X25519 encodings against OpenSSL's (#126)
 * ------------------------------------------------------------------ */

/* The zuc_pkey_format a fixture format names, and whether it is one of
 * the private-key encodings. */
static zuc_pkey_format format_of(const char *name, int *is_private)
{
    *is_private = strncmp(name, "spki", 4) != 0;
    if (strcmp(name, "sec1-der") == 0) return ZUC_PKEY_PKCS1_DER;
    if (strcmp(name, "sec1-pem") == 0) return ZUC_PKEY_PKCS1_PEM;
    if (strstr(name, "-der") != NULL) return ZUC_PKEY_INFO_DER;
    return ZUC_PKEY_INFO_PEM;
}

static void test_ec_encodings(void)
{
    table keys = read_table("ec-keys.tsv"), t = read_table("ec-encodings.tsv");
    static uint8_t out[ZUC_PKEY_MAX_WRITE_SIZE], again[ZUC_PKEY_MAX_WRITE_SIZE];
    size_t len, len2;
    int r;

    for (r = 1; r < t.nrow; r++) {
        const char *kid = get(&t, r, "key"), *fmt = get(&t, r, "format");
        int is_private;
        zuc_pkey_format f = format_of(fmt, &is_private);
        size_t want_len;
        uint8_t *want = unhex(get(&t, r, "encoding"), &want_len);
        zuc_pkey *priv = ec_key(&keys, kid, 1), *pub = ec_key(&keys, kid, 0);
        zuc_pkey *read = NULL, *half = NULL;
        uint8_t *x_der = NULL;
        const uint8_t *exp;
        size_t x_n = 0, exp_len;

        context = get(&t, r, "id");
        if (priv == NULL || pub == NULL) goto next;
        /* X25519 private keys are written with the scalar clamped (RFC 7748
         * section 5), OpenSSL's as given: #175. Until that is fixed the
         * comparison is with OpenSSL's encoding of the clamped scalar,
         * which is the same DER structure; for PEM, the DER row put in PEM
         * here, after checking that doing so gives OpenSSL's PEM. */
        x_der = NULL;
        if (is_private && zuc_pkey_type(priv) == ZUC_ALG_X25519) {
            char id[64];
            size_t dn, pn;
            uint8_t *d;
            char *p;
            snprintf(id, sizeof id, "%s-pkcs8-der", kid);
            d = unhex(get(&t, find_row(&t, id), "encoding"), &dn);
            if (f == ZUC_PKEY_INFO_PEM) {
                p = pem_wrap("PRIVATE KEY", d, dn, &pn);
                CHECK(pn == want_len && memcmp(p, want, pn) == 0,
                      "pem_wrap() is not OpenSSL's PEM");
                free(p);
            }
            d[dn - 32] &= 248;
            d[dn - 1] = (uint8_t) ((d[dn - 1] & 127) | 64);
            x_der = d;
            x_n = dn;
            if (f == ZUC_PKEY_INFO_PEM) {
                x_der = (uint8_t *) pem_wrap("PRIVATE KEY", d, dn, &x_n);
                free(d);
            }
        }
        exp = x_der != NULL ? x_der : want;
        exp_len = x_der != NULL ? x_n : want_len;
        /* Written as OpenSSL writes it: each private encoding from the
         * private key, SubjectPublicKeyInfo from either half. */
        if (is_private) {
            ST(zuc_pkey_write(priv, f, 0, out, sizeof out, &len), ZUC_OK);
            CHECK(len == exp_len && memcmp(out, exp, len) == 0,
                  "wrote %zu bytes; OpenSSL's are %zu", len, exp_len);
        } else {
            ST(zuc_pkey_write(priv, f, 1, out, sizeof out, &len), ZUC_OK);
            CHECK(len == want_len && memcmp(out, want, len) == 0,
                  "the private key's public half");
            ST(zuc_pkey_write(pub, f, 0, out, sizeof out, &len), ZUC_OK);
            CHECK(len == want_len && memcmp(out, want, len) == 0,
                  "the public key");
            /* PKCS#1 has no public EC or X25519 form. */
            len = 99;
            ST(zuc_pkey_write(pub, f == ZUC_PKEY_INFO_DER ? ZUC_PKEY_PKCS1_DER
                                                          : ZUC_PKEY_PKCS1_PEM,
                              0, out, sizeof out, &len), ZUC_ERR_UNSUPPORTED);
            CHECK(len == 0, "a refused write reports no length");
        }
        /* Read back: OpenSSL's bytes are the same key, which writes them
         * again. */
        ST(zuc_pkey_parse(want, want_len, is_private, &read), ZUC_OK);
        if (read == NULL) goto next;
        CHECK(zuc_pkey_type(read) == zuc_pkey_type(priv), "type");
        CHECK(zuc_pkey_bits(read) == zuc_pkey_bits(priv), "bits");
        CHECK(zuc_pkey_is_private(read) == is_private, "half");
        ST(zuc_pkey_write(read, f, 0, again, sizeof again, &len2), ZUC_OK);
        CHECK(len2 == exp_len && memcmp(again, exp, len2) == 0,
              "read and written again");
        if (is_private) {
            /* The public reader keeps the public half of a private key,
             * which is OpenSSL's SubjectPublicKeyInfo. */
            char id[64];
            size_t spki_len;
            uint8_t *spki;
            snprintf(id, sizeof id, "%s-spki-der", kid);
            spki = unhex(get(&t, find_row(&t, id), "encoding"), &spki_len);
            ST(zuc_pkey_parse(want, want_len, 0, &half), ZUC_OK);
            CHECK(half != NULL && !zuc_pkey_is_private(half), "public half");
            if (half != NULL) {
                ST(zuc_pkey_write(half, ZUC_PKEY_INFO_DER, 0, again,
                                  sizeof again, &len2), ZUC_OK);
                CHECK(len2 == spki_len && memcmp(again, spki, len2) == 0,
                      "the public half is OpenSSL's SubjectPublicKeyInfo");
            }
            free(spki);
        } else {
            /* A private reader handed a public key refuses it. */
            ST(zuc_pkey_parse(want, want_len, 1, &half),
               ZUC_ERR_INVALID_ARGUMENT);
            CHECK(half == NULL, "no handle for a refusal");
        }
    next:
        zuc_pkey_free(read);
        zuc_pkey_free(half);
        zuc_pkey_free(priv);
        zuc_pkey_free(pub);
        free(want);
        free(x_der);
    }

    /* X25519 has no SEC1 form; and a format outside the enumeration is a
     * usage error for every key type. */
    context = "ec formats";
    {
        zuc_pkey *x = ec_key(&keys, "rfc7748-alice", 1);
        zuc_pkey *p = ec_key(&keys, "rfc6979-p256", 1);
        ST(zuc_pkey_write(x, ZUC_PKEY_PKCS1_DER, 0, out, sizeof out, &len),
           ZUC_ERR_UNSUPPORTED);
        ST(zuc_pkey_write(x, ZUC_PKEY_PKCS1_PEM, 0, out, sizeof out, &len),
           ZUC_ERR_UNSUPPORTED);
        ST(zuc_pkey_write(p, (zuc_pkey_format) 0, 0, out, sizeof out, &len),
           ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_pkey_write(p, (zuc_pkey_format) 5, 0, out, sizeof out, &len),
           ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_pkey_write(x, (zuc_pkey_format) 0, 1, out, sizeof out, &len),
           ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_pkey_write(x, (zuc_pkey_format) 5, 1, out, sizeof out, &len),
           ZUC_ERR_INVALID_ARGUMENT);
        zuc_pkey_free(x);
        zuc_pkey_free(p);
    }
}

/* ------------------------------------------------------------------ *
 * The RSA size reader's own answers (#127)
 * ------------------------------------------------------------------ */

static void test_rsa_size_reader(void)
{
    table t = read_table("rsa-limit.tsv");
    uint8_t *spki, *pkcs8, *pub1, *priv1, *a, *b, *c;
    size_t spki_n, pkcs8_n, pub1_n, priv1_n, an, bn, cn;
    zuc_pkey *key = NULL;

    spki = limit_row(&t, "rsa8192-public-spki-der", &spki_n);
    pkcs8 = limit_row(&t, "rsa8192-private-pkcs8-der", &pkcs8_n);
    pub1 = limit_row(&t, "rsa8192-public-pkcs1-der", &pub1_n);
    priv1 = limit_row(&t, "rsa8192-private-pkcs1-der", &priv1_n);

    /* The reader looks inside one wrapper, never two: a SubjectPublicKeyInfo
     * or PrivateKeyInfo around another one is not a key, whatever size the
     * innermost modulus is. */
    context = "rsa nested spki";
    {
        uint8_t bits[1 + 8192];
        bits[0] = 0;
        memcpy(bits + 1, spki, spki_n);
        a = tlv_wrap(0x03, bits, 1 + spki_n, &an);
        b = concat(RSA_ALG_ID, sizeof RSA_ALG_ID, a, an, &bn);
        c = tlv_wrap(0x30, b, bn, &cn);
        ST(zuc_pkey_parse(c, cn, 0, &key), ZUC_ERR_INVALID_ARGUMENT);
        free(a); free(b); free(c);
    }
    context = "rsa nested pkcs8";
    {
        static const uint8_t version[] = {0x02, 0x01, 0x00};
        uint8_t *v_alg;
        size_t v_alg_n;
        v_alg = concat(version, 3, RSA_ALG_ID, sizeof RSA_ALG_ID, &v_alg_n);
        a = tlv_wrap(0x04, pkcs8, pkcs8_n, &an);
        b = concat(v_alg, v_alg_n, a, an, &bn);
        c = tlv_wrap(0x30, b, bn, &cn);
        ST(zuc_pkey_parse(c, cn, 1, &key), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_pkey_parse(c, cn, 0, &key), ZUC_ERR_INVALID_ARGUMENT);
        free(a); free(b); free(c); free(v_alg);
    }

    /* The bit count, straddled: a 4096-bit modulus behind two redundant
     * zero bytes is inside the rule, so a key the reader refuses for
     * something else (here an even modulus) is malformed, not unsupported;
     * 0x01 followed by 512 bytes is 4097 bits, outside it. Each also
     * through import, which applies the same rule to PKCS#1. */
    context = "rsa modulus bits";
    {
        static uint8_t mod[2 + 513], body[600];
        static const uint8_t e[] = {0x02, 0x03, 0x01, 0x00, 0x01};
        size_t mod_n;
        uint8_t *m;

        memset(mod, 0, sizeof mod);
        mod[2] = 0x80;                     /* 00 00 80 00 .. 00: even */
        m = tlv_wrap(0x02, mod, 2 + 512, &mod_n);
        memcpy(body, m, mod_n);
        memcpy(body + mod_n, e, sizeof e);
        a = tlv_wrap(0x30, body, mod_n + sizeof e, &an);
        ST(zuc_pkey_parse(a, an, 0, &key), ZUC_ERR_INVALID_ARGUMENT);
        ST(zuc_pkey_import(ZUC_ALG_RSA, 0, a, an, &key),
           ZUC_ERR_INVALID_ARGUMENT);
        free(m); free(a);

        memset(mod, 0x5b, sizeof mod);
        mod[0] = 0x01;                     /* 01 then 512 bytes: 4097 bits */
        m = tlv_wrap(0x02, mod, 513, &mod_n);
        memcpy(body, m, mod_n);
        memcpy(body + mod_n, e, sizeof e);
        a = tlv_wrap(0x30, body, mod_n + sizeof e, &an);
        ST(zuc_pkey_parse(a, an, 0, &key), ZUC_ERR_UNSUPPORTED);
        ST(zuc_pkey_import(ZUC_ALG_RSA, 0, a, an, &key), ZUC_ERR_UNSUPPORTED);
        free(m); free(a);
    }
    /* An all-zero modulus is no key, even with zero bytes after it. */
    context = "rsa zero modulus";
    {
        static const uint8_t zero[] = {
            0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x00, 0x80
        };
        ST(zuc_pkey_parse(zero, sizeof zero, 1, &key),
           ZUC_ERR_INVALID_ARGUMENT);
    }

    /* Every PEM label the size check knows, each over the limit: PKCS#1
     * "RSA PUBLIC KEY" and "RSA PRIVATE KEY" as well as the PKCS#8 and
     * SubjectPublicKeyInfo ones the fixture holds. And a label it does not
     * know, which is no RSA key at all. */
    context = "rsa pem labels";
    {
        static const struct {
            const char *label;
            int which, priv;
            zuc_status want;
        } cases[] = {
            {"PUBLIC KEY", 0, 0, ZUC_ERR_UNSUPPORTED},
            {"RSA PUBLIC KEY", 1, 0, ZUC_ERR_UNSUPPORTED},
            {"PRIVATE KEY", 2, 1, ZUC_ERR_UNSUPPORTED},
            {"RSA PRIVATE KEY", 3, 1, ZUC_ERR_UNSUPPORTED},
            {"RSA PRIVATE KEY", 3, 0, ZUC_ERR_UNSUPPORTED},
            {"EC PRIVATE KEY", 3, 0, ZUC_ERR_INVALID_ARGUMENT},
            {"EC PRIVATE KEY", 3, 1, ZUC_ERR_INVALID_ARGUMENT}
        };
        const uint8_t *ders[4];
        size_t lens[4], i, pn;
        ders[0] = spki; lens[0] = spki_n;
        ders[1] = pub1; lens[1] = pub1_n;
        ders[2] = pkcs8; lens[2] = pkcs8_n;
        ders[3] = priv1; lens[3] = priv1_n;
        for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            char *pem = pem_wrap(cases[i].label, ders[cases[i].which],
                                 lens[cases[i].which], &pn);
            key = NULL;
            ST(zuc_pkey_parse((const uint8_t *) pem, pn, cases[i].priv, &key),
               cases[i].want);
            CHECK(key == NULL, "%s: no handle", cases[i].label);
            free(pem);
        }
    }
    free(spki); free(pkcs8); free(pub1); free(priv1);
}

/* ------------------------------------------------------------------ *
 * The reader's other paths, and key generation (#128, #129)
 * ------------------------------------------------------------------ */

static void test_pkey_reader(void)
{
    table rk = read_table("rsa-keys.tsv");
    static uint8_t buf[ZUC_PKEY_MAX_WRITE_SIZE + 8];
    uint8_t *der;
    char *pem;
    size_t der_n, pem_n, len;
    zuc_pkey *key = NULL;
    static const char *const leads[] = {" ", "\t", "\r", "\n", " \t\r\n "};
    size_t i;

    der = rsa_der(&rk, "rfc7515-a2", &der_n);
    pem = pem_wrap("RSA PRIVATE KEY", der, der_n, &pem_n);

    /* PEM is recognised after any leading whitespace, and only from a whole
     * "-----BEGIN". */
    context = "pem whitespace";
    for (i = 0; i < sizeof leads / sizeof leads[0]; i++) {
        size_t lead = strlen(leads[i]);
        memcpy(buf, leads[i], lead);
        memcpy(buf + lead, pem, pem_n);
        key = NULL;
        ST(zuc_pkey_parse(buf, lead + pem_n, 1, &key), ZUC_OK);
        CHECK(key != NULL && zuc_pkey_bits(key) == 2048, "lead %zu", i);
        if (key != NULL) {
            ST(zuc_pkey_write(key, ZUC_PKEY_PKCS1_DER, 0, buf, sizeof buf,
                              &len), ZUC_OK);
            CHECK(len == der_n && memcmp(buf, der, len) == 0, "same key");
        }
        zuc_pkey_free(key);
    }
    context = "pem near misses";
    {
        static const char *const misses[] = {
            "-----BEGI", " -----BEGI", "-----BEGIN", "\n-----BEGIN",
            "   ", "-----BEGIN RSA PRIVATE KEY-----\n"
        };
        for (i = 0; i < sizeof misses / sizeof misses[0]; i++) {
            key = NULL;
            ST(zuc_pkey_parse((const uint8_t *) misses[i], strlen(misses[i]),
                              1, &key), ZUC_ERR_INVALID_ARGUMENT);
            CHECK(key == NULL, "near miss %zu", i);
        }
        /* An embedded NUL in PEM is refused before the reader sees it. */
        memcpy(buf, pem, pem_n);
        buf[40] = 0;
        ST(zuc_pkey_parse(buf, pem_n, 1, &key), ZUC_ERR_INVALID_ARGUMENT);
    }
    /* The reader's NUL-terminated copy of PEM input holds the key's base64:
     * it is wiped before it is freed (zuc_live.h's residue scan). */
    context = "pem copy wiped";
    {
        static uint8_t needle[24];
        memcpy(needle, pem + pem_n / 2, sizeof needle);
        key = NULL;
        zuc_int_residue_arm(needle, sizeof needle);
        ST(zuc_pkey_parse((const uint8_t *) pem, pem_n, 1, &key), ZUC_OK);
        CHECK(zuc_int_residue_disarm() == 0, "the PEM copy was freed unwiped");
        zuc_pkey_free(key);
    }
    free(pem);
    free(der);

    /* A key the reader recognises, on a curve this build does not include,
     * is unsupported to the public reader and not a private key to the
     * private one: secp256k1, d = 12345, its SubjectPublicKeyInfo as
     * OpenSSL writes it (through cryptography 50). */
    context = "unsupported curve";
    {
        static const char k1[] =
            "3056301006072a8648ce3d020106052b8104000a03420004f01d6b9018ab421d"
            "d410404cb869072065522bf85734008f105cf385a023a80f0eba29d0f0c5408e"
            "d681984dc525982abefccd9f7ff01dd26da4999cf3f6a295";
        size_t n;
        uint8_t *spki = unhex(k1, &n);
        ST(zuc_pkey_parse(spki, n, 0, &key), ZUC_ERR_UNSUPPORTED);
        ST(zuc_pkey_parse(spki, n, 1, &key), ZUC_ERR_INVALID_ARGUMENT);
        CHECK(key == NULL, "no handle");
        free(spki);
    }

    /* The documented status of each regress seed of the reader's fuzz
     * corpus (fuzz/make-seeds.R): RSA keys outside the size rule are
     * unsupported (#93, #141), the malformed DER of #91 is invalid. */
    context = "regress seeds";
    {
        static const char *const seeds[] = {
            "regress-91-",
            "regress-93-rsa4104-private-pkcs1-der",
            "regress-93-rsa4104-private-pkcs8-der",
            "regress-93-rsa4104-private-pkcs8-pem",
            "regress-93-rsa4104-public-pkcs1-der",
            "regress-93-rsa4104-public-spki-der",
            "regress-93-rsa4104-public-spki-pem",
            "regress-141-rsa512-private-pkcs1-der",
            "regress-141-rsa512-private-pkcs8-der",
            "regress-141-rsa512-private-pkcs8-pem",
            "regress-141-rsa512-public-pkcs1-der",
            "regress-141-rsa512-public-spki-der",
            "regress-141-rsa512-public-spki-pem",
            "regress-141-rsa1000-private-pkcs1-der",
            "regress-141-rsa1000-public-spki-pem",
            "regress-141-rsa1028-private-pkcs8-der",
            "regress-141-rsa1028-public-pkcs1-der",
            "regress-141-rsa2047-private-pkcs8-pem",
            "regress-141-rsa2047-public-spki-der"
        };
        char path[1200];
        static uint8_t seed[20000];
        for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++) {
            FILE *f;
            size_t n;
            snprintf(path, sizeof path, "%s/../../../fuzz/corpus/pkey/%s",
                     fixture_dir, seeds[i]);
            f = fopen(path, "rb");
            if (f == NULL) {
                CHECK(0, "cannot read %s", path);
                continue;
            }
            n = fread(seed, 1, sizeof seed, f);
            fclose(f);
            key = NULL;
            ST(zuc_pkey_parse(seed + 1, n - 1, seed[0] & 1, &key),
               i == 0 ? ZUC_ERR_INVALID_ARGUMENT : ZUC_ERR_UNSUPPORTED);
            CHECK(key == NULL, "%s left a handle", seeds[i]);
        }
    }
}

/* One key of each type, generated: the sizes it takes and refuses, and a
 * key that works -- it signs and verifies, or agrees with a peer, and
 * survives its own encoding. */
static void test_pkey_generate(void)
{
    static const struct {
        zuc_alg type;
        size_t bits, other;
    } kinds[] = {
        {ZUC_ALG_EC_P256, 256, 384},
        {ZUC_ALG_EC_P384, 384, 256},
        {ZUC_ALG_EC_P521, 521, 528},
        {ZUC_ALG_X25519, 255, 256}
    };
    static uint8_t enc[ZUC_PKEY_MAX_WRITE_SIZE], enc2[ZUC_PKEY_MAX_WRITE_SIZE];
    uint8_t digest[32], sig[256], s1[66], s2[66];
    size_t i, len, len2, sig_len, n1, n2;
    zuc_pkey *key, *other, *back;

    memset(digest, 0x42, sizeof digest);
    for (i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        context = "generate";
        key = other = back = NULL;
        ST(zuc_pkey_generate(kinds[i].type, kinds[i].other, &key),
           ZUC_ERR_BAD_LENGTH);
        CHECK(key == NULL, "no key at %zu bits", kinds[i].other);
        ST(zuc_pkey_generate(kinds[i].type, kinds[i].bits, &key), ZUC_OK);
        ST(zuc_pkey_generate(kinds[i].type, 0, &other), ZUC_OK);
        if (key == NULL || other == NULL) goto next;
        CHECK(zuc_pkey_type(key) == kinds[i].type && zuc_pkey_is_private(key),
              "type %d", (int) kinds[i].type);
        CHECK(zuc_pkey_bits(key) == kinds[i].bits &&
              zuc_pkey_bits(other) == kinds[i].bits, "bits");
        if (kinds[i].type == ZUC_ALG_X25519) {
            zuc_pkey *pa = NULL, *pb = NULL;
            ST(zuc_pkey_public(key, &pa), ZUC_OK);
            ST(zuc_pkey_public(other, &pb), ZUC_OK);
            ST(zuc_pkey_agree(key, pb, s1, sizeof s1, &n1), ZUC_OK);
            ST(zuc_pkey_agree(other, pa, s2, sizeof s2, &n2), ZUC_OK);
            CHECK(n1 == 32 && n2 == 32 && memcmp(s1, s2, 32) == 0,
                  "both sides agree");
            zuc_pkey_free(pa);
            zuc_pkey_free(pb);
        } else {
            ST(zuc_pkey_sign_hash(key, ZUC_ALG_ECDSA, ZUC_ALG_SHA256, digest,
                                  32, sig, sizeof sig, &sig_len), ZUC_OK);
            ST(zuc_pkey_verify_hash(key, ZUC_ALG_ECDSA, ZUC_ALG_SHA256, digest,
                                    32, sig, sig_len), ZUC_OK);
            ST(zuc_pkey_verify_hash(other, ZUC_ALG_ECDSA, ZUC_ALG_SHA256,
                                    digest, 32, sig, sig_len), ZUC_ERR_AUTH);
        }
        ST(zuc_pkey_write(key, ZUC_PKEY_INFO_DER, 0, enc, sizeof enc, &len),
           ZUC_OK);
        ST(zuc_pkey_parse(enc, len, 1, &back), ZUC_OK);
        if (back != NULL) {
            ST(zuc_pkey_write(back, ZUC_PKEY_INFO_DER, 0, enc2, sizeof enc2,
                              &len2), ZUC_OK);
            CHECK(len2 == len && memcmp(enc, enc2, len) == 0,
                  "generated key survives its encoding");
        }
    next:
        zuc_pkey_free(key);
        zuc_pkey_free(other);
        zuc_pkey_free(back);
    }
    /* RSA, at the smallest size, in the same way. */
    context = "generate rsa";
    key = back = NULL;
    ST(zuc_pkey_generate(ZUC_ALG_RSA, 1024, &key), ZUC_OK);
    if (key != NULL) {
        ST(zuc_pkey_sign_hash(key, ZUC_ALG_RSA_PSS, ZUC_ALG_SHA256, digest, 32,
                              sig, sizeof sig, &sig_len), ZUC_OK);
        ST(zuc_pkey_verify_hash(key, ZUC_ALG_RSA_PSS, ZUC_ALG_SHA256, digest,
                                32, sig, sig_len), ZUC_OK);
        ST(zuc_pkey_write(key, ZUC_PKEY_INFO_PEM, 0, enc, sizeof enc, &len),
           ZUC_OK);
        ST(zuc_pkey_parse(enc, len, 1, &back), ZUC_OK);
        CHECK(zuc_pkey_bits(back) == 1024, "rsa round trip");
    }
    zuc_pkey_free(key);
    zuc_pkey_free(back);
    /* Not a key type at all. */
    context = "generate refusals";
    key = NULL;
    ST(zuc_pkey_generate(ZUC_ALG_SHA256, 0, &key), ZUC_ERR_UNSUPPORTED);
    ST(zuc_pkey_generate(ZUC_ALG_ECDSA, 0, &key), ZUC_ERR_UNSUPPORTED);
    ST(zuc_pkey_generate(ZUC_ALG_EC_P256, 0, NULL), ZUC_ERR_INVALID_ARGUMENT);
    CHECK(key == NULL, "no handle");
}

/* ------------------------------------------------------------------ *
 * Edge cases of the key operations (#128)
 * ------------------------------------------------------------------ */

static void test_pkey_edges(void)
{
    table rk = read_table("rsa-keys.tsv"), ek = read_table("ec-keys.tsv");
    static uint8_t out[2048];
    uint8_t *der, digest[32], ct[256], msg[300];
    size_t der_n, len, need, sz;
    zuc_pkey *rsa = NULL, *rpub = NULL, *p256, *x, *xpub;

    der = rsa_der(&rk, "rfc7515-a2", &der_n);
    ST(zuc_pkey_parse(der, der_n, 1, &rsa), ZUC_OK);
    free(der);
    ST(zuc_pkey_public(rsa, &rpub), ZUC_OK);
    p256 = ec_key(&ek, "rfc6979-p256", 1);
    x = ec_key(&ek, "rfc7748-alice", 1);
    xpub = ec_key(&ek, "rfc7748-bob", 0);
    if (!rsa || !rpub || !p256 || !x || !xpub) return;
    memset(digest, 0x17, sizeof digest);
    memset(msg, 0x33, sizeof msg);

    /* Each output buffer a byte short, then exactly long enough: the short
     * one is refused with nothing reported, the exact one works. */
#define STRADDLE(what, call_with_size, need_)                               \
    do {                                                                    \
        context = what;                                                     \
        for (sz = (need_) - 1; sz <= (need_); sz++) {                       \
            memset(out, 0x5a, sizeof out);                                  \
            len = 99;                                                       \
            ST(call_with_size, sz < (need_) ? ZUC_ERR_BAD_LENGTH : ZUC_OK); \
            CHECK(sz < (need_) ? len == 0 : len == (need_),                 \
                  "%s at %zu: length %zu", what, sz, len);                  \
        }                                                                   \
    } while (0)
    STRADDLE("sign rsa", zuc_pkey_sign_hash(rsa, ZUC_ALG_RSA_PKCS1V15_SIGN,
             ZUC_ALG_SHA256, digest, 32, out, sz, &len), 256);
    STRADDLE("sign ecdsa", zuc_pkey_sign_hash(p256, ZUC_ALG_ECDSA,
             ZUC_ALG_SHA256, digest, 32, out, sz, &len), 64);
    STRADDLE("encrypt", zuc_pkey_encrypt(rpub, ZUC_ALG_RSA_OAEP,
             ZUC_ALG_SHA256, msg, 3, out, sz, &len), 256);
    STRADDLE("agree", zuc_pkey_agree(x, xpub, out, sz, &len), 32);
    need = 0;
    ST(zuc_pkey_export(rsa, 0, out, sizeof out, &need), ZUC_OK);
    STRADDLE("export private", zuc_pkey_export(rsa, 0, out, sz, &len), need);
    ST(zuc_pkey_export(rsa, 1, out, sizeof out, &need), ZUC_OK);
    STRADDLE("export public", zuc_pkey_export(rsa, 1, out, sz, &len), need);
    ST(zuc_pkey_export(p256, 0, out, sizeof out, &need), ZUC_OK);
    STRADDLE("export ec private", zuc_pkey_export(p256, 0, out, sz, &len),
             need);
#undef STRADDLE

    /* An early refusal still reports no length. */
    context = "early refusals";
    len = 99;
    ST(zuc_pkey_sign_hash(NULL, ZUC_ALG_ECDSA, ZUC_ALG_SHA256, digest, 32, out,
                          sizeof out, &len), ZUC_ERR_INVALID_ARGUMENT);
    CHECK(len == 0, "sign");
    len = 99;
    ST(zuc_pkey_encrypt(NULL, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, msg, 3, out,
                        sizeof out, &len), ZUC_ERR_INVALID_ARGUMENT);
    CHECK(len == 0, "encrypt");
    len = 99;
    ST(zuc_pkey_decrypt(NULL, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, msg, 3, out,
                        sizeof out, &len), ZUC_ERR_INVALID_ARGUMENT);
    CHECK(len == 0, "decrypt");
    len = 99;
    ST(zuc_pkey_export(NULL, 0, out, sizeof out, &len),
       ZUC_ERR_INVALID_ARGUMENT);
    CHECK(len == 0, "export");
    len = 99;
    ST(zuc_pkey_agree(NULL, xpub, out, sizeof out, &len),
       ZUC_ERR_INVALID_ARGUMENT);
    CHECK(len == 0, "agree");
    len = 99;
    ST(zuc_pkey_write(NULL, ZUC_PKEY_INFO_DER, 0, out, sizeof out, &len),
       ZUC_ERR_INVALID_ARGUMENT);
    CHECK(len == 0, "write");
    /* With no length to report into, a refusal is still only a refusal. */
    ST(zuc_pkey_decrypt(rsa, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, msg, 3, out,
                        sizeof out, NULL), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_pkey_agree(x, xpub, out, sizeof out, NULL),
       ZUC_ERR_INVALID_ARGUMENT);

    /* Encrypting nothing is allowed, with or without a pointer; something
     * with no pointer is not. A message longer than OAEP leaves room for
     * (256 - 2 * 32 - 2 = 190 bytes) is a length error. */
    context = "encrypt inputs";
    ST(zuc_pkey_encrypt(rpub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, NULL, 0, ct,
                        sizeof ct, &len), ZUC_OK);
    CHECK(len == 256, "empty message");
    ST(zuc_pkey_encrypt(rpub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, NULL, 5, ct,
                        sizeof ct, &len), ZUC_ERR_INVALID_ARGUMENT);
    ST(zuc_pkey_encrypt(rpub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, msg, 190, ct,
                        sizeof ct, &len), ZUC_OK);
    ST(zuc_pkey_encrypt(rpub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, msg, 191, ct,
                        sizeof ct, &len), ZUC_ERR_BAD_LENGTH);
    CHECK(len == 0 && all_bytes(ct, sizeof ct, 0), "an over-long message");

    /* An empty signature with no pointer is a signature that does not
     * verify, not a usage error; a pointer-less non-empty one is. */
    context = "verify inputs";
    ST(zuc_pkey_verify_hash(p256, ZUC_ALG_ECDSA, ZUC_ALG_SHA256, digest, 32,
                            NULL, 0), ZUC_ERR_AUTH);
    ST(zuc_pkey_verify_hash(p256, ZUC_ALG_ECDSA, ZUC_ALG_SHA256, digest, 32,
                            NULL, 64), ZUC_ERR_INVALID_ARGUMENT);

    /* RFC 7748 section 6.1: a low-order peer point would give the all-zero
     * secret. The backend refuses each canonical one at import, so
     * pkey_agree_impl()'s own all-zero check is a second line no input can
     * reach; this is the first. */
    context = "x25519 low order";
    {
        static const char *const low[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        };
        size_t i, n;
        for (i = 0; i < sizeof low / sizeof low[0]; i++) {
            zuc_pkey *peer = NULL;
            uint8_t *u = unhex(low[i], &n);
            ST(zuc_pkey_import(ZUC_ALG_X25519, 0, u, n, &peer),
               ZUC_ERR_INVALID_ARGUMENT);
            CHECK(peer == NULL, "low-order point %zu", i);
            free(u);
        }
    }
    zuc_pkey_free(rsa);
    zuc_pkey_free(rpub);
    zuc_pkey_free(p256);
    zuc_pkey_free(x);
    zuc_pkey_free(xpub);
}

/* ------------------------------------------------------------------ *
 * Construction failures at every step (#116)
 * ------------------------------------------------------------------ */

typedef zuc_status (*constructor)(void **out);

static zuc_status make_hash(void **out)
{
    return zuc_hash_new(ZUC_ALG_SHA256, (zuc_hash **) out);
}
static zuc_status make_hmac(void **out)
{
    static const uint8_t key[16] = {1};
    return zuc_hmac_new(ZUC_ALG_SHA256, key, sizeof key, (zuc_hmac **) out);
}
static zuc_status make_aes(void **out)
{
    static const uint8_t key[16] = {1};
    return zuc_aes_new(key, sizeof key, (zuc_aes **) out);
}
static void free_hash(void *p) { zuc_hash_free((zuc_hash *) p); }
static void free_hmac(void *p) { zuc_hmac_free((zuc_hmac *) p); }
static void free_aes(void *p) { zuc_aes_free((zuc_aes *) p); }

static void test_construction(void)
{
    static const struct {
        const char *name;
        constructor make;
        void (*destroy)(void *);
        long steps;
    } kinds[] = {
        /* the storage, then the hash setup */
        {"hash_new", make_hash, free_hash, 2},
        /* the storage, three key-store allocations, the MAC setup */
        {"hmac_new", make_hmac, free_hmac, 5},
        /* the storage, two key-store allocations */
        {"aes_new", make_aes, free_aes, 3}
    };
    size_t k;
    long n;

    for (k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        context = kinds[k].name;
        for (n = 1; n <= kinds[k].steps + 1; n++) {
            void *h = (void *) 0x1;
            zuc_status st;
            zuc_int_alloc_fail_at(n);
            st = kinds[k].make(&h);
            if (n <= kinds[k].steps) {
                CHECK(zuc_int_alloc_fail_pending() == 0, "step %ld not reached",
                      n);
                CHECK(st == ZUC_ERR_MEMORY && h == NULL,
                      "step %ld: %s", n, zuc_status_name(st));
                CHECK(zuc_int_live_contexts() == 0,
                      "step %ld left %ld live", n, zuc_int_live_contexts());
            } else {
                /* One past the last step: the construction is untouched. */
                CHECK(zuc_int_alloc_fail_pending() == 1,
                      "more than %ld steps", kinds[k].steps);
                CHECK(st == ZUC_OK && h != NULL && zuc_int_live_contexts() == 1,
                      "after the steps: %s", zuc_status_name(st));
            }
            zuc_int_alloc_fail_at(0);
            if (st == ZUC_OK) kinds[k].destroy(h);
            /* And the next construction works. */
            h = NULL;
            ST(kinds[k].make(&h), ZUC_OK);
            kinds[k].destroy(h);
            CHECK(zuc_int_live_contexts() == 0, "live after free");
        }
    }
}

/* ------------------------------------------------------------------ *
 * An allocation-failure sweep, in process
 * ------------------------------------------------------------------ */

typedef zuc_status (*operation)(uint8_t *out, size_t *len);

static zuc_status op_hmac_stream(uint8_t *out, size_t *len)
{
    static const uint8_t key[20] = {0x0b}, data[300] = {1};
    zuc_hmac *m = NULL;
    zuc_status st = zuc_hmac_new(ZUC_ALG_SHA384, key, sizeof key, &m);
    if (st == ZUC_OK) st = zuc_hmac_update(m, data, 100);
    if (st == ZUC_OK) st = zuc_hmac_update(m, data + 100, 200);
    if (st == ZUC_OK) st = zuc_hmac_finish(m, out, 64, len);
    zuc_hmac_free(m);
    return st;
}

static zuc_status op_aes(uint8_t *out, size_t *len)
{
    static const uint8_t key[32] = {7}, iv[16] = {3}, data[64] = {9};
    zuc_aes *a = NULL;
    zuc_status st = zuc_aes_new(key, sizeof key, &a);
    if (st == ZUC_OK) st = zuc_aes_cbc_set_state(a, iv);
    if (st == ZUC_OK) st = zuc_aes_cbc_encrypt(a, data, sizeof data, out);
    zuc_aes_free(a);
    *len = sizeof data;
    return st;
}

static zuc_status op_gcm(uint8_t *out, size_t *len)
{
    static const uint8_t key[16] = {1}, nonce[12] = {2}, aad[5] = {3},
                         data[40] = {4};
    zuc_status st = zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, sizeof key, nonce,
                                     sizeof nonce, aad, sizeof aad, data,
                                     sizeof data, out, out + 40, 16);
    *len = 56;
    return st;
}

static zuc_status op_pbkdf2(uint8_t *out, size_t *len)
{
    *len = 48;
    return zuc_pbkdf2_hmac(ZUC_ALG_SHA512, (const uint8_t *) "pw", 2,
                           (const uint8_t *) "salt", 4, 3, out, 48);
}

static uint8_t *sweep_rsa_der;
static size_t sweep_rsa_len;

static zuc_status op_rsa_sign(uint8_t *out, size_t *len)
{
    static const uint8_t digest[32] = {5};
    zuc_pkey *key = NULL;
    zuc_status st = zuc_pkey_parse(sweep_rsa_der, sweep_rsa_len, 1, &key);
    if (st == ZUC_OK) {
        st = zuc_pkey_sign_hash(key, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256,
                                digest, sizeof digest, out, 1024, len);
    }
    zuc_pkey_free(key);
    return st;
}

static zuc_status op_x25519(uint8_t *out, size_t *len)
{
    static const uint8_t a[32] = {0x77, 0x07}, b[32] = {0xde, 0x9e, 0xdb};
    zuc_pkey *ka = NULL, *kb = NULL, *pb = NULL;
    zuc_status st = zuc_pkey_import(ZUC_ALG_X25519, 1, a, 32, &ka);
    if (st == ZUC_OK) st = zuc_pkey_import(ZUC_ALG_X25519, 1, b, 32, &kb);
    if (st == ZUC_OK) st = zuc_pkey_public(kb, &pb);
    if (st == ZUC_OK) st = zuc_pkey_agree(ka, pb, out, 64, len);
    zuc_pkey_free(ka);
    zuc_pkey_free(kb);
    zuc_pkey_free(pb);
    return st;
}

/* Every position up to `limit`, stepping by `stride` (1 for all of them).
 * The large sweeps stride by default, because mutation.yaml runs this
 * binary once per mutant; ZUC_CTEST_FULL=1 makes every sweep complete. */
static long full_sweep = 0;

static void sweep(const char *name, operation op, long limit, long stride)
{
    uint8_t want[1024], got[1024];
    size_t want_len = 0, got_len;
    long n, fired = 0;
    zuc_status st;

    context = name;
    ST(op(want, &want_len), ZUC_OK);
    if (full_sweep) stride = 1;
    for (n = 1; n <= limit; n += stride) {
        memset(got, 0, sizeof got);
        got_len = 0;
        zuc_int_alloc_fail_at(n);
        st = op(got, &got_len);
        if (zuc_int_alloc_fail_pending() != 0) {
            zuc_int_alloc_fail_at(0);
            break;                      /* fewer than n allocations: done */
        }
        fired++;
        CHECK(st == ZUC_ERR_MEMORY ||
              (st == ZUC_OK && got_len == want_len &&
               memcmp(got, want, want_len) == 0),
              "allocation %ld failed: %s", n, zuc_status_name(st));
        CHECK(zuc_int_live_contexts() == 0, "allocation %ld: %ld live", n,
              zuc_int_live_contexts());
        /* And the backend works afterwards. */
        st = op(got, &got_len);
        CHECK(st == ZUC_OK && got_len == want_len &&
              memcmp(got, want, want_len) == 0,
              "after allocation %ld: %s", n, zuc_status_name(st));
    }
    CHECK(fired > 0, "the sweep reached no allocation");
    printf("  sweep %-12s %ld positions failed, stride %ld\n", name, fired,
           stride);
}

static void test_alloc_sweep(void)
{
    table keys = read_table("rsa-keys.tsv");
    sweep_rsa_der = rsa_der(&keys, "rfc7515-a2", &sweep_rsa_len);
    const char *full = getenv("ZUC_CTEST_FULL");
    full_sweep = full != NULL && strcmp(full, "1") == 0;
    sweep("hmac stream", op_hmac_stream, 1000, 1);
    sweep("aes-cbc", op_aes, 1000, 1);
    sweep("aes-gcm", op_gcm, 1000, 1);
    sweep("pbkdf2", op_pbkdf2, 1000, 1);
    sweep("rsa sign", op_rsa_sign, 20000, 7);
    sweep("x25519", op_x25519, 20000, 211);
    free(sweep_rsa_der);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc > 1) fixture_dir = argv[1];
    if (zuc_init() != ZUC_OK) {
        fprintf(stderr, "zuc_init() failed\n");
        return 2;
    }
#define RUN(f)                                                              \
    do {                                                                    \
        clock_t t0 = clock();                                               \
        f();                                                                \
        printf("%-18s %6.2f s\n", #f,                                       \
               (double) (clock() - t0) / CLOCKS_PER_SEC);                   \
    } while (0)
    RUN(test_names);
    RUN(test_digests);
    RUN(test_aes);
    RUN(test_aead);
    RUN(test_kdf);
    RUN(test_util);
    RUN(test_info);
    RUN(test_rsa);
    RUN(test_rsa_limits);
    RUN(test_pkey_outputs);
    RUN(test_ec);
    RUN(test_entropy);
    RUN(test_ec_encodings);
    RUN(test_rsa_size_reader);
    RUN(test_pkey_reader);
    RUN(test_pkey_generate);
    RUN(test_pkey_edges);
    RUN(test_construction);
    RUN(test_alloc_sweep);
    RUN(test_lifetime);   /* last: it tears the backend down and back up */
#undef RUN
    zuc_shutdown();
    printf("zuc_ctest: %ld checks, %ld failed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
