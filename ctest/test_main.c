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

    context = "stale handles";
    ST(zuc_init(), ZUC_OK);
    ST(zuc_aes_new(k2, 16, &a_new), ZUC_OK);
    ST(zuc_hmac_new(ZUC_ALG_SHA256, k2, 16, &m_new_h), ZUC_OK);
    ST(zuc_aes_cbc_set_state(a_old, zero), ZUC_OK);
    ST(zuc_aes_cbc_encrypt(a_old, zero, 16, out), ZUC_ERR_NOT_READY);
    ST(zuc_hmac_update(m_old, zero, 1), ZUC_ERR_NOT_READY);
    ST(zuc_hmac_finish(m_old, out, sizeof out, &len), ZUC_ERR_NOT_READY);
    ST(zuc_hmac_reset(m_old), ZUC_ERR_NOT_READY);
    ST(zuc_hash_update(h_old, zero, 1), ZUC_ERR_NOT_READY);
    ST(zuc_hash_finish(h_old, out, sizeof out, &len), ZUC_ERR_NOT_READY);
    ST(zuc_hash_reset(h_old), ZUC_ERR_NOT_READY);
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
    RUN(test_ec);
    RUN(test_alloc_sweep);
    RUN(test_lifetime);   /* last: it tears the backend down and back up */
#undef RUN
    zuc_shutdown();
    printf("zuc_ctest: %ld checks, %ld failed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
