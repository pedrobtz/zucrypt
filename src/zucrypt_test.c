/* zucrypt: the permanently-compiled test harness.
 *
 * The adapter has to be proved against published vectors on every platform,
 * at split points and in states the six crypt_* functions never reach.
 * These entry points are how the test suite reaches it.
 *
 * Compiled into every build, never removed, and never exported to R's search
 * path: this is zukomp's zu_test_stream() arrangement, and the reason is the
 * same. A harness that exists only in a debug build tests a binary nobody
 * runs, and the split-point sweeps below are the tests most likely to be
 * wanted again after a backend upgrade.
 *
 * The `splits` argument is what makes that possible: an integer vector of
 * chunk sizes drives the incremental path at caller-chosen boundaries, and an
 * empty one selects the one-shot entry point instead. The two must agree.
 *
 * PROTECT discipline here is deliberately simple. Every function allocates
 * its R result *before* it creates a native context, and raises no R error
 * between creating one and freeing it -- so there is no path on which a
 * longjmp strands a key or a context. Stage 3 introduces R_UnwindProtect for
 * the public functions, where interrupts during a long hash are a real
 * concern; this file does not need it and does not pretend to have it.
 */

#include <stdlib.h>
#include <string.h>

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include "zucrypt.h"
#include "zuc_live.h"

/* ------------------------------------------------------------------ *
 * Argument helpers
 * ------------------------------------------------------------------ */

static zuc_alg alg_arg(SEXP s, const char *what)
{
    zuc_alg alg;

    if (TYPEOF(s) != STRSXP || Rf_length(s) != 1) {
        Rf_error("zucrypt: %s must be a single algorithm name", what);
    }
    alg = zuc_alg_by_name(CHAR(STRING_ELT(s, 0)));
    if (alg == ZUC_ALG_NONE) {
        Rf_error("zucrypt: unknown algorithm '%s'", CHAR(STRING_ELT(s, 0)));
    }
    return alg;
}

static const uint8_t *raw_arg(SEXP s, size_t *len, const char *what)
{
    if (TYPEOF(s) != RAWSXP) {
        Rf_error("zucrypt: %s must be a raw vector", what);
    }
    *len = (size_t) XLENGTH(s);
    return (const uint8_t *) RAW(s);
}

/* Chunk sizes for the incremental path. An empty vector means "use the
 * one-shot entry point". The sizes must add up to the input length, which is
 * checked here rather than in R so that a malformed sweep fails in the test
 * that wrote it. */
static void check_splits(SEXP splits, size_t total)
{
    R_xlen_t i, n;
    double sum = 0;

    if (TYPEOF(splits) != INTSXP) {
        Rf_error("zucrypt: splits must be an integer vector");
    }
    n = XLENGTH(splits);
    for (i = 0; i < n; i++) {
        int v = INTEGER(splits)[i];
        if (v == NA_INTEGER || v < 0) {
            Rf_error("zucrypt: splits must be non-negative and not NA");
        }
        sum += v;
    }
    if (n > 0 && sum != (double) total) {
        Rf_error("zucrypt: splits sum to %.0f but the input is %.0f bytes",
                 sum, (double) total);
    }
}

static void stop_on(zuc_status st, const char *what)
{
    if (st != ZUC_OK) {
        /* Stage 3 replaces this with a structured condition carrying the
         * enumerator name. Here the name is in the message on purpose, so a
         * CI failure says which status came back. */
        Rf_error("zucrypt: %s failed: %s (%s)",
                 what, zuc_status_string(st), zuc_status_name(st));
    }
}

/* ------------------------------------------------------------------ *
 * Digest and HMAC
 * ------------------------------------------------------------------ */

SEXP zucrypt_test_hash(SEXP algorithm, SEXP data, SEXP splits)
{
    zuc_alg alg = alg_arg(algorithm, "algorithm");
    size_t len = 0;
    const uint8_t *bytes = raw_arg(data, &len, "data");
    size_t want = zuc_alg_size(alg);
    SEXP out;
    size_t got = 0;
    zuc_status st;

    check_splits(splits, len);
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));

    if (XLENGTH(splits) == 0) {
        st = zuc_hash_compute(alg, bytes, len, RAW(out), want, &got);
    } else {
        zuc_hash *h = NULL;
        R_xlen_t i;
        size_t offset = 0;

        st = zuc_hash_new(alg, &h);
        if (st == ZUC_OK) {
            for (i = 0; i < XLENGTH(splits) && st == ZUC_OK; i++) {
                size_t n = (size_t) INTEGER(splits)[i];
                st = zuc_hash_update(h, bytes + offset, n);
                offset += n;
            }
            if (st == ZUC_OK) {
                st = zuc_hash_finish(h, RAW(out), want, &got);
            }
            zuc_hash_free(h);
        }
    }
    UNPROTECT(1);
    stop_on(st, "hash");
    if (got != want) {
        Rf_error("zucrypt: hash produced %d bytes, expected %d",
                 (int) got, (int) want);
    }
    return out;
}

SEXP zucrypt_test_hmac(SEXP algorithm, SEXP key, SEXP data, SEXP splits)
{
    zuc_alg alg = alg_arg(algorithm, "algorithm");
    size_t key_len = 0, len = 0;
    const uint8_t *key_bytes = raw_arg(key, &key_len, "key");
    const uint8_t *bytes = raw_arg(data, &len, "data");
    size_t want = zuc_alg_size(alg);
    SEXP out;
    size_t got = 0;
    zuc_status st;

    check_splits(splits, len);
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));

    if (XLENGTH(splits) == 0) {
        st = zuc_hmac_compute(alg, key_bytes, key_len, bytes, len,
                              RAW(out), want, &got);
    } else {
        zuc_hmac *h = NULL;
        R_xlen_t i;
        size_t offset = 0;

        st = zuc_hmac_new(alg, key_bytes, key_len, &h);
        if (st == ZUC_OK) {
            for (i = 0; i < XLENGTH(splits) && st == ZUC_OK; i++) {
                size_t n = (size_t) INTEGER(splits)[i];
                st = zuc_hmac_update(h, bytes + offset, n);
                offset += n;
            }
            if (st == ZUC_OK) {
                st = zuc_hmac_finish(h, RAW(out), want, &got);
            }
            zuc_hmac_free(h);
        }
    }
    UNPROTECT(1);
    stop_on(st, "hmac");
    if (got != want) {
        Rf_error("zucrypt: hmac produced %d bytes, expected %d",
                 (int) got, (int) want);
    }
    return out;
}

/* A reset context must be indistinguishable from a fresh one, which cannot
 * be checked from outside: it needs one handle used twice. */
SEXP zucrypt_test_hash_reset(SEXP algorithm, SEXP first, SEXP second)
{
    zuc_alg alg = alg_arg(algorithm, "algorithm");
    size_t n1 = 0, n2 = 0;
    const uint8_t *b1 = raw_arg(first, &n1, "first");
    const uint8_t *b2 = raw_arg(second, &n2, "second");
    size_t want = zuc_alg_size(alg);
    SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    size_t got = 0;
    zuc_hash *h = NULL;
    zuc_status st;

    st = zuc_hash_new(alg, &h);
    if (st == ZUC_OK) {
        /* Absorb one message, throw it away, then hash another. */
        st = zuc_hash_update(h, b1, n1);
        if (st == ZUC_OK) st = zuc_hash_reset(h);
        if (st == ZUC_OK) st = zuc_hash_update(h, b2, n2);
        if (st == ZUC_OK) st = zuc_hash_finish(h, RAW(out), want, &got);
        zuc_hash_free(h);
    }
    UNPROTECT(1);
    stop_on(st, "hash reset");
    return out;
}

SEXP zucrypt_test_hmac_reset(SEXP algorithm, SEXP key, SEXP first, SEXP second)
{
    zuc_alg alg = alg_arg(algorithm, "algorithm");
    size_t key_len = 0, n1 = 0, n2 = 0;
    const uint8_t *k = raw_arg(key, &key_len, "key");
    const uint8_t *b1 = raw_arg(first, &n1, "first");
    const uint8_t *b2 = raw_arg(second, &n2, "second");
    size_t want = zuc_alg_size(alg);
    SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    size_t got = 0;
    zuc_hmac *h = NULL;
    zuc_status st;

    st = zuc_hmac_new(alg, k, key_len, &h);
    if (st == ZUC_OK) {
        st = zuc_hmac_update(h, b1, n1);
        if (st == ZUC_OK) st = zuc_hmac_reset(h);
        if (st == ZUC_OK) st = zuc_hmac_update(h, b2, n2);
        if (st == ZUC_OK) st = zuc_hmac_finish(h, RAW(out), want, &got);
        zuc_hmac_free(h);
    }
    UNPROTECT(1);
    stop_on(st, "hmac reset");
    return out;
}

/* The SHAVS Monte Carlo test (#67): `n` checkpoints of 1000 chained
 * digests each, MD[i] = H(MD[i-3] || MD[i-2] || MD[i-1]), the last of one
 * checkpoint seeding the next. Every one of the n * 1000 digests goes
 * through the same handle, reset between them, which is how a consumer's
 * derivation loop uses it. Returns the n checkpoints, concatenated. */
SEXP zucrypt_test_sha_monte(SEXP algorithm, SEXP seed, SEXP n_)
{
    zuc_alg alg = alg_arg(algorithm, "algorithm");
    size_t seed_len = 0, d = zuc_alg_size(alg), got = 0;
    const uint8_t *seed_bytes = raw_arg(seed, &seed_len, "seed");
    int n = Rf_asInteger(n_);
    uint8_t md[3][ZUC_MAX_DIGEST_SIZE], next[ZUC_MAX_DIGEST_SIZE];
    zuc_hash *h = NULL;
    zuc_status st;
    SEXP out;
    int i, j;

    if (n == NA_INTEGER || n < 1 || n > 100) {
        Rf_error("zucrypt: n must be 1 to 100");
    }
    if (d == 0 || d > ZUC_MAX_DIGEST_SIZE || seed_len != d) {
        Rf_error("zucrypt: the seed must be one digest long");
    }
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) n * (R_xlen_t) d));
    memcpy(next, seed_bytes, d);
    st = zuc_hash_new(alg, &h);
    for (j = 0; j < n && st == ZUC_OK; j++) {
        memcpy(md[0], next, d);
        memcpy(md[1], next, d);
        memcpy(md[2], next, d);
        for (i = 0; i < 1000 && st == ZUC_OK; i++) {
            st = zuc_hash_reset(h);
            if (st == ZUC_OK) st = zuc_hash_update(h, md[0], d);
            if (st == ZUC_OK) st = zuc_hash_update(h, md[1], d);
            if (st == ZUC_OK) st = zuc_hash_update(h, md[2], d);
            if (st == ZUC_OK) st = zuc_hash_finish(h, next, d, &got);
            if (st == ZUC_OK && got != d) st = ZUC_ERR_BAD_LENGTH;
            memcpy(md[0], md[1], d);
            memcpy(md[1], md[2], d);
            memcpy(md[2], next, d);
        }
        memcpy(RAW(out) + (size_t) j * d, next, d);
    }
    zuc_hash_free(h);
    UNPROTECT(1);
    stop_on(st, "sha monte");
    return out;
}

/* ------------------------------------------------------------------ *
 * AES
 * ------------------------------------------------------------------ */

/* mode: "cbc", the only mode since ECB left (#29); encrypt: logical; splits: chunk sizes, each a
 * multiple of the block size; reset_each: restore the original IV before
 * every chunk, which is what a segmented document format does. */
SEXP zucrypt_test_aes(SEXP mode, SEXP encrypt, SEXP key, SEXP iv, SEXP data,
                      SEXP splits, SEXP reset_each)
{
    size_t key_len = 0, iv_len = 0, len = 0;
    const uint8_t *key_bytes = raw_arg(key, &key_len, "key");
    const uint8_t *iv_bytes = raw_arg(iv, &iv_len, "iv");
    const uint8_t *bytes = raw_arg(data, &len, "data");
    int is_cbc, do_encrypt, do_reset;
    SEXP out;
    zuc_aes *aes = NULL;
    zuc_status st;

    if (TYPEOF(mode) != STRSXP || Rf_length(mode) != 1) {
        Rf_error("zucrypt: mode must be a single string");
    }
    is_cbc = strcmp(CHAR(STRING_ELT(mode, 0)), "cbc") == 0;
    if (!is_cbc) {
        Rf_error("zucrypt: mode must be \"cbc\"");
    }
    do_encrypt = Rf_asLogical(encrypt) == TRUE;
    do_reset = Rf_asLogical(reset_each) == TRUE;
    if (iv_len != ZUC_AES_BLOCK_SIZE) {
        Rf_error("zucrypt: a CBC iv must be %d bytes", ZUC_AES_BLOCK_SIZE);
    }
    check_splits(splits, len);

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) len));

    st = zuc_aes_new(key_bytes, key_len, &aes);
    if (st == ZUC_OK) {
        R_xlen_t i, n = XLENGTH(splits);
        size_t offset = 0;

        st = zuc_aes_cbc_set_state(aes, iv_bytes);
        if (n == 0) {
            n = 1;   /* one chunk covering everything */
        } else {
            n = XLENGTH(splits);
        }
        for (i = 0; i < n && st == ZUC_OK; i++) {
            size_t chunk = (XLENGTH(splits) == 0)
                ? len : (size_t) INTEGER(splits)[i];

            if (do_reset && i > 0) {
                st = zuc_aes_cbc_set_state(aes, iv_bytes);
                if (st != ZUC_OK) break;
            }
            st = do_encrypt
                ? zuc_aes_cbc_encrypt(aes, bytes + offset, chunk,
                                      RAW(out) + offset)
                : zuc_aes_cbc_decrypt(aes, bytes + offset, chunk,
                                      RAW(out) + offset);
            offset += chunk;
        }
        zuc_aes_free(aes);
    }
    UNPROTECT(1);
    stop_on(st, "aes");
    return out;
}

/* The AESAVS CBC Monte Carlo test (#67): `n` checkpoints of 1000 blocks
 * each. Within a checkpoint one handle carries the chaining state from
 * block to block, never reset, and the input of block j + 1 is the IV for
 * j = 0 and the output of block j - 1 after it. Between checkpoints the key
 * absorbs the last output bits and a new handle takes it. Returns, per
 * checkpoint, key || iv || input || output: what the response file lists
 * for that COUNT. */
SEXP zucrypt_test_cbc_mct(SEXP encrypt, SEXP key, SEXP iv, SEXP text, SEXP n_)
{
    size_t key_len = 0, iv_len = 0, text_len = 0, row, k;
    const uint8_t *key0 = raw_arg(key, &key_len, "key");
    const uint8_t *iv0 = raw_arg(iv, &iv_len, "iv");
    const uint8_t *text0 = raw_arg(text, &text_len, "text");
    int n = Rf_asInteger(n_), do_encrypt = Rf_asLogical(encrypt);
    uint8_t kbuf[32], ivbuf[16], in[16], out_blk[16], prev[16], last[32];
    zuc_aes *aes = NULL;
    zuc_status st = ZUC_OK;
    uint8_t *dst;
    SEXP out;
    int i, j;

    if (do_encrypt == NA_LOGICAL) Rf_error("zucrypt: encrypt must be TRUE or FALSE");
    if (n == NA_INTEGER || n < 1 || n > 100) Rf_error("zucrypt: n must be 1 to 100");
    if ((key_len != 16 && key_len != 24 && key_len != 32) || iv_len != 16 ||
        text_len != 16) {
        Rf_error("zucrypt: a 16, 24 or 32-byte key and 16-byte iv and text");
    }
    row = key_len + 48;
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) n * (R_xlen_t) row));
    memcpy(kbuf, key0, key_len);
    memcpy(ivbuf, iv0, 16);
    memcpy(in, text0, 16);
    memset(prev, 0, sizeof prev);
    for (i = 0; i < n && st == ZUC_OK; i++) {
        dst = RAW(out) + (size_t) i * row;
        memcpy(dst, kbuf, key_len);
        memcpy(dst + key_len, ivbuf, 16);
        memcpy(dst + key_len + 16, in, 16);
        st = zuc_aes_new(kbuf, key_len, &aes);
        if (st == ZUC_OK) st = zuc_aes_cbc_set_state(aes, ivbuf);
        for (j = 0; j < 1000 && st == ZUC_OK; j++) {
            uint8_t next_in[16];

            st = do_encrypt ? zuc_aes_cbc_encrypt(aes, in, 16, out_blk)
                            : zuc_aes_cbc_decrypt(aes, in, 16, out_blk);
            memcpy(next_in, j == 0 ? ivbuf : prev, 16);
            memcpy(prev, out_blk, 16);       /* now block j's output */
            if (j == 998) memcpy(last, out_blk, 16);
            memcpy(in, next_in, 16);
        }
        zuc_aes_free(aes);
        aes = NULL;
        if (st != ZUC_OK) break;
        memcpy(dst + key_len + 32, out_blk, 16);
        /* last = output 998 || output 999; the key takes its tail. */
        memcpy(last + 16, out_blk, 16);
        for (k = 0; k < key_len; k++) kbuf[k] ^= last[32 - key_len + k];
        memcpy(ivbuf, out_blk, 16);
        memcpy(in, last, 16);              /* output 998 */
    }
    UNPROTECT(1);
    stop_on(st, "cbc mct");
    return out;
}

/* Exact in-place: the same buffer as input and output. Supported, and worth a
 * test of its own because the decrypt path has to save the next chaining
 * value before it overwrites the input it lives in. */
SEXP zucrypt_test_aes_inplace(SEXP encrypt, SEXP key, SEXP iv, SEXP data)
{
    size_t key_len = 0, iv_len = 0, len = 0;
    const uint8_t *key_bytes = raw_arg(key, &key_len, "key");
    const uint8_t *iv_bytes = raw_arg(iv, &iv_len, "iv");
    const uint8_t *bytes = raw_arg(data, &len, "data");
    int do_encrypt = Rf_asLogical(encrypt) == TRUE;
    SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) len));
    zuc_aes *aes = NULL;
    zuc_status st;

    if (iv_len != ZUC_AES_BLOCK_SIZE) {
        Rf_error("zucrypt: iv must be %d bytes", ZUC_AES_BLOCK_SIZE);
    }
    memcpy(RAW(out), bytes, len);

    st = zuc_aes_new(key_bytes, key_len, &aes);
    if (st == ZUC_OK) {
        st = zuc_aes_cbc_set_state(aes, iv_bytes);
        if (st == ZUC_OK) {
            st = do_encrypt
                ? zuc_aes_cbc_encrypt(aes, RAW(out), len, RAW(out))
                : zuc_aes_cbc_decrypt(aes, RAW(out), len, RAW(out));
        }
        zuc_aes_free(aes);
    }
    UNPROTECT(1);
    stop_on(st, "aes in place");
    return out;
}

/* Partial overlap must be refused rather than silently corrupted. Returns the
 * status code instead of raising, because the refusal is the result. */
SEXP zucrypt_test_aes_overlap(SEXP key, SEXP iv, SEXP data, SEXP offset)
{
    size_t key_len = 0, iv_len = 0, len = 0;
    const uint8_t *key_bytes = raw_arg(key, &key_len, "key");
    const uint8_t *iv_bytes = raw_arg(iv, &iv_len, "iv");
    const uint8_t *bytes = raw_arg(data, &len, "data");
    int shift = Rf_asInteger(offset);
    SEXP buf, out;
    zuc_aes *aes = NULL;
    zuc_status st;

    if (shift < 0 || (size_t) shift >= len) {
        Rf_error("zucrypt: offset must be inside the buffer");
    }
    /* One buffer, with the output window shifted into the input window. */
    buf = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) (len + (size_t) shift)));
    memcpy(RAW(buf), bytes, len);

    st = zuc_aes_new(key_bytes, key_len, &aes);
    if (st == ZUC_OK) {
        st = zuc_aes_cbc_set_state(aes, iv_bytes);
        if (st == ZUC_OK) {
            st = zuc_aes_cbc_encrypt(aes, RAW(buf), len, RAW(buf) + shift);
        }
        zuc_aes_free(aes);
    }
    out = PROTECT(Rf_ScalarString(Rf_mkChar(zuc_status_name(st))));
    UNPROTECT(2);
    (void) iv_len;
    return out;
}

/* ------------------------------------------------------------------ *
 * Utilities and introspection
 * ------------------------------------------------------------------ */

SEXP zucrypt_test_equal(SEXP a, SEXP b)
{
    size_t na = 0, nb = 0;
    const uint8_t *pa = raw_arg(a, &na, "a");
    const uint8_t *pb = raw_arg(b, &nb, "b");

    if (na != nb) {
        Rf_error("zucrypt: zuc_equal() takes equal-length buffers; "
                 "length is the caller's business");
    }
    return Rf_ScalarLogical(zuc_equal(pa, pb, na));
}

SEXP zucrypt_test_algs(void)
{
    static const char *names[] = {"sha1", "sha256", "sha384", "sha512"};
    int n = 4, i;
    SEXP name = PROTECT(Rf_allocVector(STRSXP, n));
    SEXP size = PROTECT(Rf_allocVector(INTSXP, n));
    SEXP avail = PROTECT(Rf_allocVector(LGLSXP, n));
    SEXP out = PROTECT(Rf_allocVector(VECSXP, 3));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, 3));

    for (i = 0; i < n; i++) {
        zuc_alg alg = zuc_alg_by_name(names[i]);
        SET_STRING_ELT(name, i, Rf_mkChar(names[i]));
        INTEGER(size)[i] = (int) zuc_alg_size(alg);
        LOGICAL(avail)[i] = zuc_alg_available(alg) ? TRUE : FALSE;
    }
    SET_VECTOR_ELT(out, 0, name);
    SET_VECTOR_ELT(out, 1, size);
    SET_VECTOR_ELT(out, 2, avail);
    SET_STRING_ELT(nms, 0, Rf_mkChar("name"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("size"));
    SET_STRING_ELT(nms, 2, Rf_mkChar("available"));
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(5);
    return out;
}

/* zuc_status_string() and zuc_status_name() must answer for every enumerator
 * and for values that are not enumerators at all. */
SEXP zucrypt_test_status(SEXP code)
{
    int value = Rf_asInteger(code);
    SEXP out = PROTECT(Rf_allocVector(STRSXP, 2));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, 2));

    SET_STRING_ELT(out, 0, Rf_mkChar(zuc_status_name((zuc_status) value)));
    SET_STRING_ELT(out, 1, Rf_mkChar(zuc_status_string((zuc_status) value)));
    SET_STRING_ELT(nms, 0, Rf_mkChar("name"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("message"));
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

/* A consumer built against an older header passes a shorter struct_size. The
 * contract is that anything at least ZUC_INFO_REQUIRED_SIZE long is served
 * and anything shorter is refused with ZUC_ERR_ABI -- which is only testable
 * by lying about the size. */
SEXP zucrypt_test_info_size(SEXP struct_size)
{
    zuc_info info;
    zuc_status st;

    memset(&info, 0, sizeof info);
    info.struct_size = (uint32_t) Rf_asInteger(struct_size);
    st = zuc_get_info(&info);
    return Rf_ScalarString(Rf_mkChar(zuc_status_name(st)));
}

SEXP zucrypt_test_required_sizes(void)
{
    SEXP out = PROTECT(Rf_allocVector(INTSXP, 2));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, 2));

    INTEGER(out)[0] = (int) ZUC_INFO_REQUIRED_SIZE;
    INTEGER(out)[1] = (int) sizeof(zuc_info);
    SET_STRING_ELT(nms, 0, Rf_mkChar("required"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("current"));
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

/* ------------------------------------------------------------------ *
 * Lifetime and capacity
 * ------------------------------------------------------------------ */

/* What every backend-touching entry point returns outside an initialised
 * window. Drops the reference R_init_zucrypt holds, calls each entry point,
 * and takes the reference back -- always, whatever happened in between.
 *
 * Tearing the backend down destroys every key in the store, so this is safe
 * only when no other zucrypt context is live in the process; the test calls
 * gc() first, and the public entry points free their contexts eagerly. The
 * one handle made here is freed right after re-initialisation, before any
 * other key can be imported and reuse its identifier. No R allocation
 * happens between the shutdown and the init, so no longjmp can leave the
 * backend down. */
SEXP zucrypt_test_not_ready(void)
{
    static const char *names[] = {
        "hash_compute", "hash_new", "hmac_compute", "hmac_new", "aes_new",
        "aes_cbc_encrypt", "random_bytes", "aead_encrypt", "aead_decrypt",
        "pbkdf2_hmac", "pkey_parse", "pkey_generate", "pkey_import",
        "pkey_export", "pkey_agree", "shutdown", "init"
    };
    enum { N = 17 };
    zuc_status st[N];
    uint8_t key[ZUC_AES_KEY_SIZE_128] = {0}, block[ZUC_AES_BLOCK_SIZE] = {0};
    uint8_t out[ZUC_MAX_DIGEST_SIZE], nonce[ZUC_GCM_NONCE_SIZE] = {0};
    uint8_t tag[ZUC_GCM_TAG_SIZE] = {0};
    size_t out_len = 0;
    zuc_hash *hash = NULL;
    zuc_hmac *hmac = NULL;
    zuc_aes *aes = NULL, *live = NULL;
    zuc_pkey *pkey = NULL;
    SEXP res, nms;
    int i;

    /* The teardown destroys every key in the store, so it refuses to run
     * under a live handle rather than relying on its callers (#111). */
    if (zuc_int_live_contexts() != 0) {
        Rf_error("zucrypt: zucrypt_test_not_ready() needs no live handle, "
                 "and %ld are live", zuc_int_live_contexts());
    }
    if (zuc_aes_new(key, sizeof key, &live) != ZUC_OK) {
        Rf_error("zucrypt: could not create the handle this test needs");
    }

    st[15] = zuc_shutdown();
    st[0] = zuc_hash_compute(ZUC_ALG_SHA256, block, sizeof block,
                             out, sizeof out, &out_len);
    st[1] = zuc_hash_new(ZUC_ALG_SHA256, &hash);
    st[2] = zuc_hmac_compute(ZUC_ALG_SHA256, key, sizeof key, block,
                             sizeof block, out, sizeof out, &out_len);
    st[3] = zuc_hmac_new(ZUC_ALG_SHA256, key, sizeof key, &hmac);
    st[4] = zuc_aes_new(key, sizeof key, &aes);
    st[5] = zuc_aes_cbc_encrypt(live, block, sizeof block, block);
    st[6] = zuc_random_bytes(block, sizeof block);
    st[7] = zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, sizeof key, nonce,
                             sizeof nonce, NULL, 0, block, sizeof block,
                             out, tag, sizeof tag);
    st[8] = zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, sizeof key, nonce,
                             sizeof nonce, NULL, 0, block, sizeof block,
                             tag, sizeof tag, out);
    st[9] = zuc_pbkdf2_hmac(ZUC_ALG_SHA256, key, sizeof key, block,
                            sizeof block, 1, out, 32);
    st[10] = zuc_pkey_parse(block, sizeof block, 0, &pkey);
    st[11] = zuc_pkey_generate(ZUC_ALG_RSA, 1024, &pkey);
    st[12] = zuc_pkey_import(ZUC_ALG_X25519, 1, block, 16, &pkey);
    st[13] = zuc_pkey_export(pkey, 0, out, sizeof out, &out_len);
    st[14] = zuc_pkey_agree(pkey, pkey, out, sizeof out, &out_len);
    st[16] = zuc_init();

    /* Anything the calls above wrongly created goes too. */
    zuc_aes_free(live);
    zuc_hash_free(hash);
    zuc_hmac_free(hmac);
    zuc_aes_free(aes);
    zuc_pkey_free(pkey);

    res = PROTECT(Rf_allocVector(STRSXP, N));
    nms = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(res, i, Rf_mkChar(zuc_status_name(st[i])));
        SET_STRING_ELT(nms, i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

/* The NULL-buffer contract zucrypt.h states for the incremental and CBC
 * calls (zucrypt#43, from zuxlsx): a pointer may be NULL only when its
 * length is 0. Returns each call's status by name, plus whether a digest fed
 * only NULL/0 updates equals the digest of the empty input. Every handle is
 * freed before anything is allocated in R. */
SEXP zucrypt_test_null_buffers(void)
{
    static const char *names[] = {
        "hash_update_null_0", "hash_update_null_1",
        "hmac_new_null_key_0", "hmac_update_null_0", "hmac_update_null_1",
        "aes_encrypt_null_0", "aes_decrypt_null_0", "aes_encrypt_null_16",
        "empty_digest_matches"
    };
    enum { N = 9 };
    zuc_status st[N - 1];
    int same = 0, i;
    uint8_t key[ZUC_AES_KEY_SIZE_128] = {0}, iv[ZUC_AES_BLOCK_SIZE] = {0};
    uint8_t a[ZUC_MAX_DIGEST_SIZE], b[ZUC_MAX_DIGEST_SIZE];
    size_t alen = 0, blen = 0;
    zuc_hash *hash = NULL;
    zuc_hmac *hmac = NULL;
    zuc_aes *aes = NULL;
    SEXP res, nms;

    if (zuc_hash_new(ZUC_ALG_SHA256, &hash) != ZUC_OK ||
        zuc_aes_new(key, sizeof key, &aes) != ZUC_OK ||
        zuc_aes_cbc_set_state(aes, iv) != ZUC_OK) {
        zuc_hash_free(hash);
        zuc_aes_free(aes);
        Rf_error("zucrypt: could not create the handles this test needs");
    }

    st[0] = zuc_hash_update(hash, NULL, 0);
    st[1] = zuc_hash_update(hash, NULL, 1);
    st[2] = zuc_hmac_new(ZUC_ALG_SHA256, NULL, 0, &hmac);
    st[3] = hmac != NULL ? zuc_hmac_update(hmac, NULL, 0) : ZUC_ERR_INTERNAL;
    st[4] = hmac != NULL ? zuc_hmac_update(hmac, NULL, 1) : ZUC_ERR_INTERNAL;
    st[5] = zuc_aes_cbc_encrypt(aes, NULL, 0, NULL);
    st[6] = zuc_aes_cbc_decrypt(aes, NULL, 0, NULL);
    st[7] = zuc_aes_cbc_encrypt(aes, NULL, ZUC_AES_BLOCK_SIZE, NULL);

    if (zuc_hash_finish(hash, a, sizeof a, &alen) == ZUC_OK &&
        zuc_hash_compute(ZUC_ALG_SHA256, NULL, 0, b, sizeof b, &blen) == ZUC_OK) {
        same = alen == blen && memcmp(a, b, alen) == 0;
    }

    zuc_hash_free(hash);
    zuc_hmac_free(hmac);
    zuc_aes_free(aes);

    res = PROTECT(Rf_allocVector(STRSXP, N));
    nms = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N - 1; i++) {
        SET_STRING_ELT(res, i, Rf_mkChar(zuc_status_name(st[i])));
        SET_STRING_ELT(nms, i, Rf_mkChar(names[i]));
    }
    SET_STRING_ELT(res, N - 1, Rf_mkChar(same ? "TRUE" : "FALSE"));
    SET_STRING_ELT(nms, N - 1, Rf_mkChar(names[N - 1]));
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

/* Hold `n` live AES handles and `n` live HMAC handles at once, then run a
 * one-shot HMAC and a CBC call with all of them live, then free everything.
 * Under the static key store this failed at the 17th AES handle (#30).
 *
 * Returns the number of each actually created and the first failing status
 * of each step. The handles live in malloc'd arrays and the R result is
 * allocated only after they are all freed, so no longjmp can strand one. */
SEXP zucrypt_test_live_handles(SEXP n_)
{
    int n = Rf_asInteger(n_), i, made_aes = 0, made_hmac = 0;
    zuc_aes **aes;
    zuc_hmac **hmac;
    zuc_status st_aes = ZUC_OK, st_hmac = ZUC_OK, st_mac = ZUC_OK,
               st_cbc = ZUC_OK;
    uint8_t key[ZUC_AES_KEY_SIZE_256], block[ZUC_AES_BLOCK_SIZE] = {0};
    uint8_t out[ZUC_MAX_DIGEST_SIZE];
    size_t out_len = 0;
    SEXP res, nms;
    static const char *names[] = {
        "aes_created", "hmac_created", "aes_new", "hmac_new",
        "hmac_compute", "aes_cbc_encrypt"
    };

    if (n == NA_INTEGER || n < 1 || n > 100000) {
        Rf_error("zucrypt: n must be between 1 and 100000");
    }
    aes = calloc((size_t) n, sizeof *aes);
    hmac = calloc((size_t) n, sizeof *hmac);
    if (aes == NULL || hmac == NULL) {
        free(aes);
        free(hmac);
        Rf_error("zucrypt: out of memory");
    }
    for (i = 0; i < (int) sizeof key; i++) {
        key[i] = (uint8_t) i;
    }

    for (i = 0; i < n && st_aes == ZUC_OK; i++) {
        st_aes = zuc_aes_new(key, sizeof key, &aes[i]);
        if (st_aes == ZUC_OK) made_aes++;
    }
    for (i = 0; i < n && st_hmac == ZUC_OK; i++) {
        st_hmac = zuc_hmac_new(ZUC_ALG_SHA256, key, sizeof key, &hmac[i]);
        if (st_hmac == ZUC_OK) made_hmac++;
    }
    st_mac = zuc_hmac_compute(ZUC_ALG_SHA256, key, sizeof key, block,
                              sizeof block, out, sizeof out, &out_len);
    if (made_aes > 0) {
        st_cbc = zuc_aes_cbc_set_state(aes[0], block);
        if (st_cbc == ZUC_OK) {
            st_cbc = zuc_aes_cbc_encrypt(aes[made_aes - 1], block,
                                         sizeof block, block);
        }
    }

    for (i = 0; i < n; i++) {
        zuc_aes_free(aes[i]);
        zuc_hmac_free(hmac[i]);
    }
    free(aes);
    free(hmac);

    res = PROTECT(Rf_allocVector(VECSXP, 6));
    nms = PROTECT(Rf_allocVector(STRSXP, 6));
    SET_VECTOR_ELT(res, 0, Rf_ScalarInteger(made_aes));
    SET_VECTOR_ELT(res, 1, Rf_ScalarInteger(made_hmac));
    SET_VECTOR_ELT(res, 2, Rf_mkString(zuc_status_name(st_aes)));
    SET_VECTOR_ELT(res, 3, Rf_mkString(zuc_status_name(st_hmac)));
    SET_VECTOR_ELT(res, 4, Rf_mkString(zuc_status_name(st_mac)));
    SET_VECTOR_ELT(res, 5, Rf_mkString(zuc_status_name(st_cbc)));
    for (i = 0; i < 6; i++) {
        SET_STRING_ELT(nms, i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

/* Live native contexts in zucrypt.so; see zuc_live.h. */
SEXP zucrypt_test_live_contexts(void)
{
    return Rf_ScalarReal((double) zuc_int_live_contexts());
}

/* ------------------------------------------------------------------ *
 * Registration
 * ------------------------------------------------------------------ */

/* The contract zucrypt.h states for zuc_random_bytes(), by status name:
 * NULL with length 0 and with length 16, and a draw while the source is
 * made to fail. `wiped` says whether that failed draw left its buffer all
 * zero, having been filled with a non-zero pattern first. The switch is
 * turned off again before anything is allocated in R. */
SEXP zucrypt_test_random_contract(void)
{
    static const char *names[] = {
        "null_0", "null_16", "ok_16", "failing_16", "wiped", "after_failure"
    };
    enum { N = 6 };
    const char *got[N];
    uint8_t buf[16];
    zuc_status st;
    SEXP res, nms;
    size_t i;
    int wiped = 1;

    got[0] = zuc_status_name(zuc_random_bytes(NULL, 0));
    got[1] = zuc_status_name(zuc_random_bytes(NULL, sizeof buf));
    got[2] = zuc_status_name(zuc_random_bytes(buf, sizeof buf));

    memset(buf, 0xA5, sizeof buf);
    zuc_int_random_fail(1);
    st = zuc_random_bytes(buf, sizeof buf);
    zuc_int_random_fail(0);
    got[3] = zuc_status_name(st);
    for (i = 0; i < sizeof buf; i++) {
        if (buf[i] != 0) wiped = 0;
    }
    got[4] = wiped ? "TRUE" : "FALSE";
    got[5] = zuc_status_name(zuc_random_bytes(buf, sizeof buf));

    res = PROTECT(Rf_allocVector(STRSXP, N));
    nms = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(res, (R_xlen_t) i, Rf_mkChar(got[i]));
        SET_STRING_ELT(nms, (R_xlen_t) i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

/* Turn the random source's failure switch on or off, so the R suite can
 * check the condition crypt_rand_bytes() raises. The caller must switch it
 * off again; test-random.R does that with withr::defer(). */
SEXP zucrypt_test_random_fail(SEXP on)
{
    zuc_int_random_fail(Rf_asLogical(on) == TRUE);
    return R_NilValue;
}

/* The AEAD and KDF contracts of zucrypt.h, and design.md section 12's
 * authenticated-encryption gate, driven in C. Every case is named; its
 * value is the status the adapter returned, or "TRUE"/"FALSE" for a
 * property of the buffers afterwards. */
static int all_bytes(const uint8_t *p, size_t n, uint8_t v)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

#define AEAD_ENC(k, kl, n, nl, a, al, in, len, out, t, tl) \
    zuc_aead_encrypt(ZUC_ALG_AES_GCM, k, kl, n, nl, a, al, in, len, out, t, tl)
#define AEAD_DEC(k, kl, n, nl, a, al, in, len, t, tl, out) \
    zuc_aead_decrypt(ZUC_ALG_AES_GCM, k, kl, n, nl, a, al, in, len, t, tl, out)

SEXP zucrypt_test_aead_contract(void)
{
    enum { N = 26, LEN = 40 };
    static const char *names[N] = {
        "encrypt", "decrypt", "roundtrip",
        "tampered_ciphertext", "tampered_tag", "tampered_aad",
        "tampered_nonce", "truncated_tag", "wrong_key", "wiped_on_failure",
        "inplace_encrypt", "inplace_decrypt", "inplace_matches",
        "partial_overlap", "overlap_untouched",
        "null_key", "null_data_0", "null_aad_0", "bad_key_length",
        "bad_nonce_length", "short_tag_encrypt", "not_an_aead",
        "hash_refuses_gcm", "hmac_refuses_gcm", "pbkdf2_refuses_gcm",
        "pbkdf2_zero_iterations"
    };
    const char *got[N];
    uint8_t key[32], key2[32], nonce[ZUC_GCM_NONCE_SIZE], aad[13];
    uint8_t pt[LEN], ct[LEN], out[LEN], buf[LEN + 8];
    uint8_t tag[ZUC_GCM_TAG_SIZE], tag2[ZUC_GCM_TAG_SIZE];
    uint8_t digest[ZUC_MAX_DIGEST_SIZE];
    size_t i, dlen = 0;
    int wiped = 1;
    SEXP res, nms;

    for (i = 0; i < sizeof key; i++) key[i] = (uint8_t) i;
    memcpy(key2, key, sizeof key);
    key2[0] ^= 1;
    for (i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t) (0xC0 + i);
    for (i = 0; i < sizeof aad; i++) aad[i] = (uint8_t) (0x30 + i);
    for (i = 0; i < LEN; i++) pt[i] = (uint8_t) (i * 7);

    got[0] = zuc_status_name(AEAD_ENC(key, 32, nonce, 12, aad, sizeof aad,
                                      pt, LEN, ct, tag, sizeof tag));
    got[1] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag, sizeof tag, out));
    got[2] = memcmp(out, pt, LEN) == 0 ? "TRUE" : "FALSE";

    /* Each tamper is undone before the next. The output is filled with a
     * marker first, so "wiped" means the adapter zeroed it, not that it was
     * never written. */
#define EXPECT_WIPED() do { if (!all_bytes(out, LEN, 0)) wiped = 0; } while (0)
    ct[5] ^= 0x80;
    memset(out, 0xA5, LEN);
    got[3] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag, sizeof tag, out));
    EXPECT_WIPED();
    ct[5] ^= 0x80;

    memcpy(tag2, tag, sizeof tag);
    tag2[15] ^= 1;
    memset(out, 0xA5, LEN);
    got[4] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag2, sizeof tag2, out));
    EXPECT_WIPED();

    aad[0] ^= 1;
    memset(out, 0xA5, LEN);
    got[5] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag, sizeof tag, out));
    EXPECT_WIPED();
    aad[0] ^= 1;

    nonce[11] ^= 1;
    memset(out, 0xA5, LEN);
    got[6] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag, sizeof tag, out));
    EXPECT_WIPED();
    nonce[11] ^= 1;

    /* A truncated tag is the right prefix: GCM would verify it as a shorter
     * tag, so refusing it has to happen here, before the backend. */
    memset(out, 0xA5, LEN);
    got[7] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag, sizeof tag - 1, out));
    /* Wiped like every other ZUC_ERR_AUTH, although it is refused before
     * the backend runs: this harness used to zero the buffer itself here,
     * which hid that the adapter did not (found by fuzz/fuzz_gcm.c). */
    EXPECT_WIPED();

    memset(out, 0xA5, LEN);
    got[8] = zuc_status_name(AEAD_DEC(key2, 32, nonce, 12, aad, sizeof aad,
                                      ct, LEN, tag, sizeof tag, out));
    EXPECT_WIPED();
    got[9] = wiped ? "TRUE" : "FALSE";
#undef EXPECT_WIPED

    /* Exact in place, both directions, equal to the separate buffers. */
    memcpy(buf, pt, LEN);
    got[10] = zuc_status_name(AEAD_ENC(key, 32, nonce, 12, aad, sizeof aad,
                                       buf, LEN, buf, tag2, sizeof tag2));
    i = memcmp(buf, ct, LEN) == 0 && memcmp(tag2, tag, sizeof tag) == 0;
    got[11] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, aad, sizeof aad,
                                       buf, LEN, tag, sizeof tag, buf));
    got[12] = (i && memcmp(buf, pt, LEN) == 0) ? "TRUE" : "FALSE";

    /* Partial overlap is refused before anything is written. */
    memcpy(buf, pt, LEN);
    got[13] = zuc_status_name(AEAD_ENC(key, 32, nonce, 12, NULL, 0,
                                       buf, LEN, buf + 8, tag2, sizeof tag2));
    got[14] = memcmp(buf, pt, LEN) == 0 ? "TRUE" : "FALSE";

    got[15] = zuc_status_name(AEAD_ENC(NULL, 32, nonce, 12, NULL, 0,
                                       pt, LEN, out, tag2, sizeof tag2));
    got[16] = zuc_status_name(AEAD_ENC(key, 32, nonce, 12, NULL, 0,
                                       NULL, 0, NULL, tag2, sizeof tag2));
    got[17] = zuc_status_name(AEAD_DEC(key, 32, nonce, 12, NULL, 0,
                                       NULL, 0, tag2, sizeof tag2, NULL));
    got[18] = zuc_status_name(AEAD_ENC(key, 20, nonce, 12, NULL, 0,
                                       pt, LEN, out, tag2, sizeof tag2));
    got[19] = zuc_status_name(AEAD_ENC(key, 32, nonce, 16, NULL, 0,
                                       pt, LEN, out, tag2, sizeof tag2));
    got[20] = zuc_status_name(AEAD_ENC(key, 32, nonce, 12, NULL, 0,
                                       pt, LEN, out, tag2, 12));
    got[21] = zuc_status_name(zuc_aead_encrypt(ZUC_ALG_SHA256, key, 32, nonce,
                                               12, NULL, 0, pt, LEN, out,
                                               tag2, sizeof tag2));
    got[22] = zuc_status_name(zuc_hash_compute(ZUC_ALG_AES_GCM, pt, LEN,
                                               digest, sizeof digest, &dlen));
    got[23] = zuc_status_name(zuc_hmac_compute(ZUC_ALG_AES_GCM, key, 32, pt,
                                               LEN, digest, sizeof digest,
                                               &dlen));
    got[24] = zuc_status_name(zuc_pbkdf2_hmac(ZUC_ALG_AES_GCM, key, 32, pt,
                                              16, 1, digest, 32));
    got[25] = zuc_status_name(zuc_pbkdf2_hmac(ZUC_ALG_SHA256, key, 32, pt,
                                              16, 0, digest, 32));

    zuc_secure_zero(out, sizeof out);
    zuc_secure_zero(buf, sizeof buf);

    res = PROTECT(Rf_allocVector(STRSXP, N));
    nms = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(res, (R_xlen_t) i, Rf_mkChar(got[i]));
        SET_STRING_ELT(nms, (R_xlen_t) i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

#undef AEAD_ENC
#undef AEAD_DEC

/* The public-key contract of zucrypt.h, on a private key given as PEM or
 * DER. Each case is named; its value is a status name, or "TRUE"/"FALSE"
 * for a property of the buffers afterwards. */
SEXP zucrypt_test_pkey_contract(SEXP pem)
{
    enum { N = 16 };
    static const char *names[N] = {
        "parse", "sign", "verify", "sig_flipped", "sig_short",
        "pss_as_pkcs1", "sign_with_public", "digest_length", "sign_gcm",
        "encrypt", "decrypt_garbage", "decrypt_wiped", "decrypt_public",
        "write_small", "write_wiped", "free_null"
    };
    const char *got[N];
    zuc_pkey *key = NULL, *pub = NULL;
    uint8_t digest[32], sig[600], buf[600], small[16];
    size_t len = 0, slen = 0, i;
    SEXP res, nms;

    for (i = 0; i < N; i++) got[i] = "unset";
    for (i = 0; i < sizeof digest; i++) digest[i] = (uint8_t) i;

    got[0] = zuc_status_name(zuc_pkey_parse(RAW(pem), (size_t) XLENGTH(pem),
                                            1, &key));
    if (key == NULL || zuc_pkey_public(key, &pub) != ZUC_OK) {
        zuc_pkey_free(key);
        Rf_error("zucrypt: the contract test needs a readable private key");
    }
    got[1] = zuc_status_name(zuc_pkey_sign_hash(
        key, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256, digest, 32,
        sig, sizeof sig, &slen));
    got[2] = zuc_status_name(zuc_pkey_verify_hash(
        pub, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256, digest, 32, sig,
        slen));
    sig[0] ^= 1;
    got[3] = zuc_status_name(zuc_pkey_verify_hash(
        pub, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256, digest, 32, sig,
        slen));
    sig[0] ^= 1;
    got[4] = zuc_status_name(zuc_pkey_verify_hash(
        pub, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256, digest, 32, sig,
        slen - 1));
    got[5] = zuc_status_name(zuc_pkey_verify_hash(
        pub, ZUC_ALG_RSA_PSS, ZUC_ALG_SHA256, digest, 32, sig, slen));
    got[6] = zuc_status_name(zuc_pkey_sign_hash(
        pub, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256, digest, 32,
        sig, sizeof sig, &len));
    got[7] = zuc_status_name(zuc_pkey_sign_hash(
        key, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_SHA256, digest, 31,
        sig, sizeof sig, &len));
    got[8] = zuc_status_name(zuc_pkey_sign_hash(
        key, ZUC_ALG_RSA_PKCS1V15_SIGN, ZUC_ALG_AES_GCM, digest, 32,
        sig, sizeof sig, &len));

    got[9] = zuc_status_name(zuc_pkey_encrypt(
        pub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, digest, 32,
        sig, sizeof sig, &slen));
    /* A ciphertext of the right length that is not one: the output must be
     * the one status, and wiped. */
    memset(sig, 0x55, slen);
    memset(buf, 0xA5, sizeof buf);
    got[10] = zuc_status_name(zuc_pkey_decrypt(
        key, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, sig, slen,
        buf, sizeof buf, &len));
    got[11] = (all_bytes(buf, sizeof buf, 0) && len == 0) ? "TRUE" : "FALSE";
    got[12] = zuc_status_name(zuc_pkey_decrypt(
        pub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256, sig, slen,
        buf, sizeof buf, &len));

    memset(small, 0xA5, sizeof small);
    got[13] = zuc_status_name(zuc_pkey_write(key, ZUC_PKEY_INFO_PEM, 0,
                                             small, sizeof small, &len));
    got[14] = all_bytes(small, sizeof small, 0) ? "TRUE" : "FALSE";
    zuc_pkey_free(NULL);
    got[15] = "TRUE";

    zuc_pkey_free(pub);
    zuc_pkey_free(key);

    res = PROTECT(Rf_allocVector(STRSXP, N));
    nms = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(res, (R_xlen_t) i, Rf_mkChar(got[i]));
        SET_STRING_ELT(nms, (R_xlen_t) i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

/* The elliptic-curve contract of zucrypt.h (Stage 16a), on keys this
 * function generates. Each case is named; its value is a status name, or
 * "TRUE"/"FALSE" for a property of the buffers. */
SEXP zucrypt_test_ec_contract(void)
{
    enum { N = 18 };
    static const char *names[N] = {
        "generate", "export_point", "import_point", "off_curve",
        "scalar_zero", "sign", "verify", "verify_short", "sign_x25519",
        "pss_on_ec", "encrypt_ec", "agree", "agree_symmetric",
        "agree_other_curve", "x25519_zero", "x25519_zero_wiped",
        "pkcs1_public_ec", "pkcs1_x25519"
    };
    const char *got[N];
    zuc_pkey *a = NULL, *b = NULL, *pub = NULL, *bad = NULL, *p384 = NULL;
    zuc_pkey *x = NULL, *xzero = NULL;
    uint8_t point[133], digest[32], sig[132], k1[66], k2[66], buf[1024];
    uint8_t zero32[32] = {0}, scalar0[32] = {0};
    size_t plen = 0, slen = 0, l1 = 0, l2 = 0, len = 0, i;
    SEXP res, nms;

    for (i = 0; i < N; i++) got[i] = "unset";
    for (i = 0; i < sizeof digest; i++) digest[i] = (uint8_t) (i * 3);

    got[0] = zuc_status_name(zuc_pkey_generate(ZUC_ALG_EC_P256, 0, &a));
    if (a == NULL || zuc_pkey_generate(ZUC_ALG_EC_P256, 256, &b) != ZUC_OK ||
        zuc_pkey_generate(ZUC_ALG_EC_P384, 0, &p384) != ZUC_OK ||
        zuc_pkey_generate(ZUC_ALG_X25519, 0, &x) != ZUC_OK) {
        zuc_pkey_free(a); zuc_pkey_free(b); zuc_pkey_free(p384);
        zuc_pkey_free(x);
        Rf_error("zucrypt: the EC contract test could not generate keys");
    }
    got[1] = (zuc_pkey_export(a, 1, point, sizeof point, &plen) == ZUC_OK &&
              plen == 65 && point[0] == 0x04) ? "TRUE" : "FALSE";
    got[2] = zuc_status_name(zuc_pkey_import(ZUC_ALG_EC_P256, 0, point, plen,
                                             &pub));
    point[64] ^= 1;
    got[3] = zuc_status_name(zuc_pkey_import(ZUC_ALG_EC_P256, 0, point, plen,
                                             &bad));
    point[64] ^= 1;
    zuc_pkey_free(bad);
    bad = NULL;
    got[4] = zuc_status_name(zuc_pkey_import(ZUC_ALG_EC_P256, 1, scalar0,
                                             sizeof scalar0, &bad));
    zuc_pkey_free(bad);
    bad = NULL;

    got[5] = zuc_status_name(zuc_pkey_sign_hash(a, ZUC_ALG_ECDSA,
                                                ZUC_ALG_SHA256, digest, 32,
                                                sig, sizeof sig, &slen));
    got[6] = zuc_status_name(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA,
                                                  ZUC_ALG_SHA256, digest, 32,
                                                  sig, slen));
    got[7] = zuc_status_name(zuc_pkey_verify_hash(pub, ZUC_ALG_ECDSA,
                                                  ZUC_ALG_SHA256, digest, 32,
                                                  sig, slen - 1));
    got[8] = zuc_status_name(zuc_pkey_sign_hash(x, ZUC_ALG_ECDSA,
                                                ZUC_ALG_SHA256, digest, 32,
                                                sig, sizeof sig, &len));
    got[9] = zuc_status_name(zuc_pkey_sign_hash(a, ZUC_ALG_RSA_PSS,
                                                ZUC_ALG_SHA256, digest, 32,
                                                sig, sizeof sig, &len));
    got[10] = zuc_status_name(zuc_pkey_encrypt(a, ZUC_ALG_RSA_OAEP,
                                               ZUC_ALG_SHA256, digest, 32,
                                               buf, sizeof buf, &len));
    got[11] = zuc_status_name(zuc_pkey_agree(a, b, k1, sizeof k1, &l1));
    got[12] = (zuc_pkey_agree(b, a, k2, sizeof k2, &l2) == ZUC_OK &&
               l1 == 32 && l1 == l2 && memcmp(k1, k2, l1) == 0)
                  ? "TRUE" : "FALSE";
    got[13] = zuc_status_name(zuc_pkey_agree(a, p384, k1, sizeof k1, &l1));
    /* An all-zero public key is a low-order point: if the backend imports
     * it, agreement must still refuse the all-zero result. */
    if (zuc_pkey_import(ZUC_ALG_X25519, 0, zero32, 32, &xzero) == ZUC_OK) {
        memset(k1, 0xA5, sizeof k1);
        got[14] = zuc_status_name(zuc_pkey_agree(x, xzero, k1, sizeof k1,
                                                 &l1));
        got[15] = all_bytes(k1, sizeof k1, 0) ? "TRUE" : "FALSE";
    } else {
        got[14] = "ZUC_ERR_INVALID_ARGUMENT";
        got[15] = "TRUE";
    }
    got[16] = zuc_status_name(zuc_pkey_write(pub, ZUC_PKEY_PKCS1_DER, 0, buf,
                                             sizeof buf, &len));
    got[17] = zuc_status_name(zuc_pkey_write(x, ZUC_PKEY_PKCS1_PEM, 0, buf,
                                             sizeof buf, &len));

    zuc_pkey_free(a); zuc_pkey_free(b); zuc_pkey_free(pub);
    zuc_pkey_free(p384); zuc_pkey_free(x); zuc_pkey_free(xzero);

    res = PROTECT(Rf_allocVector(STRSXP, N));
    nms = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(res, (R_xlen_t) i, Rf_mkChar(got[i]));
        SET_STRING_ELT(nms, (R_xlen_t) i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(2);
    return res;
}

/* A handle kept across the last zuc_shutdown() (#92). Tears the backend
 * down and brings it back, as zucrypt_test_not_ready() does and under the
 * same guard, with one AES, one HMAC and one digest handle made before the
 * teardown and an AES and an HMAC handle made after it, which are handed
 * the old handles' key ids again. The old handles must refuse with
 * ZUC_ERR_NOT_READY -- reset included, which would re-use the key id -- and
 * freeing them must leave the new handles' keys alone. Returns the
 * statuses by name and the new handles' outputs, before and after the old
 * handles are freed, for R to compare with the functions it exports. No R
 * allocation happens while the backend is down. */
SEXP zucrypt_test_stale_handles(void)
{
    static const char *names[] = {
        "shutdown", "init", "aes_old_encrypt", "hmac_old_update",
        "hmac_old_finish", "hmac_old_reset", "hash_old_update",
        "hash_old_finish", "hash_old_reset", "aes_new", "hmac_new"
    };
    enum { N = 11 };
    zuc_status st[N];
    uint8_t key1[16], key2[16], zero[16] = {0}, block[16];
    uint8_t aes_before[16], aes_after[16], mac_before[32], mac_after[32];
    uint8_t mac[32];
    size_t len = 0;
    zuc_aes *aes_old = NULL, *aes_new = NULL;
    zuc_hmac *hmac_old = NULL, *hmac_new = NULL;
    zuc_hash *hash_old = NULL;
    SEXP res, nms, codes, cn;
    int i;

    if (zuc_int_live_contexts() != 0) {
        Rf_error("zucrypt: zucrypt_test_stale_handles() needs no live "
                 "handle, and %ld are live", zuc_int_live_contexts());
    }
    memset(key1, 0x01, sizeof key1);
    memset(key2, 0x02, sizeof key2);
    memset(aes_before, 0, sizeof aes_before);
    memset(aes_after, 0, sizeof aes_after);
    memset(mac_before, 0, sizeof mac_before);
    memset(mac_after, 0, sizeof mac_after);

    if (zuc_aes_new(key1, sizeof key1, &aes_old) != ZUC_OK ||
        zuc_hmac_new(ZUC_ALG_SHA256, key1, sizeof key1, &hmac_old) != ZUC_OK ||
        zuc_hash_new(ZUC_ALG_SHA256, &hash_old) != ZUC_OK) {
        zuc_aes_free(aes_old);
        zuc_hmac_free(hmac_old);
        zuc_hash_free(hash_old);
        Rf_error("zucrypt: could not create the handles this test needs");
    }

    st[0] = zuc_shutdown();
    st[1] = zuc_init();

    st[9] = zuc_aes_new(key2, sizeof key2, &aes_new);
    st[10] = zuc_hmac_new(ZUC_ALG_SHA256, key2, sizeof key2, &hmac_new);

    memcpy(block, zero, sizeof block);
    zuc_aes_cbc_set_state(aes_old, zero);
    st[2] = zuc_aes_cbc_encrypt(aes_old, zero, sizeof zero, block);
    st[3] = zuc_hmac_update(hmac_old, (const uint8_t *) "abc", 3);
    st[4] = zuc_hmac_finish(hmac_old, mac, sizeof mac, &len);
    st[5] = zuc_hmac_reset(hmac_old);
    st[6] = zuc_hash_update(hash_old, (const uint8_t *) "abc", 3);
    st[7] = zuc_hash_finish(hash_old, mac, sizeof mac, &len);
    st[8] = zuc_hash_reset(hash_old);

    if (aes_new != NULL) {
        zuc_aes_cbc_set_state(aes_new, zero);
        zuc_aes_cbc_encrypt(aes_new, zero, sizeof zero, aes_before);
    }
    if (hmac_new != NULL) {
        zuc_hmac_update(hmac_new, (const uint8_t *) "abc", 3);
        zuc_hmac_finish(hmac_new, mac_before, sizeof mac_before, &len);
    }

    zuc_aes_free(aes_old);
    zuc_hmac_free(hmac_old);
    zuc_hash_free(hash_old);

    if (aes_new != NULL) {
        zuc_aes_cbc_set_state(aes_new, zero);
        zuc_aes_cbc_encrypt(aes_new, zero, sizeof zero, aes_after);
    }
    if (hmac_new != NULL) {
        zuc_hmac_reset(hmac_new);
        zuc_hmac_update(hmac_new, (const uint8_t *) "abc", 3);
        zuc_hmac_finish(hmac_new, mac_after, sizeof mac_after, &len);
    }
    zuc_aes_free(aes_new);
    zuc_hmac_free(hmac_new);

    res = PROTECT(Rf_allocVector(VECSXP, 5));
    nms = PROTECT(Rf_allocVector(STRSXP, 5));
    codes = PROTECT(Rf_allocVector(STRSXP, N));
    cn = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(codes, i, Rf_mkChar(zuc_status_name(st[i])));
        SET_STRING_ELT(cn, i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(codes, R_NamesSymbol, cn);
    SET_VECTOR_ELT(res, 0, codes);
    SET_VECTOR_ELT(res, 1, Rf_allocVector(RAWSXP, 16));
    memcpy(RAW(VECTOR_ELT(res, 1)), aes_before, 16);
    SET_VECTOR_ELT(res, 2, Rf_allocVector(RAWSXP, 16));
    memcpy(RAW(VECTOR_ELT(res, 2)), aes_after, 16);
    SET_VECTOR_ELT(res, 3, Rf_allocVector(RAWSXP, 32));
    memcpy(RAW(VECTOR_ELT(res, 3)), mac_before, 32);
    SET_VECTOR_ELT(res, 4, Rf_allocVector(RAWSXP, 32));
    memcpy(RAW(VECTOR_ELT(res, 4)), mac_after, 32);
    SET_STRING_ELT(nms, 0, Rf_mkChar("status"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("aes_before_free"));
    SET_STRING_ELT(nms, 2, Rf_mkChar("aes_after_free"));
    SET_STRING_ELT(nms, 3, Rf_mkChar("hmac_before_free"));
    SET_STRING_ELT(nms, 4, Rf_mkChar("hmac_after_free"));
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(4);
    return res;
}

/* A backend failure inside an update (#108). Fails the backend allocation
 * that copies the update's input, then walks the handle through what a
 * consumer would do next: an empty update, a one-byte update and a finish
 * on the failed operation must all be refused, and a reset must bring it
 * back to a working digest of "abc". `kind` is "hash" or "hmac" (SHA-256,
 * the HMAC keyed with the 16 bytes 01..01). Returns the statuses by name
 * and the final digest. */
SEXP zucrypt_test_update_failure(SEXP kind)
{
    static const char *names[] = {
        "new", "failed_update", "update_empty", "update_byte", "finish",
        "reset", "update", "final"
    };
    enum { N = 8 };
    zuc_status st[N];
    uint8_t key[16], data[64], out[32];
    size_t len = 0;
    int hmac;
    zuc_hash *h = NULL;
    zuc_hmac *m = NULL;
    SEXP res, nms, codes, cn;
    int i;

    if (TYPEOF(kind) != STRSXP || XLENGTH(kind) != 1) {
        Rf_error("zucrypt: kind must be \"hash\" or \"hmac\"");
    }
    hmac = strcmp(CHAR(STRING_ELT(kind, 0)), "hmac") == 0;
    memset(key, 0x01, sizeof key);
    memset(data, 0x5a, sizeof data);
    memset(out, 0, sizeof out);

    st[0] = hmac ? zuc_hmac_new(ZUC_ALG_SHA256, key, sizeof key, &m)
                 : zuc_hash_new(ZUC_ALG_SHA256, &h);
    if (st[0] != ZUC_OK) {
        Rf_error("zucrypt: could not create the handle this test needs");
    }
    zuc_int_alloc_fail_at(1);
    st[1] = hmac ? zuc_hmac_update(m, data, sizeof data)
                 : zuc_hash_update(h, data, sizeof data);
    zuc_int_alloc_fail_at(0);
    st[2] = hmac ? zuc_hmac_update(m, data, 0) : zuc_hash_update(h, data, 0);
    st[3] = hmac ? zuc_hmac_update(m, data, 1) : zuc_hash_update(h, data, 1);
    st[4] = hmac ? zuc_hmac_finish(m, out, sizeof out, &len)
                 : zuc_hash_finish(h, out, sizeof out, &len);
    st[5] = hmac ? zuc_hmac_reset(m) : zuc_hash_reset(h);
    st[6] = hmac ? zuc_hmac_update(m, (const uint8_t *) "abc", 3)
                 : zuc_hash_update(h, (const uint8_t *) "abc", 3);
    memset(out, 0, sizeof out);
    st[7] = hmac ? zuc_hmac_finish(m, out, sizeof out, &len)
                 : zuc_hash_finish(h, out, sizeof out, &len);
    zuc_hmac_free(m);
    zuc_hash_free(h);

    res = PROTECT(Rf_allocVector(VECSXP, 2));
    nms = PROTECT(Rf_allocVector(STRSXP, 2));
    codes = PROTECT(Rf_allocVector(STRSXP, N));
    cn = PROTECT(Rf_allocVector(STRSXP, N));
    for (i = 0; i < N; i++) {
        SET_STRING_ELT(codes, i, Rf_mkChar(zuc_status_name(st[i])));
        SET_STRING_ELT(cn, i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(codes, R_NamesSymbol, cn);
    SET_VECTOR_ELT(res, 0, codes);
    SET_VECTOR_ELT(res, 1, Rf_allocVector(RAWSXP, 32));
    memcpy(RAW(VECTOR_ELT(res, 1)), out, 32);
    SET_STRING_ELT(nms, 0, Rf_mkChar("status"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("digest"));
    Rf_setAttrib(res, R_NamesSymbol, nms);
    UNPROTECT(4);
    return res;
}

/* The residue scan (#137): parse `key` (DER or PEM; `private_key` as for
 * zuc_pkey_parse()), then, armed with `needle`, run one operation and
 * report how many blocks the backend freed with `needle` still in them.
 * op: "write1".."write4" writes the key in that zuc_pkey_format (private
 * where the key is), "parse" reads `key` again. Returns
 * list(hits = integer, output = raw): the output of a write, so a caller
 * can derive a needle from it first with an empty one. */
SEXP zucrypt_test_residue(SEXP key, SEXP private_key, SEXP op, SEXP needle)
{
    size_t key_len = 0, needle_len = 0, out_len = 0;
    const uint8_t *key_bytes = raw_arg(key, &key_len, "key");
    const uint8_t *needle_bytes = raw_arg(needle, &needle_len, "needle");
    int priv = Rf_asLogical(private_key);
    const char *what;
    static uint8_t buf[ZUC_PKEY_MAX_WRITE_SIZE];
    zuc_pkey *k = NULL, *again = NULL;
    zuc_status st;
    long hits;
    SEXP out, names, written;

    if (priv == NA_LOGICAL) Rf_error("zucrypt: private_key must be TRUE or FALSE");
    if (TYPEOF(op) != STRSXP || Rf_length(op) != 1) {
        Rf_error("zucrypt: op must be a single string");
    }
    what = CHAR(STRING_ELT(op, 0));
    if (strncmp(what, "write", 5) != 0 && strcmp(what, "parse") != 0) {
        Rf_error("zucrypt: op must be write1 to write4 or parse");
    }
    out = PROTECT(Rf_allocVector(VECSXP, 2));
    names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(names, 0, Rf_mkChar("hits"));
    SET_STRING_ELT(names, 1, Rf_mkChar("output"));
    Rf_setAttrib(out, R_NamesSymbol, names);

    st = zuc_pkey_parse(key_bytes, key_len, priv, &k);
    if (st == ZUC_OK) {
        zuc_int_residue_arm(needle_bytes, needle_len);
        if (strcmp(what, "parse") == 0) {
            st = zuc_pkey_parse(key_bytes, key_len, priv, &again);
            zuc_pkey_free(again);
        } else {
            st = zuc_pkey_write(k, (zuc_pkey_format) (what[5] - '0'), 0,
                                buf, sizeof buf, &out_len);
        }
        hits = zuc_int_residue_disarm();
        zuc_pkey_free(k);
    } else {
        hits = 0;
    }
    if (st != ZUC_OK) {
        zuc_secure_zero(buf, sizeof buf);
        UNPROTECT(2);
        stop_on(st, "residue");
    }
    written = Rf_allocVector(RAWSXP, (R_xlen_t) out_len);
    SET_VECTOR_ELT(out, 1, written);
    memcpy(RAW(written), buf, out_len);
    zuc_secure_zero(buf, sizeof buf);
    SET_VECTOR_ELT(out, 0, Rf_ScalarInteger((int) hits));
    UNPROTECT(2);
    return out;
}

/* The residue scan's positive control: a block allocated and freed through
 * the backend's allocator with the needle in it is found, and one wiped
 * first is not. Returns the hits for the unwiped block (1 when the scan
 * works) plus 10 times those for the wiped one (0 when it works). */
SEXP zucrypt_test_residue_control(void)
{
    return Rf_ScalarInteger((int) zuc_int_residue_control());
}

const R_CallMethodDef zucrypt_test_call_methods[] = {
    {"zucrypt_test_hash",           (DL_FUNC) &zucrypt_test_hash,           3},
    {"zucrypt_test_hmac",           (DL_FUNC) &zucrypt_test_hmac,           4},
    {"zucrypt_test_hash_reset",     (DL_FUNC) &zucrypt_test_hash_reset,     3},
    {"zucrypt_test_hmac_reset",     (DL_FUNC) &zucrypt_test_hmac_reset,     4},
    {"zucrypt_test_aes",            (DL_FUNC) &zucrypt_test_aes,            7},
    {"zucrypt_test_aes_inplace",    (DL_FUNC) &zucrypt_test_aes_inplace,    4},
    {"zucrypt_test_aes_overlap",    (DL_FUNC) &zucrypt_test_aes_overlap,    4},
    {"zucrypt_test_equal",          (DL_FUNC) &zucrypt_test_equal,          2},
    {"zucrypt_test_algs",           (DL_FUNC) &zucrypt_test_algs,           0},
    {"zucrypt_test_status",         (DL_FUNC) &zucrypt_test_status,         1},
    {"zucrypt_test_info_size",      (DL_FUNC) &zucrypt_test_info_size,      1},
    {"zucrypt_test_required_sizes", (DL_FUNC) &zucrypt_test_required_sizes, 0},
    {"zucrypt_test_not_ready",      (DL_FUNC) &zucrypt_test_not_ready,      0},
    {"zucrypt_test_live_handles",   (DL_FUNC) &zucrypt_test_live_handles,   1},
    {"zucrypt_test_live_contexts",  (DL_FUNC) &zucrypt_test_live_contexts,  0},
    {"zucrypt_test_null_buffers",   (DL_FUNC) &zucrypt_test_null_buffers,   0},
    {"zucrypt_test_random_contract", (DL_FUNC) &zucrypt_test_random_contract, 0},
    {"zucrypt_test_random_fail",    (DL_FUNC) &zucrypt_test_random_fail,    1},
    {"zucrypt_test_aead_contract",  (DL_FUNC) &zucrypt_test_aead_contract,  0},
    {"zucrypt_test_pkey_contract",  (DL_FUNC) &zucrypt_test_pkey_contract,  1},
    {"zucrypt_test_ec_contract",    (DL_FUNC) &zucrypt_test_ec_contract,    0},
    {"zucrypt_test_stale_handles",  (DL_FUNC) &zucrypt_test_stale_handles,  0},
    {"zucrypt_test_update_failure", (DL_FUNC) &zucrypt_test_update_failure, 1},
    {"zucrypt_test_sha_monte",      (DL_FUNC) &zucrypt_test_sha_monte,      3},
    {"zucrypt_test_cbc_mct",        (DL_FUNC) &zucrypt_test_cbc_mct,        5},
    {"zucrypt_test_residue",        (DL_FUNC) &zucrypt_test_residue,        4},
    {"zucrypt_test_residue_control", (DL_FUNC) &zucrypt_test_residue_control, 0},
    {NULL, NULL, 0}
};
