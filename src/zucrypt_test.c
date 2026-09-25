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
        "aes_cbc_encrypt", "shutdown", "init"
    };
    enum { N = 8 };
    zuc_status st[N];
    uint8_t key[ZUC_AES_KEY_SIZE_128] = {0}, block[ZUC_AES_BLOCK_SIZE] = {0};
    uint8_t out[ZUC_MAX_DIGEST_SIZE];
    size_t out_len = 0;
    zuc_hash *hash = NULL;
    zuc_hmac *hmac = NULL;
    zuc_aes *aes = NULL, *live = NULL;
    SEXP res, nms;
    int i;

    if (zuc_aes_new(key, sizeof key, &live) != ZUC_OK) {
        Rf_error("zucrypt: could not create the handle this test needs");
    }

    st[6] = zuc_shutdown();
    st[0] = zuc_hash_compute(ZUC_ALG_SHA256, block, sizeof block,
                             out, sizeof out, &out_len);
    st[1] = zuc_hash_new(ZUC_ALG_SHA256, &hash);
    st[2] = zuc_hmac_compute(ZUC_ALG_SHA256, key, sizeof key, block,
                             sizeof block, out, sizeof out, &out_len);
    st[3] = zuc_hmac_new(ZUC_ALG_SHA256, key, sizeof key, &hmac);
    st[4] = zuc_aes_new(key, sizeof key, &aes);
    st[5] = zuc_aes_cbc_encrypt(live, block, sizeof block, block);
    st[7] = zuc_init();

    /* Anything the calls above wrongly created goes too. */
    zuc_aes_free(live);
    zuc_hash_free(hash);
    zuc_hmac_free(hmac);
    zuc_aes_free(aes);

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
    {NULL, NULL, 0}
};
