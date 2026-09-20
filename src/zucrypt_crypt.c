/* zucrypt: the native entry points behind the crypt_* functions.
 *
 * R-facing, so it speaks zuc_* and never PSA; tools/check-layering.sh
 * enforces that. It is not in inst/lib/libzucrypt.a.
 *
 * Two rules shape every function here.
 *
 * No Rf_error() below the outermost .Call. Each returns a two-element list
 * -- status and value -- and R turns a failing status into a condition with
 * a class (design.md section 3). The exceptions are argument *types*, which
 * R has already checked, so a wrong type arriving here is a bug in this
 * package rather than a user error.
 *
 * Nothing heap-allocated survives a longjmp. R_CheckUserInterrupt() jumps
 * past every free() beneath it, and this package's heap state is exactly the
 * state that must not leak: contexts holding key material. So a context is
 * owned by an external pointer with a finalizer from the moment it exists,
 * and is released eagerly on the success path with the pointer cleared first.
 * That is the family's pattern, and it is why the interrupt check below is
 * safe to have at all.
 */

#include <stdlib.h>
#include <string.h>

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include "zucrypt.h"

/* How much input to process between interrupt checks. Large enough that the
 * per-chunk overhead is noise on a big input, small enough that Ctrl-C on a
 * multi-gigabyte hash is answered promptly. */
#define ZUCRYPT_CHUNK (1024u * 1024u)

/* ------------------------------------------------------------------ *
 * Context ownership
 * ------------------------------------------------------------------ */

static void hash_finalizer(SEXP ptr)
{
    zuc_hash *h = (zuc_hash *) R_ExternalPtrAddr(ptr);
    if (h != NULL) {
        zuc_hash_free(h);
        R_ClearExternalPtr(ptr);
    }
}

static void hmac_finalizer(SEXP ptr)
{
    zuc_hmac *h = (zuc_hmac *) R_ExternalPtrAddr(ptr);
    if (h != NULL) {
        zuc_hmac_free(h);
        R_ClearExternalPtr(ptr);
    }
}

static void aes_finalizer(SEXP ptr)
{
    zuc_aes *a = (zuc_aes *) R_ExternalPtrAddr(ptr);
    if (a != NULL) {
        zuc_aes_free(a);
        R_ClearExternalPtr(ptr);
    }
}

/* The eager release. Clearing the pointer before freeing is the order that
 * matters: if the finalizer ran afterwards on a pointer still holding the
 * address, it would free it twice. */
static void release_ptr(SEXP ptr, void (*freefn)(void *))
{
    void *p = R_ExternalPtrAddr(ptr);
    if (p != NULL) {
        R_ClearExternalPtr(ptr);
        freefn(p);
    }
}

static void free_hash(void *p) { zuc_hash_free((zuc_hash *) p); }
static void free_hmac(void *p) { zuc_hmac_free((zuc_hmac *) p); }
static void free_aes(void *p)  { zuc_aes_free((zuc_aes *) p); }

/* ------------------------------------------------------------------ *
 * Result shape
 * ------------------------------------------------------------------ */

/* list(status = <int>, value = <whatever>). R reads the status first and
 * raises a condition if it is not ZUC_OK, so `value` on a failure is only
 * ever R_NilValue or a partially filled buffer nobody looks at. */
static SEXP result(zuc_status status, SEXP value)
{
    SEXP out = PROTECT(Rf_allocVector(VECSXP, 2));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, 2));

    SET_VECTOR_ELT(out, 0, Rf_ScalarInteger((int) status));
    SET_VECTOR_ELT(out, 1, value);
    SET_STRING_ELT(nms, 0, Rf_mkChar("status"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("value"));
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

/* ------------------------------------------------------------------ *
 * Digest and HMAC
 * ------------------------------------------------------------------ */

SEXP zucrypt_hash(SEXP data, SEXP algorithm)
{
    zuc_alg alg = zuc_alg_by_name(CHAR(STRING_ELT(algorithm, 0)));
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t total = (size_t) XLENGTH(data);
    size_t want = zuc_alg_size(alg);
    SEXP out, ptr;
    zuc_hash *h = NULL;
    zuc_status st;
    size_t got = 0, offset = 0;

    st = zuc_hash_new(alg, &h);
    if (st != ZUC_OK) {
        return result(st, R_NilValue);
    }
    /* Owned from here on, before anything below can longjmp. */
    ptr = PROTECT(R_MakeExternalPtr(h, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(ptr, hash_finalizer, TRUE);

    while (offset < total && st == ZUC_OK) {
        size_t n = total - offset;
        if (n > ZUCRYPT_CHUNK) n = ZUCRYPT_CHUNK;
        st = zuc_hash_update(h, bytes + offset, n);
        offset += n;
        /* After the update, so an interrupt never lands between reading the
         * input and accounting for it. */
        R_CheckUserInterrupt();
    }

    if (st != ZUC_OK) {
        release_ptr(ptr, free_hash);
        UNPROTECT(1);
        return result(st, R_NilValue);
    }

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    st = zuc_hash_finish(h, (uint8_t *) RAW(out), want, &got);
    release_ptr(ptr, free_hash);
    if (st == ZUC_OK && got != want) {
        st = ZUC_ERR_INTERNAL;
    }
    UNPROTECT(2);
    return result(st, st == ZUC_OK ? out : R_NilValue);
}

SEXP zucrypt_hmac(SEXP data, SEXP key, SEXP algorithm)
{
    zuc_alg alg = zuc_alg_by_name(CHAR(STRING_ELT(algorithm, 0)));
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t total = (size_t) XLENGTH(data);
    size_t want = zuc_alg_size(alg);
    SEXP out, ptr;
    zuc_hmac *h = NULL;
    zuc_status st;
    size_t got = 0, offset = 0;

    st = zuc_hmac_new(alg, (const uint8_t *) RAW(key), (size_t) XLENGTH(key), &h);
    if (st != ZUC_OK) {
        return result(st, R_NilValue);
    }
    ptr = PROTECT(R_MakeExternalPtr(h, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(ptr, hmac_finalizer, TRUE);

    while (offset < total && st == ZUC_OK) {
        size_t n = total - offset;
        if (n > ZUCRYPT_CHUNK) n = ZUCRYPT_CHUNK;
        st = zuc_hmac_update(h, bytes + offset, n);
        offset += n;
        R_CheckUserInterrupt();
    }

    if (st != ZUC_OK) {
        release_ptr(ptr, free_hmac);
        UNPROTECT(1);
        return result(st, R_NilValue);
    }

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    st = zuc_hmac_finish(h, (uint8_t *) RAW(out), want, &got);
    release_ptr(ptr, free_hmac);
    if (st == ZUC_OK && got != want) {
        st = ZUC_ERR_INTERNAL;
    }
    UNPROTECT(2);
    return result(st, st == ZUC_OK ? out : R_NilValue);
}

/* ------------------------------------------------------------------ *
 * AES-CBC
 * ------------------------------------------------------------------ */

SEXP zucrypt_aes_cbc(SEXP data, SEXP key, SEXP iv, SEXP encrypt)
{
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t total = (size_t) XLENGTH(data);
    int do_encrypt = Rf_asLogical(encrypt) == TRUE;
    SEXP out, ptr;
    zuc_aes *aes = NULL;
    zuc_status st;
    size_t offset = 0;

    st = zuc_aes_new((const uint8_t *) RAW(key), (size_t) XLENGTH(key), &aes);
    if (st != ZUC_OK) {
        return result(st, R_NilValue);
    }
    ptr = PROTECT(R_MakeExternalPtr(aes, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(ptr, aes_finalizer, TRUE);

    st = zuc_aes_cbc_set_state(aes, (const uint8_t *) RAW(iv));

    /* Allocated before the loop, so the output is never partly written into
     * a vector R is also resizing, and so an interrupt frees the context
     * rather than stranding it beside a half-built result. */
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) total));

    while (offset < total && st == ZUC_OK) {
        /* Whole blocks per chunk: CBC chains block to block, and a chunk
         * ending mid-block would be a different computation, not a slower
         * one. R has already checked that `total` is a multiple of 16. */
        size_t n = total - offset;
        if (n > ZUCRYPT_CHUNK) n = ZUCRYPT_CHUNK;
        st = do_encrypt
            ? zuc_aes_cbc_encrypt(aes, bytes + offset, n,
                                  (uint8_t *) RAW(out) + offset)
            : zuc_aes_cbc_decrypt(aes, bytes + offset, n,
                                  (uint8_t *) RAW(out) + offset);
        offset += n;
        R_CheckUserInterrupt();
    }

    release_ptr(ptr, free_aes);
    UNPROTECT(2);
    return result(st, st == ZUC_OK ? out : R_NilValue);
}

/* ------------------------------------------------------------------ *
 * Comparison and introspection
 * ------------------------------------------------------------------ */

SEXP zucrypt_equal(SEXP x, SEXP y)
{
    /* Unequal lengths never reach here: R answers FALSE without calling in,
     * because zuc_equal() takes a single length and length is not secret. */
    return Rf_ScalarLogical(zuc_equal((const uint8_t *) RAW(x),
                                      (const uint8_t *) RAW(y),
                                      (size_t) XLENGTH(x)));
}

SEXP zucrypt_algorithms(void)
{
    static const char *names[] = {"sha1", "sha256", "sha384", "sha512"};
    int n = (int) (sizeof names / sizeof names[0]);
    int i, k = 0;
    SEXP out;

    for (i = 0; i < n; i++) {
        if (zuc_alg_available(zuc_alg_by_name(names[i]))) k++;
    }
    out = PROTECT(Rf_allocVector(STRSXP, k));
    for (i = 0, k = 0; i < n; i++) {
        if (zuc_alg_available(zuc_alg_by_name(names[i]))) {
            SET_STRING_ELT(out, k++, Rf_mkChar(names[i]));
        }
    }
    UNPROTECT(1);
    return out;
}

const R_CallMethodDef zucrypt_crypt_call_methods[] = {
    {"zucrypt_hash",        (DL_FUNC) &zucrypt_hash,        2},
    {"zucrypt_hmac",        (DL_FUNC) &zucrypt_hmac,        3},
    {"zucrypt_aes_cbc",     (DL_FUNC) &zucrypt_aes_cbc,     4},
    {"zucrypt_equal",       (DL_FUNC) &zucrypt_equal,       2},
    {"zucrypt_algorithms",  (DL_FUNC) &zucrypt_algorithms,  0},
    {NULL, NULL, 0}
};
