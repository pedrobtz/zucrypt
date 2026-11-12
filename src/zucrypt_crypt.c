/* zucrypt: the native entry points behind the crypt_* functions.
 *
 * R-facing, so it speaks zuc_* and never PSA; tools/check-layering.sh
 * enforces that. It is not in libzucrypt.a.
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
 *
 * "From the moment it exists" is literal: the external pointer is made
 * first, empty, with its finalizer registered, and the context is created
 * into it. Making the pointer second -- as this file did until Stage 8 --
 * leaves one allocation (R_MakeExternalPtr's) that can fail with a live
 * context and no owner, and an R allocation failure longjmps.
 * tests/testthat/test-lifetime.R counts live contexts to hold this.
 */

#include <math.h>
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

zuc_status zucrypt_int_rand_fill(uint8_t *bytes, size_t len);

/* ------------------------------------------------------------------ *
 * Context ownership
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * Finalizers that run before the DLL goes (#144)
 *
 * Every object below is owned by an external pointer with a C finalizer,
 * and that finalizer is code in this DLL. pkgload::unload() and
 * devtools::load_all() unload the DLL while such objects may still be
 * alive; the next collection then called a finalizer in unmapped memory
 * (a segfault, on Linux and macOS alike). So each finalizer is registered
 * through a weak reference kept here, and .onUnload() (R/zzz.R) calls
 * zucrypt_unload_finalizers(), which runs every pending one with
 * R_RunWeakRefFinalizer() while the code is still mapped. Not an
 * R_unload_zucrypt(): R finds that through R_dlsym(), which returns NULL
 * for an unregistered name once R_useDynamicSymbols(dll, FALSE) is set.
 * A finalizer that has run is never run again, so a key that outlives the
 * unload is left holding a NULL address, which every entry point refuses.
 *
 * The registry is a pairlist under one preserved cell. Entries whose key
 * has been collected (its finalizer already run) are pruned as new ones
 * arrive, so it stays proportional to the live objects.
 * ------------------------------------------------------------------ */

static SEXP finalizer_registry = NULL;  /* CONS(R_NilValue, list) */
static long registry_length = 0, registry_prune_at = 64;

static void registry_prune(void)
{
    SEXP prev = finalizer_registry, node = CDR(finalizer_registry);
    registry_length = 0;
    while (node != R_NilValue) {
        if (R_WeakRefKey(CAR(node)) == R_NilValue) {
            SETCDR(prev, CDR(node));
        } else {
            prev = node;
            registry_length++;
        }
        node = CDR(node);
    }
    registry_prune_at = 2 * registry_length + 64;
}

/* R_RegisterCFinalizerEx(ptr, fin, TRUE), remembered for the unload. The
 * weak reference exists, and owns the finalizer, before anything here can
 * longjmp, so a failure to remember it leaves the object finalized as
 * before, only not early. */
static void register_finalizer(SEXP ptr, R_CFinalizer_t fin)
{
    SEXP w = PROTECT(R_MakeWeakRefC(ptr, R_NilValue, fin, TRUE));
    if (finalizer_registry == NULL) {
        finalizer_registry = Rf_cons(R_NilValue, R_NilValue);
        R_PreserveObject(finalizer_registry);
    }
    if (registry_length >= registry_prune_at) {
        registry_prune();
    }
    SETCDR(finalizer_registry, Rf_cons(w, CDR(finalizer_registry)));
    registry_length++;
    UNPROTECT(1);
}

SEXP zucrypt_unload_finalizers(void)
{
    SEXP node;
    if (finalizer_registry == NULL) {
        return R_NilValue;
    }
    for (node = CDR(finalizer_registry); node != R_NilValue; node = CDR(node)) {
        R_RunWeakRefFinalizer(CAR(node));
    }
    R_ReleaseObject(finalizer_registry);
    finalizer_registry = NULL;
    registry_length = 0;
    return R_NilValue;
}

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
 * Arguments C relies on (#106, #107)
 * ------------------------------------------------------------------ */

/* R validates every argument before calling in, for its messages and
 * classes. But R measures with length(), an internal generic a classed
 * vector can answer however it likes, while C reads XLENGTH(); and a value
 * reaching C through .Call directly has had no check at all. So every
 * precondition that governs a buffer access, a cast or a branch is checked
 * again here, where it is relied on. A failure is a bug in the caller, not
 * a user error, so it is a plain error -- raised before any context or
 * owning pointer exists, so nothing is stranded. */
static int flag_arg(SEXP x, const char *what)
{
    if (TYPEOF(x) != LGLSXP || XLENGTH(x) != 1 ||
        LOGICAL(x)[0] == NA_LOGICAL) {
        Rf_error("zucrypt: `%s` must be TRUE or FALSE", what);
    }
    return LOGICAL(x)[0] != 0;
}

/* A double R has checked is a whole number in [lo, hi]. */
static double whole_arg(SEXP x, double lo, double hi, const char *what)
{
    double v;
    if (TYPEOF(x) != REALSXP || XLENGTH(x) != 1) {
        Rf_error("zucrypt: `%s` must be a single number", what);
    }
    v = REAL(x)[0];
    if (!R_FINITE(v) || v != floor(v) || v < lo || v > hi) {
        Rf_error("zucrypt: `%s` must be a whole number in [%.0f, %.0f]",
                 what, lo, hi);
    }
    return v;
}

/* A single, non-NA name. */
static const char *name_arg(SEXP x, const char *what)
{
    if (TYPEOF(x) != STRSXP || XLENGTH(x) != 1 ||
        STRING_ELT(x, 0) == NA_STRING) {
        Rf_error("zucrypt: `%s` must be a single name", what);
    }
    return CHAR(STRING_ELT(x, 0));
}

static zuc_alg alg_name_arg(SEXP x, const char *what)
{
    return zuc_alg_by_name(name_arg(x, what));
}

/* The largest vector length, as a double: 2^52 on a 64-bit build. */
#define ZUCRYPT_MAX_LEN ((double) R_XLEN_T_MAX)

/* ------------------------------------------------------------------ *
 * Digest and HMAC
 * ------------------------------------------------------------------ */

SEXP zucrypt_hash(SEXP data, SEXP algorithm)
{
    zuc_alg alg = alg_name_arg(algorithm, "algorithm");
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t total = (size_t) XLENGTH(data);
    size_t want = zuc_alg_size(alg);
    SEXP out, ptr, res;
    zuc_hash *h = NULL;
    zuc_status st;
    size_t got = 0, offset = 0;

    /* The owner first, then the context into it: nothing between the
     * context's creation and its owner can longjmp. */
    ptr = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
    register_finalizer(ptr, hash_finalizer);
    st = zuc_hash_new(alg, &h);
    if (st != ZUC_OK) {
        res = result(st, R_NilValue);
        UNPROTECT(1);
        return res;
    }
    R_SetExternalPtrAddr(ptr, h);

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
        res = result(st, R_NilValue);
        UNPROTECT(1);
        return res;
    }

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    st = zuc_hash_finish(h, (uint8_t *) RAW(out), want, &got);
    release_ptr(ptr, free_hash);
    if (st == ZUC_OK && got != want) {
        st = ZUC_ERR_INTERNAL;
    }
    /* result() allocates, so it is called while `out` is still protected.
     * Reversing these two lines is a use-after-free: R's garbage collector is
     * precise and does not scan the C stack, so an unprotected `out` can be
     * collected inside result()'s first allocation and stored into the list
     * as a dangling pointer. The symptom would be a wrong digest returned
     * successfully, not a crash. */
    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(2);
    return res;
}

SEXP zucrypt_hmac(SEXP data, SEXP key, SEXP algorithm)
{
    zuc_alg alg = alg_name_arg(algorithm, "algorithm");
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t total = (size_t) XLENGTH(data);
    size_t want = zuc_alg_size(alg);
    SEXP out, ptr, res;
    zuc_hmac *h = NULL;
    zuc_status st;
    size_t got = 0, offset = 0;

    ptr = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
    register_finalizer(ptr, hmac_finalizer);
    st = zuc_hmac_new(alg, (const uint8_t *) RAW(key), (size_t) XLENGTH(key), &h);
    if (st != ZUC_OK) {
        res = result(st, R_NilValue);
        UNPROTECT(1);
        return res;
    }
    R_SetExternalPtrAddr(ptr, h);

    while (offset < total && st == ZUC_OK) {
        size_t n = total - offset;
        if (n > ZUCRYPT_CHUNK) n = ZUCRYPT_CHUNK;
        st = zuc_hmac_update(h, bytes + offset, n);
        offset += n;
        R_CheckUserInterrupt();
    }

    if (st != ZUC_OK) {
        release_ptr(ptr, free_hmac);
        res = result(st, R_NilValue);
        UNPROTECT(1);
        return res;
    }

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    st = zuc_hmac_finish(h, (uint8_t *) RAW(out), want, &got);
    release_ptr(ptr, free_hmac);
    if (st == ZUC_OK && got != want) {
        st = ZUC_ERR_INTERNAL;
    }
    /* result() allocates, so it is called while `out` is still protected.
     * Reversing these two lines is a use-after-free: R's garbage collector is
     * precise and does not scan the C stack, so an unprotected `out` can be
     * collected inside result()'s first allocation and stored into the list
     * as a dangling pointer. The symptom would be a wrong digest returned
     * successfully, not a crash. */
    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(2);
    return res;
}

/* ------------------------------------------------------------------ *
 * Streaming digest and HMAC, for connection input (#11)
 *
 * R reads the connection in chunks and feeds them here, so the whole input
 * is never in memory and the loop is interruptible in R. The context lives
 * in an external pointer between calls, with the same ownership rules as
 * above: the pointer exists, finalized, before the context; finish releases
 * it eagerly; an interrupt leaves it to the finalizer. The pointer's tag is
 * c(kind, alg), kind 0 for a digest and 1 for an HMAC.
 * ------------------------------------------------------------------ */

#define ZUCRYPT_STREAM_HASH 0
#define ZUCRYPT_STREAM_HMAC 1

static SEXP stream_ptr(int kind, zuc_alg alg)
{
    SEXP tag = PROTECT(Rf_allocVector(INTSXP, 2));
    SEXP ptr;
    INTEGER(tag)[0] = kind;
    INTEGER(tag)[1] = (int) alg;
    ptr = PROTECT(R_MakeExternalPtr(NULL, tag, R_NilValue));
    register_finalizer(ptr, kind == ZUCRYPT_STREAM_HASH
                                    ? hash_finalizer : hmac_finalizer);
    UNPROTECT(2);
    return ptr;
}

/* The tag of a pointer this file made. Anything else arriving here is a bug
 * in R/hash.R, not a user error, so it is an R error rather than a status. */
static const int *stream_tag(SEXP ptr)
{
    SEXP tag;
    if (TYPEOF(ptr) != EXTPTRSXP) {
        Rf_error("internal error: not a zucrypt stream");
    }
    tag = R_ExternalPtrTag(ptr);
    if (TYPEOF(tag) != INTSXP || XLENGTH(tag) != 2) {
        Rf_error("internal error: not a zucrypt stream");
    }
    return INTEGER(tag);
}

SEXP zucrypt_hash_stream_new(SEXP algorithm)
{
    zuc_alg alg = alg_name_arg(algorithm, "algorithm");
    SEXP ptr = PROTECT(stream_ptr(ZUCRYPT_STREAM_HASH, alg));
    zuc_hash *h = NULL;
    zuc_status st = zuc_hash_new(alg, &h);
    SEXP res;

    if (st == ZUC_OK) R_SetExternalPtrAddr(ptr, h);
    res = result(st, st == ZUC_OK ? ptr : R_NilValue);
    UNPROTECT(1);
    return res;
}

SEXP zucrypt_hmac_stream_new(SEXP key, SEXP algorithm)
{
    zuc_alg alg = alg_name_arg(algorithm, "algorithm");
    SEXP ptr = PROTECT(stream_ptr(ZUCRYPT_STREAM_HMAC, alg));
    zuc_hmac *h = NULL;
    zuc_status st = zuc_hmac_new(alg, (const uint8_t *) RAW(key),
                                 (size_t) XLENGTH(key), &h);
    SEXP res;

    if (st == ZUC_OK) R_SetExternalPtrAddr(ptr, h);
    res = result(st, st == ZUC_OK ? ptr : R_NilValue);
    UNPROTECT(1);
    return res;
}

/* Returns a bare status: nothing to hand back on success. A finished (or
 * never-started) stream is ZUC_ERR_INVALID_ARGUMENT. */
SEXP zucrypt_stream_update(SEXP ptr, SEXP data)
{
    const int *tag = stream_tag(ptr);
    void *ctx = R_ExternalPtrAddr(ptr);
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t n = (size_t) XLENGTH(data);
    zuc_status st;

    if (ctx == NULL) {
        return Rf_ScalarInteger((int) ZUC_ERR_INVALID_ARGUMENT);
    }
    st = tag[0] == ZUCRYPT_STREAM_HASH
        ? zuc_hash_update((zuc_hash *) ctx, bytes, n)
        : zuc_hmac_update((zuc_hmac *) ctx, bytes, n);
    /* As in the one-shot loops: after the update, once per chunk. The R loop
     * that calls this runs too few evaluations for R's own polling to answer
     * Ctrl-C (or setTimeLimit()) promptly, and the context is owned by `ptr`,
     * so the longjmp strands nothing. */
    R_CheckUserInterrupt();
    return Rf_ScalarInteger((int) st);
}

SEXP zucrypt_stream_finish(SEXP ptr)
{
    const int *tag = stream_tag(ptr);
    int kind = tag[0];
    size_t want = zuc_alg_size((zuc_alg) tag[1]);
    void *ctx = R_ExternalPtrAddr(ptr);
    size_t got = 0;
    zuc_status st;
    SEXP out, res;

    if (ctx == NULL) {
        return result(ZUC_ERR_INVALID_ARGUMENT, R_NilValue);
    }
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) want));
    st = kind == ZUCRYPT_STREAM_HASH
        ? zuc_hash_finish((zuc_hash *) ctx, (uint8_t *) RAW(out), want, &got)
        : zuc_hmac_finish((zuc_hmac *) ctx, (uint8_t *) RAW(out), want, &got);
    release_ptr(ptr, kind == ZUCRYPT_STREAM_HASH ? free_hash : free_hmac);
    if (st == ZUC_OK && got != want) {
        st = ZUC_ERR_INTERNAL;
    }
    /* result() allocates, so `out` stays protected across it; see
     * zucrypt_hash(). */
    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(1);
    return res;
}

/* ------------------------------------------------------------------ *
 * AES-CBC
 * ------------------------------------------------------------------ */

SEXP zucrypt_aes_cbc(SEXP data, SEXP key, SEXP iv, SEXP encrypt)
{
    const uint8_t *bytes = (const uint8_t *) RAW(data);
    size_t total = (size_t) XLENGTH(data);
    int do_encrypt = flag_arg(encrypt, "encrypt");
    SEXP out, ptr, res;
    zuc_aes *aes = NULL;
    zuc_status st;
    size_t offset = 0;

    /* zuc_aes_cbc_set_state() reads exactly one block, and takes no length
     * to check it against. */
    if (TYPEOF(iv) != RAWSXP || XLENGTH(iv) != ZUC_AES_BLOCK_SIZE) {
        return result(ZUC_ERR_BAD_LENGTH, R_NilValue);
    }

    ptr = PROTECT(R_MakeExternalPtr(NULL, R_NilValue, R_NilValue));
    register_finalizer(ptr, aes_finalizer);
    st = zuc_aes_new((const uint8_t *) RAW(key), (size_t) XLENGTH(key), &aes);
    if (st != ZUC_OK) {
        res = result(st, R_NilValue);
        UNPROTECT(1);
        return res;
    }
    R_SetExternalPtrAddr(ptr, aes);

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
    /* result() allocates, so it is called while `out` is still protected.
     * Reversing these two lines is a use-after-free: R's garbage collector is
     * precise and does not scan the C stack, so an unprotected `out` can be
     * collected inside result()'s first allocation and stored into the list
     * as a dangling pointer. The symptom would be a wrong digest returned
     * successfully, not a crash. */
    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(2);
    return res;
}

/* ------------------------------------------------------------------ *
 * Comparison, encoding and introspection
 * ------------------------------------------------------------------ */

SEXP zucrypt_equal(SEXP x, SEXP y)
{
    /* zuc_equal() takes a single length, so unequal ones are answered here,
     * by their true lengths: R answers FALSE before calling in, but by
     * length(), which a classed vector can misreport (#106). Length is not
     * secret. */
    if (TYPEOF(x) != RAWSXP || TYPEOF(y) != RAWSXP) {
        Rf_error("zucrypt: `x` and `y` must be raw vectors");
    }
    if (XLENGTH(x) != XLENGTH(y)) {
        return Rf_ScalarLogical(FALSE);
    }
    return Rf_ScalarLogical(zuc_equal((const uint8_t *) RAW(x),
                                      (const uint8_t *) RAW(y),
                                      (size_t) XLENGTH(x)));
}

/* Lower-case hexadecimal, two digits per byte and nothing else (#59). Here
 * rather than in R because paste(format(x), collapse = "") costs several
 * times what hashing a short input does. R has already checked the type and
 * that 2 * length fits in a CHARSXP, whose length is an int. R_alloc'd, so
 * an allocation failure longjmps with nothing to leak. */
SEXP zucrypt_hex(SEXP data)
{
    static const char digits[] = "0123456789abcdef";
    const uint8_t *in = (const uint8_t *) RAW(data);
    size_t n = (size_t) XLENGTH(data), i;
    char *buf;
    SEXP chr, out;

    /* The CHARSXP's length is an int. R checks this too, by length(). */
    if (n > 1073741823u) {
        Rf_error("zucrypt: `x` is too long to encode as one hex string");
    }
    buf = R_alloc(2 * n + 1, 1);

    for (i = 0; i < n; i++) {
        buf[2 * i]     = digits[in[i] >> 4];
        buf[2 * i + 1] = digits[in[i] & 0x0f];
    }
    buf[2 * n] = '\0';

    chr = PROTECT(Rf_mkCharLenCE(buf, (int) (2 * n), CE_NATIVE));
    out = PROTECT(Rf_allocVector(STRSXP, 1));
    SET_STRING_ELT(out, 0, chr);
    UNPROTECT(2);
    return out;
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

/* ------------------------------------------------------------------ *
 * Randomness
 * ------------------------------------------------------------------ */

/* `n` arrives as a double that R has already checked is a whole number in
 * [0, R_XLEN_T_MAX]. The output is allocated first and filled in 1 MiB
 * chunks, with an interrupt check after each: there is no native state to
 * strand, because zuc_random_bytes() holds none between calls. On a failure
 * every byte already drawn is wiped before the vector is dropped. */
/* The fill loop, apart so that zucrypt_test_rand_fill() can run it over a
 * buffer pre-filled with a sentinel and see that no byte was left (#100). */
zuc_status zucrypt_int_rand_fill(uint8_t *bytes, size_t len)
{
    size_t offset = 0;
    zuc_status st = ZUC_OK;

    while (offset < len && st == ZUC_OK) {
        size_t chunk = len - offset;
        if (chunk > ZUCRYPT_CHUNK) chunk = ZUCRYPT_CHUNK;
        st = zuc_random_bytes(bytes + offset, chunk);
        offset += chunk;
        R_CheckUserInterrupt();
    }
    if (st != ZUC_OK) {
        zuc_secure_zero(bytes, len);
    }
    return st;
}

SEXP zucrypt_rand_bytes(SEXP n)
{
    R_xlen_t total = (R_xlen_t) whole_arg(n, 0, ZUCRYPT_MAX_LEN, "n");
    SEXP out = PROTECT(Rf_allocVector(RAWSXP, total));
    zuc_status st = zucrypt_int_rand_fill((uint8_t *) RAW(out),
                                          (size_t) total);
    SEXP res;

    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(1);
    return res;
}

/* ------------------------------------------------------------------ *
 * Authenticated encryption and key derivation (Stage 14a)
 * ------------------------------------------------------------------ */

/* AES-GCM, one-shot. R has checked every type and length: `data`, `key`
 * and `iv` are raw with valid lengths, `aad` is raw or NULL, and for
 * decryption `tag` is raw (any length; a wrong one is an authentication
 * failure, which the adapter reports).
 *
 * There is no loop and no interrupt check: the adapter has no incremental
 * AEAD (design.md section 6, "one-shot first"), so there is no native state
 * to strand and nothing to own with an external pointer. The outputs are
 * allocated before the call. On encryption the value is list(ciphertext,
 * tag); on decryption the plaintext. On a failure the adapter has already
 * zeroed what it wrote, and the value is NULL. */
SEXP zucrypt_aes_gcm(SEXP data, SEXP key, SEXP iv, SEXP aad, SEXP tag,
                     SEXP encrypt)
{
    size_t len = (size_t) XLENGTH(data);
    const uint8_t *a = Rf_isNull(aad) ? NULL : (const uint8_t *) RAW(aad);
    size_t aad_len = Rf_isNull(aad) ? 0 : (size_t) XLENGTH(aad);
    int do_encrypt = flag_arg(encrypt, "encrypt");
    SEXP out, value, res;
    zuc_status st;

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) len));
    if (do_encrypt) {
        SEXP t = PROTECT(Rf_allocVector(RAWSXP, ZUC_GCM_TAG_SIZE));
        st = zuc_aead_encrypt(ZUC_ALG_AES_GCM,
                              RAW(key), (size_t) XLENGTH(key),
                              RAW(iv), (size_t) XLENGTH(iv),
                              a, aad_len,
                              len ? RAW(data) : NULL, len,
                              len ? RAW(out) : NULL,
                              RAW(t), ZUC_GCM_TAG_SIZE);
        value = PROTECT(Rf_allocVector(VECSXP, 2));
        SET_VECTOR_ELT(value, 0, out);
        SET_VECTOR_ELT(value, 1, t);
        res = result(st, st == ZUC_OK ? value : R_NilValue);
        UNPROTECT(3);
        return res;
    }
    st = zuc_aead_decrypt(ZUC_ALG_AES_GCM,
                          RAW(key), (size_t) XLENGTH(key),
                          RAW(iv), (size_t) XLENGTH(iv),
                          a, aad_len,
                          len ? RAW(data) : NULL, len,
                          RAW(tag), (size_t) XLENGTH(tag),
                          len ? RAW(out) : NULL);
    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(1);
    return res;
}

/* PBKDF2-HMAC. R has checked the types and ranges: `password` and `salt`
 * raw, `iterations` a double holding a whole number in [1, 2^32 - 1],
 * `size` a double holding a whole number >= 1, `algorithm` a digest name.
 * One uninterruptible call; the documentation says so. */
SEXP zucrypt_pbkdf2(SEXP password, SEXP salt, SEXP iterations, SEXP size,
                    SEXP algorithm)
{
    size_t n = (size_t) whole_arg(size, 1, ZUCRYPT_MAX_LEN, "size");
    uint32_t iter = (uint32_t) whole_arg(iterations, 1, 4294967295.0,
                                         "iterations");
    zuc_alg alg = alg_name_arg(algorithm, "algorithm");
    size_t plen = (size_t) XLENGTH(password), slen = (size_t) XLENGTH(salt);
    SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) n));
    SEXP res;
    zuc_status st;

    st = zuc_pbkdf2_hmac(alg,
                         plen ? RAW(password) : NULL, plen,
                         slen ? RAW(salt) : NULL, slen,
                         iter,
                         RAW(out), n);
    res = result(st, st == ZUC_OK ? out : R_NilValue);
    UNPROTECT(1);
    return res;
}

/* ------------------------------------------------------------------ *
 * Public keys (Stage 15a)
 * ------------------------------------------------------------------ */

/* Key objects are external pointers tagged with this symbol, so a pointer
 * from anywhere else is refused rather than dereferenced. The pointer is
 * created first and owns the handle from the moment it exists; a key
 * restored by readRDS() has a NULL address and is refused too. */
static SEXP pkey_tag(void)
{
    static SEXP tag = NULL;
    if (tag == NULL) tag = Rf_install("zucrypt_pkey");
    return tag;
}

static void pkey_finalizer(SEXP ptr)
{
    zuc_pkey *key = (zuc_pkey *) R_ExternalPtrAddr(ptr);
    if (key != NULL) {
        zuc_pkey_free(key);
        R_ClearExternalPtr(ptr);
    }
}

static SEXP pkey_ptr(void)
{
    SEXP ptr = PROTECT(R_MakeExternalPtr(NULL, pkey_tag(), R_NilValue));
    register_finalizer(ptr, pkey_finalizer);
    UNPROTECT(1);
    return ptr;
}

static const zuc_pkey *pkey_get(SEXP ptr)
{
    if (TYPEOF(ptr) != EXTPTRSXP || R_ExternalPtrTag(ptr) != pkey_tag()) {
        return NULL;
    }
    return (const zuc_pkey *) R_ExternalPtrAddr(ptr);
}

/* Finish a constructor: on success the handle moves into the pointer. */
static SEXP pkey_result(zuc_status st, SEXP ptr, zuc_pkey *key)
{
    SEXP res;
    if (st == ZUC_OK) {
        R_SetExternalPtrAddr(ptr, key);
    }
    res = result(st, st == ZUC_OK ? ptr : R_NilValue);
    return res;
}

SEXP zucrypt_pkey_parse(SEXP data, SEXP private_key)
{
    int want_private = flag_arg(private_key, "private_key");
    SEXP ptr = PROTECT(pkey_ptr()), res;
    zuc_pkey *key = NULL;
    zuc_status st = zuc_pkey_parse(RAW(data), (size_t) XLENGTH(data),
                                   want_private, &key);
    res = pkey_result(st, ptr, key);
    UNPROTECT(1);
    return res;
}

/* `type` is a zuc_alg name R has checked: "rsa", "p256", ..., "x25519". */
SEXP zucrypt_pkey_generate(SEXP type, SEXP bits)
{
    zuc_alg alg = alg_name_arg(type, "type");
    size_t nbits = (size_t) whole_arg(bits, 0, 65536, "bits");
    SEXP ptr = PROTECT(pkey_ptr()), res;
    zuc_pkey *key = NULL;
    zuc_status st = zuc_pkey_generate(alg, nbits, &key);
    res = pkey_result(st, ptr, key);
    UNPROTECT(1);
    return res;
}

SEXP zucrypt_pkey_public(SEXP ptr)
{
    const zuc_pkey *key = pkey_get(ptr);
    SEXP out = PROTECT(pkey_ptr()), res;
    zuc_pkey *pub = NULL;
    zuc_status st = key == NULL ? ZUC_ERR_INVALID_ARGUMENT
                                : zuc_pkey_public(key, &pub);
    res = pkey_result(st, out, pub);
    UNPROTECT(1);
    return res;
}

/* list(status, value = list(type, bits, private)), so that a stale or
 * foreign pointer is a condition like any other. */
SEXP zucrypt_pkey_info(SEXP ptr)
{
    const zuc_pkey *key = pkey_get(ptr);
    SEXP value, nms, res;

    if (key == NULL) {
        return result(ZUC_ERR_INVALID_ARGUMENT, R_NilValue);
    }
    value = PROTECT(Rf_allocVector(VECSXP, 3));
    nms = PROTECT(Rf_allocVector(STRSXP, 3));
    SET_VECTOR_ELT(value, 0, Rf_mkString(zuc_alg_name(zuc_pkey_type(key))));
    SET_VECTOR_ELT(value, 1, Rf_ScalarReal((double) zuc_pkey_bits(key)));
    SET_VECTOR_ELT(value, 2, Rf_ScalarLogical(zuc_pkey_is_private(key)));
    SET_STRING_ELT(nms, 0, Rf_mkChar("type"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("bits"));
    SET_STRING_ELT(nms, 2, Rf_mkChar("private"));
    Rf_setAttrib(value, R_NamesSymbol, nms);
    res = result(ZUC_OK, value);
    UNPROTECT(2);
    return res;
}

/* Output sized for the worst case, then trimmed to what was written. */
static SEXP trimmed(zuc_status st, SEXP buf, size_t len)
{
    SEXP out, res;
    if (st != ZUC_OK) {
        zuc_secure_zero(RAW(buf), (size_t) XLENGTH(buf));
        return result(st, R_NilValue);
    }
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) len));
    if (len) memcpy(RAW(out), RAW(buf), len);
    zuc_secure_zero(RAW(buf), (size_t) XLENGTH(buf));
    res = result(st, out);
    UNPROTECT(1);
    return res;
}

SEXP zucrypt_pkey_write(SEXP ptr, SEXP format, SEXP public_only)
{
    const zuc_pkey *key = pkey_get(ptr);
    int pub = flag_arg(public_only, "public_only");
    SEXP buf = PROTECT(Rf_allocVector(RAWSXP, ZUC_PKEY_MAX_WRITE_SIZE)), res;
    size_t len = 0;
    zuc_status st = key == NULL
        ? ZUC_ERR_INVALID_ARGUMENT
        : zuc_pkey_write(key, (zuc_pkey_format) Rf_asInteger(format), pub,
                         RAW(buf), (size_t) XLENGTH(buf), &len);
    res = trimmed(st, buf, len);
    UNPROTECT(1);
    return res;
}

/* `scheme` and `hash` arrive as zuc_alg names R has checked. */
static zuc_alg alg_arg(SEXP name)
{
    return Rf_isNull(name) ? ZUC_ALG_NONE : alg_name_arg(name, "scheme or hash");
}

SEXP zucrypt_pkey_sign(SEXP ptr, SEXP scheme, SEXP hash, SEXP digest)
{
    const zuc_pkey *key = pkey_get(ptr);
    /* Enough for any signature: 512 bytes for RSA-4096, 132 for P-521. */
    size_t cap = 1024, len = 0;
    SEXP buf = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) cap)), res;
    zuc_status st = key == NULL
        ? ZUC_ERR_INVALID_ARGUMENT
        : zuc_pkey_sign_hash(key, alg_arg(scheme), alg_arg(hash),
                             RAW(digest), (size_t) XLENGTH(digest),
                             RAW(buf), cap, &len);
    res = trimmed(st, buf, len);
    UNPROTECT(1);
    return res;
}

SEXP zucrypt_pkey_verify(SEXP ptr, SEXP scheme, SEXP hash, SEXP digest,
                         SEXP sig)
{
    const zuc_pkey *key = pkey_get(ptr);
    size_t sig_len = (size_t) XLENGTH(sig);
    zuc_status st = key == NULL
        ? ZUC_ERR_INVALID_ARGUMENT
        : zuc_pkey_verify_hash(key, alg_arg(scheme), alg_arg(hash),
                               RAW(digest), (size_t) XLENGTH(digest),
                               sig_len ? RAW(sig) : NULL, sig_len);
    return result(st, st == ZUC_OK ? Rf_ScalarLogical(TRUE) : R_NilValue);
}

SEXP zucrypt_pkey_crypt(SEXP ptr, SEXP scheme, SEXP hash, SEXP data,
                        SEXP encrypt)
{
    const zuc_pkey *key = pkey_get(ptr);
    int do_encrypt = flag_arg(encrypt, "encrypt");
    size_t cap = key == NULL ? 1 : zuc_pkey_bits(key) / 8 + 1, len = 0;
    size_t n = (size_t) XLENGTH(data);
    SEXP buf = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) cap)), res;
    zuc_status st;

    if (key == NULL) {
        st = ZUC_ERR_INVALID_ARGUMENT;
    } else if (do_encrypt) {
        st = zuc_pkey_encrypt(key, alg_arg(scheme), alg_arg(hash),
                              n ? RAW(data) : NULL, n, RAW(buf), cap, &len);
    } else {
        st = zuc_pkey_decrypt(key, alg_arg(scheme), alg_arg(hash),
                              n ? RAW(data) : RAW(buf), n,
                              RAW(buf), cap, &len);
    }
    res = trimmed(st, buf, len);
    UNPROTECT(1);
    return res;
}

/* A key from its raw material (zucrypt.h, zuc_pkey_import()). */
SEXP zucrypt_pkey_import(SEXP type, SEXP private_key, SEXP data)
{
    zuc_alg alg = alg_name_arg(type, "type");
    int want_private = flag_arg(private_key, "private_key");
    SEXP ptr = PROTECT(pkey_ptr()), res;
    zuc_pkey *key = NULL;
    zuc_status st = zuc_pkey_import(alg, want_private,
                                    RAW(data), (size_t) XLENGTH(data), &key);
    res = pkey_result(st, ptr, key);
    UNPROTECT(1);
    return res;
}

SEXP zucrypt_pkey_export(SEXP ptr, SEXP public_only)
{
    const zuc_pkey *key = pkey_get(ptr);
    int pub = flag_arg(public_only, "public_only");
    SEXP buf = PROTECT(Rf_allocVector(RAWSXP, ZUC_PKEY_MAX_WRITE_SIZE)), res;
    size_t len = 0;
    zuc_status st = key == NULL
        ? ZUC_ERR_INVALID_ARGUMENT
        : zuc_pkey_export(key, pub,
                          RAW(buf), (size_t) XLENGTH(buf), &len);
    res = trimmed(st, buf, len);
    UNPROTECT(1);
    return res;
}

SEXP zucrypt_pkey_agree(SEXP ptr, SEXP peer)
{
    const zuc_pkey *key = pkey_get(ptr), *other = pkey_get(peer);
    SEXP buf = PROTECT(Rf_allocVector(RAWSXP, 128)), res;
    size_t len = 0;
    zuc_status st = (key == NULL || other == NULL)
        ? ZUC_ERR_INVALID_ARGUMENT
        : zuc_pkey_agree(key, other, RAW(buf), (size_t) XLENGTH(buf), &len);
    res = trimmed(st, buf, len);
    UNPROTECT(1);
    return res;
}

const R_CallMethodDef zucrypt_crypt_call_methods[] = {
    {"zucrypt_hash",        (DL_FUNC) &zucrypt_hash,        2},
    {"zucrypt_unload_finalizers", (DL_FUNC) &zucrypt_unload_finalizers, 0},
    {"zucrypt_hmac",        (DL_FUNC) &zucrypt_hmac,        3},
    {"zucrypt_aes_cbc",     (DL_FUNC) &zucrypt_aes_cbc,     4},
    {"zucrypt_equal",       (DL_FUNC) &zucrypt_equal,       2},
    {"zucrypt_hex",         (DL_FUNC) &zucrypt_hex,         1},
    {"zucrypt_hash_stream_new", (DL_FUNC) &zucrypt_hash_stream_new, 1},
    {"zucrypt_hmac_stream_new", (DL_FUNC) &zucrypt_hmac_stream_new, 2},
    {"zucrypt_stream_update",   (DL_FUNC) &zucrypt_stream_update,   2},
    {"zucrypt_stream_finish",   (DL_FUNC) &zucrypt_stream_finish,   1},
    {"zucrypt_algorithms",  (DL_FUNC) &zucrypt_algorithms,  0},
    {"zucrypt_rand_bytes",  (DL_FUNC) &zucrypt_rand_bytes,  1},
    {"zucrypt_aes_gcm",     (DL_FUNC) &zucrypt_aes_gcm,     6},
    {"zucrypt_pbkdf2",      (DL_FUNC) &zucrypt_pbkdf2,      5},
    {"zucrypt_pkey_parse",    (DL_FUNC) &zucrypt_pkey_parse,    2},
    {"zucrypt_pkey_generate", (DL_FUNC) &zucrypt_pkey_generate, 2},
    {"zucrypt_pkey_import",   (DL_FUNC) &zucrypt_pkey_import,   3},
    {"zucrypt_pkey_export",   (DL_FUNC) &zucrypt_pkey_export,   2},
    {"zucrypt_pkey_agree",    (DL_FUNC) &zucrypt_pkey_agree,    2},
    {"zucrypt_pkey_public",   (DL_FUNC) &zucrypt_pkey_public,   1},
    {"zucrypt_pkey_info",     (DL_FUNC) &zucrypt_pkey_info,     1},
    {"zucrypt_pkey_write",    (DL_FUNC) &zucrypt_pkey_write,    3},
    {"zucrypt_pkey_sign",     (DL_FUNC) &zucrypt_pkey_sign,     4},
    {"zucrypt_pkey_verify",   (DL_FUNC) &zucrypt_pkey_verify,   5},
    {"zucrypt_pkey_crypt",    (DL_FUNC) &zucrypt_pkey_crypt,    5},
    {NULL, NULL, 0}
};
