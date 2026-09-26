/* zucryptlink: zucrypt consumed as zuxlsx will consume it.
 *
 * LinkingTo for <zucrypt.h>, libzucrypt.a linked statically by ./configure,
 * and no Imports: -- so every zuc_* call below lands in this shared object's
 * own private copy of the adapter and the backend, never in zucrypt.so. That
 * is the shape design.md section 8.3 describes, and the one that a plain C
 * main() never exercised: position-independent archive objects linked into a
 * package's shared object, hidden backend symbols, a second copy of the
 * backend in a process that may also have zucrypt.so loaded, and the
 * consumer owning the backend's lifetime.
 *
 * Lifetime: this package takes one backend reference when its DLL loads and
 * drops it when the DLL unloads. A failed zuc_init() is remembered rather
 * than raised -- R_init_ must not longjmp -- and every entry point reports it.
 *
 * PROTECT and ownership: every function allocates its R result before it
 * creates a native context, and raises no R error while one is live, so no
 * longjmp can strand a context. (zucrypt's own entry points need finalized
 * external pointers because they check for interrupts mid-loop; nothing here
 * does.)
 */

#include <string.h>

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

#include <zucrypt.h>

static zuc_status init_status = ZUC_ERR_NOT_READY;

static void require_backend(void)
{
    if (init_status != ZUC_OK) {
        Rf_error("zucryptlink: zuc_init() failed (%s)",
                 zuc_status_name(init_status));
    }
}

static zuc_alg alg_arg(SEXP algorithm)
{
    zuc_alg alg;

    if (TYPEOF(algorithm) != STRSXP || XLENGTH(algorithm) != 1) {
        Rf_error("zucryptlink: algorithm must be a single string");
    }
    alg = zuc_alg_by_name(CHAR(STRING_ELT(algorithm, 0)));
    if (alg == ZUC_ALG_NONE || !zuc_alg_available(alg)) {
        Rf_error("zucryptlink: unknown algorithm '%s'",
                 CHAR(STRING_ELT(algorithm, 0)));
    }
    return alg;
}

static void raw_arg(SEXP x, const char *what)
{
    if (TYPEOF(x) != RAWSXP) {
        Rf_error("zucryptlink: %s must be a raw vector", what);
    }
}

/* What was actually linked: read from the archive by calling it, never from
 * a macro, so that a header on the include path with no archive behind it
 * fails at link time instead of reporting a version it does not have. */
SEXP zl_backend(void)
{
    zuc_info info;
    zuc_status st;
    SEXP out, nms;

    require_backend();
    memset(&info, 0, sizeof info);
    info.struct_size = (uint32_t) sizeof info;
    st = zuc_get_info(&info);
    if (st != ZUC_OK) {
        Rf_error("zucryptlink: zuc_get_info() failed (%s)", zuc_status_name(st));
    }

    out = PROTECT(Rf_allocVector(VECSXP, 4));
    nms = PROTECT(Rf_allocVector(STRSXP, 4));
    SET_VECTOR_ELT(out, 0, Rf_mkString(info.backend_name));
    SET_VECTOR_ELT(out, 1, Rf_mkString(info.backend_version));
    SET_VECTOR_ELT(out, 2, Rf_ScalarInteger((int) info.abi_version));
    SET_VECTOR_ELT(out, 3, Rf_ScalarInteger((int) ZUCRYPT_ABI_VERSION));
    SET_STRING_ELT(nms, 0, Rf_mkChar("name"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("version"));
    SET_STRING_ELT(nms, 2, Rf_mkChar("abi_version"));
    SET_STRING_ELT(nms, 3, Rf_mkChar("header_abi_version"));
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

SEXP zl_hash(SEXP algorithm, SEXP data)
{
    zuc_alg alg = alg_arg(algorithm);
    size_t n = 0;
    zuc_status st;
    SEXP out;

    require_backend();
    raw_arg(data, "data");
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) zuc_alg_size(alg)));
    st = zuc_hash_compute(alg, RAW(data), (size_t) XLENGTH(data),
                          RAW(out), (size_t) XLENGTH(out), &n);
    UNPROTECT(1);
    if (st != ZUC_OK || n != (size_t) XLENGTH(out)) {
        Rf_error("zucryptlink: zuc_hash_compute() failed (%s)", zuc_status_name(st));
    }
    return out;
}

SEXP zl_hmac(SEXP algorithm, SEXP key, SEXP data)
{
    zuc_alg alg = alg_arg(algorithm);
    size_t n = 0;
    zuc_status st;
    SEXP out;

    require_backend();
    raw_arg(key, "key");
    raw_arg(data, "data");
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) zuc_alg_size(alg)));
    st = zuc_hmac_compute(alg, RAW(key), (size_t) XLENGTH(key),
                          RAW(data), (size_t) XLENGTH(data),
                          RAW(out), (size_t) XLENGTH(out), &n);
    UNPROTECT(1);
    if (st != ZUC_OK || n != (size_t) XLENGTH(out)) {
        Rf_error("zucryptlink: zuc_hmac_compute() failed (%s)", zuc_status_name(st));
    }
    return out;
}

/* H_0 = hash(seed); H_n = hash(int32le(n - 1) || H_{n-1}), through one
 * reused incremental context -- the loop zuxlsx's agile decryption runs,
 * without anything Office-specific in it. The same rehearsal as
 * tools/zucrypttest, through the archive instead of the table. */
SEXP zl_derive(SEXP seed, SEXP spins, SEXP algorithm)
{
    zuc_alg alg = alg_arg(algorithm);
    int total = Rf_asInteger(spins), i;
    size_t size = zuc_alg_size(alg), n = 0;
    uint8_t digest[ZUC_MAX_DIGEST_SIZE], counter[4];
    zuc_hash *h = NULL;
    zuc_status st;
    SEXP out;

    require_backend();
    raw_arg(seed, "seed");
    if (total == NA_INTEGER || total < 0) {
        Rf_error("zucryptlink: spins must be a non-negative integer");
    }
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) size));

    /* No R call from here to zuc_hash_free(). */
    st = zuc_hash_new(alg, &h);
    if (st == ZUC_OK) st = zuc_hash_update(h, RAW(seed), (size_t) XLENGTH(seed));
    if (st == ZUC_OK) st = zuc_hash_finish(h, digest, sizeof digest, &n);
    for (i = 0; i < total && st == ZUC_OK; i++) {
        /* Little-endian by construction, not by casting an int's bytes, so a
         * big-endian machine gives the same answer. */
        counter[0] = (uint8_t) (i & 0xFF);
        counter[1] = (uint8_t) ((i >> 8) & 0xFF);
        counter[2] = (uint8_t) ((i >> 16) & 0xFF);
        counter[3] = (uint8_t) ((i >> 24) & 0xFF);
        st = zuc_hash_reset(h);
        if (st == ZUC_OK) st = zuc_hash_update(h, counter, sizeof counter);
        if (st == ZUC_OK) st = zuc_hash_update(h, digest, size);
        if (st == ZUC_OK) st = zuc_hash_finish(h, digest, sizeof digest, &n);
    }
    zuc_hash_free(h);

    if (st == ZUC_OK) {
        memcpy(RAW(out), digest, size);
    }
    zuc_secure_zero(digest, sizeof digest);
    UNPROTECT(1);
    if (st != ZUC_OK) {
        Rf_error("zucryptlink: derivation failed (%s)", zuc_status_name(st));
    }
    return out;
}

/* CBC with the chaining state reset to `iv` at every segment boundary, the
 * shape the agile profiles specify for the encrypted package. */
SEXP zl_segments(SEXP data, SEXP key, SEXP iv, SEXP segment, SEXP encrypt)
{
    size_t total, seg = (size_t) Rf_asInteger(segment), offset = 0;
    int do_encrypt = Rf_asLogical(encrypt) == TRUE;
    zuc_aes *aes = NULL;
    zuc_status st;
    SEXP out;

    require_backend();
    raw_arg(data, "data");
    raw_arg(key, "key");
    raw_arg(iv, "iv");
    if (XLENGTH(iv) != ZUC_AES_BLOCK_SIZE) {
        Rf_error("zucryptlink: iv must be %d bytes", ZUC_AES_BLOCK_SIZE);
    }
    if (seg == 0 || seg % ZUC_AES_BLOCK_SIZE != 0) {
        Rf_error("zucryptlink: segment must be a positive multiple of %d",
                 ZUC_AES_BLOCK_SIZE);
    }
    total = (size_t) XLENGTH(data);
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) total));

    /* No R call from here to zuc_aes_free(). */
    st = zuc_aes_new(RAW(key), (size_t) XLENGTH(key), &aes);
    while (st == ZUC_OK && offset < total) {
        size_t n = total - offset;
        if (n > seg) n = seg;
        st = zuc_aes_cbc_set_state(aes, RAW(iv));
        if (st != ZUC_OK) break;
        st = do_encrypt
            ? zuc_aes_cbc_encrypt(aes, RAW(data) + offset, n, RAW(out) + offset)
            : zuc_aes_cbc_decrypt(aes, RAW(data) + offset, n, RAW(out) + offset);
        offset += n;
    }
    zuc_aes_free(aes);

    UNPROTECT(1);
    if (st != ZUC_OK) {
        Rf_error("zucryptlink: segmented CBC failed (%s)", zuc_status_name(st));
    }
    return out;
}

static const R_CallMethodDef call_methods[] = {
    {"zl_backend",  (DL_FUNC) &zl_backend,  0},
    {"zl_hash",     (DL_FUNC) &zl_hash,     2},
    {"zl_hmac",     (DL_FUNC) &zl_hmac,     3},
    {"zl_derive",   (DL_FUNC) &zl_derive,   3},
    {"zl_segments", (DL_FUNC) &zl_segments, 5},
    {NULL, NULL, 0}
};

void attribute_visible R_init_zucryptlink(DllInfo *dll)
{
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
    init_status = zuc_init();
}

void attribute_visible R_unload_zucryptlink(DllInfo *dll)
{
    (void) dll;
    if (init_status == ZUC_OK) {
        zuc_shutdown();
        init_status = ZUC_ERR_NOT_READY;
    }
}
