/* The consumer side of zucrypt's registered function table.
 *
 * This file is the point of the whole fixture. It is compiled in another
 * package's tree, against zucrypt's installed headers, with no access to
 * zucrypt's sources and nothing linked from it -- which is exactly the
 * position zuhttp or any other Imports:-carrying consumer is in.
 *
 * It calls every entry in the table. Not for coverage: a pointer that was
 * never assigned is indistinguishable from a working one until something
 * calls it, and the table is filled field by field in zucrypt_api.c, which
 * is precisely the shape of code where one line goes missing.
 */

#include <string.h>

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include <zucrypt-r.h>

/* Collects failures so one run reports everything wrong rather than the
 * first thing. Bounded, because a fixture that runs out of memory while
 * reporting failures is not reporting anything. */
#define MAX_FAILURES 64
typedef struct {
    const char *msg[MAX_FAILURES];
    int n;
} failures;

static void fail(failures *f, const char *msg)
{
    if (f->n < MAX_FAILURES) {
        f->msg[f->n++] = msg;
    }
}

static void check(failures *f, int ok, const char *msg)
{
    if (!ok) fail(f, msg);
}

SEXP zucrypttest_api_available(void)
{
    return Rf_ScalarLogical(zucrypt_api() != NULL);
}

/* Asking for an ABI version this build does not implement must return NULL.
 * zucrypt_api() cannot express that -- it always passes the version its own
 * header was compiled with -- so this resolves the callable directly, which
 * is also a check that the callable is registered under the name the header
 * uses. */
SEXP zucrypttest_abi_reject(SEXP version)
{
    union {
        DL_FUNC fn;
        const zucrypt_api_v1 *(*get)(uint32_t);
    } resolve;

    resolve.fn = R_GetCCallable("zucrypt", "zucrypt_get_api");
    if (resolve.fn == NULL) {
        Rf_error("zucrypttest: zucrypt_get_api is not registered");
    }
    return Rf_ScalarLogical(
        resolve.get((uint32_t) Rf_asInteger(version)) == NULL);
}

SEXP zucrypttest_backend(void)
{
    const zucrypt_api_v1 *api = zucrypt_api();
    zuc_info info;
    SEXP out, nms;

    if (api == NULL) {
        Rf_error("zucrypttest: the zucrypt API is unavailable");
    }
    info.struct_size = (uint32_t) sizeof info;
    if (api->get_info(&info) != ZUC_OK) {
        Rf_error("zucrypttest: zuc_get_info failed");
    }

    out = PROTECT(Rf_allocVector(STRSXP, 2));
    nms = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(out, 0, Rf_mkChar(info.backend_name));
    SET_STRING_ELT(out, 1, Rf_mkChar(info.backend_version));
    SET_STRING_ELT(nms, 0, Rf_mkChar("name"));
    SET_STRING_ELT(nms, 1, Rf_mkChar("version"));
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

/* FIPS 180-2 B.1 and NIST SP 800-38A F.2.1, so the fixture checks answers
 * rather than merely that nothing crashed. */
static const uint8_t SHA256_ABC[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};
static const uint8_t AES128_KEY[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8_t CBC_IV[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint8_t CBC_PT[32] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
};
static const uint8_t CBC_CT[32] = {
    0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
    0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2
};
static const uint8_t ECB_CT1[16] = {
    0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
};

SEXP zucrypttest_exercise(void)
{
    const zucrypt_api_v1 *api = zucrypt_api();
    failures f;
    uint8_t out[ZUC_MAX_DIGEST_SIZE];
    uint8_t buf[32];
    uint8_t state[ZUC_AES_BLOCK_SIZE];
    size_t n = 0;
    zuc_hash *h = NULL;
    zuc_hmac *m = NULL;
    zuc_aes *aes = NULL;
    zuc_info info;
    SEXP result;
    int i;

    f.n = 0;
    if (api == NULL) {
        Rf_error("zucrypttest: the zucrypt API is unavailable");
    }

    /* The table has to describe itself before anything in it is trusted. */
    check(&f, api->abi_version == (uint32_t) ZUCRYPT_ABI_VERSION,
          "abi_version does not match the header");
    check(&f, api->struct_size >= sizeof(zucrypt_api_v1),
          "struct_size is smaller than the table this consumer was built against");

    /* Identification. */
    check(&f, api->status_string(ZUC_OK) != NULL, "status_string returned NULL");
    check(&f, strcmp(api->status_name(ZUC_ERR_BAD_LENGTH),
                     "ZUC_ERR_BAD_LENGTH") == 0, "status_name is wrong");
    check(&f, strcmp(api->alg_name(ZUC_ALG_SHA256), "sha256") == 0,
          "alg_name is wrong");
    check(&f, api->alg_by_name("sha256") == ZUC_ALG_SHA256,
          "alg_by_name is wrong");
    check(&f, api->alg_by_name("sha-256") == ZUC_ALG_NONE,
          "alg_by_name matched a name it should not");
    check(&f, api->alg_available(ZUC_ALG_SHA256), "sha256 reports unavailable");
    check(&f, api->alg_size(ZUC_ALG_SHA512) == 64, "alg_size is wrong");

    info.struct_size = (uint32_t) sizeof info;
    check(&f, api->get_info(&info) == ZUC_OK, "get_info failed");
    check(&f, info.backend_version != NULL && info.backend_version[0] != '\0',
          "get_info reported no backend version");
    info.struct_size = 1;
    check(&f, api->get_info(&info) == ZUC_ERR_ABI,
          "get_info accepted an impossibly small struct_size");

    /* Digest, both paths. */
    check(&f, api->hash_compute(ZUC_ALG_SHA256, (const uint8_t *) "abc", 3,
                                out, sizeof out, &n) == ZUC_OK,
          "hash_compute failed");
    check(&f, n == 32 && memcmp(out, SHA256_ABC, 32) == 0,
          "hash_compute produced the wrong digest");

    if (api->hash_new(ZUC_ALG_SHA256, &h) != ZUC_OK) {
        fail(&f, "hash_new failed");
    } else {
        check(&f, api->hash_update(h, (const uint8_t *) "a", 1) == ZUC_OK,
              "hash_update failed");
        check(&f, api->hash_update(h, (const uint8_t *) "bc", 2) == ZUC_OK,
              "hash_update failed on the second chunk");
        check(&f, api->hash_finish(h, out, sizeof out, &n) == ZUC_OK,
              "hash_finish failed");
        check(&f, n == 32 && memcmp(out, SHA256_ABC, 32) == 0,
              "incremental hash disagreed with one-shot");
        /* A reset context must behave like a fresh one. */
        check(&f, api->hash_reset(h) == ZUC_OK, "hash_reset failed");
        check(&f, api->hash_update(h, (const uint8_t *) "abc", 3) == ZUC_OK,
              "hash_update after reset failed");
        check(&f, api->hash_finish(h, out, sizeof out, &n) == ZUC_OK,
              "hash_finish after reset failed");
        check(&f, memcmp(out, SHA256_ABC, 32) == 0,
              "a reset context did not behave like a fresh one");
        api->hash_free(h);
    }

    /* HMAC, both paths. The two must agree; the value itself is checked
     * against a published vector in zucrypt's own suite. */
    {
        uint8_t key[20];
        uint8_t one_shot[ZUC_MAX_DIGEST_SIZE];
        size_t k = 0;
        memset(key, 0x0b, sizeof key);

        check(&f, api->hmac_compute(ZUC_ALG_SHA256, key, sizeof key,
                                    (const uint8_t *) "Hi There", 8,
                                    one_shot, sizeof one_shot, &k) == ZUC_OK,
              "hmac_compute failed");
        if (api->hmac_new(ZUC_ALG_SHA256, key, sizeof key, &m) != ZUC_OK) {
            fail(&f, "hmac_new failed");
        } else {
            check(&f, api->hmac_update(m, (const uint8_t *) "Hi ", 3) == ZUC_OK,
                  "hmac_update failed");
            check(&f, api->hmac_update(m, (const uint8_t *) "There", 5) == ZUC_OK,
                  "hmac_update failed on the second chunk");
            check(&f, api->hmac_finish(m, out, sizeof out, &n) == ZUC_OK,
                  "hmac_finish failed");
            check(&f, n == k && memcmp(out, one_shot, k) == 0,
                  "incremental HMAC disagreed with one-shot");
            check(&f, api->hmac_reset(m) == ZUC_OK, "hmac_reset failed");
            check(&f, api->hmac_update(m, (const uint8_t *) "Hi There", 8) == ZUC_OK,
                  "hmac_update after reset failed");
            check(&f, api->hmac_finish(m, out, sizeof out, &n) == ZUC_OK,
                  "hmac_finish after reset failed");
            check(&f, memcmp(out, one_shot, k) == 0,
                  "a reset HMAC context lost its key");
            api->hmac_free(m);
        }
    }

    /* AES, and the explicit chaining state that makes a segmented format
     * expressible at all. */
    if (api->aes_new(AES128_KEY, sizeof AES128_KEY, &aes) != ZUC_OK) {
        fail(&f, "aes_new failed");
    } else {
        check(&f, api->aes_cbc_set_state(aes, CBC_IV) == ZUC_OK,
              "aes_cbc_set_state failed");
        check(&f, api->aes_cbc_encrypt(aes, CBC_PT, 32, buf) == ZUC_OK,
              "aes_cbc_encrypt failed");
        check(&f, memcmp(buf, CBC_CT, 32) == 0,
              "aes_cbc_encrypt produced the wrong ciphertext");

        /* After the call the state is the last ciphertext block. */
        check(&f, api->aes_cbc_get_state(aes, state) == ZUC_OK,
              "aes_cbc_get_state failed");
        check(&f, memcmp(state, CBC_CT + 16, 16) == 0,
              "the chaining state is not the last ciphertext block");

        check(&f, api->aes_cbc_set_state(aes, CBC_IV) == ZUC_OK,
              "aes_cbc_set_state failed on the second call");
        check(&f, api->aes_cbc_decrypt(aes, CBC_CT, 32, buf) == ZUC_OK,
              "aes_cbc_decrypt failed");
        check(&f, memcmp(buf, CBC_PT, 32) == 0,
              "aes_cbc_decrypt produced the wrong plaintext");

        check(&f, api->aes_ecb_encrypt(aes, CBC_PT, 16, buf) == ZUC_OK,
              "aes_ecb_encrypt failed");
        check(&f, memcmp(buf, ECB_CT1, 16) == 0,
              "aes_ecb_encrypt produced the wrong ciphertext");
        check(&f, api->aes_ecb_decrypt(aes, ECB_CT1, 16, buf) == ZUC_OK,
              "aes_ecb_decrypt failed");
        check(&f, memcmp(buf, CBC_PT, 16) == 0,
              "aes_ecb_decrypt produced the wrong plaintext");

        /* The lengths the header promises to refuse. */
        check(&f, api->aes_cbc_encrypt(aes, CBC_PT, 17, buf) == ZUC_ERR_BAD_LENGTH,
              "a partial block was not refused");
        api->aes_free(aes);
    }
    {
        zuc_aes *bad = NULL;
        check(&f, api->aes_new(AES128_KEY, 17, &bad) == ZUC_ERR_BAD_LENGTH,
              "a 17-byte key was not refused");
        check(&f, bad == NULL, "a failed aes_new returned a handle anyway");
    }

    /* Utilities. */
    check(&f, api->equal(SHA256_ABC, SHA256_ABC, 32) == 1,
          "equal said two identical buffers differ");
    memcpy(buf, SHA256_ABC, 32);
    buf[31] ^= 0x01;
    check(&f, api->equal(SHA256_ABC, buf, 32) == 0,
          "equal said two different buffers match");

    memset(buf, 0xAA, sizeof buf);
    api->secure_zero(buf, sizeof buf);
    for (i = 0; i < (int) sizeof buf; i++) {
        if (buf[i] != 0) {
            fail(&f, "secure_zero left something behind");
            break;
        }
    }

    result = PROTECT(Rf_allocVector(STRSXP, f.n));
    for (i = 0; i < f.n; i++) {
        SET_STRING_ELT(result, i, Rf_mkChar(f.msg[i]));
    }
    UNPROTECT(1);
    return result;
}

/* ------------------------------------------------------------------ *
 * The Office derivation rehearsal
 * ------------------------------------------------------------------ */

/* H_0 = hash(seed); H_n = hash(int32le(n - 1) || H_{n-1}).
 *
 * This is the generic shape of the iterative key derivation the Office
 * formats specify, with the spin count left to the caller. It is not Office
 * support -- no constants, no block keys, no salts, none of which belong in
 * this package. It is the ABI validation gate: the loop reuses one
 * incremental context for tens of thousands of iterations, and if the
 * incremental interface were missing a primitive, or reset were subtly
 * different from fresh, this is where it would show.
 */
SEXP zucrypttest_derive(SEXP seed, SEXP spins, SEXP algorithm)
{
    const zucrypt_api_v1 *api = zucrypt_api();
    zuc_alg alg;
    zuc_hash *h = NULL;
    uint8_t digest[ZUC_MAX_DIGEST_SIZE];
    uint8_t counter[4];
    size_t size, n = 0;
    int i, total = Rf_asInteger(spins);
    SEXP out;
    zuc_status st;

    if (api == NULL) {
        Rf_error("zucrypttest: the zucrypt API is unavailable");
    }
    alg = api->alg_by_name(CHAR(STRING_ELT(algorithm, 0)));
    if (alg == ZUC_ALG_NONE) {
        Rf_error("zucrypttest: unknown algorithm");
    }
    size = api->alg_size(alg);

    st = api->hash_new(alg, &h);
    if (st != ZUC_OK) {
        Rf_error("zucrypttest: hash_new failed (%s)", api->status_name(st));
    }

    /* H_0 */
    st = api->hash_update(h, (const uint8_t *) RAW(seed), (size_t) XLENGTH(seed));
    if (st == ZUC_OK) st = api->hash_finish(h, digest, sizeof digest, &n);

    for (i = 0; i < total && st == ZUC_OK; i++) {
        /* int32 little-endian, written byte by byte rather than by casting a
         * pointer: this has to give the same answer on a big-endian machine,
         * and a memcpy of an int would not. */
        counter[0] = (uint8_t) (i & 0xFF);
        counter[1] = (uint8_t) ((i >> 8) & 0xFF);
        counter[2] = (uint8_t) ((i >> 16) & 0xFF);
        counter[3] = (uint8_t) ((i >> 24) & 0xFF);

        st = api->hash_reset(h);
        if (st == ZUC_OK) st = api->hash_update(h, counter, 4);
        if (st == ZUC_OK) st = api->hash_update(h, digest, size);
        if (st == ZUC_OK) st = api->hash_finish(h, digest, sizeof digest, &n);
    }
    api->hash_free(h);

    if (st != ZUC_OK) {
        Rf_error("zucrypttest: derivation failed (%s)", api->status_name(st));
    }
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) size));
    memcpy(RAW(out), digest, size);
    api->secure_zero(digest, sizeof digest);
    UNPROTECT(1);
    return out;
}

/* CBC where the chaining state is reset to the IV at every segment boundary.
 * The other half of the rehearsal: a streaming-only cipher interface could
 * not express this without tearing the operation down and rebuilding it. */
SEXP zucrypttest_segments(SEXP data, SEXP key, SEXP iv, SEXP segment,
                          SEXP encrypt)
{
    const zucrypt_api_v1 *api = zucrypt_api();
    zuc_aes *aes = NULL;
    size_t total = (size_t) XLENGTH(data);
    size_t seg = (size_t) Rf_asInteger(segment);
    int do_encrypt = Rf_asLogical(encrypt) == TRUE;
    size_t offset = 0;
    SEXP out;
    zuc_status st;

    if (api == NULL) {
        Rf_error("zucrypttest: the zucrypt API is unavailable");
    }
    if (seg == 0 || seg % ZUC_AES_BLOCK_SIZE != 0) {
        Rf_error("zucrypttest: segment size must be a non-zero multiple of %d",
                 ZUC_AES_BLOCK_SIZE);
    }

    st = api->aes_new((const uint8_t *) RAW(key), (size_t) XLENGTH(key), &aes);
    if (st != ZUC_OK) {
        Rf_error("zucrypttest: aes_new failed (%s)", api->status_name(st));
    }

    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) total));
    while (offset < total && st == ZUC_OK) {
        size_t n = total - offset;
        if (n > seg) n = seg;
        st = api->aes_cbc_set_state(aes, (const uint8_t *) RAW(iv));
        if (st != ZUC_OK) break;
        st = do_encrypt
            ? api->aes_cbc_encrypt(aes, (const uint8_t *) RAW(data) + offset, n,
                                   (uint8_t *) RAW(out) + offset)
            : api->aes_cbc_decrypt(aes, (const uint8_t *) RAW(data) + offset, n,
                                   (uint8_t *) RAW(out) + offset);
        offset += n;
    }
    api->aes_free(aes);
    if (st != ZUC_OK) {
        UNPROTECT(1);
        Rf_error("zucrypttest: segmented CBC failed (%s)", api->status_name(st));
    }
    UNPROTECT(1);
    return out;
}

static const R_CallMethodDef call_methods[] = {
    {"zucrypttest_api_available", (DL_FUNC) &zucrypttest_api_available, 0},
    {"zucrypttest_abi_reject",    (DL_FUNC) &zucrypttest_abi_reject,    1},
    {"zucrypttest_exercise",      (DL_FUNC) &zucrypttest_exercise,      0},
    {"zucrypttest_derive",        (DL_FUNC) &zucrypttest_derive,        3},
    {"zucrypttest_segments",      (DL_FUNC) &zucrypttest_segments,      5},
    {"zucrypttest_backend",       (DL_FUNC) &zucrypttest_backend,       0},
    {NULL, NULL, 0}
};

void R_init_zucrypttest(DllInfo *dll)
{
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
    /* Deliberately no zucrypt call here. Resolving the table from R_init_ is
     * the ordering trap zucrypt-r.h warns about; zucrypt_api() is lazy so
     * that nothing has to. */
}
