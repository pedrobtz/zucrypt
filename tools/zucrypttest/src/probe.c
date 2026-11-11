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

    /* Utilities. ZUCRYPT_API_HAS is how a consumer tests for a field before
     * calling it; pkey_agree is the table's last field, so the test covers
     * the whole struct_size arithmetic. Every field this fixture calls is
     * present in the table it was built against, so it must say yes. */
    check(&f, ZUCRYPT_API_HAS(api, equal) && ZUCRYPT_API_HAS(api, secure_zero) &&
              ZUCRYPT_API_HAS(api, random_bytes) &&
              ZUCRYPT_API_HAS(api, aead_encrypt) &&
              ZUCRYPT_API_HAS(api, aead_decrypt) &&
              ZUCRYPT_API_HAS(api, pbkdf2_hmac) &&
              ZUCRYPT_API_HAS(api, pkey_decrypt) &&
              ZUCRYPT_API_HAS(api, pkey_agree),
          "ZUCRYPT_API_HAS denies a field the table has");
    check(&f, !ZUCRYPT_API_HAS((const zucrypt_api_v1 *) NULL, equal),
          "ZUCRYPT_API_HAS accepted a NULL table");
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

    /* Randomness, appended after ABI 1. Two 32-byte draws that came back
     * equal would mean the field is wired to something that is not random. */
    {
        uint8_t r1[32], r2[32];
        check(&f, api->random_bytes(r1, sizeof r1) == ZUC_OK &&
                  api->random_bytes(r2, sizeof r2) == ZUC_OK,
              "random_bytes failed");
        check(&f, memcmp(r1, r2, sizeof r1) != 0,
              "random_bytes returned the same bytes twice");
        check(&f, api->random_bytes(NULL, 16) == ZUC_ERR_INVALID_ARGUMENT,
              "random_bytes accepted a NULL buffer");
    }

    /* AES-GCM and PBKDF2, appended after ABI 1 (Stage 14a). The GCM
     * specification's test case 2 (all-zero key, nonce and block) and
     * RFC 6070's test case 2; then a flipped tag bit must be refused and the
     * output wiped. */
    {
        static const uint8_t ct2[16] = {
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
        };
        static const uint8_t tag2[16] = {
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
            0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
        };
        static const uint8_t dk2[20] = {
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
            0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
        };
        uint8_t key[16] = {0}, nonce[12] = {0}, pt[16] = {0};
        uint8_t ct[16], tag[16], back[16], dk[20];

        check(&f, api->aead_encrypt(ZUC_ALG_AES_GCM, key, 16, nonce, 12,
                                    NULL, 0, pt, 16, ct, tag, 16) == ZUC_OK &&
                  memcmp(ct, ct2, 16) == 0 && memcmp(tag, tag2, 16) == 0,
              "aead_encrypt does not reproduce GCM test case 2");
        check(&f, api->aead_decrypt(ZUC_ALG_AES_GCM, key, 16, nonce, 12,
                                    NULL, 0, ct, 16, tag, 16, back) == ZUC_OK &&
                  memcmp(back, pt, 16) == 0,
              "aead_decrypt does not reverse GCM test case 2");
        tag[0] ^= 1;
        memset(back, 0xA5, sizeof back);
        check(&f, api->aead_decrypt(ZUC_ALG_AES_GCM, key, 16, nonce, 12,
                                    NULL, 0, ct, 16, tag, 16, back) ==
                      ZUC_ERR_AUTH &&
                  back[0] == 0 && back[15] == 0,
              "aead_decrypt accepted a flipped tag bit or left output behind");
        check(&f, api->pbkdf2_hmac(ZUC_ALG_SHA1,
                                   (const uint8_t *) "password", 8,
                                   (const uint8_t *) "salt", 4, 2,
                                   dk, sizeof dk) == ZUC_OK &&
                  memcmp(dk, dk2, sizeof dk) == 0,
              "pbkdf2_hmac does not reproduce RFC 6070 test case 2");
    }

    /* RSA, appended after ABI 1 (Stage 15a): every pkey field, on a
     * generated 1024-bit key. Sign and verify, a flipped signature
     * refused, OAEP both ways, the encodings written and read back. */
    {
        zuc_pkey *key = NULL, *pub = NULL, *back = NULL;
        uint8_t digest[32], sig[128], ct[128], pt[128], pem[ZUC_PKEY_MAX_WRITE_SIZE];
        size_t sl = 0, cl = 0, pl = 0, wl = 0;

        memcpy(digest, SHA256_ABC, 32);
        check(&f, api->pkey_generate(ZUC_ALG_RSA, 1024, &key) == ZUC_OK &&
                  api->pkey_type(key) == ZUC_ALG_RSA &&
                  api->pkey_bits(key) == 1024 && api->pkey_is_private(key),
              "pkey_generate did not make a 1024-bit RSA private key");
        check(&f, api->pkey_public(key, &pub) == ZUC_OK &&
                  !api->pkey_is_private(pub),
              "pkey_public did not make a public key");
        check(&f, api->pkey_sign_hash(key, ZUC_ALG_RSA_PSS, ZUC_ALG_SHA256,
                                      digest, 32, sig, sizeof sig, &sl)
                      == ZUC_OK &&
                  api->pkey_verify_hash(pub, ZUC_ALG_RSA_PSS, ZUC_ALG_SHA256,
                                        digest, 32, sig, sl) == ZUC_OK,
              "pkey_sign_hash and pkey_verify_hash do not agree");
        sig[0] ^= 1;
        check(&f, api->pkey_verify_hash(pub, ZUC_ALG_RSA_PSS, ZUC_ALG_SHA256,
                                        digest, 32, sig, sl) == ZUC_ERR_AUTH,
              "pkey_verify_hash accepted a flipped signature");
        check(&f, api->pkey_encrypt(pub, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256,
                                    digest, 32, ct, sizeof ct, &cl) == ZUC_OK &&
                  api->pkey_decrypt(key, ZUC_ALG_RSA_OAEP, ZUC_ALG_SHA256,
                                    ct, cl, pt, sizeof pt, &pl) == ZUC_OK &&
                  pl == 32 && memcmp(pt, digest, 32) == 0,
              "pkey_encrypt and pkey_decrypt do not round-trip");
        check(&f, api->pkey_write(key, ZUC_PKEY_INFO_PEM, 0, pem, sizeof pem,
                                  &wl) == ZUC_OK &&
                  api->pkey_parse(pem, wl, 1, &back) == ZUC_OK &&
                  api->pkey_bits(back) == 1024,
              "pkey_write and pkey_parse do not round-trip");
        api->pkey_free(back);
        api->pkey_free(pub);
        api->pkey_free(key);
    }

    /* Elliptic curves, appended after ABI 1 (Stage 16a): the RFC 7748
     * section 6.1 X25519 exchange through pkey_import, pkey_export and
     * pkey_agree. */
    {
        static const uint8_t a[32] = {
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
            0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
            0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
        };
        static const uint8_t B[32] = {
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
            0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
            0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
        };
        static const uint8_t K[32] = {
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
            0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
            0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
        };
        zuc_pkey *alice = NULL, *bob = NULL;
        uint8_t k[32], raw[32];
        size_t kl = 0, rl = 0;

        check(&f, api->pkey_import(ZUC_ALG_X25519, 1, a, 32, &alice) == ZUC_OK &&
                  api->pkey_import(ZUC_ALG_X25519, 0, B, 32, &bob) == ZUC_OK,
              "pkey_import refused RFC 7748's X25519 keys");
        check(&f, api->pkey_agree(alice, bob, k, sizeof k, &kl) == ZUC_OK &&
                  kl == 32 && memcmp(k, K, 32) == 0,
              "pkey_agree does not reproduce RFC 7748 section 6.1");
        check(&f, api->pkey_export(bob, 0, raw, sizeof raw, &rl) == ZUC_OK &&
                  rl == 32 && memcmp(raw, B, 32) == 0,
              "pkey_export does not return the key pkey_import was given");
        api->pkey_free(bob);
        api->pkey_free(alice);
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

/* src/cxx.cpp: the same table, resolved and called from C++ (#113). */
SEXP zucrypttest_cxx_sha256(SEXP data);

static const R_CallMethodDef call_methods[] = {
    {"zucrypttest_api_available", (DL_FUNC) &zucrypttest_api_available, 0},
    {"zucrypttest_abi_reject",    (DL_FUNC) &zucrypttest_abi_reject,    1},
    {"zucrypttest_exercise",      (DL_FUNC) &zucrypttest_exercise,      0},
    {"zucrypttest_derive",        (DL_FUNC) &zucrypttest_derive,        3},
    {"zucrypttest_segments",      (DL_FUNC) &zucrypttest_segments,      5},
    {"zucrypttest_backend",       (DL_FUNC) &zucrypttest_backend,       0},
    {"zucrypttest_cxx_sha256",    (DL_FUNC) &zucrypttest_cxx_sha256,    1},
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
