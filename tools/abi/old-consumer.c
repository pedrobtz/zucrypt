/* A consumer of the archive as v0.1.0 published it (#139).
 *
 * Compiled against tools/abi/v0.1.0/zucrypt.h, the frozen release header,
 * and linked to the current libzucrypt.a: what a package built against
 * zucrypt 0.1.0's LinkingTo headers and relinked against a later archive
 * runs. It calls every function v0.1.0 declared and checks each answer
 * against a published vector, so a renumbered enumerator, a moved field or
 * a changed meaning fails here even when the current headers and the current
 * archive agree with each other. Run by tools/ci/check-abi.sh. */
#include <stdio.h>
#include <string.h>
#include "zucrypt.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, what)                                         \
    do {                                                          \
        checks++;                                                 \
        if (!(cond)) {                                            \
            failures++;                                           \
            fprintf(stderr, "FAIL %s (line %d)\n", what, __LINE__); \
        }                                                         \
    } while (0)

static void unhex(const char *h, uint8_t *out)
{
    size_t i;
    for (i = 0; h[2 * i]; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t) v;
    }
}

static int same_hex(const uint8_t *got, size_t n, const char *want)
{
    uint8_t w[128];
    if (strlen(want) != 2 * n) return 0;
    unhex(want, w);
    return memcmp(got, w, n) == 0;
}

int main(void)
{
    static const struct { zuc_alg alg; const char *name, *abc; size_t n; } d[] = {
        {ZUC_ALG_SHA1, "sha1",
         "a9993e364706816aba3e25717850c26c9cd0d89d", 20},
        {ZUC_ALG_SHA256, "sha256",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32},
        {ZUC_ALG_SHA384, "sha384",
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
         "8086072ba1e7cc2358baeca134c825a7", 48},
        {ZUC_ALG_SHA512, "sha512",
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64}
    };
    const uint8_t abc[3] = {'a', 'b', 'c'};
    uint8_t out[ZUC_MAX_DIGEST_SIZE], key[16], iv[16], pt[16], ct[16], st[16];
    size_t n = 0, i;
    zuc_hash *h = NULL;
    zuc_hmac *m = NULL;
    zuc_aes *a = NULL;
    zuc_info info;

    CHECK(zuc_init() == ZUC_OK, "zuc_init");

    /* Status codes and names keep their values and meanings. */
    CHECK(strcmp(zuc_status_name(ZUC_ERR_NOT_READY), "ZUC_ERR_NOT_READY") == 0,
          "status name of 9");
    CHECK(strcmp(zuc_status_name(ZUC_ERR_ABI), "ZUC_ERR_ABI") == 0,
          "status name of 7");
    CHECK(zuc_status_string(ZUC_OK) != NULL, "status string");

    /* zuc_get_info() with the struct as v0.1.0 knew it. */
    memset(&info, 0, sizeof info);
    info.struct_size = (uint32_t) sizeof info;
    CHECK(zuc_get_info(&info) == ZUC_OK, "get_info");
    CHECK(info.abi_version == ZUCRYPT_ABI_VERSION, "abi_version");
    CHECK(info.backend_name != NULL && info.random_backend != NULL,
          "info strings");
    info.struct_size = (uint32_t) ZUC_INFO_REQUIRED_SIZE - 1;
    CHECK(zuc_get_info(&info) == ZUC_ERR_ABI, "get_info below required");

    /* Every digest, one-shot and incremental, by enumerator and by name. */
    for (i = 0; i < 4; i++) {
        CHECK(zuc_alg_by_name(d[i].name) == d[i].alg, d[i].name);
        CHECK(strcmp(zuc_alg_name(d[i].alg), d[i].name) == 0, d[i].name);
        CHECK(zuc_alg_available(d[i].alg), d[i].name);
        CHECK(zuc_alg_size(d[i].alg) == d[i].n, d[i].name);
        CHECK(zuc_hash_compute(d[i].alg, abc, 3, out, sizeof out, &n) == ZUC_OK &&
              n == d[i].n && same_hex(out, n, d[i].abc), d[i].name);
        CHECK(zuc_hash_new(d[i].alg, &h) == ZUC_OK, "hash_new");
        CHECK(zuc_hash_update(h, abc, 1) == ZUC_OK &&
              zuc_hash_update(h, abc + 1, 2) == ZUC_OK &&
              zuc_hash_finish(h, out, sizeof out, &n) == ZUC_OK &&
              same_hex(out, n, d[i].abc), "incremental digest");
        CHECK(zuc_hash_reset(h) == ZUC_OK &&
              zuc_hash_update(h, abc, 3) == ZUC_OK &&
              zuc_hash_finish(h, out, sizeof out, &n) == ZUC_OK &&
              same_hex(out, n, d[i].abc), "digest after reset");
        zuc_hash_free(h);
        h = NULL;
    }

    /* HMAC-SHA-256, RFC 4231 test case 2. */
    {
        static const char *mac =
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        const uint8_t jefe[4] = {'J', 'e', 'f', 'e'};
        const char *msg = "what do ya want for nothing?";
        size_t len = strlen(msg);

        CHECK(zuc_hmac_compute(ZUC_ALG_SHA256, jefe, 4, (const uint8_t *) msg,
                               len, out, sizeof out, &n) == ZUC_OK &&
              same_hex(out, n, mac), "hmac_compute");
        CHECK(zuc_hmac_new(ZUC_ALG_SHA256, jefe, 4, &m) == ZUC_OK, "hmac_new");
        CHECK(zuc_hmac_update(m, (const uint8_t *) msg, 5) == ZUC_OK &&
              zuc_hmac_update(m, (const uint8_t *) msg + 5, len - 5) == ZUC_OK &&
              zuc_hmac_finish(m, out, sizeof out, &n) == ZUC_OK &&
              same_hex(out, n, mac), "incremental hmac");
        CHECK(zuc_hmac_reset(m) == ZUC_OK &&
              zuc_hmac_update(m, (const uint8_t *) msg, len) == ZUC_OK &&
              zuc_hmac_finish(m, out, sizeof out, &n) == ZUC_OK &&
              same_hex(out, n, mac), "hmac after reset");
        zuc_hmac_free(m);
    }

    /* AES-128-CBC, NIST SP 800-38A F.2.1 and F.2.2, first block. */
    unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
    unhex("000102030405060708090a0b0c0d0e0f", iv);
    unhex("6bc1bee22e409f96e93d7e117393172a", pt);
    CHECK(zuc_aes_new(key, 16, &a) == ZUC_OK, "aes_new");
    CHECK(zuc_aes_cbc_set_state(a, iv) == ZUC_OK &&
          zuc_aes_cbc_encrypt(a, pt, 16, ct) == ZUC_OK &&
          same_hex(ct, 16, "7649abac8119b246cee98e9b12e9197d"), "cbc encrypt");
    CHECK(zuc_aes_cbc_get_state(a, st) == ZUC_OK && memcmp(st, ct, 16) == 0,
          "cbc state is the last ciphertext block");
    CHECK(zuc_aes_cbc_set_state(a, iv) == ZUC_OK &&
          zuc_aes_cbc_decrypt(a, ct, 16, out) == ZUC_OK &&
          memcmp(out, pt, 16) == 0, "cbc decrypt");
    zuc_aes_free(a);

    CHECK(zuc_equal(pt, pt, 16) == 1 && zuc_equal(pt, ct, 16) == 0, "equal");
    zuc_secure_zero(key, sizeof key);
    for (i = 0; i < sizeof key; i++) CHECK(key[i] == 0, "secure_zero");

    CHECK(zuc_shutdown() == ZUC_OK, "zuc_shutdown");
    printf("old-consumer: %d checks, %d failed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
