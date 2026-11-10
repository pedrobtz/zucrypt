/* Fuzz signature verification, zuc_pkey_verify_hash() (#94).
 *
 * Input: a control byte choosing the scheme (RSA PKCS#1 v1.5, RSA-PSS,
 * ECDSA P-256) and the digest (SHA-256, -384, -512), a second control byte
 * choosing a bit, and the rest as the message. The keys are fixed
 * (fuzz_keys.h), so the fuzzer explores signatures, not key generation.
 *
 * The oracle:
 *
 * 1. A signature made over the message's digest verifies, under the public
 *    key and under the private key.
 * 2. That signature with one bit changed, or the digest with one bit
 *    changed, is ZUC_ERR_AUTH. So is the signature cut short or extended.
 * 3. The message itself, offered as a signature over the digest of the
 *    empty string, is refused: accepting it would be a forgery from bytes
 *    the fuzzer chose. Only ZUC_ERR_AUTH or a length refusal may come back.
 */
#include "fuzz_common.h"
#include "fuzz_keys.h"

static zuc_pkey *rsa_key, *rsa_pub, *ec_key, *ec_pub;

static void load_keys(void)
{
    static uint8_t der[4096];
    uint8_t d[32];
    size_t n;

    if (rsa_key != NULL) return;
    n = fuzz_unhex(FUZZ_RSA_DER, der, sizeof der);
    REQUIRE(zuc_pkey_parse(der, n, 1, &rsa_key) == ZUC_OK, "RSA key");
    REQUIRE(zuc_pkey_public(rsa_key, &rsa_pub) == ZUC_OK, "RSA public");
    n = fuzz_unhex(FUZZ_P256_D, d, sizeof d);
    REQUIRE(zuc_pkey_import(ZUC_ALG_EC_P256, 1, d, n, &ec_key) == ZUC_OK,
            "P-256 key");
    REQUIRE(zuc_pkey_public(ec_key, &ec_pub) == ZUC_OK, "P-256 public");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const zuc_alg hashes[] = {ZUC_ALG_SHA256, ZUC_ALG_SHA384,
                                     ZUC_ALG_SHA512};
    uint8_t digest[64], empty[64], sig[1024];
    size_t dlen, elen, slen, k;
    const zuc_pkey *key, *pub;
    zuc_alg scheme, verify_scheme, hash;
    zuc_status st;
    uint8_t bit;
    long live;

    fuzz_init();
    load_keys();
    if (size < 2) return 0;
    live = zuc_int_live_contexts();
    switch (data[0] % 3) {
    case 0:
        scheme = verify_scheme = ZUC_ALG_RSA_PKCS1V15_SIGN;
        key = rsa_key; pub = rsa_pub;
        break;
    case 1:
        scheme = verify_scheme = ZUC_ALG_RSA_PSS;
        key = rsa_key; pub = rsa_pub;
        break;
    default:
        scheme = ZUC_ALG_ECDSA_DETERMINISTIC;
        verify_scheme = ZUC_ALG_ECDSA;
        key = ec_key; pub = ec_pub;
        break;
    }
    hash = hashes[(data[0] / 3) % 3];
    bit = (uint8_t) (1u << (data[1] & 7));

    REQUIRE(zuc_hash_compute(hash, size > 2 ? data + 2 : NULL, size - 2,
                             digest, sizeof digest, &dlen) == ZUC_OK, "hash");
    REQUIRE(zuc_hash_compute(hash, NULL, 0, empty, sizeof empty, &elen)
            == ZUC_OK, "hash of empty");

    /* 1. */
    st = zuc_pkey_sign_hash(key, scheme, hash, digest, dlen, sig, sizeof sig,
                            &slen);
    REQUIRE(st == ZUC_OK, "sign: %s", zuc_status_name(st));
    REQUIRE(zuc_pkey_verify_hash(pub, verify_scheme, hash, digest, dlen, sig,
                                 slen) == ZUC_OK, "own signature refused");
    REQUIRE(zuc_pkey_verify_hash(key, verify_scheme, hash, digest, dlen, sig,
                                 slen) == ZUC_OK,
            "own signature refused by the private key");

    /* 2. */
    k = (size_t) data[1] % slen;
    sig[k] ^= bit;
    st = zuc_pkey_verify_hash(pub, verify_scheme, hash, digest, dlen, sig,
                              slen);
    REQUIRE(st == ZUC_ERR_AUTH, "changed signature: %s", zuc_status_name(st));
    sig[k] ^= bit;
    /* ECDSA reads only as many leading bits of the digest as the curve
     * order has (FIPS 186-5 6.4.2): with P-256, bytes past the 32nd of a
     * SHA-384 or SHA-512 digest do not count, and changing one is not a
     * different message to the verifier. */
    k = (size_t) data[1] % (verify_scheme == ZUC_ALG_ECDSA && dlen > 32 ? 32
                                                                        : dlen);
    digest[k] ^= bit;
    st = zuc_pkey_verify_hash(pub, verify_scheme, hash, digest, dlen, sig,
                              slen);
    REQUIRE(st == ZUC_ERR_AUTH, "changed digest: %s", zuc_status_name(st));
    digest[k] ^= bit;
    st = zuc_pkey_verify_hash(pub, verify_scheme, hash, digest, dlen, sig,
                              slen - 1);
    REQUIRE(st == ZUC_ERR_AUTH || st == ZUC_ERR_BAD_LENGTH,
            "short signature: %s", zuc_status_name(st));
    sig[slen] = 0;
    st = zuc_pkey_verify_hash(pub, verify_scheme, hash, digest, dlen, sig,
                              slen + 1);
    REQUIRE(st == ZUC_ERR_AUTH || st == ZUC_ERR_BAD_LENGTH,
            "long signature: %s", zuc_status_name(st));

    /* 3. */
    st = zuc_pkey_verify_hash(pub, verify_scheme, hash, empty, elen,
                              size > 2 ? data + 2 : NULL, size - 2);
    REQUIRE(st == ZUC_ERR_AUTH || st == ZUC_ERR_BAD_LENGTH ||
            st == ZUC_ERR_INVALID_ARGUMENT,
            "fuzzer bytes as a signature: %s", zuc_status_name(st));

    REQUIRE(zuc_int_live_contexts() == live, "a handle outlived the input");
    return 0;
}
