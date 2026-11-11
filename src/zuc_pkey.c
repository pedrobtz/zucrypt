/* zucrypt: public-key cryptography, RSA (Stage 15a) and elliptic curves
 * (Stage 16a); design.md section 6, tranches 3 and 4.
 *
 * A zuc_pkey holds key *material*, not a key in the backend's store: the
 * key's canonical encoding (RSAPrivateKey or RSAPublicKey DER, the format
 * the backend imports), its size and whether it is private. Each operation
 * imports it with exactly the policy that operation needs -- one algorithm,
 * one usage -- uses it once and destroys it. That is how one RSA key can
 * sign with PKCS#1 v1.5 and PSS under any digest and also encrypt: the
 * backend's key policy names a single algorithm, and a long-lived backend
 * key would have to be imported once per algorithm or given a wildcard
 * policy. It is also what makes a handle trivially safe to keep across
 * calls: there is no backend state behind it.
 *
 * Reading goes through the backend's PK layer, which speaks DER and PEM in
 * PKCS#1, SEC1, PKCS#8 and SubjectPublicKeyInfo. Writing uses its public-key
 * writer for SubjectPublicKeyInfo. The private encodings are built here, so
 * that they match what OpenSSL writes byte for byte: PKCS#8 around an RSA
 * key's PKCS#1, SEC1 for an EC key (with its curve, and inside PKCS#8
 * without), and RFC 8410 for X25519.
 *
 * Key material, by type, as the backend imports and exports it:
 *   RSA       RSAPrivateKey or RSAPublicKey DER;
 *   EC        the private scalar d, or the uncompressed point 04 || x || y;
 *   X25519    32 bytes, private or public.
 */

#include <stdlib.h>
#include <string.h>

#include <mbedtls/asn1.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>

#include "zuc_internal.h"

struct zuc_pkey {
    zuc_alg        type;
    psa_key_type_t ptype;     /* the backend type of `der`: pair or public */
    int            is_private;
    size_t         bits;
    uint8_t       *der;       /* the key material, see above */
    size_t         der_len;
};

/* The operations, defined below and exported through the wrappers at the
 * end of this file. */
static zuc_status pkey_parse_impl(const uint8_t *in, size_t len, int private_key,
                                  zuc_pkey **out);
static zuc_status pkey_generate_impl(zuc_alg type, size_t bits, zuc_pkey **out);
static zuc_status pkey_public_impl(const zuc_pkey *key, zuc_pkey **out);
static zuc_status pkey_write_impl(const zuc_pkey *key, zuc_pkey_format format,
                                  int public_only,
                                  uint8_t *out, size_t out_size, size_t *out_len);
static zuc_status pkey_sign_hash_impl(const zuc_pkey *key, zuc_alg scheme,
                                      zuc_alg hash,
                                      const uint8_t *digest, size_t digest_len,
                                      uint8_t *sig, size_t sig_size, size_t *sig_len);
static zuc_status pkey_verify_hash_impl(const zuc_pkey *key, zuc_alg scheme,
                                        zuc_alg hash,
                                        const uint8_t *digest, size_t digest_len,
                                        const uint8_t *sig, size_t sig_len);
static zuc_status pkey_encrypt_impl(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                                    const uint8_t *in, size_t len,
                                    uint8_t *out, size_t out_size, size_t *out_len);
static zuc_status pkey_decrypt_impl(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                                    const uint8_t *in, size_t len,
                                    uint8_t *out, size_t out_size, size_t *out_len);
static zuc_status pkey_import_impl(zuc_alg type, int private_key,
                                   const uint8_t *data, size_t len,
                                   zuc_pkey **out);
static zuc_status pkey_export_impl(const zuc_pkey *key, int public_only,
                                   uint8_t *out, size_t out_size,
                                   size_t *out_len);
static zuc_status pkey_agree_impl(const zuc_pkey *key, const zuc_pkey *peer,
                                  uint8_t *out, size_t out_size,
                                  size_t *out_len);

/* ------------------------------------------------------------------ *
 * Key types
 * ------------------------------------------------------------------ */

/* The RSA size rule (zucrypt.h, #141): a modulus of 1024 to 4096 bits,
 * a whole number of bytes. The backend refuses moduli over 4096 bits or not
 * byte-aligned, and zucrypt refuses the weak ones under 1024. */
#define ZUC_RSA_MIN_BITS 1024

static int rsa_size_ok(size_t bits)
{
    return bits >= ZUC_RSA_MIN_BITS && bits <= PSA_VENDOR_RSA_MAX_KEY_BITS &&
           bits % 8 == 0;
}

/* The zuc_alg of a backend key type, or ZUC_ALG_NONE for one this build
 * does not offer, an RSA key outside the size rule included. Every handle
 * is made by pkey_from_psa(), which asks this, so the rule holds however a
 * key arrived: parsed, imported or generated. */
static zuc_alg alg_of_psa(psa_key_type_t type, size_t bits)
{
    if (PSA_KEY_TYPE_IS_RSA(type)) {
        return rsa_size_ok(bits) ? ZUC_ALG_RSA : ZUC_ALG_NONE;
    }
    if (PSA_KEY_TYPE_IS_ECC(type)) {
        psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(type);
        if (family == PSA_ECC_FAMILY_SECP_R1) {
            if (bits == 256) return ZUC_ALG_EC_P256;
            if (bits == 384) return ZUC_ALG_EC_P384;
            if (bits == 521) return ZUC_ALG_EC_P521;
        }
        if (family == PSA_ECC_FAMILY_MONTGOMERY && bits == 255) {
            return ZUC_ALG_X25519;
        }
    }
    return ZUC_ALG_NONE;
}

/* The backend key-pair type and size of an EC or X25519 zuc_alg; 0 for
 * anything else. */
static psa_key_type_t ec_pair_type(zuc_alg type, size_t *bits)
{
    switch (type) {
    case ZUC_ALG_EC_P256:
        *bits = 256;
        return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    case ZUC_ALG_EC_P384:
        *bits = 384;
        return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    case ZUC_ALG_EC_P521:
        *bits = 521;
        return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    case ZUC_ALG_X25519:
        *bits = 255;
        return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
    default:
        *bits = 0;
        return 0;
    }
}

static int is_nist_curve(zuc_alg type)
{
    return type == ZUC_ALG_EC_P256 || type == ZUC_ALG_EC_P384 ||
           type == ZUC_ALG_EC_P521;
}

/* Bytes in a scalar or coordinate of the key's curve. */
static size_t ec_bytes(const zuc_pkey *key)
{
    return (key->bits + 7) / 8;
}

/* How long a signature by `key` is: the modulus for RSA, r || s for
 * ECDSA. */
static size_t signature_size(const zuc_pkey *key)
{
    return key->type == ZUC_ALG_RSA ? key->bits / 8 : 2 * ec_bytes(key);
}

/* ------------------------------------------------------------------ *
 * Handles
 * ------------------------------------------------------------------ */

static void pkey_destroy(zuc_pkey *key)
{
    if (key == NULL) {
        return;
    }
    if (key->der != NULL) {
        zuc_secure_zero(key->der, key->der_len);
        free(key->der);
    }
    zuc_secure_zero(key, sizeof *key);
    free(key);
}

void zuc_pkey_free(zuc_pkey *key)
{
    if (key == NULL) {
        return;
    }
    pkey_destroy(key);
    zuc_int_live_add(-1);
}

zuc_alg zuc_pkey_type(const zuc_pkey *key)
{
    return key == NULL ? ZUC_ALG_NONE : key->type;
}

size_t zuc_pkey_bits(const zuc_pkey *key)
{
    return key == NULL ? 0 : key->bits;
}

int zuc_pkey_is_private(const zuc_pkey *key)
{
    return key != NULL && key->is_private;
}

/* A handle from a key in the backend's store, which must be exportable.
 * `want_private` 0 keeps only the public half. */
static zuc_status pkey_from_psa(psa_key_id_t id, int want_private,
                                zuc_pkey **out)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_type_t type;
    zuc_pkey *key;
    size_t cap, len = 0;
    uint8_t *buf;
    psa_status_t ps;
    int is_pair;

    ps = psa_get_key_attributes(id, &attr);
    if (ps != PSA_SUCCESS) {
        return zuc_int_from_psa(ps);
    }
    type = psa_get_key_type(&attr);
    if (alg_of_psa(type, psa_get_key_bits(&attr)) == ZUC_ALG_NONE) {
        psa_reset_key_attributes(&attr);
        return ZUC_ERR_UNSUPPORTED;
    }
    is_pair = PSA_KEY_TYPE_IS_KEY_PAIR(type) && want_private;
    cap = is_pair
        ? PSA_EXPORT_KEY_OUTPUT_SIZE(type, psa_get_key_bits(&attr))
        : PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(type, psa_get_key_bits(&attr));

    key = calloc(1, sizeof *key);
    buf = malloc(cap);
    if (key == NULL || buf == NULL) {
        free(key);
        free(buf);
        psa_reset_key_attributes(&attr);
        return ZUC_ERR_MEMORY;
    }
    ps = is_pair ? psa_export_key(id, buf, cap, &len)
                 : psa_export_public_key(id, buf, cap, &len);
    if (ps != PSA_SUCCESS) {
        zuc_secure_zero(buf, cap);
        free(buf);
        free(key);
        psa_reset_key_attributes(&attr);
        return zuc_int_from_psa(ps);
    }
    key->type = alg_of_psa(type, psa_get_key_bits(&attr));
    key->ptype = is_pair ? type : PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type);
    key->is_private = is_pair;
    key->bits = psa_get_key_bits(&attr);
    key->der = buf;
    key->der_len = len;
    psa_reset_key_attributes(&attr);
    *out = key;
    zuc_int_live_add(1);
    return ZUC_OK;
}

/* Load a handle's key into the backend for one operation. */
static zuc_status pkey_import(const zuc_pkey *key, psa_algorithm_t alg,
                              psa_key_usage_t usage, psa_key_id_t *id)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_status_t ps;

    psa_set_key_type(&attr, key->ptype);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_usage_flags(&attr, usage);
    ps = psa_import_key(&attr, key->der, key->der_len, id);
    psa_reset_key_attributes(&attr);
    return zuc_int_from_psa(ps);
}

/* ------------------------------------------------------------------ *
 * Reading, generating, deriving
 * ------------------------------------------------------------------ */

static int looks_like_pem(const uint8_t *in, size_t len)
{
    static const char begin[] = "-----BEGIN";
    size_t i = 0;

    /* Leading whitespace is tolerated, as files often have it. */
    while (i < len && (in[i] == ' ' || in[i] == '\t' || in[i] == '\r' ||
                       in[i] == '\n')) {
        i++;
    }
    return len - i >= sizeof begin - 1 &&
           memcmp(in + i, begin, sizeof begin - 1) == 0;
}

/* What a failed read means. Allocation failure is itself; a key of a type
 * or curve the reader recognises but this build does not include -- an EC
 * key, without the EC modules -- is unsupported; anything else is input
 * that is not a key. */
static zuc_status parse_status(int ret)
{
    switch (ret) {
    case PSA_ERROR_INSUFFICIENT_MEMORY:
        return ZUC_ERR_MEMORY;
    case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
    case MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE:
    case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
        return ZUC_ERR_UNSUPPORTED;
    default:
        return ZUC_ERR_INVALID_ARGUMENT;
    }
}

/* An RSA key's modulus length, read from whichever of the four encodings
 * the readers take holds it -- SubjectPublicKeyInfo, RSAPublicKey,
 * PKCS#8 PrivateKeyInfo or RSAPrivateKey -- or 0 if `der` is none of them.
 * `*is_private` says which half it was. Only ever asked after the PK reader
 * has refused the input, to tell a well-formed key over the backend's size
 * limit, which the reader reports as malformed or as unavailable depending
 * on the encoding, from input that is not a key (#93). It reads; it
 * validates nothing it does not need. */
static const unsigned char rsa_oid[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};

static int is_rsa_alg(unsigned char **p, const unsigned char *end)
{
    mbedtls_asn1_buf oid, params;
    return mbedtls_asn1_get_alg(p, end, &oid, &params) == 0 &&
           oid.len == sizeof rsa_oid &&
           memcmp(oid.p, rsa_oid, sizeof rsa_oid) == 0;
}

static size_t integer_bits(const unsigned char *p, size_t n)
{
    size_t bits;
    unsigned int top;

    while (n > 0 && *p == 0) {
        p++;
        n--;
    }
    if (n == 0) {
        return 0;
    }
    bits = (n - 1) * 8;
    for (top = *p; top != 0; top >>= 1) {
        bits++;
    }
    return bits;
}

static size_t rsa_key_bits(const uint8_t *der, size_t len, int depth,
                           int *is_private)
{
    const int seq = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    unsigned char *p = (unsigned char *) der, *end = p + len, *q, *first;
    size_t n, first_len;

    if (depth > 1 || mbedtls_asn1_get_tag(&p, end, &n, seq) != 0) {
        return 0;
    }
    end = p + n;
    q = p;
    if (is_rsa_alg(&q, end)) {
        /* SubjectPublicKeyInfo: the RSAPublicKey is in a BIT STRING. */
        if (mbedtls_asn1_get_bitstring_null(&q, end, &n) != 0) {
            return 0;
        }
        return rsa_key_bits(q, n, depth + 1, is_private);
    }
    if (mbedtls_asn1_get_tag(&p, end, &first_len, MBEDTLS_ASN1_INTEGER) != 0) {
        return 0;
    }
    first = p;
    p += first_len;
    if (!(first_len == 1 && first[0] == 0)) {
        /* RSAPublicKey: the modulus comes first. */
        *is_private = 0;
        return integer_bits(first, first_len);
    }
    /* Version 0: PrivateKeyInfo, with the RSAPrivateKey in an OCTET
     * STRING, or the RSAPrivateKey itself, with the modulus next. */
    q = p;
    if (is_rsa_alg(&q, end)) {
        if (mbedtls_asn1_get_tag(&q, end, &n, MBEDTLS_ASN1_OCTET_STRING) != 0) {
            return 0;
        }
        return rsa_key_bits(q, n, depth + 1, is_private);
    }
    if (mbedtls_asn1_get_tag(&p, end, &n, MBEDTLS_ASN1_INTEGER) != 0) {
        return 0;
    }
    *is_private = 1;
    return integer_bits(p, n);
}

/* Is this a well-formed RSA key, of the half the reader was asked for,
 * whose modulus is outside the size rule? `pem` is the NUL-terminated copy
 * when the input is PEM, else NULL. */
static int rsa_outside_rule(const uint8_t *in, size_t len, const uint8_t *pem,
                          int want_private)
{
    static const char *const labels[][2] = {
        {"-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"},
        {"-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"},
        {"-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"},
        {"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"}
    };
    size_t i, bits = 0;
    int is_private = 0;

    if (pem == NULL) {
        bits = rsa_key_bits(in, len, 0, &is_private);
    }
    for (i = 0; pem != NULL && i < sizeof labels / sizeof labels[0] &&
                bits == 0; i++) {
        mbedtls_pem_context ctx;
        const unsigned char *der;
        size_t der_len, used = 0;

        mbedtls_pem_init(&ctx);
        if (mbedtls_pem_read_buffer(&ctx, labels[i][0], labels[i][1], pem,
                                    NULL, 0, &used) == 0) {
            der = mbedtls_pem_get_buffer(&ctx, &der_len);
            bits = rsa_key_bits(der, der_len, 0, &is_private);
        }
        mbedtls_pem_free(&ctx);
    }
    /* A private reader handed a public key is refusing the right thing. */
    if (want_private && !is_private) {
        return 0;
    }
    return bits != 0 && !rsa_size_ok(bits);
}

static zuc_status pkey_parse_impl(const uint8_t *in, size_t len, int private_key,
                                  zuc_pkey **out)
{
    mbedtls_pk_context pk;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = 0;
    uint8_t *copy = NULL;
    const uint8_t *src = in;
    size_t src_len = len;
    zuc_status st;
    int ret, is_pair = 0;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (in == NULL || len == 0) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* The PK reader takes PEM as a NUL-terminated string whose length
     * includes the NUL, and refuses an embedded one. */
    if (looks_like_pem(in, len)) {
        if (memchr(in, 0, len) != NULL) {
            return ZUC_ERR_INVALID_ARGUMENT;
        }
        copy = malloc(len + 1);
        if (copy == NULL) {
            return ZUC_ERR_MEMORY;
        }
        memcpy(copy, in, len);
        copy[len] = 0;
        src = copy;
        src_len = len + 1;
    }

    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_key(&pk, src, src_len, NULL, 0);
    if (ret == 0) {
        is_pair = 1;
    } else if (!private_key) {
        int first = ret;
        mbedtls_pk_free(&pk);
        mbedtls_pk_init(&pk);
        ret = mbedtls_pk_parse_public_key(&pk, src, src_len);
        /* Of the two failures, the more specific one says more. */
        if (ret != 0 && parse_status(first) == ZUC_ERR_UNSUPPORTED) {
            ret = first;
        }
    }
    /* A well-formed RSA key outside the size rule -- over the backend's
     * limit or not byte-aligned -- is refused by the reader as unavailable
     * or as malformed, depending on the encoding and the half. It is
     * unsupported, whichever reader met it (#93, #141). */
    if (ret != 0 && parse_status(ret) == ZUC_ERR_INVALID_ARGUMENT &&
        rsa_outside_rule(in, len, copy, private_key)) {
        ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }
    if (copy != NULL) {
        zuc_secure_zero(copy, len + 1);
        free(copy);
    }
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return parse_status(ret);
    }

    /* The PK layer describes a key only for a usage it supports: signing
     * for RSA and the NIST curves, key agreement for X25519 key pairs.
     * Whichever answers gives the key's type; its policy is replaced below,
     * since the key is imported only to be exported. */
    ret = mbedtls_pk_get_psa_attributes(
        &pk, is_pair ? PSA_KEY_USAGE_SIGN_HASH : PSA_KEY_USAGE_VERIFY_HASH,
        &attr);
    if (ret != 0 && is_pair) {
        psa_reset_key_attributes(&attr);
        ret = mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_DERIVE, &attr);
    }
    if (ret != 0 && !is_pair && mbedtls_pk_get_bitlen(&pk) == 255) {
        /* A public X25519 key has no usage the PK layer will describe; its
         * raw 32 bytes are what the backend imports. */
        uint8_t raw[32];
        size_t raw_len = 0;
        psa_reset_key_attributes(&attr);
        ret = mbedtls_pk_write_pubkey_psa(&pk, raw, sizeof raw, &raw_len);
        mbedtls_pk_free(&pk);
        if (ret != 0 || raw_len != sizeof raw) {
            return ZUC_ERR_UNSUPPORTED;
        }
        return pkey_import_impl(ZUC_ALG_X25519, 0, raw, raw_len, out);
    }
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        psa_reset_key_attributes(&attr);
        /* A well-formed key the PK layer knows, of a type or curve this
         * build does not handle. */
        return ZUC_ERR_UNSUPPORTED;
    }
    psa_set_key_algorithm(&attr, PSA_ALG_NONE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    ret = mbedtls_pk_import_into_psa(&pk, &attr, &id);
    mbedtls_pk_free(&pk);
    psa_reset_key_attributes(&attr);
    if (ret != 0) {
        return ret == PSA_ERROR_INSUFFICIENT_MEMORY ? ZUC_ERR_MEMORY
                                                    : ZUC_ERR_INVALID_ARGUMENT;
    }
    /* A private key was asked for only if `private_key`; otherwise the
     * backend exports just the public half of whatever was read. */
    st = pkey_from_psa(id, private_key && is_pair, out);
    psa_destroy_key(id);
    if (st == ZUC_OK && private_key && !(*out)->is_private) {
        zuc_pkey_free(*out);
        *out = NULL;
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    return st;
}

static zuc_status pkey_generate_impl(zuc_alg type, size_t bits, zuc_pkey **out)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (!zuc_alg_available(type)) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (type == ZUC_ALG_RSA) {
        if (!rsa_size_ok(bits)) {
            return ZUC_ERR_BAD_LENGTH;
        }
        psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    } else {
        size_t curve_bits = 0;
        psa_key_type_t pt = ec_pair_type(type, &curve_bits);
        if (pt == 0) {
            return ZUC_ERR_UNSUPPORTED;
        }
        if (bits != 0 && bits != curve_bits) {
            return ZUC_ERR_BAD_LENGTH;
        }
        bits = curve_bits;
        psa_set_key_type(&attr, pt);
    }
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    ps = psa_generate_key(&attr, &id);
    psa_reset_key_attributes(&attr);
    if (ps != PSA_SUCCESS) {
        return zuc_int_from_psa(ps);
    }
    st = pkey_from_psa(id, 1, out);
    psa_destroy_key(id);
    return st;
}

static zuc_status pkey_public_impl(const zuc_pkey *key, zuc_pkey **out)
{
    psa_key_id_t id = 0;
    zuc_status st;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (key == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    st = pkey_import(key, PSA_ALG_NONE, PSA_KEY_USAGE_EXPORT, &id);
    if (st != ZUC_OK) {
        return st;
    }
    st = pkey_from_psa(id, 0, out);
    psa_destroy_key(id);
    return st;
}

/* ------------------------------------------------------------------ *
 * Writing
 * ------------------------------------------------------------------ */

/* The public key material of any handle (RSAPublicKey DER, an EC point,
 * 32 X25519 bytes), into a fresh buffer. */
static zuc_status public_der(const zuc_pkey *key, uint8_t **der,
                             size_t *der_len)
{
    zuc_pkey *pub = NULL;
    zuc_status st;

    if (!key->is_private) {
        *der = malloc(key->der_len);
        if (*der == NULL) {
            return ZUC_ERR_MEMORY;
        }
        memcpy(*der, key->der, key->der_len);
        *der_len = key->der_len;
        return ZUC_OK;
    }
    st = pkey_public_impl(key, &pub);
    if (st != ZUC_OK) {
        return st;
    }
    /* Not reachable -- success always returns a handle -- but the analyzer
     * cannot see that through pkey_from_psa(), and a NULL here would be a
     * crash rather than an error. */
    if (pub == NULL) {
        return ZUC_ERR_INTERNAL;
    }
    *der = pub->der;
    *der_len = pub->der_len;
    pub->der = NULL;
    pub->der_len = 0;
    zuc_pkey_free(pub);
    return ZUC_OK;
}

/* DER length octets for `n`, written at `p`; returns how many. */
static size_t der_length(size_t n, uint8_t *p)
{
    if (n < 0x80) {
        p[0] = (uint8_t) n;
        return 1;
    }
    if (n <= 0xFF) {
        p[0] = 0x81;
        p[1] = (uint8_t) n;
        return 2;
    }
    p[0] = 0x82;
    p[1] = (uint8_t) (n >> 8);
    p[2] = (uint8_t) n;
    return 3;
}

/* PKCS#8 PrivateKeyInfo (RFC 5208 section 5) around an RSAPrivateKey:
 * SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption, NULL },
 *            OCTET STRING { RSAPrivateKey } }. */
static zuc_status pkcs8_wrap(const uint8_t *pkcs1, size_t pkcs1_len,
                             uint8_t **out, size_t *out_len)
{
    static const uint8_t head[] = {
        0x02, 0x01, 0x00,                               /* version 0 */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, /* rsaEncryption */
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00        /* NULL */
    };
    uint8_t octet_len[3], seq_len[3];
    size_t ol, sl, body, total;
    uint8_t *p;

    /* A 4096-bit RSAPrivateKey is about 2.4 KB, well inside two length
     * octets; anything over 64 KiB is not a key this build makes. */
    if (pkcs1_len > 0xFFFF - 64) {
        return ZUC_ERR_INTERNAL;
    }
    ol = der_length(pkcs1_len, octet_len);
    body = sizeof head + 1 + ol + pkcs1_len;
    sl = der_length(body, seq_len);
    total = 1 + sl + body;
    p = malloc(total);
    if (p == NULL) {
        return ZUC_ERR_MEMORY;
    }
    *out = p;
    *out_len = total;
    *p++ = 0x30;
    memcpy(p, seq_len, sl);
    p += sl;
    memcpy(p, head, sizeof head);
    p += sizeof head;
    *p++ = 0x04;
    memcpy(p, octet_len, ol);
    p += ol;
    memcpy(p, pkcs1, pkcs1_len);
    return ZUC_OK;
}

/* SubjectPublicKeyInfo DER, through the PK writer. */
static zuc_status spki_der(const zuc_pkey *key, uint8_t **out,
                           size_t *out_len)
{
    mbedtls_pk_context pk;
    psa_key_id_t id = 0;
    uint8_t *buf;
    zuc_status st;
    int ret;

    st = pkey_import(key, PSA_ALG_NONE, PSA_KEY_USAGE_EXPORT, &id);
    if (st != ZUC_OK) {
        return st;
    }
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_copy_public_from_psa(id, &pk);
    psa_destroy_key(id);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return zuc_int_from_psa((psa_status_t) ret);
    }
    buf = malloc(ZUC_PKEY_MAX_WRITE_SIZE);
    if (buf == NULL) {
        mbedtls_pk_free(&pk);
        return ZUC_ERR_MEMORY;
    }
    /* The writer fills the buffer from its end and returns the length. */
    ret = mbedtls_pk_write_pubkey_der(&pk, buf, ZUC_PKEY_MAX_WRITE_SIZE);
    mbedtls_pk_free(&pk);
    if (ret <= 0) {
        free(buf);
        return zuc_int_from_psa((psa_status_t) ret);
    }
    memmove(buf, buf + ZUC_PKEY_MAX_WRITE_SIZE - (size_t) ret, (size_t) ret);
    *out = buf;
    *out_len = (size_t) ret;
    return ZUC_OK;
}

/* --- EC and X25519 encodings ------------------------------------------ */

/* Bytes a DER element with `n` content bytes takes. */
static size_t tlv_size(size_t n)
{
    return 1 + (n < 0x80 ? 1 : n <= 0xFF ? 2 : 3) + n;
}

/* Write a tag and length at `p`; returns the bytes written. Content follows
 * at p + the return value. */
static size_t tlv_head(uint8_t *p, uint8_t tag, size_t n)
{
    p[0] = tag;
    return 1 + der_length(n, p + 1);
}

static size_t tlv(uint8_t *p, uint8_t tag, const uint8_t *v, size_t n)
{
    size_t h = tlv_head(p, tag, n);
    memcpy(p + h, v, n);
    return h + n;
}

/* id-ecPublicKey (RFC 5480), and the curve OIDs of P-256, P-384, P-521. */
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};
static const uint8_t OID_P256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};
static const uint8_t OID_P384[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OID_P521[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
/* id-X25519 (RFC 8410). */
static const uint8_t OID_X25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x6e };

static void curve_oid(zuc_alg type, const uint8_t **oid, size_t *len)
{
    switch (type) {
    case ZUC_ALG_EC_P256: *oid = OID_P256; *len = sizeof OID_P256; break;
    case ZUC_ALG_EC_P384: *oid = OID_P384; *len = sizeof OID_P384; break;
    default:              *oid = OID_P521; *len = sizeof OID_P521; break;
    }
}

/* SEC1 ECPrivateKey (RFC 5915): SEQUENCE { 1, OCTET STRING d,
 * [0] curve (when `params`), [1] BIT STRING point }. Written at `p` when
 * `p` is not NULL; returns its size either way. */
static size_t ec_sec1(uint8_t *p, const zuc_pkey *key, const uint8_t *point,
                      size_t point_len, int params)
{
    const uint8_t *oid;
    size_t oid_len, body, n = 0;

    curve_oid(key->type, &oid, &oid_len);
    body = 3 + tlv_size(key->der_len) +
           (params ? tlv_size(oid_len) : 0) +
           tlv_size(tlv_size(point_len + 1));
    if (p == NULL) {
        return tlv_size(body);
    }
    n += tlv_head(p, 0x30, body);
    p[n++] = 0x02; p[n++] = 0x01; p[n++] = 0x01;
    n += tlv(p + n, 0x04, key->der, key->der_len);
    if (params) {
        n += tlv(p + n, 0xa0, oid, oid_len);
    }
    n += tlv_head(p + n, 0xa1, tlv_size(point_len + 1));
    n += tlv_head(p + n, 0x03, point_len + 1);
    p[n++] = 0x00;
    memcpy(p + n, point, point_len);
    return n + point_len;
}

/* The private encodings of an EC or X25519 key, and its PKCS#1-slot
 * refusal. Public keys are SubjectPublicKeyInfo, through the PK writer. */
static zuc_status ec_encode(const zuc_pkey *key, zuc_pkey_format format,
                            int private_out, uint8_t **der, size_t *der_len,
                            const char **label)
{
    const int pkcs1 = format == ZUC_PKEY_PKCS1_DER ||
                      format == ZUC_PKEY_PKCS1_PEM;
    uint8_t *point = NULL, *p;
    size_t point_len = 0, total, n = 0;
    zuc_status st;

    if (format < ZUC_PKEY_PKCS1_DER || format > ZUC_PKEY_INFO_PEM) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!private_out) {
        if (pkcs1) {
            return ZUC_ERR_UNSUPPORTED;
        }
        *label = "PUBLIC KEY";
        return spki_der(key, der, der_len);
    }
    if (key->type == ZUC_ALG_X25519) {
        /* RFC 8410 section 7: SEQUENCE { 0, SEQUENCE { id-X25519 },
         * OCTET STRING { OCTET STRING k } }. There is no SEC1 form. */
        size_t alg = tlv_size(sizeof OID_X25519);
        size_t inner = tlv_size(key->der_len);
        size_t body = 3 + alg + tlv_size(inner);
        if (pkcs1) {
            return ZUC_ERR_UNSUPPORTED;
        }
        total = tlv_size(body);
        p = malloc(total);
        if (p == NULL) {
            return ZUC_ERR_MEMORY;
        }
        n += tlv_head(p, 0x30, body);
        p[n++] = 0x02; p[n++] = 0x01; p[n++] = 0x00;
        n += tlv(p + n, 0x30, OID_X25519, sizeof OID_X25519);
        n += tlv_head(p + n, 0x04, inner);
        n += tlv(p + n, 0x04, key->der, key->der_len);
        *der = p;
        *der_len = n;
        *label = "PRIVATE KEY";
        return ZUC_OK;
    }

    st = public_der(key, &point, &point_len);
    if (st != ZUC_OK) {
        return st;
    }
    if (pkcs1) {
        /* SEC1 with the curve, as OpenSSL writes "EC PRIVATE KEY". */
        total = ec_sec1(NULL, key, point, point_len, 1);
        p = malloc(total);
        if (p != NULL) {
            n = ec_sec1(p, key, point, point_len, 1);
        }
        *label = "EC PRIVATE KEY";
    } else {
        /* PKCS#8 (RFC 5915 section 3): the curve in the algorithm
         * identifier, and SEC1 without it inside. */
        const uint8_t *oid;
        size_t oid_len, sec1, alg, body;
        curve_oid(key->type, &oid, &oid_len);
        sec1 = ec_sec1(NULL, key, point, point_len, 0);
        alg = sizeof OID_EC_PUBLIC_KEY + oid_len;
        body = 3 + tlv_size(alg) + tlv_size(sec1);
        total = tlv_size(body);
        p = malloc(total);
        if (p != NULL) {
            n += tlv_head(p, 0x30, body);
            p[n++] = 0x02; p[n++] = 0x01; p[n++] = 0x00;
            n += tlv_head(p + n, 0x30, alg);
            memcpy(p + n, OID_EC_PUBLIC_KEY, sizeof OID_EC_PUBLIC_KEY);
            n += sizeof OID_EC_PUBLIC_KEY;
            memcpy(p + n, oid, oid_len);
            n += oid_len;
            n += tlv_head(p + n, 0x04, sec1);
            n += ec_sec1(p + n, key, point, point_len, 0);
        }
        *label = "PRIVATE KEY";
    }
    zuc_secure_zero(point, point_len);
    free(point);
    if (p == NULL) {
        return ZUC_ERR_MEMORY;
    }
    *der = p;
    *der_len = n;
    return ZUC_OK;
}

static zuc_status pkey_write_impl(const zuc_pkey *key, zuc_pkey_format format,
                                  int public_only,
                                  uint8_t *out, size_t out_size, size_t *out_len)
{
    const int private_out = key != NULL && key->is_private && !public_only;
    const char *label;
    uint8_t *der = NULL;
    size_t der_len = 0;
    zuc_status st;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (key == NULL || out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }

    if (key->type != ZUC_ALG_RSA) {
        st = ec_encode(key, format, private_out, &der, &der_len, &label);
    } else switch (format) {
    case ZUC_PKEY_PKCS1_DER:
    case ZUC_PKEY_PKCS1_PEM:
        if (private_out) {
            der = malloc(key->der_len);
            if (der == NULL) {
                return ZUC_ERR_MEMORY;
            }
            memcpy(der, key->der, key->der_len);
            der_len = key->der_len;
            st = ZUC_OK;
        } else {
            st = public_der(key, &der, &der_len);
        }
        label = private_out ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY";
        break;
    case ZUC_PKEY_INFO_DER:
    case ZUC_PKEY_INFO_PEM:
        st = private_out ? pkcs8_wrap(key->der, key->der_len, &der, &der_len)
                         : spki_der(key, &der, &der_len);
        label = private_out ? "PRIVATE KEY" : "PUBLIC KEY";
        break;
    default:
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (st != ZUC_OK) {
        return st;
    }

    if (format == ZUC_PKEY_PKCS1_DER || format == ZUC_PKEY_INFO_DER) {
        if (der_len > out_size) {
            st = ZUC_ERR_BAD_LENGTH;
        } else {
            memcpy(out, der, der_len);
            *out_len = der_len;
        }
    } else {
        char header[48], footer[48];
        size_t olen = 0;
        int ret;

        /* `label` is one of the constants above, so these fit. */
        strcpy(header, "-----BEGIN ");
        strcat(header, label);
        strcat(header, "-----\n");
        strcpy(footer, "-----END ");
        strcat(footer, label);
        strcat(footer, "-----\n");
        ret = mbedtls_pem_write_buffer(header, footer, der, der_len,
                                       out, out_size, &olen);
        if (ret == PSA_ERROR_BUFFER_TOO_SMALL) {
            st = ZUC_ERR_BAD_LENGTH;
        } else if (ret != 0) {
            st = zuc_int_from_psa((psa_status_t) ret);
        } else if (olen == 0) {
            st = ZUC_ERR_BACKEND;
        } else {
            /* olen counts the terminating NUL, which is not part of PEM. */
            *out_len = olen - 1;
        }
    }
    zuc_secure_zero(der, der_len);
    free(der);
    if (st != ZUC_OK) {
        zuc_secure_zero(out, out_size);
    }
    return st;
}

/* ------------------------------------------------------------------ *
 * Signatures
 * ------------------------------------------------------------------ */

static psa_algorithm_t sign_alg(zuc_alg scheme, zuc_alg hash)
{
    psa_algorithm_t h = zuc_int_digest_available(hash) ? zuc_int_psa_hash(hash)
                                                       : 0;
    if (h == 0) {
        return 0;
    }
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
    if (scheme == ZUC_ALG_RSA_PKCS1V15_SIGN) {
        return PSA_ALG_RSA_PKCS1V15_SIGN(h);
    }
#endif
#if defined(PSA_WANT_ALG_RSA_PSS)
    if (scheme == ZUC_ALG_RSA_PSS) {
        return PSA_ALG_RSA_PSS(h);
    }
#endif
#if defined(PSA_WANT_ALG_ECDSA)
    if (scheme == ZUC_ALG_ECDSA) {
        return PSA_ALG_ECDSA(h);
    }
#endif
#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
    if (scheme == ZUC_ALG_ECDSA_DETERMINISTIC) {
        return PSA_ALG_DETERMINISTIC_ECDSA(h);
    }
#endif
    return 0;
}

/* Does `scheme` belong to `key`'s type? An RSA scheme on an EC key, or the
 * reverse, is a usage error. */
static int scheme_fits(const zuc_pkey *key, zuc_alg scheme)
{
    if (scheme == ZUC_ALG_RSA_PKCS1V15_SIGN || scheme == ZUC_ALG_RSA_PSS) {
        return key->type == ZUC_ALG_RSA;
    }
    if (scheme == ZUC_ALG_ECDSA || scheme == ZUC_ALG_ECDSA_DETERMINISTIC) {
        return is_nist_curve(key->type);
    }
    return 0;
}

static zuc_status pkey_sign_hash_impl(const zuc_pkey *key, zuc_alg scheme,
                                      zuc_alg hash,
                                      const uint8_t *digest, size_t digest_len,
                                      uint8_t *sig, size_t sig_size, size_t *sig_len)
{
    psa_algorithm_t alg;
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;

    if (sig_len != NULL) {
        *sig_len = 0;
    }
    if (key == NULL || digest == NULL || sig == NULL || sig_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (!key->is_private) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    alg = sign_alg(scheme, hash);
    if (alg == 0) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (!scheme_fits(key, scheme)) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (digest_len != zuc_alg_size(hash) || sig_size < signature_size(key)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    st = pkey_import(key, alg, PSA_KEY_USAGE_SIGN_HASH, &id);
    if (st != ZUC_OK) {
        return st;
    }
    ps = psa_sign_hash(id, alg, digest, digest_len, sig, sig_size, sig_len);
    psa_destroy_key(id);
    if (ps != PSA_SUCCESS) {
        zuc_secure_zero(sig, sig_size);
        *sig_len = 0;
        return zuc_int_from_psa(ps);
    }
    return ZUC_OK;
}

static zuc_status pkey_verify_hash_impl(const zuc_pkey *key, zuc_alg scheme,
                                        zuc_alg hash,
                                        const uint8_t *digest, size_t digest_len,
                                        const uint8_t *sig, size_t sig_len)
{
    psa_algorithm_t alg;
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;

    if (key == NULL || digest == NULL || (sig == NULL && sig_len != 0)) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    alg = sign_alg(scheme, hash);
    if (alg == 0) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (!scheme_fits(key, scheme)) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (digest_len != zuc_alg_size(hash)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    /* A signature of the wrong length is a signature that does not verify,
     * not a usage error. */
    if (sig_len != signature_size(key)) {
        return ZUC_ERR_AUTH;
    }
    st = pkey_import(key, alg, PSA_KEY_USAGE_VERIFY_HASH, &id);
    if (st != ZUC_OK) {
        return st;
    }
    ps = psa_verify_hash(id, alg, digest, digest_len, sig, sig_len);
    psa_destroy_key(id);
    /* Every argument has been checked above, so an "invalid argument" from
     * the backend is about the signature: one whose integer is not below
     * the modulus (or an ECDSA r or s out of range) is refused as bad input
     * rather than as a bad signature. Either way it does not verify. */
    if (ps == PSA_ERROR_INVALID_SIGNATURE || ps == PSA_ERROR_INVALID_ARGUMENT) {
        return ZUC_ERR_AUTH;
    }
    return zuc_int_from_psa(ps);
}

/* ------------------------------------------------------------------ *
 * Encryption
 * ------------------------------------------------------------------ */

static psa_algorithm_t crypt_alg(zuc_alg scheme, zuc_alg hash)
{
#if defined(PSA_WANT_ALG_RSA_OAEP)
    if (scheme == ZUC_ALG_RSA_OAEP) {
        psa_algorithm_t h = zuc_int_digest_available(hash)
                                ? zuc_int_psa_hash(hash) : 0;
        return h == 0 ? 0 : PSA_ALG_RSA_OAEP(h);
    }
#endif
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
    if (scheme == ZUC_ALG_RSA_PKCS1V15_CRYPT && hash == ZUC_ALG_NONE) {
        return PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
#endif
    (void) hash;
    return 0;
}

static zuc_status pkey_encrypt_impl(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                                    const uint8_t *in, size_t len,
                                    uint8_t *out, size_t out_size, size_t *out_len)
{
    static const uint8_t none = 0;
    psa_algorithm_t alg;
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (key == NULL || (in == NULL && len != 0) || out == NULL ||
        out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    alg = crypt_alg(scheme, hash);
    if (alg == 0 || key->type != ZUC_ALG_RSA) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (out_size < key->bits / 8) {
        return ZUC_ERR_BAD_LENGTH;
    }
    st = pkey_import(key, alg, PSA_KEY_USAGE_ENCRYPT, &id);
    if (st != ZUC_OK) {
        return st;
    }
    ps = psa_asymmetric_encrypt(id, alg, len ? in : &none, len, NULL, 0,
                                out, out_size, out_len);
    psa_destroy_key(id);
    if (ps != PSA_SUCCESS) {
        zuc_secure_zero(out, out_size);
        *out_len = 0;
        /* The one refusal a caller can cause with a valid key: a message
         * longer than the key and padding leave room for. */
        return ps == PSA_ERROR_INVALID_ARGUMENT ? ZUC_ERR_BAD_LENGTH
                                                : zuc_int_from_psa(ps);
    }
    return ZUC_OK;
}

static zuc_status pkey_decrypt_impl(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                                    const uint8_t *in, size_t len,
                                    uint8_t *out, size_t out_size, size_t *out_len)
{
    psa_algorithm_t alg;
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (key == NULL || in == NULL || out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (!key->is_private) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    alg = crypt_alg(scheme, hash);
    if (alg == 0 || key->type != ZUC_ALG_RSA) {
        return ZUC_ERR_UNSUPPORTED;
    }
    st = pkey_import(key, alg, PSA_KEY_USAGE_DECRYPT, &id);
    if (st != ZUC_OK) {
        return st;
    }
    ps = psa_asymmetric_decrypt(id, alg, in, len, NULL, 0,
                                out, out_size, out_len);
    psa_destroy_key(id);
    if (ps != PSA_SUCCESS) {
        zuc_secure_zero(out, out_size);
        *out_len = 0;
        /* Out of memory and a failing entropy source stay themselves
         * (#140); every other failure -- bad padding, a ciphertext of the
         * wrong length or value, an output buffer too small for what it
         * would hold -- is the one status, so that the status reveals
         * nothing about the padding. Neither exception does: memory is
         * allocated, and the blinding value drawn, before the ciphertext
         * is looked at. */
        st = zuc_int_from_psa(ps);
        return st == ZUC_ERR_MEMORY || st == ZUC_ERR_ENTROPY ? st
                                                             : ZUC_ERR_AUTH;
    }
    return ZUC_OK;
}

/* ------------------------------------------------------------------ *
 * Raw key material, and key agreement
 * ------------------------------------------------------------------ */

static zuc_status pkey_import_impl(zuc_alg type, int private_key,
                                   const uint8_t *data, size_t len,
                                   zuc_pkey **out)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_type_t pt;
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;
    size_t bits = 0;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (data == NULL || len == 0) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_alg_available(type)) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (type == ZUC_ALG_RSA) {
        pt = PSA_KEY_TYPE_RSA_KEY_PAIR;
    } else {
        pt = ec_pair_type(type, &bits);
        if (pt == 0) {
            return ZUC_ERR_UNSUPPORTED;
        }
    }
    psa_set_key_type(&attr, private_key ? pt
                                        : PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(pt));
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    /* The backend validates as it imports: a point not on the curve, a
     * scalar out of range, an RSA key whose parts do not agree. */
    ps = psa_import_key(&attr, data, len, &id);
    psa_reset_key_attributes(&attr);
    if (ps != PSA_SUCCESS) {
        int is_private = 0;
        size_t rsa_bits;
        if (ps == PSA_ERROR_INSUFFICIENT_MEMORY) {
            return ZUC_ERR_MEMORY;
        }
        /* As in the reader: a well-formed RSA key outside the size rule is
         * unsupported, not malformed (#141). */
        rsa_bits = type == ZUC_ALG_RSA
                 ? rsa_key_bits(data, len, 0, &is_private) : 0;
        if (rsa_bits != 0 && !rsa_size_ok(rsa_bits) &&
            (is_private || !private_key)) {
            return ZUC_ERR_UNSUPPORTED;
        }
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    st = pkey_from_psa(id, private_key, out);
    psa_destroy_key(id);
    return st;
}

static zuc_status pkey_export_impl(const zuc_pkey *key, int public_only,
                                   uint8_t *out, size_t out_size,
                                   size_t *out_len)
{
    uint8_t *der = NULL;
    size_t der_len = 0;
    zuc_status st;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (key == NULL || out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (key->is_private && !public_only) {
        if (key->der_len > out_size) {
            return ZUC_ERR_BAD_LENGTH;
        }
        memcpy(out, key->der, key->der_len);
        *out_len = key->der_len;
        return ZUC_OK;
    }
    st = public_der(key, &der, &der_len);
    if (st != ZUC_OK) {
        return st;
    }
    if (der_len > out_size) {
        st = ZUC_ERR_BAD_LENGTH;
    } else {
        memcpy(out, der, der_len);
        *out_len = der_len;
    }
    free(der);
    return st;
}

static zuc_status pkey_agree_impl(const zuc_pkey *key, const zuc_pkey *peer,
                                  uint8_t *out, size_t out_size,
                                  size_t *out_len)
{
    uint8_t *point = NULL;
    size_t point_len = 0, i;
    psa_key_id_t id = 0;
    psa_status_t ps;
    zuc_status st;
    int zero = 1;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (key == NULL || peer == NULL || out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (key->type == ZUC_ALG_RSA || !zuc_alg_available(ZUC_ALG_ECDH)) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (!key->is_private || peer->type != key->type) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (out_size < ec_bytes(key)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    st = public_der(peer, &point, &point_len);
    if (st != ZUC_OK) {
        return st;
    }
    st = pkey_import(key, PSA_ALG_ECDH, PSA_KEY_USAGE_DERIVE, &id);
    if (st == ZUC_OK) {
        ps = psa_raw_key_agreement(PSA_ALG_ECDH, id, point, point_len,
                                   out, out_size, out_len);
        psa_destroy_key(id);
        /* Memory and entropy (the blinding scalar, #140) stay themselves;
         * any other failure is the peer's point. */
        st = zuc_int_from_psa(ps);
        if (st != ZUC_OK && st != ZUC_ERR_MEMORY && st != ZUC_ERR_ENTROPY) {
            st = ZUC_ERR_INVALID_ARGUMENT;
        }
    }
    free(point);
    /* RFC 7748 section 6.1: an all-zero X25519 result means a low-order
     * peer point, and contributes nothing secret. */
    if (st == ZUC_OK && key->type == ZUC_ALG_X25519) {
        for (i = 0; i < *out_len; i++) {
            if (out[i] != 0) zero = 0;
        }
        if (zero) {
            st = ZUC_ERR_INVALID_ARGUMENT;
        }
    }
    if (st != ZUC_OK) {
        zuc_secure_zero(out, out_size);
        *out_len = 0;
    }
    return st;
}

/* ------------------------------------------------------------------ *
 * The public entry points
 * ------------------------------------------------------------------ */

/* Each operation runs under the watch (zuc_internal.h): a failure that
 * followed a failed allocation inside the backend is ZUC_ERR_MEMORY, and
 * one that followed a failed draw from the random source ZUC_ERR_ENTROPY
 * (#140), never the "invalid key", "bad padding" or generic error the
 * backend may have turned it into. Internal calls use the _impl functions,
 * so that a nested call does not clear the watch. */

zuc_status zuc_pkey_parse(const uint8_t *in, size_t len, int private_key,
                          zuc_pkey **out)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_parse_impl(in, len, private_key, out));
}

zuc_status zuc_pkey_generate(zuc_alg type, size_t bits, zuc_pkey **out)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_generate_impl(type, bits, out));
}

zuc_status zuc_pkey_public(const zuc_pkey *key, zuc_pkey **out)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_public_impl(key, out));
}

zuc_status zuc_pkey_write(const zuc_pkey *key, zuc_pkey_format format,
                          int public_only,
                          uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_write_impl(key, format, public_only, out, out_size, out_len));
}

zuc_status zuc_pkey_sign_hash(const zuc_pkey *key, zuc_alg scheme,
                              zuc_alg hash,
                              const uint8_t *digest, size_t digest_len,
                              uint8_t *sig, size_t sig_size, size_t *sig_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_sign_hash_impl(key, scheme, hash, digest, digest_len, sig, sig_size, sig_len));
}

zuc_status zuc_pkey_verify_hash(const zuc_pkey *key, zuc_alg scheme,
                                zuc_alg hash,
                                const uint8_t *digest, size_t digest_len,
                                const uint8_t *sig, size_t sig_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_verify_hash_impl(key, scheme, hash, digest, digest_len, sig, sig_len));
}

zuc_status zuc_pkey_encrypt(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                            const uint8_t *in, size_t len,
                            uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_encrypt_impl(key, scheme, hash, in, len, out, out_size, out_len));
}

zuc_status zuc_pkey_decrypt(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                            const uint8_t *in, size_t len,
                            uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_decrypt_impl(key, scheme, hash, in, len, out, out_size, out_len));
}

zuc_status zuc_pkey_import(zuc_alg type, int private_key,
                           const uint8_t *data, size_t len, zuc_pkey **out)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_import_impl(type, private_key, data, len,
                                              out));
}

zuc_status zuc_pkey_export(const zuc_pkey *key, int public_only,
                           uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_export_impl(key, public_only, out, out_size,
                                              out_len));
}

zuc_status zuc_pkey_agree(const zuc_pkey *key, const zuc_pkey *peer,
                          uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_watch();
    return zuc_int_watched_or(pkey_agree_impl(key, peer, out, out_size,
                                             out_len));
}
