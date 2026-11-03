/* zucrypt: public-key cryptography, RSA (Stage 15a, design.md section 6,
 * tranche 3).
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
 * Reading and writing go through the backend's PK layer, which speaks DER
 * and PEM in PKCS#1, PKCS#8 and SubjectPublicKeyInfo. Its writer emits a
 * private RSA key only as PKCS#1, so PKCS#8 is the PKCS#1 encoding inside a
 * fixed PrivateKeyInfo wrapper, built here.
 */

#include <stdlib.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/pem.h>

#include "zuc_internal.h"

struct zuc_pkey {
    zuc_alg  type;
    int      is_private;
    size_t   bits;
    uint8_t *der;       /* RSAPrivateKey or RSAPublicKey */
    size_t   der_len;
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
    if (!PSA_KEY_TYPE_IS_RSA(type)) {
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
    key->type = ZUC_ALG_RSA;
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

    psa_set_key_type(&attr, key->is_private ? PSA_KEY_TYPE_RSA_KEY_PAIR
                                            : PSA_KEY_TYPE_RSA_PUBLIC_KEY);
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
    if (copy != NULL) {
        zuc_secure_zero(copy, len + 1);
        free(copy);
    }
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return parse_status(ret);
    }

    ret = mbedtls_pk_get_psa_attributes(
        &pk, is_pair ? PSA_KEY_USAGE_SIGN_HASH : PSA_KEY_USAGE_VERIFY_HASH,
        &attr);
    if (ret != 0 || !PSA_KEY_TYPE_IS_RSA(psa_get_key_type(&attr))) {
        mbedtls_pk_free(&pk);
        psa_reset_key_attributes(&attr);
        /* A well-formed key the PK layer knows, of a type this build does
         * not handle: an EC key, for one. */
        return ZUC_ERR_UNSUPPORTED;
    }
    psa_set_key_usage_flags(&attr, psa_get_key_usage_flags(&attr) |
                                   PSA_KEY_USAGE_EXPORT);
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
    if (type != ZUC_ALG_RSA || !zuc_alg_available(type)) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (bits < 1024 || bits > 4096) {
        return ZUC_ERR_BAD_LENGTH;
    }
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
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

/* RSAPublicKey DER for any handle, into a fresh buffer. */
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
        return ret == PSA_ERROR_INSUFFICIENT_MEMORY ? ZUC_ERR_MEMORY
                                                    : ZUC_ERR_BACKEND;
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
        return ret == PSA_ERROR_INSUFFICIENT_MEMORY ? ZUC_ERR_MEMORY
                                                    : ZUC_ERR_BACKEND;
    }
    memmove(buf, buf + ZUC_PKEY_MAX_WRITE_SIZE - (size_t) ret, (size_t) ret);
    *out = buf;
    *out_len = (size_t) ret;
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

    switch (format) {
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

        /* `label` is one of four constants above, so these fit. */
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
        } else if (ret != 0 || olen == 0) {
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
    if (digest_len != zuc_alg_size(hash) || sig_size < key->bits / 8) {
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
    if (digest_len != zuc_alg_size(hash)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    /* A signature of the wrong length is a signature that does not verify,
     * not a usage error. */
    if (sig_len != key->bits / 8) {
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
     * the modulus is refused as bad input rather than as a bad signature.
     * Either way it does not verify. */
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
    if (alg == 0) {
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
    if (alg == 0) {
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
        /* Out of memory stays itself; every other failure -- bad padding,
         * a ciphertext of the wrong length or value, an output buffer too
         * small for what it would hold -- is the one status, so that the
         * status reveals nothing about the padding. */
        return ps == PSA_ERROR_INSUFFICIENT_MEMORY ? ZUC_ERR_MEMORY
                                                   : ZUC_ERR_AUTH;
    }
    return ZUC_OK;
}

/* ------------------------------------------------------------------ *
 * The public entry points
 * ------------------------------------------------------------------ */

/* Each operation runs under the allocation watch (zuc_internal.h): a
 * failure that followed a failed allocation inside the backend is
 * ZUC_ERR_MEMORY, never the "invalid key" or "bad padding" the backend may
 * have turned it into. Internal calls use the _impl functions, so that a
 * nested call does not clear the watch. */

zuc_status zuc_pkey_parse(const uint8_t *in, size_t len, int private_key,
                          zuc_pkey **out)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_parse_impl(in, len, private_key, out));
}

zuc_status zuc_pkey_generate(zuc_alg type, size_t bits, zuc_pkey **out)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_generate_impl(type, bits, out));
}

zuc_status zuc_pkey_public(const zuc_pkey *key, zuc_pkey **out)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_public_impl(key, out));
}

zuc_status zuc_pkey_write(const zuc_pkey *key, zuc_pkey_format format,
                          int public_only,
                          uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_write_impl(key, format, public_only, out, out_size, out_len));
}

zuc_status zuc_pkey_sign_hash(const zuc_pkey *key, zuc_alg scheme,
                              zuc_alg hash,
                              const uint8_t *digest, size_t digest_len,
                              uint8_t *sig, size_t sig_size, size_t *sig_len)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_sign_hash_impl(key, scheme, hash, digest, digest_len, sig, sig_size, sig_len));
}

zuc_status zuc_pkey_verify_hash(const zuc_pkey *key, zuc_alg scheme,
                                zuc_alg hash,
                                const uint8_t *digest, size_t digest_len,
                                const uint8_t *sig, size_t sig_len)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_verify_hash_impl(key, scheme, hash, digest, digest_len, sig, sig_len));
}

zuc_status zuc_pkey_encrypt(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                            const uint8_t *in, size_t len,
                            uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_encrypt_impl(key, scheme, hash, in, len, out, out_size, out_len));
}

zuc_status zuc_pkey_decrypt(const zuc_pkey *key, zuc_alg scheme, zuc_alg hash,
                            const uint8_t *in, size_t len,
                            uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_int_alloc_watch();
    return zuc_int_memory_or(pkey_decrypt_impl(key, scheme, hash, in, len, out, out_size, out_len));
}
