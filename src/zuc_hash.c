/* zucrypt: digests and HMAC.
 *
 * Both have the same shape -- one-shot, and an opaque incremental handle
 * with new/update/finish/reset/free -- because a consumer driving the Office
 * derivation loop needs the incremental form and everything else needs the
 * one-shot form. The two must agree byte for byte at every split point,
 * which is what the equivalence tests in test-kat.R exist to check.
 */

#include <stdlib.h>
#include <string.h>

#include "zuc_internal.h"

struct zuc_hash {
    zuc_alg              alg;
    psa_algorithm_t      palg;
    psa_hash_operation_t op;
    int                  active;   /* set up and accepting updates */
};

struct zuc_hmac {
    zuc_alg             alg;
    psa_algorithm_t     palg;      /* PSA_ALG_HMAC(hash) */
    psa_key_id_t        key;
    psa_mac_operation_t op;
    int                 active;
};

/* ------------------------------------------------------------------ *
 * Shared checks
 * ------------------------------------------------------------------ */

static zuc_status check_digest_args(zuc_alg alg, const uint8_t *data,
                                    size_t data_len, const uint8_t *out,
                                    size_t out_size, const size_t *out_len)
{
    if (!zuc_int_ready()) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* NULL input is allowed only for an empty input. The digest of nothing
     * is well defined, and a caller with an empty R raw vector has a valid
     * question to ask; a NULL with a non-zero length is a bug. */
    if (data == NULL && data_len != 0) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_alg_available(alg)) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if (out_size < zuc_alg_size(alg)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    return ZUC_OK;
}

/* ------------------------------------------------------------------ *
 * Digest
 * ------------------------------------------------------------------ */

zuc_status zuc_hash_compute(zuc_alg alg,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_status st = check_digest_args(alg, data, data_len, out, out_size, out_len);
    psa_status_t ps;

    if (st != ZUC_OK) {
        return st;
    }
    *out_len = 0;
    ps = psa_hash_compute(zuc_int_psa_hash(alg),
                          data == NULL ? (const uint8_t *) "" : data, data_len,
                          out, out_size, out_len);
    return zuc_int_from_psa(ps);
}

zuc_status zuc_hash_new(zuc_alg alg, zuc_hash **out)
{
    zuc_hash *h;
    psa_status_t ps;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* Cleared first, so that every failure below leaves the caller with a
     * NULL it can safely pass to zuc_hash_free(). */
    *out = NULL;

    if (!zuc_int_ready()) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_alg_available(alg)) {
        return ZUC_ERR_UNSUPPORTED;
    }

    h = calloc(1, sizeof *h);
    if (h == NULL) {
        return ZUC_ERR_MEMORY;
    }
    h->alg  = alg;
    h->palg = zuc_int_psa_hash(alg);
    h->op   = psa_hash_operation_init();

    ps = psa_hash_setup(&h->op, h->palg);
    if (ps != PSA_SUCCESS) {
        /* A partially built context is destroyed, never returned. Handing
         * one back and trusting the caller to free it is how a failed init
         * turns into a leak or a use of half-initialised backend state. */
        psa_hash_abort(&h->op);
        zuc_secure_zero(h, sizeof *h);
        free(h);
        return zuc_int_from_psa(ps);
    }
    h->active = 1;
    *out = h;
    return ZUC_OK;
}

zuc_status zuc_hash_update(zuc_hash *hash, const uint8_t *data, size_t data_len)
{
    if (hash == NULL || (data == NULL && data_len != 0)) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!hash->active) {
        /* Finished, and not reset. Updating would silently produce a digest
         * of a different message than the caller believes. */
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (data_len == 0) {
        return ZUC_OK;
    }
    return zuc_int_from_psa(psa_hash_update(&hash->op, data, data_len));
}

zuc_status zuc_hash_finish(zuc_hash *hash,
                           uint8_t *out, size_t out_size, size_t *out_len)
{
    psa_status_t ps;

    if (hash == NULL || out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!hash->active) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (out_size < zuc_alg_size(hash->alg)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    *out_len = 0;
    ps = psa_hash_finish(&hash->op, out, out_size, out_len);
    /* The backend's operation is consumed either way, so the handle stops
     * accepting updates whether or not this succeeded. */
    hash->active = 0;
    return zuc_int_from_psa(ps);
}

zuc_status zuc_hash_reset(zuc_hash *hash)
{
    psa_status_t ps;

    if (hash == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (hash->active) {
        psa_hash_abort(&hash->op);
        hash->active = 0;
    }
    hash->op = psa_hash_operation_init();
    ps = psa_hash_setup(&hash->op, hash->palg);
    if (ps != PSA_SUCCESS) {
        psa_hash_abort(&hash->op);
        return zuc_int_from_psa(ps);
    }
    hash->active = 1;
    return ZUC_OK;
}

void zuc_hash_free(zuc_hash *hash)
{
    if (hash == NULL) {
        return;
    }
    /* Abort first: the backend owns buffered message bytes, and only it can
     * release them. Then wipe our own struct, which holds the algorithm and
     * whatever the operation object kept inline. */
    psa_hash_abort(&hash->op);
    zuc_secure_zero(hash, sizeof *hash);
    free(hash);
}

/* ------------------------------------------------------------------ *
 * HMAC
 * ------------------------------------------------------------------ */

/* The key is imported once into the backend's key store and kept for the
 * handle's lifetime, so that reset does not need the caller's key buffer
 * again -- which means this library never retains a pointer into it. */
static zuc_status import_hmac_key(zuc_alg alg, const uint8_t *key, size_t key_len,
                                  psa_algorithm_t palg, psa_key_id_t *out)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_status_t ps;

    (void) alg;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, palg);
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

    /* RFC 2104 places no lower bound on the key length, and an empty key is
     * a legitimate (if useless) HMAC. The backend rejects a zero-length
     * import, so the empty key is carried as a single zero byte, which is
     * what HMAC's own key padding would produce from it anyway. */
    if (key_len == 0) {
        static const uint8_t empty = 0;
        ps = psa_import_key(&attr, &empty, 1, out);
    } else {
        ps = psa_import_key(&attr, key, key_len, out);
    }
    psa_reset_key_attributes(&attr);
    return zuc_int_from_psa(ps);
}

zuc_status zuc_hmac_compute(zuc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t out_size, size_t *out_len)
{
    zuc_status st = check_digest_args(alg, data, data_len, out, out_size, out_len);
    psa_algorithm_t palg;
    psa_key_id_t k = 0;
    psa_status_t ps;

    if (st != ZUC_OK) {
        return st;
    }
    if (key == NULL && key_len != 0) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out_len = 0;

    palg = PSA_ALG_HMAC(zuc_int_psa_hash(alg));
    st = import_hmac_key(alg, key, key_len, palg, &k);
    if (st != ZUC_OK) {
        return st;
    }
    ps = psa_mac_compute(k, palg,
                         data == NULL ? (const uint8_t *) "" : data, data_len,
                         out, out_size, out_len);
    /* Destroyed on both paths: the key store is global, and a key left
     * behind by a failed MAC is key material living past its use. */
    psa_destroy_key(k);
    return zuc_int_from_psa(ps);
}

zuc_status zuc_hmac_new(zuc_alg alg, const uint8_t *key, size_t key_len,
                        zuc_hmac **out)
{
    zuc_hmac *h;
    zuc_status st;
    psa_status_t ps;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    if (!zuc_int_ready()) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (key == NULL && key_len != 0) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_alg_available(alg)) {
        return ZUC_ERR_UNSUPPORTED;
    }

    h = calloc(1, sizeof *h);
    if (h == NULL) {
        return ZUC_ERR_MEMORY;
    }
    h->alg  = alg;
    h->palg = PSA_ALG_HMAC(zuc_int_psa_hash(alg));
    h->op   = psa_mac_operation_init();

    st = import_hmac_key(alg, key, key_len, h->palg, &h->key);
    if (st != ZUC_OK) {
        zuc_secure_zero(h, sizeof *h);
        free(h);
        return st;
    }

    ps = psa_mac_sign_setup(&h->op, h->key, h->palg);
    if (ps != PSA_SUCCESS) {
        psa_mac_abort(&h->op);
        psa_destroy_key(h->key);
        zuc_secure_zero(h, sizeof *h);
        free(h);
        return zuc_int_from_psa(ps);
    }
    h->active = 1;
    *out = h;
    return ZUC_OK;
}

zuc_status zuc_hmac_update(zuc_hmac *hmac, const uint8_t *data, size_t data_len)
{
    if (hmac == NULL || (data == NULL && data_len != 0)) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!hmac->active) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (data_len == 0) {
        return ZUC_OK;
    }
    return zuc_int_from_psa(psa_mac_update(&hmac->op, data, data_len));
}

zuc_status zuc_hmac_finish(zuc_hmac *hmac,
                           uint8_t *out, size_t out_size, size_t *out_len)
{
    psa_status_t ps;

    if (hmac == NULL || out == NULL || out_len == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!hmac->active) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (out_size < zuc_alg_size(hmac->alg)) {
        return ZUC_ERR_BAD_LENGTH;
    }
    *out_len = 0;
    ps = psa_mac_sign_finish(&hmac->op, out, out_size, out_len);
    hmac->active = 0;
    return zuc_int_from_psa(ps);
}

zuc_status zuc_hmac_reset(zuc_hmac *hmac)
{
    psa_status_t ps;

    if (hmac == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (hmac->active) {
        psa_mac_abort(&hmac->op);
        hmac->active = 0;
    }
    hmac->op = psa_mac_operation_init();
    ps = psa_mac_sign_setup(&hmac->op, hmac->key, hmac->palg);
    if (ps != PSA_SUCCESS) {
        psa_mac_abort(&hmac->op);
        return zuc_int_from_psa(ps);
    }
    hmac->active = 1;
    return ZUC_OK;
}

void zuc_hmac_free(zuc_hmac *hmac)
{
    if (hmac == NULL) {
        return;
    }
    psa_mac_abort(&hmac->op);
    /* The key is in the backend's store, not in this struct, so wiping the
     * struct is not enough -- the destroy is what erases the key material. */
    psa_destroy_key(hmac->key);
    zuc_secure_zero(hmac, sizeof *hmac);
    free(hmac);
}
