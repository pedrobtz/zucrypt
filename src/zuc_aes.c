/* zucrypt: AES-CBC, without padding and without authentication.
 *
 * The chaining state is explicit and owned by the caller's handle, which is
 * the design point (design.md section 8.1): a document format that restarts
 * CBC at every segment boundary -- which is what the Office Agile profiles
 * do -- cannot be driven by an API that hides the IV inside a streaming
 * operation.
 *
 * Each call therefore stands alone: it seeds a fresh backend operation from
 * the stored chaining value, processes the whole buffer, and advances the
 * value to the last ciphertext block. That this is exactly equivalent to one
 * long streaming operation is a property of CBC, and it is tested rather than
 * assumed -- two half-length calls must equal one full call.
 *
 * The alternative, holding a live backend operation open across calls, would
 * make the handle's validity depend on the order of the caller's calls and
 * would still need this state exposed. It buys one setup per call, and a
 * caller passing whole segments makes that immeasurable.
 *
 * ECB lived here too until design revision 3 (#29): its one consumer was
 * Office Standard encryption, which zuxlsx put out of scope. Each handle
 * used to import the key twice -- a PSA key policy names one algorithm --
 * which is half of why the static key store ran out at 16 handles (#30).
 */

#include <stdlib.h>
#include <string.h>

#include "zuc_internal.h"

struct zuc_aes {
    psa_key_id_t key;
    uint8_t      chain[ZUC_AES_BLOCK_SIZE];
};

/* One volatile key per handle, in the dynamic key store
 * (MBEDTLS_PSA_KEY_STORE_DYNAMIC), so the number of live handles is bounded
 * by memory alone. The key is not reachable from outside this file. */
static zuc_status import_aes_key(const uint8_t *key, size_t key_len,
                                 psa_algorithm_t alg, psa_key_id_t *out)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_status_t ps;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    ps = psa_import_key(&attr, key, key_len, out);
    psa_reset_key_attributes(&attr);
    return zuc_int_from_psa(ps);
}

zuc_status zuc_aes_new(const uint8_t *key, size_t key_len, zuc_aes **out)
{
    zuc_aes *aes;
    zuc_status st;

    if (out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (key == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* Checked here rather than left to the backend so that the caller gets
     * ZUC_ERR_BAD_LENGTH, which names the problem, instead of a generic
     * backend refusal. */
    if (key_len != ZUC_AES_KEY_SIZE_128 &&
        key_len != ZUC_AES_KEY_SIZE_192 &&
        key_len != ZUC_AES_KEY_SIZE_256) {
        return ZUC_ERR_BAD_LENGTH;
    }

    aes = calloc(1, sizeof *aes);
    if (aes == NULL) {
        return ZUC_ERR_MEMORY;
    }

    st = import_aes_key(key, key_len, PSA_ALG_CBC_NO_PADDING, &aes->key);
    if (st != ZUC_OK) {
        zuc_secure_zero(aes, sizeof *aes);
        free(aes);
        return st;
    }
    *out = aes;
    return ZUC_OK;
}

void zuc_aes_free(zuc_aes *aes)
{
    if (aes == NULL) {
        return;
    }
    psa_destroy_key(aes->key);
    /* The chaining state is not secret in the way a key is, but it is
     * derived from the data, so it goes too. */
    zuc_secure_zero(aes, sizeof *aes);
    free(aes);
}

zuc_status zuc_aes_cbc_set_state(zuc_aes *aes, const uint8_t *state)
{
    if (aes == NULL || state == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    memcpy(aes->chain, state, ZUC_AES_BLOCK_SIZE);
    return ZUC_OK;
}

zuc_status zuc_aes_cbc_get_state(const zuc_aes *aes, uint8_t *state)
{
    if (aes == NULL || state == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    memcpy(state, aes->chain, ZUC_AES_BLOCK_SIZE);
    return ZUC_OK;
}

/* Everything both directions check before touching the backend. */
static zuc_status check_block_args(const zuc_aes *aes, const uint8_t *in,
                                   size_t len, const uint8_t *out)
{
    if (aes == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (len == 0) {
        return ZUC_OK;
    }
    if (in == NULL || out == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* No padding is ever added, so a partial block has no defined meaning
     * here and is refused rather than rounded, truncated or silently
     * padded. */
    if (len % ZUC_AES_BLOCK_SIZE != 0) {
        return ZUC_ERR_BAD_LENGTH;
    }
    if (zuc_int_overlaps(in, out, len)) {
        return ZUC_ERR_OVERLAP;
    }
    return ZUC_OK;
}

/* One CBC pass from an explicit IV. */
static zuc_status cipher_run(psa_key_id_t key, int encrypt, const uint8_t *iv,
                             const uint8_t *in, size_t len, uint8_t *out)
{
    const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t ps;
    size_t produced = 0, finished = 0;

    ps = encrypt ? psa_cipher_encrypt_setup(&op, key, alg)
                 : psa_cipher_decrypt_setup(&op, key, alg);
    if (ps != PSA_SUCCESS) {
        goto fail;
    }
    ps = psa_cipher_set_iv(&op, iv, ZUC_AES_BLOCK_SIZE);
    if (ps != PSA_SUCCESS) {
        goto fail;
    }
    ps = psa_cipher_update(&op, in, len, out, len, &produced);
    if (ps != PSA_SUCCESS) {
        goto fail;
    }
    ps = psa_cipher_finish(&op, out + produced, len - produced, &finished);
    if (ps != PSA_SUCCESS) {
        goto fail;
    }
    /* With no padding and a whole number of blocks the backend emits
     * everything from update() and nothing from finish(). If that ever
     * stops being true the output buffer is partly stale, which is a wrong
     * answer rather than an error -- so it is checked, not trusted. */
    if (produced + finished != len) {
        psa_cipher_abort(&op);
        return ZUC_ERR_INTERNAL;
    }
    return ZUC_OK;

fail:
    psa_cipher_abort(&op);
    return zuc_int_from_psa(ps);
}

zuc_status zuc_aes_cbc_encrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out)
{
    zuc_status st = check_block_args(aes, in, len, out);

    if (st != ZUC_OK || len == 0) {
        return st;
    }
    st = cipher_run(aes->key, 1, aes->chain, in, len, out);
    if (st != ZUC_OK) {
        return st;
    }
    /* The chaining value for whatever comes next is the last ciphertext
     * block, which on this path is in the output. */
    memcpy(aes->chain, out + len - ZUC_AES_BLOCK_SIZE, ZUC_AES_BLOCK_SIZE);
    return ZUC_OK;
}

zuc_status zuc_aes_cbc_decrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out)
{
    zuc_status st = check_block_args(aes, in, len, out);
    uint8_t next[ZUC_AES_BLOCK_SIZE];

    if (st != ZUC_OK || len == 0) {
        return st;
    }
    /* Saved before the pass, not after: decrypting in place overwrites the
     * input, and the next chaining value is the last *ciphertext* block. */
    memcpy(next, in + len - ZUC_AES_BLOCK_SIZE, ZUC_AES_BLOCK_SIZE);

    st = cipher_run(aes->key, 0, aes->chain, in, len, out);
    if (st != ZUC_OK) {
        zuc_secure_zero(next, sizeof next);
        return st;
    }
    memcpy(aes->chain, next, ZUC_AES_BLOCK_SIZE);
    zuc_secure_zero(next, sizeof next);
    return ZUC_OK;
}
