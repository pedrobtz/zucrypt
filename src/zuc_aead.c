/* zucrypt: authenticated encryption, one-shot (design.md section 6).
 *
 * RFC 5116's contract: encryption returns the ciphertext and the tag;
 * decryption checks the tag over the nonce, associated data and ciphertext,
 * and on any failure returns no plaintext. "No plaintext" is enforced here,
 * not assumed of the backend: every failure path zeroes the caller's whole
 * output buffer before returning.
 *
 * The backend's multipart AEAD interface is used rather than its one-shot
 * psa_aead_encrypt(), because the one-shot form writes ciphertext and tag
 * into one buffer and reads them from one buffer. Keeping them apart there
 * would mean a heap copy of the whole message on every call. Multipart takes
 * them separately and allocates nothing.
 *
 * Multipart decryption writes plaintext from psa_aead_update() before
 * psa_aead_verify() has checked the tag. That plaintext is in the caller's
 * buffer for the length of this function only: on a mismatch it is zeroed
 * before ZUC_ERR_AUTH is returned, and this library is main-thread only
 * (zucrypt.h), so nothing else can read it in between.
 *
 * Each call imports the key, uses it once and destroys it. There is no
 * handle: a nonce must never repeat under one key, and an interface that
 * keeps a key alive across messages invites the caller to forget that.
 */

#include <string.h>

#include "zuc_internal.h"

static psa_algorithm_t psa_aead_alg(zuc_alg alg)
{
#if defined(PSA_WANT_ALG_GCM)
    if (alg == ZUC_ALG_AES_GCM) {
        return PSA_ALG_GCM;
    }
#endif
    (void) alg;
    return 0;
}

/* Everything both directions check before touching the backend. */
static zuc_status check_aead_args(int encrypt, zuc_alg alg,
                                  const uint8_t *key, size_t key_len,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *in, size_t len,
                                  const uint8_t *out,
                                  const uint8_t *tag, size_t tag_len)
{
    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (key == NULL || nonce == NULL || tag == NULL ||
        (aad == NULL && aad_len != 0) ||
        ((in == NULL || out == NULL) && len != 0)) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* Overlap before every length check (#138): a tag of the wrong length
     * on decryption is ZUC_ERR_AUTH, which zeroes the output, and an output
     * overlapping the input would then wipe the caller's ciphertext. The
     * buffers written are the output and, on encryption, the tag; each may
     * share no byte with any other buffer, except that the output may be
     * the input exactly (zuc_int_overlaps()). Two buffers that are only read
     * may share bytes. */
    {
        const uint8_t *rd[5];
        size_t rn[5], i, nr = 0;

        rd[nr] = key;   rn[nr++] = key_len;
        rd[nr] = nonce; rn[nr++] = nonce_len;
        rd[nr] = aad;   rn[nr++] = aad_len;
        if (!encrypt) {
            rd[nr] = tag; rn[nr++] = tag_len;
        }
        for (i = 0; i < nr; i++) {
            if (zuc_int_spans_overlap(out, len, rd[i], rn[i]) ||
                (encrypt && zuc_int_spans_overlap(tag, tag_len, rd[i], rn[i]))) {
                return ZUC_ERR_OVERLAP;
            }
        }
        if (len != 0 && zuc_int_overlaps(in, out, len)) {
            return ZUC_ERR_OVERLAP;
        }
        if (encrypt && (zuc_int_spans_overlap(tag, tag_len, in, len) ||
                        zuc_int_spans_overlap(tag, tag_len, out, len))) {
            return ZUC_ERR_OVERLAP;
        }
    }
    if (psa_aead_alg(alg) == 0) {
        return ZUC_ERR_UNSUPPORTED;
    }
    if ((key_len != ZUC_AES_KEY_SIZE_128 &&
         key_len != ZUC_AES_KEY_SIZE_192 &&
         key_len != ZUC_AES_KEY_SIZE_256) ||
        nonce_len != ZUC_GCM_NONCE_SIZE) {
        return ZUC_ERR_BAD_LENGTH;
    }
    /* A received tag of another length cannot match: a truncated tag is an
     * authentication failure, not a usage error (design.md section 12). A
     * tag to be written must be the full size. */
    if (tag_len != ZUC_GCM_TAG_SIZE) {
        return encrypt ? ZUC_ERR_BAD_LENGTH : ZUC_ERR_AUTH;
    }
    return ZUC_OK;
}

static zuc_status import_aead_key(const uint8_t *key, size_t key_len,
                                  psa_algorithm_t palg, psa_key_id_t *out)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_status_t ps;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, palg);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    ps = psa_import_key(&attr, key, key_len, out);
    psa_reset_key_attributes(&attr);
    return zuc_int_from_psa(ps);
}

/* One pass. `encrypt` selects the direction; for decryption `tag` is read,
 * for encryption it is written. */
static zuc_status aead_run(int encrypt, zuc_alg alg,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t len, uint8_t *out,
                           uint8_t *tag, size_t tag_len)
{
    const psa_algorithm_t palg = psa_aead_alg(alg);
    psa_aead_operation_t op = psa_aead_operation_init();
    psa_key_id_t k = 0;
    psa_status_t ps;
    zuc_status st;
    size_t produced = 0, finished = 0, tag_out = 0;

    st = import_aead_key(key, key_len, palg, &k);
    if (st != ZUC_OK) {
        return st;
    }
    ps = encrypt ? psa_aead_encrypt_setup(&op, k, palg)
                 : psa_aead_decrypt_setup(&op, k, palg);
    if (ps == PSA_SUCCESS) {
        ps = psa_aead_set_nonce(&op, nonce, nonce_len);
    }
    if (ps == PSA_SUCCESS && aad_len != 0) {
        ps = psa_aead_update_ad(&op, aad, aad_len);
    }
    if (ps == PSA_SUCCESS && len != 0) {
        ps = psa_aead_update(&op, in, len, out, len, &produced);
    }
    if (ps == PSA_SUCCESS) {
        /* `out` may be NULL when `len` is 0, and NULL + 0 is undefined in
         * C, which UBSan reports; so the offset is taken only when there is
         * a buffer to take it in. */
        uint8_t *rest = len != 0 ? out + produced : out;
        if (encrypt) {
            ps = psa_aead_finish(&op, rest, len - produced,
                                 &finished, tag, tag_len, &tag_out);
        } else {
            ps = psa_aead_verify(&op, rest, len - produced,
                                 &finished, tag, tag_len);
        }
    }
    if (ps != PSA_SUCCESS) {
        psa_aead_abort(&op);
        psa_destroy_key(k);
        /* A tag mismatch is the one backend status with a meaning of its
         * own here; every other failure keeps its general mapping. */
        return ps == PSA_ERROR_INVALID_SIGNATURE ? ZUC_ERR_AUTH
                                                 : zuc_int_from_psa(ps);
    }
    psa_destroy_key(k);
    /* GCM is a stream mode: update() emits every byte and finish() none.
     * If that ever changes the output is partly stale -- a wrong answer, not
     * an error -- so it is checked rather than trusted. */
    if (produced + finished != len || (encrypt && tag_out != tag_len)) {
        return ZUC_ERR_INTERNAL;
    }
    return ZUC_OK;
}

zuc_status zuc_aead_encrypt(zuc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t len,
                            uint8_t *ciphertext,
                            uint8_t *tag, size_t tag_len)
{
    zuc_status st = check_aead_args(1, alg, key, key_len, nonce, nonce_len,
                                    aad, aad_len, plaintext, len, ciphertext,
                                    tag, tag_len);
    if (st != ZUC_OK) {
        /* An argument error writes nothing: with in-place buffers the output
         * is also the caller's input. */
        return st;
    }
    st = aead_run(1, alg, key, key_len, nonce, nonce_len, aad, aad_len,
                  plaintext, len, ciphertext, tag, tag_len);
    if (st != ZUC_OK) {
        /* Nothing half-made leaves: neither a partial ciphertext nor a tag. */
        if (len != 0) {
            zuc_secure_zero(ciphertext, len);
        }
        zuc_secure_zero(tag, tag_len);
    }
    return st;
}

zuc_status zuc_aead_decrypt(zuc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t len,
                            const uint8_t *tag, size_t tag_len,
                            uint8_t *plaintext)
{
    zuc_status st = check_aead_args(0, alg, key, key_len, nonce, nonce_len,
                                    aad, aad_len, ciphertext, len, plaintext,
                                    tag, tag_len);
    if (st == ZUC_ERR_AUTH && len != 0) {
        /* A tag of the wrong length is refused here, before the backend,
         * but it is an authentication failure like any other, and every
         * ZUC_ERR_AUTH leaves the output zeroed: a caller may rely on that
         * whichever check refused it. Every NULL and overlap check runs
         * before the tag length is looked at, so the output written here is
         * the caller's own and overlaps nothing it reads. */
        zuc_secure_zero(plaintext, len);
    }
    if (st != ZUC_OK) {
        return st;
    }
    st = aead_run(0, alg, key, key_len, nonce, nonce_len, aad, aad_len,
                  ciphertext, len, plaintext, (uint8_t *) tag, tag_len);
    if (st != ZUC_OK && len != 0) {
        /* The contract: no unauthenticated plaintext, ever. */
        zuc_secure_zero(plaintext, len);
    }
    return st;
}
