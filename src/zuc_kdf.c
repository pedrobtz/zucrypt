/* zucrypt: key derivation (design.md section 6, tranche 2).
 *
 * PBKDF2 with HMAC as the PRF, RFC 8018 section 5.2, through the backend's
 * key-derivation interface. The password goes in as bytes, not as an
 * imported key, which is what lets the derived output be read back as bytes
 * rather than only as another key.
 *
 * There is no handle and no incremental form: a derivation is one call.
 */

#include "zuc_internal.h"

zuc_status zuc_pbkdf2_hmac(zuc_alg hash,
                           const uint8_t *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *out, size_t out_len)
{
    static const uint8_t none = 0;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_algorithm_t halg;
    psa_status_t ps;

    if (!zuc_int_ready()) {
        return ZUC_ERR_NOT_READY;
    }
    if (out == NULL ||
        (password == NULL && password_len != 0) ||
        (salt == NULL && salt_len != 0) ||
        iterations == 0) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (out_len == 0) {
        return ZUC_ERR_BAD_LENGTH;
    }
    /* An empty password or salt is legal in RFC 8018. The backend is given
     * a real pointer for it either way, never NULL. */
    if (password_len == 0) {
        password = &none;
    }
    if (salt_len == 0) {
        salt = &none;
    }
#if defined(PSA_WANT_ALG_PBKDF2_HMAC)
    halg = zuc_int_digest_available(hash) ? zuc_int_psa_hash(hash) : 0;
#else
    halg = 0;
#endif
    if (halg == 0) {
        return ZUC_ERR_UNSUPPORTED;
    }

    ps = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(halg));
    if (ps == PSA_SUCCESS) {
        ps = psa_key_derivation_input_integer(
            &op, PSA_KEY_DERIVATION_INPUT_COST, iterations);
    }
    if (ps == PSA_SUCCESS) {
        ps = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
    }
    if (ps == PSA_SUCCESS) {
        ps = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_PASSWORD, password, password_len);
    }
    if (ps == PSA_SUCCESS) {
        ps = psa_key_derivation_output_bytes(&op, out, out_len);
    }
    psa_key_derivation_abort(&op);
    if (ps != PSA_SUCCESS) {
        zuc_secure_zero(out, out_len);
        return zuc_int_from_psa(ps);
    }
    return ZUC_OK;
}
