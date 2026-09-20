/* zucrypt: backend lifetime and identification.
 *
 * The reference count lives here rather than in the R layer because the
 * archive consumer has no R layer: it links libzucrypt.a into its own shared
 * object and calls zuc_init() itself. Both consumers therefore go through the
 * same counter, and neither can tear the backend down while the other holds a
 * context.
 */

#include <stddef.h>

#include <psa/crypto.h>

#include "zuc_internal.h"

/* Not atomic, and it does not need to be: zuc_init() and zuc_shutdown() are
 * main-thread only in this version (see the header). Making it atomic would
 * suggest a thread-safety guarantee the rest of the library does not make. */
static unsigned int zuc_refcount = 0;

int zuc_int_ready(void)
{
    return zuc_refcount > 0;
}

zuc_status zuc_init(void)
{
    psa_status_t status;

    if (zuc_refcount > 0) {
        /* A wrap would let a later shutdown tear the backend down under a
         * live consumer, which is exactly the failure the count exists to
         * prevent. Refusing is the safe direction: the caller gets no new
         * reference and knows it. */
        if (zuc_refcount == 0xFFFFFFFFu) {
            return ZUC_ERR_INTERNAL;
        }
        zuc_refcount++;
        return ZUC_OK;
    }

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return zuc_int_from_psa(status);
    }
    zuc_refcount = 1;
    return ZUC_OK;
}

zuc_status zuc_shutdown(void)
{
    if (zuc_refcount == 0) {
        /* More shutdowns than inits. Reporting it rather than ignoring it:
         * the imbalance is a bug in the caller, and the next zuc_init()
         * would otherwise appear to work while the count is wrong. */
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    if (--zuc_refcount == 0) {
        mbedtls_psa_crypto_free();
    }
    return ZUC_OK;
}

zuc_status zuc_get_info(zuc_info *info)
{
    if (info == NULL) {
        return ZUC_ERR_INVALID_ARGUMENT;
    }
    /* The caller's struct_size, not ours. A consumer built against an older
     * header has a shorter struct, and writing past its end would be a stack
     * smash in its binary. Anything at least as long as the prefix we
     * dereference is fine; shorter is refused. */
    if (info->struct_size < ZUC_INFO_REQUIRED_SIZE) {
        return ZUC_ERR_ABI;
    }

    info->abi_version     = ZUCRYPT_ABI_VERSION;
    info->backend_name    = "TF-PSA-Crypto";
    info->backend_version = TF_PSA_CRYPTO_VERSION_STRING;
    info->random_backend  = zuc_int_random_backend();
    return ZUC_OK;
}
