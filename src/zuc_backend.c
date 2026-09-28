/* zucrypt: backend lifetime and identification.
 *
 * The reference count lives here rather than in the R layer because the
 * archive consumer has no R layer: it links libzucrypt.a into its own shared
 * object and calls zuc_init() itself. That consumer's copy of the archive is
 * a separate backend with its own counter and its own key store; what is
 * shared is the counter within one copy -- in zucrypt.so, the R functions
 * and every table consumer -- so none of those can tear the backend down
 * while another holds a context.
 */

/* mbedtls_aes_get_implementation() is one of upstream's private
 * identifiers, declared only under this macro -- the way upstream's own
 * sources see it. It is the one way to ask which AES implementation runs
 * (#51). This is the adapter, pinned to one release and verified by
 * tools/vendor/verify, so reaching one private declaration here is a
 * contained dependency: a release bump that renamed it would fail to
 * compile, not misbehave. Set before any backend header. */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include <stddef.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/private/aes.h>

#include "zuc_internal.h"

/* Not atomic, and it does not need to be: zuc_init() and zuc_shutdown() are
 * main-thread only in this version (see the header). Making it atomic would
 * suggest a thread-safety guarantee the rest of the library does not make. */
static unsigned int zuc_refcount = 0;

/* See zuc_live.h. Same threading argument as the refcount above. */
static long zuc_live = 0;

void zuc_int_live_add(int delta)
{
    zuc_live += delta;
}

long zuc_int_live_contexts(void)
{
    return zuc_live;
}

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

/* Which AES implementation this machine actually runs, asked of the backend
 * at run time: AES-NI and the Arm Cryptography Extension are compiled in
 * (src/zuc_crypto_config.h) and used only where the CPU has them, with the
 * table-based software path otherwise. The software path is the one
 * upstream's SECURITY.md warns leaks key material through cache timing, so
 * which one is in use is worth being able to see (#51). */
static const char *zuc_int_aes_implementation(void)
{
    switch (mbedtls_aes_get_implementation()) {
    case MBEDTLS_AES_IMP_AESNI_ASM:
    case MBEDTLS_AES_IMP_AESNI_INTRINSICS:
        return "aesni";
    case MBEDTLS_AES_IMP_AESCE:
        return "aesce";
    case MBEDTLS_AES_IMP_SOFTWARE:
        return "software";
    case MBEDTLS_AES_IMP_UNKNOWN:
        break;
    }
    return "unknown";
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

    /* Appended after the required prefix, so written only when the caller's
     * struct is long enough to have it. */
    if (info->struct_size >= offsetof(zuc_info, hardware_acceleration) +
                             sizeof info->hardware_acceleration) {
        const char *imp = zuc_int_aes_implementation();
        info->hardware_acceleration =
            strcmp(imp, "aesni") == 0 || strcmp(imp, "aesce") == 0;
    }
    if (info->struct_size >= offsetof(zuc_info, aes_implementation) +
                             sizeof info->aes_implementation) {
        info->aes_implementation = zuc_int_aes_implementation();
    }
    return ZUC_OK;
}
