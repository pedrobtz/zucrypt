/* zucrypt: backend bring-up and identification.
 *
 * The only file in Stage 1 that includes an upstream header, which is the
 * boundary design.md section 8 asks for: everything above this line speaks
 * zuc_*, and no PSA type or macro reaches an installed header or an R source.
 */

#include <psa/crypto.h>

#include "zuc_internal.h"

int zuc_int_backend_init(void)
{
    psa_status_t status = psa_crypto_init();

    return status == PSA_SUCCESS ? 0 : (int) status;
}

const char *zuc_int_backend_version(void)
{
    /* TF_PSA_CRYPTO_VERSION_STRING comes from tf-psa-crypto/build_info.h,
     * which psa/crypto.h includes; the standalone version.h is not vendored,
     * because nothing in the trim includes it. This is the version of the
     * headers these objects were compiled against, so a vendored tree that
     * disagrees with the built library cannot hide behind a manifest. */
    return TF_PSA_CRYPTO_VERSION_STRING;
}
