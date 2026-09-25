/* zucrypt: status codes and algorithm identification.
 *
 * No backend call happens here, deliberately: a caller reporting an error
 * must not need a working library to do it, and zuc_status_string() is the
 * function most likely to be called when something has already gone wrong.
 */

#include <string.h>

#include "zuc_internal.h"

const char *zuc_status_string(zuc_status status)
{
    switch (status) {
    case ZUC_OK:                   return "success";
    case ZUC_ERR_INVALID_ARGUMENT: return "invalid argument";
    case ZUC_ERR_UNSUPPORTED:      return "algorithm or operation not supported by this build";
    case ZUC_ERR_BAD_LENGTH:       return "incorrect key, initialisation vector or buffer length";
    case ZUC_ERR_OVERLAP:          return "input and output buffers overlap";
    case ZUC_ERR_MEMORY:           return "memory allocation failed";
    case ZUC_ERR_BACKEND:          return "the cryptographic backend reported a failure";
    case ZUC_ERR_ABI:              return "ABI version or structure size mismatch";
    case ZUC_ERR_INTERNAL:         return "internal error";
    case ZUC_ERR_NOT_READY:        return "the library is not initialised; call zuc_init() first";
    }
    /* No default label above, so a new enumerator is a compiler warning
     * here rather than a silent fall-through. This line is for a value that
     * is not an enumerator at all, which a C caller can pass. */
    return "unknown status";
}

const char *zuc_status_name(zuc_status status)
{
    switch (status) {
    case ZUC_OK:                   return "ZUC_OK";
    case ZUC_ERR_INVALID_ARGUMENT: return "ZUC_ERR_INVALID_ARGUMENT";
    case ZUC_ERR_UNSUPPORTED:      return "ZUC_ERR_UNSUPPORTED";
    case ZUC_ERR_BAD_LENGTH:       return "ZUC_ERR_BAD_LENGTH";
    case ZUC_ERR_OVERLAP:          return "ZUC_ERR_OVERLAP";
    case ZUC_ERR_MEMORY:           return "ZUC_ERR_MEMORY";
    case ZUC_ERR_BACKEND:          return "ZUC_ERR_BACKEND";
    case ZUC_ERR_ABI:              return "ZUC_ERR_ABI";
    case ZUC_ERR_INTERNAL:         return "ZUC_ERR_INTERNAL";
    case ZUC_ERR_NOT_READY:        return "ZUC_ERR_NOT_READY";
    }
    return "ZUC_ERR_UNKNOWN";
}

zuc_status zuc_int_from_psa(psa_status_t status)
{
    switch (status) {
    case PSA_SUCCESS:                     return ZUC_OK;
    case PSA_ERROR_NOT_SUPPORTED:         return ZUC_ERR_UNSUPPORTED;
    case PSA_ERROR_INVALID_ARGUMENT:      return ZUC_ERR_INVALID_ARGUMENT;
    case PSA_ERROR_BUFFER_TOO_SMALL:      return ZUC_ERR_BAD_LENGTH;
    case PSA_ERROR_INSUFFICIENT_MEMORY:   return ZUC_ERR_MEMORY;
    case PSA_ERROR_BAD_STATE:             return ZUC_ERR_INTERNAL;
    default:                              return ZUC_ERR_BACKEND;
    }
}

psa_algorithm_t zuc_int_psa_hash(zuc_alg alg)
{
    switch (alg) {
    case ZUC_ALG_SHA1:   return PSA_ALG_SHA_1;
    case ZUC_ALG_SHA256: return PSA_ALG_SHA_256;
    case ZUC_ALG_SHA384: return PSA_ALG_SHA_384;
    case ZUC_ALG_SHA512: return PSA_ALG_SHA_512;
    case ZUC_ALG_NONE:   return 0;
    }
    return 0;
}

const char *zuc_alg_name(zuc_alg alg)
{
    switch (alg) {
    case ZUC_ALG_SHA1:   return "sha1";
    case ZUC_ALG_SHA256: return "sha256";
    case ZUC_ALG_SHA384: return "sha384";
    case ZUC_ALG_SHA512: return "sha512";
    case ZUC_ALG_NONE:   return NULL;
    }
    return NULL;
}

zuc_alg zuc_alg_by_name(const char *name)
{
    /* Exact match only. No prefix matching and no aliases: "sha-256" and
     * "SHA256" are not this library's spelling, and quietly accepting them
     * would make the accepted set impossible to document. */
    static const zuc_alg all[] = {
        ZUC_ALG_SHA1, ZUC_ALG_SHA256, ZUC_ALG_SHA384, ZUC_ALG_SHA512
    };
    size_t i;

    if (name == NULL) {
        return ZUC_ALG_NONE;
    }
    for (i = 0; i < sizeof all / sizeof all[0]; i++) {
        const char *candidate = zuc_alg_name(all[i]);
        if (candidate != NULL && strcmp(candidate, name) == 0) {
            return all[i];
        }
    }
    return ZUC_ALG_NONE;
}

size_t zuc_alg_size(zuc_alg alg)
{
    switch (alg) {
    case ZUC_ALG_SHA1:   return 20;
    case ZUC_ALG_SHA256: return 32;
    case ZUC_ALG_SHA384: return 48;
    case ZUC_ALG_SHA512: return 64;
    case ZUC_ALG_NONE:   return 0;
    }
    return 0;
}

int zuc_alg_available(zuc_alg alg)
{
    /* Answered from the build configuration rather than by probing the
     * backend, so that it is also answerable before zuc_init(). The
     * identifiers are permanent: an algorithm compiled out keeps its number
     * and reports 0 here, which is the whole reason the enum has fixed
     * values. tests/testthat/test-kat.R checks the two against each other --
     * anything reporting available must produce the published vector. */
    switch (alg) {
#if defined(PSA_WANT_ALG_SHA_1)
    case ZUC_ALG_SHA1:   return 1;
#endif
#if defined(PSA_WANT_ALG_SHA_256)
    case ZUC_ALG_SHA256: return 1;
#endif
#if defined(PSA_WANT_ALG_SHA_384)
    case ZUC_ALG_SHA384: return 1;
#endif
#if defined(PSA_WANT_ALG_SHA_512)
    case ZUC_ALG_SHA512: return 1;
#endif
    default: return 0;
    }
}
