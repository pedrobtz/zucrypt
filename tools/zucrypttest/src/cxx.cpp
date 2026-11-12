/* The table, consumed from C++ (#113).
 *
 * zucrypt-r.h resolves the table through a union in C and through
 * reinterpret_cast in C++, where reading a union through another member is
 * undefined. This translation unit is the C++ branch: it includes the
 * header from C++, resolves the table and calls through it, so the branch
 * is compiled and run on every OS consumer.yaml reaches. */
#include <cstring>

#include <R.h>
#include <Rinternals.h>
#include <zucrypt-r.h>

extern "C" SEXP zucrypttest_cxx_sha256(SEXP data)
{
    const zucrypt_api_v1 *api = zucrypt_api();
    uint8_t out[ZUC_MAX_DIGEST_SIZE];
    size_t len = 0;
    SEXP res;

    if (api == NULL || TYPEOF(data) != RAWSXP) {
        return R_NilValue;
    }
    if (api->hash_compute(ZUC_ALG_SHA256, RAW(data), (size_t) XLENGTH(data),
                          out, sizeof out, &len) != ZUC_OK) {
        return R_NilValue;
    }
    res = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) len));
    std::memcpy(RAW(res), out, len);
    UNPROTECT(1);
    return res;
}
