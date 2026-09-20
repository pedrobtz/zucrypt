/* zucrypt: the R-facing translation unit.
 *
 * The only file in src/ that includes an R header, and it stays that way:
 * src/zuc_*.c and src/vendor/ become inst/lib/libzucrypt.a in Stage 2, and a
 * consumer links that archive into its own shared object, where R glue would
 * be both useless and a duplicate symbol (design.md section 8.3).
 *
 * Stage 1 has one entry point, backing the placeholder crypt_info(). The six
 * crypt_* functions and their conditions arrive in Stage 3.
 */

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

#include "zuc_internal.h"

/* Returns a character vector of the backend version and the compiled-in
 * random source. No allocation happens between the PROTECT and the return,
 * and nothing below this function can raise an R error. */
static SEXP zucrypt_backend_info(void)
{
    const char *names[] = {"backend_version", "random_backend"};
    SEXP out = PROTECT(allocVector(STRSXP, 2));
    SEXP nms = PROTECT(allocVector(STRSXP, 2));

    SET_STRING_ELT(out, 0, mkChar(zuc_int_backend_version()));
    SET_STRING_ELT(out, 1, mkChar(zuc_int_random_backend()));
    SET_STRING_ELT(nms, 0, mkChar(names[0]));
    SET_STRING_ELT(nms, 1, mkChar(names[1]));
    setAttrib(out, R_NamesSymbol, nms);

    UNPROTECT(2);
    return out;
}

static const R_CallMethodDef call_methods[] = {
    {"zucrypt_backend_info", (DL_FUNC) &zucrypt_backend_info, 0},
    {NULL, NULL, 0}
};

void attribute_visible R_init_zucrypt(DllInfo *dll)
{
    int status;

    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);

    /* Bringing the backend up at load time rather than lazily keeps the
     * failure at library(zucrypt), where it can be read, instead of inside
     * the first hash. Stage 2 replaces this with a reference-counted
     * zuc_init()/zuc_shutdown() pair that an archive consumer drives itself. */
    status = zuc_int_backend_init();
    if (status != 0) {
        Rf_error("zucrypt: the cryptographic backend failed to start (status %d)",
                 status);
    }
}
