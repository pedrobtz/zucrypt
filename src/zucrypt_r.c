/* zucrypt: the R-facing translation unit.
 *
 * One of the four zucrypt_*.c files that include an R header -- with
 * zucrypt_crypt.c, zucrypt_api.c and zucrypt_test.c -- none of which goes
 * into libzucrypt.a. A consumer links that archive into its own shared
 * object, where R glue would be a duplicate symbol and could not work anyway.
 * tools/check-layering.sh enforces the split.
 *
 * What is here: package registration, what crypt_info() reads, and the
 * status-code table the R condition mapping is keyed on.
 */

#include <stdio.h>
#include <stdlib.h>

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

#include "zucrypt.h"

/* Declared here rather than in a header: nothing else calls them, and the
 * test harness has its own registration table. */
SEXP zucrypt_backend_info(void);
SEXP zucrypt_status_codes(void);
void R_init_zucrypt(DllInfo *dll);

/* Defined in zucrypt_test.c; registered below so the harness ships in every
 * build, the way zukomp keeps zu_test_stream() permanently compiled. A test
 * entry point that exists only in a debug build tests a binary nobody runs. */
extern const R_CallMethodDef zucrypt_test_call_methods[];

/* Defined in zucrypt_crypt.c: the entry points behind the crypt_* functions. */
extern const R_CallMethodDef zucrypt_crypt_call_methods[];

/* Defined in zucrypt_api.c: publishes the table to LinkingTo consumers. */
extern void zucrypt_register_api(void);

SEXP zucrypt_backend_info(void)
{
    zuc_info info;
    zuc_status st;
    SEXP out, nms;
    const char *names[] = {"backend_name", "backend_version", "random_backend",
                           "abi_version", "hardware_acceleration"};
    int i, n = 5;

    info.struct_size = (uint32_t) sizeof info;
    st = zuc_get_info(&info);
    if (st != ZUC_OK) {
        Rf_error("zucrypt: could not read backend information (%s)",
                 zuc_status_string(st));
    }

    /* A list rather than a character vector, so abi_version crosses as an
     * integer. It used to be formatted to a string here and parsed back with
     * as.integer() in R, which is two conversions to move a number. */
    out = PROTECT(Rf_allocVector(VECSXP, n));
    nms = PROTECT(Rf_allocVector(STRSXP, n));
    SET_VECTOR_ELT(out, 0, Rf_mkString(info.backend_name));
    SET_VECTOR_ELT(out, 1, Rf_mkString(info.backend_version));
    SET_VECTOR_ELT(out, 2, Rf_mkString(info.random_backend));
    SET_VECTOR_ELT(out, 3, Rf_ScalarInteger((int) info.abi_version));
    SET_VECTOR_ELT(out, 4, Rf_ScalarLogical(info.hardware_acceleration != 0));
    for (i = 0; i < n; i++) {
        SET_STRING_ELT(nms, i, Rf_mkChar(names[i]));
    }
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

SEXP zucrypt_status_codes(void)
{
    /* A named integer vector: enumerator name to value.
     *
     * The R condition classes are keyed on the *name*, fetched from here
     * at runtime rather than written as literals in R. That is the point: a
     * renumbering of zuc_status would otherwise silently remap every
     * condition class, and nothing would fail until a user caught the wrong
     * one. */
    static const zuc_status all[] = {
        ZUC_OK, ZUC_ERR_INVALID_ARGUMENT, ZUC_ERR_UNSUPPORTED,
        ZUC_ERR_BAD_LENGTH, ZUC_ERR_OVERLAP, ZUC_ERR_MEMORY,
        ZUC_ERR_BACKEND, ZUC_ERR_ABI, ZUC_ERR_INTERNAL, ZUC_ERR_NOT_READY
    };
    int n = (int) (sizeof all / sizeof all[0]);
    SEXP out = PROTECT(Rf_allocVector(INTSXP, n));
    SEXP nms = PROTECT(Rf_allocVector(STRSXP, n));
    int i;

    for (i = 0; i < n; i++) {
        INTEGER(out)[i] = (int) all[i];
        SET_STRING_ELT(nms, i, Rf_mkChar(zuc_status_name(all[i])));
    }
    Rf_setAttrib(out, R_NamesSymbol, nms);
    UNPROTECT(2);
    return out;
}

static const R_CallMethodDef call_methods[] = {
    {"zucrypt_backend_info", (DL_FUNC) &zucrypt_backend_info, 0},
    {"zucrypt_status_codes", (DL_FUNC) &zucrypt_status_codes, 0},
    {NULL, NULL, 0}
};

/* The two tables are concatenated at load time rather than merged by hand,
 * so the harness can grow without this file changing. */
static R_CallMethodDef *all_call_methods(void)
{
    const R_CallMethodDef *tables[] = {
        call_methods, zucrypt_crypt_call_methods, zucrypt_test_call_methods
    };
    int n_tables = (int) (sizeof tables / sizeof tables[0]);
    int total = 0, t, i, k = 0;
    R_CallMethodDef *all;

    for (t = 0; t < n_tables; t++) {
        for (i = 0; tables[t][i].name != NULL; i++) total++;
    }
    all = (R_CallMethodDef *) calloc((size_t) total + 1, sizeof *all);
    if (all == NULL) {
        return NULL;
    }
    for (t = 0; t < n_tables; t++) {
        for (i = 0; tables[t][i].name != NULL; i++) all[k++] = tables[t][i];
    }
    return all;
}

void attribute_visible R_init_zucrypt(DllInfo *dll)
{
    R_CallMethodDef *methods = all_call_methods();
    zuc_status st;

    if (methods == NULL) {
        Rf_error("zucrypt: out of memory while registering native routines");
    }
    R_registerRoutines(dll, NULL, methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
    /* R copies what it needs out of the table during registration, so the
     * array is ours to release. */
    free(methods);

    /* One reference, taken when the namespace loads and never released.
     * Nothing in R calls zuc_shutdown(): R does not reliably unload a
     * package's DLL, and tearing the backend down while an R object still
     * holds a context would be worse than leaking it. design.md section 8.2
     * says unloading zucrypt while consumer contexts exist is unsupported,
     * and this is how that is enforced rather than merely documented.
     *
     * An archive consumer is a separate copy entirely, not a second holder
     * of this count. zucrypt.so links the adapter objects directly and a
     * LinkingTo consumer links libzucrypt.a into its own shared object, so
     * there are two zuc_refcount variables and two PSA key stores, kept
     * apart by hidden visibility (design.md section 8.3).
     *
     * That is the intended arrangement and it has a consequence worth being
     * explicit about: a handle created through one shape cannot be used
     * through the other. A zuc_aes obtained from the registered table belongs
     * to this library's key store, and passing it to a function linked from
     * the archive would look up a key that store does not have. */
    st = zuc_init();
    if (st != ZUC_OK) {
        Rf_error("zucrypt: the cryptographic backend failed to start (%s)",
                 zuc_status_string(st));
    }

    /* After the backend is up, never before: a consumer that resolves the
     * table is entitled to assume the functions in it will work. */
    zucrypt_register_api();
}
