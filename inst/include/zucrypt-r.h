/* zucrypt's R-facing linkage header.
 *
 * Include this instead of <zucrypt.h> when you are an R *package* consuming
 * zucrypt's C ABI through the registered function table. It pulls in
 * zucrypt.h, then adds the one piece that unavoidably knows about R: how to
 * get hold of the table.
 *
 * Why a table at all: LinkingTo supplies headers, not object code. Nothing
 * links across installed packages, so the ABI is delivered through R's
 * registered C-callable mechanism -- and through a single versioned table,
 * so a consumer does one lookup instead of one per function.
 *
 * Usage:
 *
 *     #include <zucrypt-r.h>
 *
 *     const zucrypt_api_v1 *api = zucrypt_api();
 *     if (api == NULL) { ... zucrypt does not implement this ABI version ... }
 *
 *     uint8_t out[ZUC_MAX_DIGEST_SIZE];
 *     size_t n;
 *     zuc_status st = api->hash_compute(ZUC_ALG_SHA256, data, len,
 *                                       out, sizeof out, &n);
 *
 * DESCRIPTION needs both:
 *
 *     Imports:   zucrypt        # loads the DLL, providing the C-callable
 *     LinkingTo: zucrypt        # provides these headers
 *
 * and NAMESPACE needs a real import directive, e.g.
 * importFrom(zucrypt, crypt_info). See the warning on zucrypt_api() below:
 * Imports alone does not load zucrypt's namespace, and without an actual
 * import the DLL may not be loaded when your R_init_ runs.
 *
 * If you cannot carry an Imports: -- because you link the static archive
 * libzucrypt.a instead -- you do not want this header. Include
 * <zucrypt.h>, link the archive, and call zuc_init() yourself.
 *
 * STABILITY: the table is EXPERIMENTAL (design.md section 8.6). No package
 * uses it yet; a test fixture calls every entry on every push. Until a real
 * consumer does, it may change in any release, and every change is recorded
 * in NEWS.md. The static archive is the primary C shape.
 *
 * Copyright (c) 2026 Pedro Baltazar. MIT licence; see the LICENSE file.
 */

#ifndef ZUCRYPT_R_H
#define ZUCRYPT_R_H

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include "zucrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The versioned function table.
 *
 * `abi_version` and `struct_size` together are what let a later version
 * append fields safely: a consumer checks the version it asked for and reads
 * only the fields its own header knows about. Fields are only ever appended,
 * never removed, reordered, or given a new meaning.
 *
 * struct_size versions the *table*. It cannot see a layout change in
 * zuc_info or any other type declared in zucrypt.h -- and R does not rebuild
 * LinkingTo dependents when zucrypt is upgraded, so an old consumer's
 * compiled code would keep the old layout. Any such change therefore renames
 * the registered callable (see zucrypt_api() below), so that consumer fails
 * loudly at R_GetCCallable() instead of corrupting its own stack.
 *
 * None of these functions raises an R error, allocates an R object, or calls
 * back into R. They return status codes. That is what makes them safe to
 * call from a consumer's own C code without worrying about a longjmp through
 * it.
 *
 * Ownership, throughout: an object the provider allocated is destroyed only
 * by a provider function, and no caller buffer is retained after a call
 * returns. Pass a stack buffer if you like; the library will not remember it.
 */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;

    /* Identification and diagnostics. */
    const char *(*status_string)(zuc_status status);
    const char *(*status_name)(zuc_status status);
    const char *(*alg_name)(zuc_alg alg);
    zuc_alg     (*alg_by_name)(const char *name);
    int         (*alg_available)(zuc_alg alg);
    size_t      (*alg_size)(zuc_alg alg);
    zuc_status  (*get_info)(zuc_info *info);

    /* Digests: one-shot, then incremental. */
    zuc_status  (*hash_compute)(zuc_alg alg, const uint8_t *data, size_t len,
                                uint8_t *out, size_t out_size, size_t *out_len);
    zuc_status  (*hash_new)(zuc_alg alg, zuc_hash **out);
    zuc_status  (*hash_update)(zuc_hash *hash, const uint8_t *data, size_t len);
    zuc_status  (*hash_finish)(zuc_hash *hash, uint8_t *out, size_t out_size,
                               size_t *out_len);
    zuc_status  (*hash_reset)(zuc_hash *hash);
    void        (*hash_free)(zuc_hash *hash);

    /* HMAC: the same shape, keyed at creation. */
    zuc_status  (*hmac_compute)(zuc_alg alg, const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t len,
                                uint8_t *out, size_t out_size, size_t *out_len);
    zuc_status  (*hmac_new)(zuc_alg alg, const uint8_t *key, size_t key_len,
                            zuc_hmac **out);
    zuc_status  (*hmac_update)(zuc_hmac *hmac, const uint8_t *data, size_t len);
    zuc_status  (*hmac_finish)(zuc_hmac *hmac, uint8_t *out, size_t out_size,
                               size_t *out_len);
    zuc_status  (*hmac_reset)(zuc_hmac *hmac);
    void        (*hmac_free)(zuc_hmac *hmac);

    /* AES. The chaining state is explicit; see zucrypt.h for why. */
    zuc_status  (*aes_new)(const uint8_t *key, size_t key_len, zuc_aes **out);
    void        (*aes_free)(zuc_aes *aes);
    zuc_status  (*aes_cbc_set_state)(zuc_aes *aes, const uint8_t *state);
    zuc_status  (*aes_cbc_get_state)(const zuc_aes *aes, uint8_t *state);
    zuc_status  (*aes_cbc_encrypt)(zuc_aes *aes, const uint8_t *in, size_t len,
                                   uint8_t *out);
    zuc_status  (*aes_cbc_decrypt)(zuc_aes *aes, const uint8_t *in, size_t len,
                                   uint8_t *out);

    /* Utilities. */
    int         (*equal)(const uint8_t *a, const uint8_t *b, size_t len);
    void        (*secure_zero)(void *buffer, size_t len);
} zucrypt_api_v1;

/* Does this table have `field`? Fields are appended over time, and a
 * consumer built against a newer header can meet an older zucrypt: test
 * before calling any field added after the one you first built against.
 *
 *     if (ZUCRYPT_API_HAS(api, secure_zero)) api->secure_zero(buf, n);
 *
 * The same idea as zuxml.h's ZUXML_API_HAS: the table's own struct_size
 * says how far the provider filled it in. */
#define ZUCRYPT_API_HAS(api, field)                                   \
    ((api) != NULL &&                                                 \
     (size_t) (api)->struct_size >=                                   \
         offsetof(zucrypt_api_v1, field) + sizeof((api)->field))

/* The backend's lifetime is not the consumer's problem on this path.
 *
 * zucrypt takes one reference to the backend when its namespace loads and
 * never releases it, so any context obtained through this table stays valid
 * for as long as zucrypt is loaded. There is deliberately no init or
 * shutdown in the table: a consumer that could call shutdown could pull the
 * backend out from under zucrypt's own R functions.
 *
 * Unloading zucrypt while consumer contexts exist is unsupported. R does not
 * reliably unload a package's DLL anyway, and nothing here tries to make that
 * case work.
 *
 * Threads: main thread only, including this resolution. See zuc_init().
 */

/* Resolves the table, lazily, and caches it.
 *
 * Lazily on purpose. `Imports: zucrypt` in DESCRIPTION does NOT load
 * zucrypt's namespace unless your NAMESPACE also contains a real
 * import()/importFrom() directive -- and without that, calling
 * R_GetCCallable("zucrypt", ...) from your own R_init_ can fail because
 * zucrypt's DLL is not loaded yet. Resolving on first use instead sidesteps
 * the ordering problem entirely.
 *
 * Returns NULL if zucrypt does not implement the ABI version this header
 * asks for, so a mismatch is a clean error at your call site rather than a
 * wild call through a garbage pointer.
 *
 * NULL is the ONLY failure it reports by returning. If zucrypt is not
 * installed, not loaded, or too old to register "zucrypt_get_api" at all,
 * R_GetCCallable() does not return NULL: it raises an R error, which
 * longjmps out of your C code. So resolve the table before you acquire
 * anything a longjmp would strand -- an unprotected SEXP, a malloc'd buffer,
 * an open file -- and make sure your NAMESPACE imports zucrypt so the
 * missing case cannot arise in a correctly installed package.
 *
 * `static inline`, not plain `static`: a header-defined plain static function
 * is an unused-function warning in every translation unit that includes this
 * header without calling it -- which is most of them -- and a hard failure
 * for a consumer building with -Werror. Each translation unit still gets its
 * own `cached`.
 */
static inline const zucrypt_api_v1 *zucrypt_api(void)
{
    static const zucrypt_api_v1 *cached = NULL;
    if (cached == NULL) {
        /* R_GetCCallable returns DL_FUNC, i.e. void (*)(void). Casting that
         * directly to the real signature is what every example does, and
         * modern compilers reject it under -Wcast-function-type-mismatch,
         * which -Wall -Wextra -Werror turns into a build failure for the
         * *consumer*. Going through a union keeps this header usable by a
         * package with strict flags, which is the whole point of shipping
         * it. */
        union {
            DL_FUNC fn;
            const zucrypt_api_v1 *(*get)(uint32_t);
        } resolve;
        resolve.fn = R_GetCCallable("zucrypt", "zucrypt_get_api");
        if (resolve.fn != NULL) {
            cached = resolve.get((uint32_t) ZUCRYPT_ABI_VERSION);
        }
    }
    return cached;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZUCRYPT_R_H */
