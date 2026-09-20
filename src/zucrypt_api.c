/* zucrypt: the registered function table.
 *
 * R-facing -- it needs R_RegisterCCallable -- so it lives beside the other
 * zucrypt_*.c files and is not in inst/lib/libzucrypt.a. The table itself
 * holds pointers to the adapter, which is in the archive; this file adds no
 * behaviour of its own, on purpose. Anything it computed would be behaviour
 * the archive consumer cannot reach, and the two shapes have to be the same
 * library.
 */

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

/* The same header a consumer includes, which is the point: the table this
 * file fills in and the table a consumer reads are one declaration, so a
 * field added on one side cannot be forgotten on the other. It brings in
 * zucrypt.h itself. */
#include "zucrypt-r.h"

/* Declared here rather than in zucrypt-r.h: a consumer never calls this
 * directly, it goes through zucrypt_api(). */
const zucrypt_api_v1 *zucrypt_get_api(uint32_t requested);
void zucrypt_register_api(void);

/* Filled once, at first use. Static storage rather than a compile-time
 * initialiser because designated initialisers are C99 and this has to stay
 * readable when a field is appended: every entry names the field it fills. */
static zucrypt_api_v1 api;
static int api_ready = 0;

static void fill_api(void)
{
    api.abi_version = ZUCRYPT_ABI_VERSION;
    api.struct_size = (uint32_t) sizeof api;

    api.status_string = zuc_status_string;
    api.status_name   = zuc_status_name;
    api.alg_name      = zuc_alg_name;
    api.alg_by_name   = zuc_alg_by_name;
    api.alg_available = zuc_alg_available;
    api.alg_size      = zuc_alg_size;
    api.get_info      = zuc_get_info;

    api.hash_compute  = zuc_hash_compute;
    api.hash_new      = zuc_hash_new;
    api.hash_update   = zuc_hash_update;
    api.hash_finish   = zuc_hash_finish;
    api.hash_reset    = zuc_hash_reset;
    api.hash_free     = zuc_hash_free;

    api.hmac_compute  = zuc_hmac_compute;
    api.hmac_new      = zuc_hmac_new;
    api.hmac_update   = zuc_hmac_update;
    api.hmac_finish   = zuc_hmac_finish;
    api.hmac_reset    = zuc_hmac_reset;
    api.hmac_free     = zuc_hmac_free;

    api.aes_new           = zuc_aes_new;
    api.aes_free          = zuc_aes_free;
    api.aes_cbc_set_state = zuc_aes_cbc_set_state;
    api.aes_cbc_get_state = zuc_aes_cbc_get_state;
    api.aes_cbc_encrypt   = zuc_aes_cbc_encrypt;
    api.aes_cbc_decrypt   = zuc_aes_cbc_decrypt;
    api.aes_ecb_encrypt   = zuc_aes_ecb_encrypt;
    api.aes_ecb_decrypt   = zuc_aes_ecb_decrypt;

    api.equal       = zuc_equal;
    api.secure_zero = zuc_secure_zero;

    api_ready = 1;
}

const zucrypt_api_v1 *zucrypt_get_api(uint32_t requested)
{
    /* Major-version match, not "at least". A consumer compiled against a
     * major version this library does not implement gets NULL and can say
     * so, which is the entire point: the alternative is a call through a
     * pointer whose meaning has changed.
     *
     * Still an equality test now that the ABI is frozen at 1, because there
     * is exactly one version to serve. It grows a range check when there is
     * a second one and not before: a range check with one version in it is
     * untested code that looks like it has been thought about. */
    if (requested != (uint32_t) ZUCRYPT_ABI_VERSION) {
        return NULL;
    }
    if (!api_ready) {
        fill_api();
    }
    return &api;
}

/* Registered from R_init_zucrypt, after the backend is up, so a consumer
 * that reaches the table can rely on it. The name carries the version of
 * every type in zucrypt.h that struct_size cannot see: change any of those
 * layouts and this name changes with it, so an old consumer fails at
 * R_GetCCallable() rather than reading a struct that has moved. */
void zucrypt_register_api(void)
{
    R_RegisterCCallable("zucrypt", "zucrypt_get_api", (DL_FUNC) zucrypt_get_api);
}
