/* zucrypt: cryptographic primitives for C consumers.
 *
 * This header is the entire public C surface. It compiles standalone as C99
 * against <stddef.h> and <stdint.h> and nothing else -- no R header, no
 * backend header, and no type, macro or identifier belonging to either. That
 * is a hard rule, not a preference: a consumer linking inst/lib/libzucrypt.a
 * has no way to reproduce the backend's build configuration, and a leaked
 * backend type would make its translation unit depend on a configuration it
 * cannot see. A comment here may name the backend; a declaration may not.
 *
 * Two ways to reach these functions:
 *
 *   1. The registered function table, for a consumer that can carry an
 *      Imports:. Include <zucrypt-r.h> instead, which includes this file.
 *   2. The static archive inst/lib/libzucrypt.a, for a consumer that cannot.
 *      Link it and call these functions directly.
 *
 * Shape 2 owns the backend's lifetime: call zuc_init() before anything else
 * and zuc_shutdown() when done. Shape 1 does not -- the zucrypt package
 * initialises the backend when its namespace loads.
 *
 * Threads: main thread only in this version. See the note on zuc_init().
 *
 * Copyright (c) 2026 Pedro Baltazar. MIT licence; see the LICENSE file.
 */

#ifndef ZUCRYPT_H
#define ZUCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * Versioning
 * ------------------------------------------------------------------ */

/* The ABI this header describes. 0 while the surface is still moving; it
 * becomes 1 at v0.1.0, at which point the promise begins: within a major
 * version, fields and functions may be added and nothing is removed,
 * reordered or given a new meaning. */
#define ZUCRYPT_ABI_VERSION 0

/* ------------------------------------------------------------------ *
 * Status codes
 * ------------------------------------------------------------------ */

/* Every function that can fail returns one of these. No value is negative,
 * so `if (st)` reliably means "not success".
 *
 * Numeric values are permanent. The R layer maps them to condition classes
 * by enumerator *name*, fetched from C at runtime, precisely so that a
 * renumbering here cannot silently remap a condition -- but a consumer in C
 * may well compare against the numbers, so they do not move either. */
typedef enum {
    ZUC_OK                   = 0,  /* success */
    ZUC_ERR_INVALID_ARGUMENT = 1,  /* a NULL pointer, or a nonsensical combination */
    ZUC_ERR_UNSUPPORTED      = 2,  /* valid request, not available in this build */
    ZUC_ERR_BAD_LENGTH       = 3,  /* wrong key, IV, buffer or block length */
    ZUC_ERR_OVERLAP          = 4,  /* input and output buffers overlap partially */
    ZUC_ERR_MEMORY           = 5,  /* allocation failed */
    ZUC_ERR_BACKEND          = 6,  /* the backend refused; details are not public */
    ZUC_ERR_ABI              = 7,  /* version or struct_size mismatch */
    ZUC_ERR_INTERNAL         = 8   /* a broken invariant; report it */
} zuc_status;

/* A short, stable, English description. Never returns NULL, including for a
 * value outside the enum -- a caller reporting an error should never fail
 * while doing so. The strings are static; do not free them. */
const char *zuc_status_string(zuc_status status);

/* The enumerator's own name, e.g. "ZUC_ERR_BAD_LENGTH". This is what the R
 * layer keys its condition classes on. Never returns NULL. */
const char *zuc_status_name(zuc_status status);

/* ------------------------------------------------------------------ *
 * Algorithms
 * ------------------------------------------------------------------ */

/* Fixed identifiers. A value is permanent once assigned: an algorithm that
 * is compiled out keeps its number and reports itself unavailable, rather
 * than letting the numbering shift under a consumer built against another
 * configuration.
 *
 * SHA-1 exists for compatibility with document formats that specify it. It
 * is not a default for anything new, and neither is ECB below. */
typedef enum {
    ZUC_ALG_NONE   = 0,

    ZUC_ALG_SHA1   = 1,
    ZUC_ALG_SHA256 = 2,
    ZUC_ALG_SHA384 = 3,
    ZUC_ALG_SHA512 = 4

    /* 5..15 reserved for further digests. */
} zuc_alg;

/* Lower-case canonical name, e.g. "sha256". NULL for an unknown value. */
const char *zuc_alg_name(zuc_alg alg);

/* The algorithm this name denotes, or ZUC_ALG_NONE. Exact match only: no
 * prefix matching, no aliases, no case folding. */
zuc_alg zuc_alg_by_name(const char *name);

/* Non-zero if this build can actually perform the algorithm. */
int zuc_alg_available(zuc_alg alg);

/* Digest length in bytes, or 0 if `alg` is not a digest. */
size_t zuc_alg_size(zuc_alg alg);

/* Largest value zuc_alg_size() can return, for sizing a stack buffer. */
#define ZUC_MAX_DIGEST_SIZE 64

/* AES block and IV size. Both are 16 for every AES key length. */
#define ZUC_AES_BLOCK_SIZE 16

/* The three permitted AES key lengths, in bytes. */
#define ZUC_AES_KEY_SIZE_128 16
#define ZUC_AES_KEY_SIZE_192 24
#define ZUC_AES_KEY_SIZE_256 32

/* ------------------------------------------------------------------ *
 * Library lifetime
 * ------------------------------------------------------------------ */

/* Bring the backend up. Reference counted: every successful zuc_init() must
 * be matched by one zuc_shutdown(), and the backend is torn down only when
 * the last one returns. A consumer holding a context must therefore keep its
 * own reference, or the context can outlive the backend.
 *
 * Main thread only, and not reentrant. The backend's key store needs
 * upstream's threading support, which needs pthreads, which this build does
 * not enable. Calls from more than one thread are undefined; this is
 * deliberately stricter than zukomp's promise, so that a consumer written
 * against that one does not assume it here. */
zuc_status zuc_init(void);

/* Drop one reference. Returns ZUC_OK even when other references remain. */
zuc_status zuc_shutdown(void);

/* Information about the running library. Fill in struct_size before the
 * call; the core reads no field beyond what your size covers, and refuses
 * with ZUC_ERR_ABI if it is smaller than ZUC_INFO_REQUIRED_SIZE.
 *
 * All strings are static and owned by the library. Do not free them; they
 * stay valid after zuc_shutdown(). */
typedef struct {
    uint32_t    struct_size;       /* in: sizeof(zuc_info) as you know it */
    uint32_t    abi_version;       /* out: ZUCRYPT_ABI_VERSION of the library */
    const char *backend_name;      /* out: e.g. "TF-PSA-Crypto" */
    const char *backend_version;   /* out: e.g. "1.1.1" */
    const char *random_backend;    /* out: the OS random source compiled in */
} zuc_info;

/* The prefix zuc_get_info() dereferences -- deliberately not sizeof(zuc_info),
 * which would make every appended field a breaking change for a consumer
 * built against an older header. */
#define ZUC_INFO_REQUIRED_SIZE \
    (offsetof(zuc_info, random_backend) + sizeof(const char *))

zuc_status zuc_get_info(zuc_info *info);

/* ------------------------------------------------------------------ *
 * Digests
 * ------------------------------------------------------------------ */

/* One-shot. `out_size` must be at least zuc_alg_size(alg); the number of
 * bytes written is stored in *out_len. `data` may be NULL only when
 * `data_len` is 0 -- the digest of the empty input is well defined and is
 * what you get. */
zuc_status zuc_hash_compute(zuc_alg alg,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t out_size, size_t *out_len);

/* Incremental. The handle is opaque and heap-allocated by the library; only
 * zuc_hash_free() may release it. A handle is valid until freed or until the
 * backend is shut down, whichever comes first. */
typedef struct zuc_hash zuc_hash;

/* On failure *out is set to NULL and nothing is allocated: a partially
 * built context is destroyed rather than returned. */
zuc_status zuc_hash_new(zuc_alg alg, zuc_hash **out);

/* Feed more input. A zero-length update is valid and does nothing. */
zuc_status zuc_hash_update(zuc_hash *hash, const uint8_t *data, size_t data_len);

/* Produce the digest. The handle is finished afterwards and must be reset
 * before it can be updated again. */
zuc_status zuc_hash_finish(zuc_hash *hash,
                           uint8_t *out, size_t out_size, size_t *out_len);

/* Return the handle to its just-created state, same algorithm. A reset
 * handle is indistinguishable from a fresh one. */
zuc_status zuc_hash_reset(zuc_hash *hash);

/* Free a handle. NULL is accepted and ignored. Any buffered input is wiped. */
void zuc_hash_free(zuc_hash *hash);

/* ------------------------------------------------------------------ *
 * HMAC
 * ------------------------------------------------------------------ */

/* Same shape as the digest interface, keyed at creation. Any key length is
 * accepted, including 0, as RFC 2104 specifies. The key is copied into the
 * library's own storage and wiped when the handle is freed; the caller's
 * buffer is not retained. */
zuc_status zuc_hmac_compute(zuc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t out_size, size_t *out_len);

typedef struct zuc_hmac zuc_hmac;

zuc_status zuc_hmac_new(zuc_alg alg, const uint8_t *key, size_t key_len,
                        zuc_hmac **out);
zuc_status zuc_hmac_update(zuc_hmac *hmac, const uint8_t *data, size_t data_len);
zuc_status zuc_hmac_finish(zuc_hmac *hmac,
                           uint8_t *out, size_t out_size, size_t *out_len);
zuc_status zuc_hmac_reset(zuc_hmac *hmac);
void zuc_hmac_free(zuc_hmac *hmac);

/* ------------------------------------------------------------------ *
 * AES
 * ------------------------------------------------------------------ */

/* An AES key, plus the chaining state that CBC advances.
 *
 * NO PADDING IS EVER ADDED OR REMOVED, and no authentication is provided.
 * Every buffer length must be a multiple of ZUC_AES_BLOCK_SIZE. A ciphertext
 * produced here can be modified by anyone who can reach it, undetectably;
 * authenticating it is the caller's job and is not optional for anything but
 * reading an existing file format that already specifies otherwise. */
typedef struct zuc_aes zuc_aes;

/* `key_len` must be 16, 24 or 32; anything else is ZUC_ERR_BAD_LENGTH. The
 * key is copied and the caller's buffer is not retained. The chaining state
 * starts all-zero; set it with zuc_aes_cbc_set_state() before the first CBC
 * call. */
zuc_status zuc_aes_new(const uint8_t *key, size_t key_len, zuc_aes **out);

/* Free the key and wipe its material. NULL is accepted and ignored. */
void zuc_aes_free(zuc_aes *aes);

/* The CBC chaining state: 16 bytes, read and written explicitly.
 *
 * This is the mutable running value, not the immutable IV an R caller
 * passes. Starting a stream means setting it to the IV; continuing one means
 * leaving it alone between calls; and a format that restarts CBC at each
 * segment boundary -- which is what the Office Agile profiles do -- means
 * setting it again at each boundary. After a call it equals the last
 * ciphertext block processed, in both directions. */
zuc_status zuc_aes_cbc_set_state(zuc_aes *aes, const uint8_t *state);
zuc_status zuc_aes_cbc_get_state(const zuc_aes *aes, uint8_t *state);

/* CBC over a whole number of blocks, continuing from the chaining state and
 * advancing it. `len` must be a multiple of ZUC_AES_BLOCK_SIZE; 0 is valid
 * and does nothing.
 *
 * Overlap: `in` and `out` may be the same pointer (exact in-place is
 * supported and tested). Any other overlap is rejected with ZUC_ERR_OVERLAP
 * rather than silently producing wrong output. */
zuc_status zuc_aes_cbc_encrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out);
zuc_status zuc_aes_cbc_decrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out);

/* ECB, for compatibility with formats that specify it. Stateless: it neither
 * reads nor advances the chaining state. Identical plaintext blocks produce
 * identical ciphertext blocks, which is why this is not a general-purpose
 * tool. Same length rule and same overlap rule as CBC. */
zuc_status zuc_aes_ecb_encrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out);
zuc_status zuc_aes_ecb_decrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out);

/* ------------------------------------------------------------------ *
 * Utilities
 * ------------------------------------------------------------------ */

/* Compare two buffers of equal length in time that does not depend on their
 * contents. Returns 1 if equal, 0 otherwise.
 *
 * `len` is not secret and is not hidden: comparing buffers of different
 * lengths is the caller's decision to make before calling. Passing len == 0
 * returns 1. */
int zuc_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Overwrite a buffer and mean it -- a plain memset over memory that is about
 * to go out of scope is removable under the as-if rule, and compilers do
 * remove it. Use this for keys, passwords and intermediate key material. */
void zuc_secure_zero(void *buffer, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZUCRYPT_H */
