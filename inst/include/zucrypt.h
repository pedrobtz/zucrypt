/* zucrypt: cryptographic primitives for C consumers.
 *
 * This header is the entire public C surface. It compiles standalone as C99
 * against <stddef.h> and <stdint.h> and nothing else -- no R header, no
 * backend header, and no type, macro or identifier belonging to either. That
 * is a hard rule, not a preference: a consumer linking libzucrypt.a
 * has no way to reproduce the backend's build configuration, and a leaked
 * backend type would make its translation unit depend on a configuration it
 * cannot see. A comment here may name the backend; a declaration may not.
 *
 * Two ways to reach these functions:
 *
 *   1. The registered function table, for a consumer that can carry an
 *      Imports:. Include <zucrypt-r.h> instead, which includes this file.
 *   2. The static archive libzucrypt.a, for a consumer that cannot. It is
 *      installed to lib${R_ARCH}/ in the zucrypt package -- on Windows that
 *      is lib/x64/, elsewhere plain lib/ -- so resolve
 *      system.file("lib", .Platform$r_arch, package = "zucrypt") first and
 *      plain "lib" second. Link it and call these functions directly.
 *
 * Shape 2 owns the backend's lifetime: call zuc_init() before anything else
 * and zuc_shutdown() when done. In an R package that is zuc_init() in
 * R_init_<pkg>() and zuc_shutdown() in R_unload_<pkg>() -- and R calls the
 * latter only when the DLL is unloaded, which with useDynLib happens only if
 * the package's .onUnload() calls library.dynam.unload("<pkg>", libpath).
 * Without that line the backend is never shut down. Shape 1 does not own the
 * lifetime -- the zucrypt package initialises the backend when its namespace
 * loads.
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

/* The ABI this header describes.
 *
 * Stability (design.md section 8.6): this header and libzucrypt.a are
 * FROZEN as ABI 1 from v0.1.0, zucrypt's first CRAN release. The freeze
 * followed its first consumer: zuxlsx's agile decryption was written against
 * the archive, linked it on Linux, macOS and Windows, and decrypted a real
 * encrypted workbook with it (zucrypt#43, zuxlsx#22). The registered
 * function table in zucrypt-r.h is EXPERIMENTAL and outside the promise
 * below until a package that is not a test fixture uses it.
 *
 * The promise, within major version 1:
 *
 *   - Functions may be added. Nothing declared here is removed, renamed, or
 *     given a different signature or meaning.
 *   - Fields may be appended to zucrypt_api_v1 and to any struct carrying a
 *     struct_size. Nothing is removed, reordered, or retyped, and a
 *     ZUC_*_REQUIRED_SIZE macro never grows -- it names the prefix the
 *     library dereferences, so a consumer built against an older header
 *     keeps working without being rebuilt.
 *   - Enumerator values are permanent. An algorithm compiled out of a build
 *     keeps its number and reports itself unavailable; it does not vanish
 *     and let the next one take its place.
 *   - A layout change to any type here that struct_size cannot see renames
 *     the registered callable instead, so an old consumer fails loudly at
 *     R_GetCCallable() rather than reading a structure that has moved.
 *
 * What is deliberately not promised: the numeric value of a backend status
 * behind ZUC_ERR_BACKEND, the contents of an opaque handle, and thread
 * safety beyond the main thread. */
#define ZUCRYPT_ABI_VERSION 1

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
    ZUC_ERR_INTERNAL         = 8,  /* a broken invariant; report it */
    ZUC_ERR_NOT_READY        = 9,  /* called before zuc_init() or after the
                                      last zuc_shutdown() */
    ZUC_ERR_ENTROPY          = 10, /* the operating system's random source
                                      failed; appended after ABI 1 */
    ZUC_ERR_AUTH             = 11  /* authenticated decryption failed: the
                                      tag does not match the key, nonce,
                                      associated data and ciphertext. No
                                      plaintext is released. Appended after
                                      ABI 1 */
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
 * Values are grouped into ranges, reserved before the freeze so that a
 * family added later has room without renumbering (design.md section 8.1).
 * A range says what kind of identifier a value is; no value inside one is
 * assigned in advance, and assignment within a range is in order of
 * arrival. The bounds are inclusive.
 *
 *     1 -  63   digests
 *    64 -  95   MACs other than HMAC (HMAC is named by its digest)
 *    96 - 159   ciphers and cipher modes, AEAD included
 *   160 - 191   key derivation
 *   192 - 223   key families (RSA, curves)
 *   224 - 255   signature schemes
 *
 * SHA-1 exists for compatibility with document formats that specify it. It
 * is not a default for anything new. */
typedef enum {
    ZUC_ALG_NONE   = 0,

    ZUC_ALG_SHA1   = 1,
    ZUC_ALG_SHA256 = 2,
    ZUC_ALG_SHA384 = 3,
    ZUC_ALG_SHA512 = 4,

    /* 5..63 reserved for further digests. */

    /* AES-GCM (NIST SP 800-38D), for zuc_aead_encrypt() and
     * zuc_aead_decrypt(). The key length selects AES-128, -192 or -256.
     * Appended after ABI 1. zuc_alg_size() is 0 for it: it is not a
     * digest, and the hash and HMAC functions refuse it. */
    ZUC_ALG_AES_GCM = 96

    /* 97..159 reserved for further ciphers and AEAD modes. */
} zuc_alg;

#define ZUC_ALG_DIGEST_FIRST     1
#define ZUC_ALG_DIGEST_LAST     63
#define ZUC_ALG_MAC_FIRST       64
#define ZUC_ALG_MAC_LAST        95
#define ZUC_ALG_CIPHER_FIRST    96
#define ZUC_ALG_CIPHER_LAST    159
#define ZUC_ALG_KDF_FIRST      160
#define ZUC_ALG_KDF_LAST       191
#define ZUC_ALG_KEY_FIRST      192
#define ZUC_ALG_KEY_LAST       223
#define ZUC_ALG_SIGNATURE_FIRST 224
#define ZUC_ALG_SIGNATURE_LAST  255

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
    /* Appended after the required prefix: each is written only when
     * struct_size covers it, so a caller built against an older header is
     * unaffected. */
    int         hardware_acceleration; /* out: 1 if AES runs on this CPU's
                                          AES instructions, 0 if on the
                                          software fallback */
    const char *aes_implementation;    /* out: "aesni", "aesce" or
                                          "software" -- decided at run time,
                                          on this machine */
} zuc_info;

/* The prefix zuc_get_info() dereferences -- deliberately not sizeof(zuc_info),
 * which would make every appended field a breaking change for a consumer
 * built against an older header. */
#define ZUC_INFO_REQUIRED_SIZE \
    (offsetof(zuc_info, random_backend) + sizeof(const char *))

zuc_status zuc_get_info(zuc_info *info);

/* Every function below that needs the backend returns ZUC_ERR_NOT_READY
 * when called outside an initialised window. zuc_status_string(),
 * zuc_status_name() and the zuc_alg_* functions do not need it. */

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

/* Feed more input. A zero-length update is valid and does nothing, and
 * `data` may then be NULL; with a nonzero length, NULL is
 * ZUC_ERR_INVALID_ARGUMENT. */
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

/* Same shape as the digest interface, keyed at creation, with the same NULL
 * rule: `data` (and `key`) may be NULL only when its length is 0. Any key length is
 * accepted, including 0, as RFC 2104 specifies; a key longer than the hash's
 * block is replaced by its hash, as RFC 2104 also specifies, which gives the
 * same MAC. The key is copied into the library's own storage and wiped when
 * the handle is freed; the caller's buffer is not retained. */
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
 * Each handle (and each zuc_hmac) holds one key in the backend's key store,
 * which grows on demand: the number of live handles is bounded only by
 * memory, and running out is ZUC_ERR_MEMORY.
 *
 * NO PADDING IS EVER ADDED OR REMOVED, and no authentication is provided.
 * Every buffer length must be a multiple of ZUC_AES_BLOCK_SIZE. A ciphertext
 * produced here can be modified by anyone who can reach it, undetectably;
 * authenticating it is the caller's job and is not optional for anything but
 * reading an existing file format that already specifies otherwise.
 *
 * SIDE CHANNELS. AES runs on the CPU's AES instructions where it has them --
 * AES-NI on x86, the Cryptography Extension on ARMv8 -- chosen at run time.
 * On a CPU without them it falls back to a table-based software AES whose
 * memory accesses depend on the key and the data; the backend's own security
 * policy warns that an attacker able to observe cache timing (another
 * process on the same machine, or a precise enough network observer) can
 * recover the key from it. zuc_get_info() reports which path this machine
 * uses in `aes_implementation`; if it is "software" and that threat is in
 * your model, do not use this AES for secrets that matter. */
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
 * and does nothing, and `in` and `out` may then be NULL.
 *
 * Overlap: `in` and `out` may be the same pointer (exact in-place is
 * supported and tested). Any other overlap is rejected with ZUC_ERR_OVERLAP
 * rather than silently producing wrong output. */
zuc_status zuc_aes_cbc_encrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out);
zuc_status zuc_aes_cbc_decrypt(zuc_aes *aes,
                               const uint8_t *in, size_t len, uint8_t *out);

/* ------------------------------------------------------------------ *
 * Authenticated encryption (AEAD)
 * ------------------------------------------------------------------ */

/* The nonce and tag sizes AES-GCM takes here. */
#define ZUC_GCM_NONCE_SIZE 12
#define ZUC_GCM_TAG_SIZE   16

/* One-shot authenticated encryption, with RFC 5116's contract.
 *
 * `alg` is ZUC_ALG_AES_GCM; any other value is ZUC_ERR_UNSUPPORTED. `key_len`
 * is 16, 24 or 32. `nonce_len` must be ZUC_GCM_NONCE_SIZE and `tag_len`
 * ZUC_GCM_TAG_SIZE: shorter tags and other nonce lengths are not offered.
 * Any other key or nonce length is ZUC_ERR_BAD_LENGTH, and so is another tag
 * length on encryption. On decryption a tag of another length is
 * ZUC_ERR_AUTH: a truncated tag cannot match.
 *
 * Encryption writes `len` bytes of ciphertext to `ciphertext` and the tag to
 * `tag`. Decryption checks `tag` against the key, nonce, associated data and
 * ciphertext. Only if it matches does it return ZUC_OK with `len` bytes of
 * plaintext in `plaintext`; otherwise it returns ZUC_ERR_AUTH.
 *
 * An argument error (a NULL, a length, an overlap) is reported before
 * anything is written. Any failure after that zeroes all `len` bytes of the
 * output, and on encryption the tag too: no unauthenticated plaintext ever
 * reaches the caller, and no half-made ciphertext either.
 *
 * A pointer may be NULL only when its length is 0: `aad` with `aad_len` 0,
 * the data buffers with `len` 0. The output and the input may be the same
 * pointer (exact in-place); any other overlap is ZUC_ERR_OVERLAP. The key is
 * imported for the call and destroyed before it returns.
 *
 * THE NONCE MUST NEVER REPEAT UNDER ONE KEY. Two messages encrypted with the
 * same key and nonce disclose the XOR of their plaintexts, and let anyone
 * who sees them forge tags for that key. A random 12-byte nonce from
 * zuc_random_bytes() is safe for up to about 2^32 messages per key.
 *
 * AES runs on the path described under AES below, with the same side-channel
 * note for the software fallback; GHASH, the authentication half of GCM,
 * also uses tables on that path.
 *
 * Added after ABI 1 was frozen. A table consumer tests for them with
 * ZUCRYPT_API_HAS(api, aead_decrypt). */
zuc_status zuc_aead_encrypt(zuc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t len,
                            uint8_t *ciphertext,
                            uint8_t *tag, size_t tag_len);

zuc_status zuc_aead_decrypt(zuc_alg alg,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t len,
                            const uint8_t *tag, size_t tag_len,
                            uint8_t *plaintext);

/* ------------------------------------------------------------------ *
 * Key derivation
 * ------------------------------------------------------------------ */

/* PBKDF2 (RFC 8018 section 5.2) with HMAC over `hash` as the PRF, which is
 * ZUC_ALG_SHA1, ZUC_ALG_SHA256, ZUC_ALG_SHA384 or ZUC_ALG_SHA512.
 *
 * Writes `out_len` bytes to `out`. `iterations` must be at least 1 and
 * `out_len` at least 1; otherwise ZUC_ERR_INVALID_ARGUMENT or
 * ZUC_ERR_BAD_LENGTH. `password` and `salt` may be NULL only when their
 * length is 0, and either may be empty. If the derivation itself fails, all
 * `out_len` bytes of `out` are zeroed; an argument error writes nothing.
 *
 * The cost grows linearly with `iterations`, and the call cannot be
 * interrupted. A caller taking `iterations` from untrusted input must bound
 * it first.
 *
 * PBKDF2 derives a key from a password. It is not a password hash format
 * and not a file format: the salt, the iteration count and what the key is
 * for are the caller's to store and specify.
 *
 * Added after ABI 1 was frozen. A table consumer tests for it with
 * ZUCRYPT_API_HAS(api, pbkdf2_hmac). */
zuc_status zuc_pbkdf2_hmac(zuc_alg hash,
                           const uint8_t *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *out, size_t out_len);

/* ------------------------------------------------------------------ *
 * Randomness
 * ------------------------------------------------------------------ */

/* Fill `out` with `len` bytes from the operating system's cryptographic
 * random source: rand_s on Windows, arc4random_buf on macOS and the BSDs,
 * getrandom on glibc 2.25 and later, /dev/urandom otherwise.
 * zuc_get_info() names the one compiled in, in `random_backend`.
 *
 * The bytes come straight from the operating system. There is no generator
 * in between to seed or reseed, and no state is shared with anything else
 * in the process.
 *
 * `out` may be NULL only when `len` is 0, which does nothing. A failure of
 * the source is ZUC_ERR_ENTROPY, and on any failure all `len` bytes of `out`
 * are zeroed, so a partial fill can never be mistaken for a random one.
 *
 * Added after ABI 1 was frozen, as the promise above allows. A table
 * consumer tests for it with ZUCRYPT_API_HAS(api, random_bytes); an archive
 * consumer gets it by linking a libzucrypt.a that has it. */
zuc_status zuc_random_bytes(uint8_t *out, size_t len);

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
