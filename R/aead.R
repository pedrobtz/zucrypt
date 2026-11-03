#' AES-GCM Authenticated Encryption
#'
#' @description
#' `crypt_aes_gcm_encrypt()` encrypts and authenticates `data`, and
#' `crypt_aes_gcm_decrypt()` checks the authentication tag before it returns
#' anything. This is AES in Galois/Counter Mode (NIST SP 800-38D) with RFC
#' 5116's contract: a 12-byte nonce, a 16-byte tag, and optional associated
#' data that is authenticated but not encrypted.
#'
#' Decryption either returns the plaintext of an untouched message or signals
#' `zucrypt_auth_error` and returns nothing. A changed ciphertext, tag, nonce
#' or associated data, a truncated tag and a wrong key all fail the same way.
#'
#' @param data A raw vector: the plaintext to encrypt, or the ciphertext to
#'   decrypt. Character input is not accepted.
#' @param key A raw vector of exactly 16, 24 or 32 bytes, selecting AES-128,
#'   AES-192 or AES-256. This is a key, not a password; [crypt_pbkdf2()]
#'   derives one from a password.
#' @param iv The nonce: a raw vector of exactly 12 bytes. Encryption draws a
#'   fresh one with [crypt_rand_bytes()] unless you pass one. **It must never
#'   repeat under the same key** (see "Nonces" below). Decryption reads it
#'   from the ciphertext's `iv` attribute unless you pass one.
#' @param tag The 16-byte authentication tag. Decryption reads it from the
#'   ciphertext's `tag` attribute unless you pass one.
#' @param aad Additional authenticated data, as a raw vector, or `NULL` for
#'   none. It is not encrypted and not returned. Decryption needs the same
#'   bytes, and fails if they differ.
#'
#' @return `crypt_aes_gcm_encrypt()` returns the ciphertext, a raw vector the
#'   length of `data`, with attributes `iv` (the nonce) and `tag` (the
#'   authentication tag). Store or send all three. `crypt_aes_gcm_decrypt()`
#'   returns the plaintext as a plain raw vector.
#'
#' @section Nonces:
#' Two messages encrypted under one key with one nonce disclose the XOR of
#' their plaintexts. They also let anyone who sees both forge tags for that
#' key. The default nonce is 12 random bytes, which is safe for up to about
#' 2^32 messages per key. Pass your own only when a protocol specifies it,
#' and then make sure it never repeats.
#'
#' @section Errors:
#' An authentication failure signals `zucrypt_auth_error` and returns no
#' plaintext. A key or nonce of the wrong length is `zucrypt_bad_length`, and
#' a missing or non-raw argument is `zucrypt_invalid_argument`.
#'
#' @section Compared with openssl:
#' The names and argument order follow `openssl::aes_gcm_encrypt()` and
#' `openssl::aes_gcm_decrypt()`, and the ciphertext bytes are the same. The
#' behaviour differs on purpose. openssl's encryption returns no tag, and
#' its decryption returns altered plaintext without an error. Here the tag
#' is returned, and decryption fails on any alteration, so these functions
#' are not drop-in replacements.
#'
#' @section Side channels:
#' AES runs on the CPU's AES instructions where it has them, and on a
#' table-based software fallback otherwise; `crypt_info()` reports which, in
#' `build_flags$aes_implementation`. On the fallback both AES and GHASH, the
#' authentication half of GCM, read tables at addresses that depend on the
#' key. See [crypt_aes_cbc_nopad] for what that exposes.
#'
#' @seealso [crypt_rand_bytes()] for keys and nonces, [crypt_pbkdf2()] to
#'   derive a key from a password.
#'
#' @examples
#' key <- crypt_rand_bytes(32)
#' sealed <- crypt_aes_gcm_encrypt(charToRaw("attack at dawn"), key)
#' sealed
#'
#' rawToChar(crypt_aes_gcm_decrypt(sealed, key))
#'
#' # Associated data is authenticated, not encrypted.
#' header <- charToRaw("message 7")
#' sealed <- crypt_aes_gcm_encrypt(charToRaw("hi"), key, aad = header)
#' rawToChar(crypt_aes_gcm_decrypt(sealed, key, aad = header))
#'
#' # Any change is caught, and nothing is decrypted.
#' sealed[1] <- xor(sealed[1], as.raw(1))
#' try(crypt_aes_gcm_decrypt(sealed, key, aad = header))
#'
#' @name crypt_aes_gcm
NULL

#' @rdname crypt_aes_gcm
#' @export
crypt_aes_gcm_encrypt <- function(data, key, iv = crypt_rand_bytes(12),
                                  aad = NULL) {
  algorithm <- check_gcm_args(data, key, iv, aad)
  res <- .Call(zucrypt_aes_gcm, data, key, iv, aad, NULL, TRUE)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  out <- res$value[[1L]]
  attr(out, "iv") <- iv
  attr(out, "tag") <- res$value[[2L]]
  out
}

#' @rdname crypt_aes_gcm
#' @export
crypt_aes_gcm_decrypt <- function(data, key, iv = attr(data, "iv"),
                                  tag = attr(data, "tag"), aad = NULL) {
  algorithm <- check_gcm_args(data, key, iv, aad)
  check_raw(tag, "tag", algorithm = algorithm)
  res <- .Call(zucrypt_aes_gcm, data, key, iv, aad, tag, FALSE)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}

# The checks both directions share, with the condition's call set to the
# exported function. Returns the algorithm label for conditions.
check_gcm_args <- function(data, key, iv, aad, call = sys.call(-1L)) {
  bits <- if (is.raw(key)) 8L * length(key) else NA_integer_
  algorithm <- if (bits %in% c(128L, 192L, 256L)) {
    sprintf("aes-%d-gcm", bits)
  } else {
    "aes-gcm"
  }
  check_raw(data, "data", algorithm = algorithm, call = call)
  check_raw(key, "key", algorithm = algorithm, call = call)
  if (!length(key) %in% c(16L, 24L, 32L)) {
    zucrypt_abort(
      "zucrypt_bad_length",
      sprintf(paste0("`key` must be 16, 24 or 32 bytes (AES-128, AES-192 or ",
                     "AES-256), not %d. This function takes a key, never a ",
                     "password: crypt_pbkdf2() derives one."),
              length(key)),
      algorithm = algorithm,
      call = call
    )
  }
  check_raw(iv, "iv", algorithm = algorithm, call = call)
  if (length(iv) != 12L) {
    zucrypt_abort(
      "zucrypt_bad_length",
      sprintf("`iv` must be exactly 12 bytes, not %d.", length(iv)),
      algorithm = algorithm,
      call = call
    )
  }
  if (!is.null(aad)) {
    check_raw(aad, "aad", algorithm = algorithm, call = call)
  }
  algorithm
}
