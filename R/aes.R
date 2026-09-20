#' AES-CBC, without padding and without authentication
#'
#' @description
#' **These functions provide confidentiality only. They do not authenticate
#' anything.** Ciphertext produced here can be altered by anyone who can reach
#' it, and decryption will return the altered plaintext without complaint.
#' Detecting that is your job: compute a MAC over the ciphertext with
#' [crypt_hmac()] and verify it with [crypt_equal()] before decrypting, or use
#' an authenticated format.
#'
#' They also add and strip no padding. The input length must already be a
#' multiple of 16 bytes.
#'
#' These are interoperability tools, for reading and writing formats that
#' specify unauthenticated CBC -- the Office encryption profiles are the
#' reason they exist. They are not a general-purpose way to encrypt something
#' of your own; that needs an authenticated construction, a nonce policy and a
#' key derivation step, none of which this package provides.
#'
#' @param data A raw vector whose length is a multiple of 16 bytes.
#' @param key A raw vector of exactly 16, 24 or 32 bytes, selecting AES-128,
#'   AES-192 or AES-256. This is a key, not a password.
#' @param iv A raw vector of exactly 16 bytes, the initialisation vector. For
#'   encryption it must be unpredictable and must not be reused with the same
#'   key; for decryption it is whatever the format says it is.
#'
#' @return A raw vector the same length as `data`. `data` itself is never
#'   modified.
#'
#' @section Segmented formats:
#' Each call starts from `iv` and treats `data` as one continuous CBC stream.
#' A format that restarts the chaining at segment boundaries -- which is what
#' the Office Agile profiles do -- is expressed as one call per segment, each
#' with that segment's own IV. The C interface exposes the running chaining
#' state directly for consumers that need finer control; see `?zucrypt`.
#'
#' @examples
#' key <- as.raw(rep(0x2b, 16))
#' iv <- as.raw(seq.int(0, 15))
#' plaintext <- charToRaw("sixteen bytes!! and sixteen more")
#'
#' ciphertext <- crypt_aes_cbc_encrypt(plaintext, key, iv)
#' ciphertext
#'
#' identical(crypt_aes_cbc_decrypt(ciphertext, key, iv), plaintext)
#'
#' # Authentication is separate, and is not optional.
#' mac_key <- as.raw(rep(0x5c, 32))
#' tag <- crypt_hmac(ciphertext, mac_key)
#' crypt_equal(tag, crypt_hmac(ciphertext, mac_key))
#'
#' @name crypt_aes_cbc
NULL

#' @rdname crypt_aes_cbc
#' @export
crypt_aes_cbc_encrypt <- function(data, key, iv) {
  check_raw(data, "data")
  check_aes_key(key)
  check_aes_iv(iv)
  check_block_multiple(data)

  res <- .Call(zucrypt_aes_cbc, data, key, iv, TRUE)
  if (res$status != 0L) {
    abort_native(res$status)
  }
  res$value
}

#' @rdname crypt_aes_cbc
#' @export
crypt_aes_cbc_decrypt <- function(data, key, iv) {
  check_raw(data, "data")
  check_aes_key(key)
  check_aes_iv(iv)
  check_block_multiple(data)

  res <- .Call(zucrypt_aes_cbc, data, key, iv, FALSE)
  if (res$status != 0L) {
    abort_native(res$status)
  }
  res$value
}
