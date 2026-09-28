#' AES-CBC, without padding and without authentication
#'
#' @description
#' **These functions provide confidentiality only. They do not authenticate
#' anything.** Ciphertext produced here can be altered by anyone who can reach
#' it, and decryption will return the altered plaintext without complaint.
#' Detecting that is your job, or use an authenticated format. If you must
#' authenticate CBC yourself, the minimum is encrypt-then-MAC, done in full:
#'
#' * compute [crypt_hmac()] over the IV **and** the ciphertext,
#'   `c(iv, ciphertext)`. A MAC over the ciphertext alone lets anyone change
#'   the IV, and with it the first plaintext block, without the tag noticing;
#' * use a MAC key independent of the encryption key;
#' * verify the tag with [crypt_equal()] **before** decrypting, and do not
#'   decrypt at all if it fails.
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
#' @section Side channels:
#' AES runs on the CPU's AES instructions where it has them -- AES-NI on x86,
#' the Cryptography Extension on 64-bit Arm -- chosen at run time, and falls
#' back to a software implementation where it does not. `crypt_info()` says
#' which one this machine uses, in `build_flags$aes_implementation`.
#'
#' The software fallback reads lookup tables at addresses that depend on the
#' key and the data. The backend's own security policy warns that an attacker
#' who can observe cache timing -- another process on the same machine, or,
#' with enough precision, the network -- can recover the key from that. If
#' `aes_implementation` is `"software"` and such an attacker is in your
#' threat model, do not use these functions for secrets that matter. Every
#' implementation produces the same bytes; only this exposure differs.
#'
#' @section Segmented formats:
#' Each call starts from `iv` and treats `data` as one continuous CBC stream.
#' A format that restarts the chaining at segment boundaries -- which is what
#' the Office Agile profiles do -- is expressed as one call per segment, each
#' with that segment's own IV. The C interface exposes the running chaining
#' state directly for consumers that need finer control; see [zucrypt_c_api].
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
#' # Authentication is separate, and is not optional. The tag covers the IV
#' # as well as the ciphertext, under a key of its own.
#' mac_key <- as.raw(rep(0x5c, 32))
#' tag <- crypt_hmac(c(iv, ciphertext), mac_key)
#'
#' # The receiver checks the tag first, and decrypts only if it matches.
#' crypt_equal(tag, crypt_hmac(c(iv, ciphertext), mac_key))
#'
#' # A changed IV would alter the first plaintext block. Because the tag
#' # covers the IV, the change is caught before anything is decrypted.
#' tampered_iv <- iv
#' tampered_iv[1] <- xor(tampered_iv[1], as.raw(1))
#' crypt_equal(tag, crypt_hmac(c(tampered_iv, ciphertext), mac_key))
#'
#' @name crypt_aes_cbc
NULL

#' @rdname crypt_aes_cbc
#' @export
crypt_aes_cbc_encrypt <- function(data, key, iv) {
  check_aes_key(key)
  algorithm <- aes_algorithm(key)
  check_aes_iv(iv, algorithm)
  # check_block_multiple() checks the type as well as the length, so a
  # separate check_raw(data) here would report the same problem twice.
  check_block_multiple(data, algorithm)

  res <- .Call(zucrypt_aes_cbc, data, key, iv, TRUE)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}

#' @rdname crypt_aes_cbc
#' @export
crypt_aes_cbc_decrypt <- function(data, key, iv) {
  check_aes_key(key)
  algorithm <- aes_algorithm(key)
  check_aes_iv(iv, algorithm)
  # check_block_multiple() checks the type as well as the length, so a
  # separate check_raw(data) here would report the same problem twice.
  check_block_multiple(data, algorithm)

  res <- .Call(zucrypt_aes_cbc, data, key, iv, FALSE)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}
