#' Cryptographically Secure Random Bytes
#'
#' Draws `n` bytes from the operating system's cryptographic random source:
#' `rand_s` on Windows, `arc4random_buf` on macOS and the BSDs, `getrandom` on
#' Linux with glibc 2.25 or later, and `/dev/urandom` elsewhere.
#' [crypt_info()] names the one compiled in, in
#' `build_flags$random_backend`. Use these bytes for keys, initialisation
#' vectors, nonces and salts.
#'
#' **R's random number generator is never involved.** [set.seed()] has no
#' effect on these bytes and they do not change `.Random.seed`, so drawing
#' them does not disturb a reproducible simulation running beside them. That
#' is deliberate: R's generator is seeded from the session and reproducible on
#' purpose, which is exactly what a key must not be.
#'
#' The name, argument and default mirror `openssl::rand_bytes()`, so code
#' moving from openssl changes only the prefix.
#'
#' @param n The number of bytes: a single non-negative whole number. `n = 0`
#'   returns `raw(0)`.
#'
#' @return A raw vector of length `n`.
#'
#' @section Errors:
#' A failure of the operating-system source raises an error of class
#' `zucrypt_entropy_error`. It never returns fewer bytes than asked for, and
#' never returns bytes from a source that reported failure. An invalid `n` is
#' `zucrypt_invalid_argument`.
#'
#' @seealso [crypt_aes_cbc_encrypt_nopad()], whose `iv` for encryption must be
#'   unpredictable: `crypt_rand_bytes(16)` is one.
#'
#' @examples
#' crypt_rand_bytes(16)
#'
#' # A 256-bit key, printed as hex.
#' crypt_hex(crypt_rand_bytes(32))
#'
#' # set.seed() does not repeat it.
#' set.seed(1)
#' a <- crypt_rand_bytes(8)
#' set.seed(1)
#' b <- crypt_rand_bytes(8)
#' identical(a, b)
#'
#' @export
crypt_rand_bytes <- function(n = 1) {
  if (!is.numeric(n) || length(n) != 1L || is.na(n) || !is.finite(n) ||
        n < 0 || n != trunc(n) || n > 2^52) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`n` must be a single non-negative whole number of bytes."
    )
  }
  res <- .Call(zucrypt_rand_bytes, as.double(n))
  if (res$status != 0L) {
    abort_native(res$status)
  }
  res$value
}
