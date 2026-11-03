#' Derive a Key from a Password with PBKDF2
#'
#' `crypt_pbkdf2()` stretches a password into a key with PBKDF2 (RFC 8018,
#' section 5.2), using HMAC with the chosen digest as the pseudorandom
#' function.
#'
#' PBKDF2 derives a key. It is not an encryption format and not a password
#' storage format. The salt, the iteration count and the digest are yours to
#' choose, store beside what the key protects, and supply again to derive the
#' same key.
#'
#' @param password The password, as a raw vector. A string is not accepted,
#'   because its bytes depend on an encoding: convert deliberately, for
#'   example with `charToRaw(enc2utf8(x))`. It may be empty.
#' @param salt The salt, as a raw vector. Use at least 16 random bytes from
#'   [crypt_rand_bytes()], a fresh salt for each password. It may be empty,
#'   which only interoperability with an existing format justifies.
#' @param iterations The iteration count, a whole number from 1 to
#'   4294967295. It has no default, because the right value depends on the
#'   digest, the hardware and the time you can afford. OWASP recommended
#'   600,000 for `"sha256"` in 2023.
#' @param length The number of bytes to derive, a whole number of at least 1.
#'   32 gives an AES-256 key.
#' @param algorithm The digest for the HMAC: `"sha256"` (the default),
#'   `"sha384"`, `"sha512"` or `"sha1"`. `"sha1"` is for formats that specify
#'   it, never for anything new.
#'
#' @return A raw vector of `length` bytes.
#'
#' @section Cost:
#' The time is proportional to `iterations` times the number of digest-sized
#' blocks in `length`, and the call cannot be interrupted. Bound
#' `iterations` before passing a value that came from untrusted input, such
#' as a file header.
#'
#' @section Errors:
#' An invalid argument is `zucrypt_invalid_argument`, and an unknown digest
#' is `zucrypt_unsupported_algorithm`.
#'
#' @seealso [crypt_aes_gcm_encrypt()], which takes the key this derives.
#'
#' @examples
#' salt <- crypt_rand_bytes(16)
#' key <- crypt_pbkdf2(charToRaw("correct horse"), salt, iterations = 10000)
#' key
#'
#' # RFC 6070, test case 2.
#' crypt_hex(crypt_pbkdf2(charToRaw("password"), charToRaw("salt"),
#'                        iterations = 2, length = 20, algorithm = "sha1"))
#'
#' @export
crypt_pbkdf2 <- function(password, salt, iterations, length = 32,
                         algorithm = "sha256") {
  check_raw(password, "password", algorithm = "pbkdf2")
  check_raw(salt, "salt", algorithm = "pbkdf2")
  check_algorithm(algorithm)
  if (!is_count(iterations, 1, 4294967295)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`iterations` must be a single whole number from 1 to 4294967295.",
      algorithm = "pbkdf2"
    )
  }
  if (!is_count(length, 1, 2^31 - 1)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`length` must be a single whole number of bytes, at least 1.",
      algorithm = "pbkdf2"
    )
  }
  res <- .Call(zucrypt_pbkdf2, password, salt, as.double(iterations),
               as.double(length), algorithm)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = "pbkdf2")
  }
  res$value
}

# A single whole number in [lo, hi].
is_count <- function(x, lo, hi) {
  is.numeric(x) && length(x) == 1L && !is.na(x) && is.finite(x) &&
    x == trunc(x) && x >= lo && x <= hi
}
