#' Compute a message digest
#'
#' Hashes a raw vector with one of the digest algorithms this build provides.
#'
#' @param data A raw vector. Character input is never accepted: this package
#'   does not guess a text encoding and never treats a string as a file name.
#'   Convert deliberately with [charToRaw()] or [serialize()].
#' @param algorithm A single algorithm name: one of `"sha1"`, `"sha256"`,
#'   `"sha384"` or `"sha512"`, and whatever `crypt_info()$algorithms` reports
#'   is what this build actually accepts. Matched exactly -- there is no
#'   partial matching and no fallback, so a typo is an error rather than a
#'   quietly different algorithm.
#'
#' @return A raw vector of the digest, 20 bytes for `"sha1"` and 32, 48 or 64
#'   for the SHA-2 family. Hex formatting is an explicit step at the call
#'   site; see the examples.
#'
#' @section Choosing an algorithm:
#' `"sha256"` is the default and the right answer unless something external
#' requires otherwise. `"sha1"` is available because document formats specify
#' it -- notably the Office encryption profiles this package exists to
#' support -- and it is not collision resistant. Do not select it for
#' anything new.
#'
#' @seealso [crypt_hmac()] for a keyed digest, [crypt_equal()] for comparing
#'   digests without leaking timing information.
#'
#' @examples
#' digest <- crypt_hash(charToRaw("the quick brown fox"))
#' digest
#'
#' # Hex, when you need it, is an explicit conversion.
#' paste(format(digest), collapse = "")
#'
#' # The digest of empty input is well defined.
#' crypt_hash(raw(0))
#'
#' crypt_hash(charToRaw("abc"), "sha512")
#'
#' @export
crypt_hash <- function(data, algorithm = "sha256") {
  check_raw(data, "data")
  check_algorithm(algorithm)

  res <- .Call(zucrypt_hash, data, algorithm)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}

#' Compute an HMAC
#'
#' Computes a keyed message authentication code (RFC 2104) over a raw vector.
#'
#' @inheritParams crypt_hash
#' @param key A raw vector holding the key. Any length is accepted, including
#'   zero, as the standard specifies. This is a key, not a password: deriving
#'   a key from a password is the caller's responsibility and is not something
#'   this package does for you.
#'
#' @return A raw vector the length of the underlying digest.
#'
#' @section Verifying a MAC:
#' Compare with [crypt_equal()], never with `identical()` or `==`. An ordinary
#' comparison stops at the first differing byte, and the time it takes is
#' therefore a measurement of how much of the expected value an attacker has
#' guessed.
#'
#' @examples
#' key <- as.raw(rep(0x0b, 20))
#' tag <- crypt_hmac(charToRaw("Hi There"), key)
#' tag
#'
#' # Verification, done properly.
#' crypt_equal(tag, crypt_hmac(charToRaw("Hi There"), key))
#'
#' @export
crypt_hmac <- function(data, key, algorithm = "sha256") {
  check_raw(data, "data")
  check_raw(key, "key")
  check_algorithm(algorithm)

  res <- .Call(zucrypt_hmac, data, key, algorithm)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}

#' Compare two raw vectors without leaking timing information
#'
#' Compares in time that does not depend on the contents of the buffers. Use
#' it whenever one side is a secret: an authentication tag, a password
#' verifier, a derived key.
#'
#' @param x,y Raw vectors.
#'
#' @return `TRUE` if the vectors have the same length and the same contents,
#'   otherwise `FALSE`.
#'
#' @section Length is not hidden:
#' Vectors of different lengths return `FALSE` immediately, without comparing
#' anything. Hiding a length difference is not something a comparison function
#' can do, and pretending otherwise would be worse than saying so: if the
#' length of your secret is itself secret, compare digests of the values
#' rather than the values.
#'
#' @examples
#' a <- crypt_hash(charToRaw("message"))
#' b <- crypt_hash(charToRaw("message"))
#' crypt_equal(a, b)
#'
#' crypt_equal(a, crypt_hash(charToRaw("different")))
#'
#' # Different lengths are simply not equal.
#' crypt_equal(a, raw(0))
#'
#' @export
crypt_equal <- function(x, y) {
  check_raw(x, "x")
  check_raw(y, "y")

  if (length(x) != length(y)) {
    return(FALSE)
  }
  .Call(zucrypt_equal, x, y)
}
