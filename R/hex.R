#' Encode Bytes as Hexadecimal
#'
#' Converts a raw vector to one lower-case hexadecimal string, two digits per
#' byte, with no separators and no prefix: the form `sha256sum` prints and
#' most formats store. The conversion runs in C, so for a short digest it
#' costs far less than the hash itself.
#'
#' Hex is an explicit step at the call site rather than an option on
#' [crypt_hash()] and [crypt_hmac()], so the digest functions return one type
#' and a caller who wants text says so. It works on any bytes: a digest, a
#' MAC, a key you need to print for a test.
#'
#' @param x A raw vector, at most 2^30 - 1 bytes long (a longer result would
#'   exceed R's limit on the length of a single string).
#'
#' @return A character vector of length one, `2 * length(x)` characters long.
#'   `crypt_hex(raw(0))` is `""`.
#'
#' @seealso [crypt_hash()] and [crypt_hmac()], whose results this is usually
#'   applied to.
#'
#' @examples
#' crypt_hex(crypt_hash(charToRaw("abc")))
#'
#' crypt_hex(as.raw(c(0x00, 0x0f, 0xa0, 0xff)))
#'
#' crypt_hex(raw(0))
#'
#' @export
crypt_hex <- function(x) {
  check_raw(x, "x")
  # A CHARSXP's length is an int, and the result is two characters a byte.
  if (length(x) > 1073741823) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("`x` is too long to encode as a single hex string ",
             "(the limit is 2^30 - 1 bytes).")
    )
  }
  .Call(zucrypt_hex, x)
}
