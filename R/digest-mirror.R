#' Digests in the Style of openssl
#'
#' @description
#' `crypt_sha1()`, `crypt_sha256()`, `crypt_sha384()` and `crypt_sha512()`
#' mirror `openssl::sha1()` and its siblings for raw input: the digest, or
#' with `key` the HMAC, as a raw vector of class `c("hash", "<algorithm>")`,
#' and `"hmac"` after them for an HMAC.
#' They exist first so that [crypt_signature_create()] can take `hash =
#' crypt_sha256` as `openssl::signature_create()` takes `hash = sha256`.
#'
#' This version accepts raw vectors only. openssl also hashes character
#' vectors element-wise and reads connections; that typing, and the other
#' digests, arrive with the rest of the openssl-shaped layer.
#'
#' `crypt_sha1()` is for formats that specify SHA-1. It is not collision
#' resistant; use `crypt_sha256()` for anything new.
#'
#' @param x A raw vector.
#' @param key `NULL` for a digest, or a raw key for an HMAC.
#'
#' @return A raw vector of class `c("hash", "<algorithm>")`: 20, 32, 48 or 64
#'   bytes.
#'
#' @seealso [crypt_hash()] and [crypt_hmac()], the core functions these
#'   wrap.
#'
#' @examples
#' crypt_sha256(charToRaw("abc"))
#' crypt_sha256(charToRaw("abc"), key = charToRaw("secret"))
#'
#' @name crypt_sha
NULL

mirror_digest <- function(x, key, algorithm) {
  call <- sys.call(-1L)
  if (!is.raw(x)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("`x` must be a raw vector. Character and connection input to ",
             "the openssl-style digests is not supported yet; use ",
             "charToRaw() or crypt_hash(file(path))."),
      algorithm = algorithm,
      call = call
    )
  }
  out <- if (is.null(key)) {
    crypt_hash(x, algorithm)
  } else {
    check_raw(key, "key", algorithm = algorithm, call = call)
    crypt_hmac(x, key, algorithm)
  }
  structure(out, class = c("hash", algorithm, if (!is.null(key)) "hmac"))
}

#' @rdname crypt_sha
#' @export
crypt_sha1 <- function(x, key = NULL) mirror_digest(x, key, "sha1")

#' @rdname crypt_sha
#' @export
crypt_sha256 <- function(x, key = NULL) mirror_digest(x, key, "sha256")

#' @rdname crypt_sha
#' @export
crypt_sha384 <- function(x, key = NULL) mirror_digest(x, key, "sha384")

#' @rdname crypt_sha
#' @export
crypt_sha512 <- function(x, key = NULL) mirror_digest(x, key, "sha512")
