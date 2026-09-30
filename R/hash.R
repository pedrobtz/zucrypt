#' Compute a Message Digest
#'
#' Hashes a raw vector, or everything a connection yields, with one of the
#' digest algorithms this build provides.
#'
#' @param data A raw vector, or a connection to read to its end (see
#'   "Files and connections" below). Character input is never accepted: this
#'   package does not guess a text encoding and never treats a string as a
#'   file name. Convert deliberately with [charToRaw()] or [serialize()], or
#'   pass `file(path)` to hash a file.
#' @param algorithm A single algorithm name: one of `"sha1"`, `"sha256"`,
#'   `"sha384"` or `"sha512"`, and whatever `crypt_info()$algorithms` reports
#'   is what this build actually accepts. Matched exactly -- there is no
#'   partial matching and no fallback, so a typo is an error rather than a
#'   quietly different algorithm.
#'
#' @return A raw vector of the digest, 20 bytes for `"sha1"` and 32, 48 or 64
#'   for the SHA-2 family. Hex formatting is an explicit step at the call
#'   site, with [crypt_hex()]; see the examples.
#'
#' @section Choosing an algorithm:
#' `"sha256"` is the default and the right answer unless something external
#' requires otherwise. `"sha1"` is available because document formats specify
#' it -- notably the Office encryption profiles this package exists to
#' support -- and it is not collision resistant. Do not select it for
#' anything new.
#'
#' @section Files and connections:
#' A connection is read in 1 MiB chunks, so a file of any size is hashed
#' without being held in memory, and the call can be interrupted. Pass an
#' unopened connection, such as `file(path)`, and it is opened in binary mode
#' (`"rb"`) and closed again afterwards; pass one you have already opened and
#' it is read from where it stands to its end, and left open.
#'
#' An open connection must be in binary mode. A text-mode connection can
#' re-encode or translate line endings before the bytes arrive, which would
#' hash something other than the file, so it is refused with
#' `zucrypt_invalid_argument`. A connection that cannot be opened signals
#' `zucrypt_connection_error`, as does a non-blocking connection that runs out
#' of data before its end, which is refused rather than hashed short. An
#' error while reading is R's own.
#'
#' What is hashed is what the connection yields: `gzfile()` gives the
#' decompressed bytes, `file()` the bytes on disk.
#'
#' @seealso [crypt_hmac()] for a keyed digest, [crypt_equal()] for comparing
#'   digests without leaking timing information, [crypt_hex()] for hex.
#'
#' @examples
#' digest <- crypt_hash(charToRaw("the quick brown fox"))
#' digest
#'
#' # Hex, when you need it, is an explicit conversion.
#' crypt_hex(digest)
#'
#' # The digest of empty input is well defined.
#' crypt_hash(raw(0))
#'
#' crypt_hash(charToRaw("abc"), "sha512")
#'
#' # A file, read in chunks rather than all at once.
#' path <- tempfile()
#' writeBin(charToRaw("abc"), path)
#' identical(crypt_hash(file(path)), crypt_hash(charToRaw("abc")))
#' unlink(path)
#'
#' @export
crypt_hash <- function(data, algorithm = "sha256") {
  if (inherits(data, "connection")) {
    check_algorithm(algorithm)
    return(digest_connection(data, algorithm))
  }
  check_raw(data, "data", connection_ok = TRUE)
  check_algorithm(algorithm)

  res <- .Call(zucrypt_hash, data, algorithm)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}

#' Compute an HMAC
#'
#' Computes a keyed message authentication code (RFC 2104) over a raw vector,
#' or over everything a connection yields.
#'
#' @inheritParams crypt_hash
#' @param key A raw vector holding the key. Any length is accepted, including
#'   zero, as the standard specifies. This is a key, not a password: deriving
#'   a key from a password is the caller's responsibility and is not something
#'   this package does for you.
#'
#' @return A raw vector the length of the underlying digest.
#'
#' @section Files and connections:
#' `data` may be a connection, read in chunks exactly as for [crypt_hash()];
#' see "Files and connections" there. The key is always a raw vector.
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
  if (inherits(data, "connection")) {
    check_raw(key, "key")
    check_algorithm(algorithm)
    return(digest_connection(data, algorithm, key = key))
  }
  check_raw(data, "data", connection_ok = TRUE)
  check_raw(key, "key")
  check_algorithm(algorithm)

  res <- .Call(zucrypt_hmac, data, key, algorithm)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm)
  }
  res$value
}

#' Compare Two Raw Vectors Without Leaking Timing Information
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

# Stream a connection through a native digest or HMAC context (#11). R reads
# and C hashes: each chunk is a readBin() of at most 1 MiB, so memory stays
# flat, and the loop is R code, so an interrupt lands between chunks. The
# context lives in an external pointer from zucrypt_*_stream_new() onwards;
# finish releases it eagerly, and an interrupt or error leaves it to the
# finalizer (tests/testthat/test-lifetime.R).
digest_connection <- function(con, algorithm, key = NULL,
                              call = sys.call(-1L)) {
  open_now <- tryCatch(isOpen(con), error = function(e) e)
  if (inherits(open_now, "error")) {
    zucrypt_abort(
      "zucrypt_connection_error",
      sprintf("Not a usable connection: %s", conditionMessage(open_now)),
      algorithm = algorithm, call = call
    )
  }
  if (!open_now) {
    # Opened here, so closed here, on every path: close() on a connection
    # whose open() failed destroys it, rather than leaving R to warn later
    # about an unused connection.
    on.exit(close(con), add = TRUE)
    failed <- tryCatch(
      {
        open(con, "rb")
        NULL
      },
      # file() warns with the reason and then errors with "cannot open the
      # connection"; the warning is the part worth reporting.
      warning = function(w) w,
      error = function(e) e
    )
    if (!is.null(failed)) {
      zucrypt_abort(
        "zucrypt_connection_error",
        sprintf("Cannot open the connection for reading: %s",
                conditionMessage(failed)),
        algorithm = algorithm, call = call
      )
    }
  }

  info <- summary(con)
  if (!identical(info[["can read"]], "yes") ||
      !identical(info[["text"]], "binary")) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("The connection must be readable and in binary mode (\"rb\"). ",
             "A text-mode connection may re-encode the bytes before they ",
             "are hashed; open it with open = \"rb\", or pass it unopened."),
      algorithm = algorithm, call = call
    )
  }

  res <- if (is.null(key)) {
    .Call(zucrypt_hash_stream_new, algorithm)
  } else {
    .Call(zucrypt_hmac_stream_new, key, algorithm)
  }
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm, call = call)
  }
  stream <- res$value

  # readBin() is deliberately not wrapped: a handler here would also catch
  # an interrupt-time error (setTimeLimit()) and misreport it as the
  # connection's fault. A read error mid-stream is R's own error.
  repeat {
    chunk <- readBin(con, "raw", n = 1048576L)
    if (length(chunk) == 0L) {
      break
    }
    status <- .Call(zucrypt_stream_update, stream, chunk)
    if (status != 0L) {
      abort_native(status, algorithm = algorithm, call = call)
    }
  }

  # A non-blocking connection returns nothing when it has nothing *yet*;
  # stopping there would hash a prefix and report it as the whole.
  if (isIncomplete(con)) {
    zucrypt_abort(
      "zucrypt_connection_error",
      paste0("The connection had no more data available before its end ",
             "(is it non-blocking?); hashing a prefix would be wrong."),
      algorithm = algorithm, call = call
    )
  }

  res <- .Call(zucrypt_stream_finish, stream)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = algorithm, call = call)
  }
  res$value
}
