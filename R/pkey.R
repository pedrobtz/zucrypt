#' RSA Keys
#'
#' @description
#' Read, write, generate and take apart RSA keys. The names, arguments and
#' defaults follow the `openssl` package with a `crypt_` prefix, and the
#' encodings interoperate: a key one package writes, the other reads.
#'
#' * `crypt_read_key()` reads a private key and `crypt_read_pubkey()` a
#'   public key, from PEM or DER: PKCS#1, PKCS#8 or SubjectPublicKeyInfo.
#'   `crypt_read_pubkey()` also accepts a private key and keeps its public
#'   half.
#' * `crypt_write_pem()` writes PKCS#8 (`PRIVATE KEY`) or
#'   SubjectPublicKeyInfo (`PUBLIC KEY`) PEM; `crypt_write_pkcs1()` writes
#'   PKCS#1 PEM (`RSA PRIVATE KEY`, `RSA PUBLIC KEY`); `crypt_write_der()`
#'   writes a private key as PKCS#1 DER and a public key as
#'   SubjectPublicKeyInfo DER, as `openssl::write_der()` does.
#' * `crypt_rsa_keygen()` generates a key pair from the operating system's
#'   random source.
#' * `crypt_rsa_key()` builds a key from its integers, as a JSON Web Key
#'   carries them, and `as.list()` takes one apart again.
#'
#' A key object is an external pointer to key material held in C, and the
#' material of a private key is wiped when the object is garbage collected.
#' Key objects do not survive [saveRDS()]; save the PEM instead.
#'
#' @param file The key: a raw vector of DER or PEM bytes, a single string of
#'   PEM text, a path to a file holding either, or a connection.
#' @param password Not supported yet: password-protected keys arrive in a
#'   later version. Must be `NULL`.
#' @param der Accepted for compatibility with `openssl`; the encoding is
#'   recognised from the content.
#' @param x A key from `crypt_read_key()`, `crypt_read_pubkey()`,
#'   `crypt_rsa_keygen()` or `crypt_rsa_key()`.
#' @param path `NULL` to return the encoding, or a file to write it to.
#' @param bits The modulus size, a multiple of 8 from 1024 to 4096. 2048 is
#'   the minimum for new keys; use 3072 or more for keys meant to last.
#' @param n,e The modulus and the public exponent, as raw big-endian
#'   unsigned integers.
#' @param d,p,q,dp,dq,qi The private exponent, the primes and the CRT
#'   parameters, as raw big-endian unsigned integers. Give all six for a
#'   private key, or none for a public key.
#'
#' @return `crypt_read_key()`, `crypt_rsa_keygen()` and `crypt_rsa_key()`
#'   with the private members return a key of class `c("crypt_key",
#'   "crypt_rsa")`; `crypt_read_pubkey()` and `crypt_rsa_key()` without them
#'   return one of class `c("crypt_pubkey", "crypt_rsa")`. `crypt_write_pem()`
#'   and `crypt_write_pkcs1()` return a string, and `crypt_write_der()` a raw
#'   vector, or with `path` write it and return `path` invisibly. `as.list()`
#'   returns `type`, `size`, for a private key `pubkey`, and `data`: the
#'   integers as raw vectors, `e`, `n` and for a private key `p`, `q`, `d`,
#'   `dp`, `dq` and `qi`.
#'
#' @section Errors:
#' Input that is not a readable key is `zucrypt_invalid_argument`, and so
#' is a public key object given where a private key is needed. A
#' well-formed key this version cannot use (an RSA key outside the size
#' rule, a curve other than P-256, P-384 and P-521, or an encrypted key) is
#' `zucrypt_unsupported_algorithm`. A condition about a key carries the
#' key's type in its `algorithm` field (`"rsa"`, `"p256"`, `"p384"`,
#' `"p521"` or `"x25519"`), and `NA` when the input is not a key.
#'
#' @section Key objects:
#' A key object refers to key material held outside R, so a copy is the same
#' key, not a new one: changing the attributes of `k2 <- k` changes `k`
#' too. Key objects do not survive `saveRDS()`; save the output of
#' `crypt_write_pem()` instead.
#'
#' @section Compared with openssl:
#' RSA keys are read only if the modulus is 1024 to 4096 bits, a whole
#' number of bytes; `openssl` also reads smaller keys, which are weak, and
#' larger ones. EC keys on P-256, P-384 and P-521, and X25519 keys, are read
#' as `openssl` writes them. Encrypted keys, SSH formats and fingerprints
#' come later. `as.list()` gives the integers as raw vectors rather than
#' `bignum`s. There is no default key:
#' `openssl` reads `~/.ssh/id_rsa`, and this package never reads your files
#' unless you name them.
#'
#' @examples
#' key <- crypt_rsa_keygen(2048)
#' key
#' pem <- crypt_write_pem(key$pubkey)
#' cat(pem)
#' pub <- crypt_read_pubkey(pem)
#'
#' # The integers a JSON Web Key carries, and back.
#' parts <- as.list(pub)$data
#' identical(crypt_write_der(crypt_rsa_key(parts$n, parts$e)),
#'           crypt_write_der(pub))
#'
#' @name crypt_rsa_keys
NULL

# --- input --------------------------------------------------------------

# openssl's path_or_raw(): raw as is, PEM text as its bytes, a path read,
# a connection read to its end.
key_input <- function(file, arg = "file", call = sys.call(-1L)) {
  if (is.raw(file)) {
    return(file)
  }
  if (inherits(file, "connection")) {
    return(read_all(file, call))
  }
  if (is.character(file) && length(file) == 1L && !is.na(file)) {
    if (grepl("-----BEGIN", file, fixed = TRUE)) {
      return(charToRaw(file))
    }
    if (dir.exists(file)) {
      zucrypt_abort(
        "zucrypt_invalid_argument",
        sprintf("`%s` names a directory, not a file.", arg),
        call = call
      )
    }
    if (file.exists(file)) {
      # Read to its end through a connection rather than by file.size(),
      # which a growing file outruns: the bytes read are the bytes there.
      return(read_all(file(file), call))
    }
  }
  zucrypt_abort(
    "zucrypt_invalid_argument",
    sprintf(paste0("`%s` must be a raw vector, PEM text, the path of an ",
                   "existing file, or a connection."), arg),
    call = call
  )
}

# A connection's bytes, through read_connection()'s guards (#145).
read_all <- function(con, call) {
  chunks <- list(raw())
  read_connection(con, function(chunk) {
    chunks[[length(chunks) + 1L]] <<- chunk
  }, call = call)
  do.call(c, chunks)
}

no_password <- function(password, call = sys.call(-1L),
                        algorithm = NA_character_) {
  if (!is.null(password)) {
    zucrypt_abort(
      "zucrypt_unsupported_algorithm",
      "Password-protected keys are not supported in this version.",
      algorithm = algorithm,
      call = call
    )
  }
}

# The type of a key object ("rsa", "p256", "p384", "p521", "x25519"), for a
# condition's `algorithm` field, or NA when `x` is not a live key (#143).
key_algorithm <- function(x) {
  if (!inherits(x, c("crypt_key", "crypt_pubkey"))) {
    return(NA_character_)
  }
  res <- .Call(zucrypt_pkey_info, x)
  if (res$status != 0L) NA_character_ else res$value$type
}

# A key argument of a function that needs a private key: a key object, or
# anything crypt_read_key() reads. A public key object is refused as such,
# naming `arg` and the user's function (#143).
private_key_arg <- function(x, arg, call) {
  if (inherits(x, "crypt_key")) {
    return(x)
  }
  if (inherits(x, "crypt_pubkey")) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      sprintf("`%s` is a public key; this needs a private key.", arg),
      algorithm = key_algorithm(x),
      call = call
    )
  }
  parse_key(key_input(x, arg, call), TRUE, call)
}

# A key argument of a function that uses a public key: a public key object,
# the public half of a private one, or anything crypt_read_pubkey() reads.
public_key_arg <- function(x, arg, call) {
  if (inherits(x, "crypt_pubkey")) {
    return(x)
  }
  if (inherits(x, "crypt_key")) {
    return(public_of(x, call))
  }
  parse_key(key_input(x, arg, call), FALSE, call)
}

# The zuc_alg names of key types, and the class and curve name each gets.
key_families <- c(rsa = "crypt_rsa", p256 = "crypt_ecdsa",
                  p384 = "crypt_ecdsa", p521 = "crypt_ecdsa",
                  x25519 = "crypt_x25519")
curve_names <- c(p256 = "P-256", p384 = "P-384", p521 = "P-521")

new_key <- function(ptr) {
  info <- pkey_info(ptr)
  class(ptr) <- c(if (info$private) "crypt_key" else "crypt_pubkey",
                  unname(key_families[info$type]))
  ptr
}

# openssl's type names, for as.list() and print().
key_type_name <- function(type) {
  c(rsa = "rsa", p256 = "ecdsa", p384 = "ecdsa", p521 = "ecdsa",
    x25519 = "x25519")[[type]]
}

pkey_info <- function(x, call = sys.call(-1L)) {
  res <- .Call(zucrypt_pkey_info, x)
  if (res$status != 0L) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("This key object is no longer valid. Key objects do not ",
             "survive saveRDS(); save crypt_write_pem() output instead."),
      call = call
    )
  }
  res$value
}

# Key objects are passed to C as they are: an external pointer is never
# duplicated, so stripping its attributes here would strip the caller's.
parse_key <- function(bytes, private, call) {
  res <- .Call(zucrypt_pkey_parse, bytes, private)
  if (res$status != 0L) {
    name <- names(zuc_status_codes())[match(res$status, zuc_status_codes())]
    if (identical(name, "ZUC_ERR_INVALID_ARGUMENT")) {
      zucrypt_abort(
        "zucrypt_invalid_argument",
        sprintf(paste0("The input is not %s key in PEM or DER that this ",
                       "version can read."),
                if (private) "an unencrypted private" else "a"),
        call = call
      )
    }
    if (identical(name, "ZUC_ERR_UNSUPPORTED")) {
      zucrypt_abort(
        "zucrypt_unsupported_algorithm",
        paste0("Only RSA keys of 1024 to 4096 bits, in whole bytes, and ",
               "P-256, P-384, P-521 and X25519 keys, are supported."),
        call = call
      )
    }
    abort_native(res$status, call = call)
  }
  new_key(res$value)
}

#' @rdname crypt_rsa_keys
#' @export
crypt_read_key <- function(file, password = NULL, der = is.raw(file)) {
  call <- sys.call()
  no_password(password, call, key_algorithm(file))
  private_key_arg(file, "file", call)
}

#' @rdname crypt_rsa_keys
#' @export
crypt_read_pubkey <- function(file, der = is.raw(file)) {
  public_key_arg(file, "file", sys.call())
}

public_of <- function(key, call) {
  info <- pkey_info(key, call)
  res <- .Call(zucrypt_pkey_public, key)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = info$type, call = call)
  }
  new_key(res$value)
}

#' @rdname crypt_rsa_keys
#' @export
crypt_rsa_keygen <- function(bits = 2048) {
  call <- sys.call()
  if (!is_count(bits, 1024, 4096) || bits %% 8 != 0) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`bits` must be a multiple of 8 from 1024 to 4096.",
      algorithm = "rsa",
      call = call
    )
  }
  res <- .Call(zucrypt_pkey_generate, "rsa", as.double(bits))
  if (res$status != 0L) {
    abort_native(res$status, algorithm = "rsa", call = call)
  }
  new_key(res$value)
}

# --- output -------------------------------------------------------------

# zuc_pkey_format values in zucrypt.h.
pkey_formats <- c(pkcs1_der = 1L, pkcs1_pem = 2L, info_der = 3L,
                  info_pem = 4L)

check_key_object <- function(x, call) {
  if (!inherits(x, c("crypt_key", "crypt_pubkey"))) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("`x` must be a key object, from crypt_read_key(), ",
             "crypt_read_pubkey() or one of the key constructors."),
      call = call
    )
  }
  pkey_info(x, call)
}

write_key <- function(x, format, call, public_only = FALSE) {
  info <- check_key_object(x, call)
  res <- .Call(zucrypt_pkey_write, x, pkey_formats[[format]],
               public_only)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = info$type, call = call)
  }
  res$value
}

write_out <- function(value, path) {
  if (is.null(path)) {
    return(value)
  }
  if (is.character(value)) writeLines(value, path, sep = "") else
    writeBin(value, path)
  invisible(path)
}

#' @rdname crypt_rsa_keys
#' @export
crypt_write_pem <- function(x, path = NULL, password = NULL) {
  call <- sys.call()
  no_password(password, call, key_algorithm(x))
  write_out(rawToChar(write_key(x, "info_pem", call)), path)
}

#' @rdname crypt_rsa_keys
#' @export
crypt_write_der <- function(x, path = NULL) {
  call <- sys.call()
  # As openssl::write_der(): a private RSA or EC key in its own structure
  # (PKCS#1, SEC1); an X25519 key, which has none, and every public key in
  # the standard ones (PKCS#8, SubjectPublicKeyInfo).
  format <- if (inherits(x, "crypt_key") && !inherits(x, "crypt_x25519")) {
    "pkcs1_der"
  } else {
    "info_der"
  }
  write_out(write_key(x, format, call), path)
}

#' @rdname crypt_rsa_keys
#' @export
crypt_write_pkcs1 <- function(x, path = NULL, password = NULL) {
  call <- sys.call()
  no_password(password, call, key_algorithm(x))
  write_out(rawToChar(write_key(x, "pkcs1_pem", call)), path)
}

# --- integers -----------------------------------------------------------

# Minimal DER for the two PKCS#1 structures (RFC 8017 appendix A.1.1 and
# A.1.2): a SEQUENCE of INTEGERs. The C side parses and validates the
# result, so a malformed key is refused there.
der_length <- function(n) {
  if (n < 128) {
    return(as.raw(n))
  }
  bytes <- raw()
  while (n > 0) {
    bytes <- c(as.raw(n %% 256), bytes)
    n <- n %/% 256
  }
  c(as.raw(0x80 + length(bytes)), bytes)
}

der_integer <- function(x) {
  x <- x[cumsum(x != as.raw(0)) > 0]
  if (!length(x)) x <- as.raw(0)
  if (as.integer(x[[1]]) >= 128L) x <- c(as.raw(0), x)
  c(as.raw(0x02), der_length(length(x)), x)
}

der_sequence <- function(parts) {
  body <- unlist(parts, use.names = FALSE)
  c(as.raw(0x30), der_length(length(body)), body)
}

# The INTEGERs of a DER SEQUENCE, as unsigned big-endian raw vectors, or an
# error when `der` is not exactly such a SEQUENCE (#91). Every length is
# checked against the input before it is used, because indexing a raw vector
# past its end gives 00 rather than an error, and a truncated INTEGER would
# come back padded with invented zeros. The result must then re-encode to
# the input byte for byte, which is what makes the reading strict: a
# negative or non-minimal INTEGER, a non-minimal or indefinite length, and
# trailing bytes all re-encode differently. The backend's own PKCS#1 output
# is canonical DER, so as.list() on a key is unaffected.
der_integers <- function(der) {
  bad <- function() stop("not a DER SEQUENCE of INTEGERs", call. = FALSE)
  n <- length(der)
  read_len <- function(pos) {
    if (pos > n) bad()
    b <- as.integer(der[[pos]])
    if (b < 128L) return(c(b, 1L))
    k <- b - 128L
    if (k < 1L || k > 4L || pos + k > n) bad()
    c(sum(as.integer(der[pos + seq_len(k)]) * 256^((k - 1):0)), 1L + k)
  }
  if (n < 2L || der[[1]] != as.raw(0x30)) bad()
  seq_len_at <- read_len(2L)
  pos <- 2L + seq_len_at[[2]]
  if (pos - 1L + seq_len_at[[1]] != n) bad()
  out <- list()
  while (pos <= n) {
    if (der[[pos]] != as.raw(0x02)) bad()
    l <- read_len(pos + 1L)
    start <- pos + 1L + l[[2]]
    if (l[[1]] < 1 || start + l[[1]] - 1L > n) bad()
    value <- der[start + seq_len(l[[1]]) - 1L]
    if (as.integer(value[[1]]) >= 128L) bad()
    value <- value[cumsum(value != as.raw(0)) > 0]
    out[[length(out) + 1L]] <- if (length(value)) value else as.raw(0)
    pos <- start + l[[1]]
  }
  if (!identical(der_sequence(lapply(out, der_integer)), der)) bad()
  out
}

#' @rdname crypt_rsa_keys
#' @export
crypt_rsa_key <- function(n, e, d = NULL, p = NULL, q = NULL, dp = NULL,
                          dq = NULL, qi = NULL) {
  call <- sys.call()
  check_raw(n, "n", algorithm = "rsa", call = call)
  check_raw(e, "e", algorithm = "rsa", call = call)
  private <- list(d = d, p = p, q = q, dp = dp, dq = dq, qi = qi)
  given <- !vapply(private, is.null, logical(1))
  if (any(given) && !all(given)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("A private key needs all of `d`, `p`, `q`, `dp`, `dq` and ",
             "`qi`; a public key needs none of them."),
      algorithm = "rsa",
      call = call
    )
  }
  for (name in names(private)[given]) {
    check_raw(private[[name]], name, algorithm = "rsa", call = call)
  }
  der <- if (all(given)) {
    der_sequence(lapply(
      list(as.raw(0), n, e, d, p, q, dp, dq, qi),
      der_integer
    ))
  } else {
    der_sequence(lapply(list(n, e), der_integer))
  }
  parse_key(der, all(given), call)
}

#' @export
as.list.crypt_key <- function(x, ...) {
  call <- sys.call()
  info <- pkey_info(x, call)
  if (info$type != "rsa") {
    return(ec_as_list(x, info, call))
  }
  v <- der_integers(write_key(x, "pkcs1_der", call))
  names(v) <- c("version", "n", "e", "d", "p", "q", "dp", "dq", "qi")
  list(
    type = info$type,
    size = info$bits,
    pubkey = public_of(x, call),
    data = v[c("e", "n", "p", "q", "d", "dp", "dq", "qi")]
  )
}

#' @export
as.list.crypt_pubkey <- function(x, ...) {
  call <- sys.call()
  info <- pkey_info(x, call)
  if (info$type != "rsa") {
    return(ec_as_list(x, info, call))
  }
  v <- der_integers(write_key(x, "pkcs1_der", call))
  names(v) <- c("n", "e")
  list(type = info$type, size = info$bits, data = v[c("e", "n")])
}

#' @export
`$.crypt_key` <- function(x, name) as.list(x)[[name]]

#' @export
`$.crypt_pubkey` <- function(x, name) as.list(x)[[name]]

#' @export
print.crypt_key <- function(x, ...) {
  info <- pkey_info(x)
  cat(sprintf("[%d-bit %s private key]\n", as.integer(info$bits),
              key_type_name(info$type)))
  invisible(x)
}

#' @export
print.crypt_pubkey <- function(x, ...) {
  info <- pkey_info(x)
  cat(sprintf("[%d-bit %s public key]\n", as.integer(info$bits),
              key_type_name(info$type)))
  invisible(x)
}
