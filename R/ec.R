#' Elliptic-Curve and X25519 Keys
#'
#' @description
#' Generate, build and use keys on the NIST curves P-256, P-384 and P-521
#' and on Curve25519, with `openssl`'s names and arguments under a `crypt_`
#' prefix.
#'
#' * `crypt_ec_keygen()` generates a key on a NIST curve, for ECDSA
#'   signatures with [crypt_signature_create()] and for key agreement with
#'   `crypt_ec_dh()`.
#' * `crypt_ec_key()` builds one from its coordinates, as a JSON Web Key
#'   carries them, and `as.list()` takes one apart again.
#' * `crypt_x25519_keygen()`, `crypt_read_x25519_key()` and
#'   `crypt_read_x25519_pubkey()` make X25519 keys (RFC 7748), and
#'   `crypt_x25519_diffie_hellman()` computes their shared secret.
#' * `crypt_ecdsa_parse()` and `crypt_ecdsa_write()` convert an ECDSA
#'   signature between DER, as [crypt_signature_create()] returns it, and its
#'   integers `r` and `s`.
#'
#' Keys of these types are read and written by [crypt_read_key()],
#' [crypt_write_pem()] and the other key functions, as for RSA.
#'
#' A Diffie-Hellman result is a shared secret, not a key: derive keys from it
#' with a key-derivation function. A peer key on another curve, a point that
#' is not on the curve, and an X25519 peer that yields an all-zero secret are
#' refused.
#'
#' @param curve `"P-256"`, `"P-384"` or `"P-521"`.
#' @param x,y The public point's coordinates, as raw big-endian integers.
#'   For an X25519 key, `x` is the 32-byte key.
#' @param d The private scalar, as a raw big-endian integer, or `NULL` for a
#'   public key.
#' @param key A private key.
#' @param peerkey,pubkey The other party's public key, or a private key whose
#'   public half is used.
#' @param password Not supported; must be `NULL`.
#' @param sig An ECDSA signature in DER.
#' @param r,s The signature's integers, as raw big-endian vectors.
#'
#' @return `crypt_ec_keygen()`, `crypt_x25519_keygen()`,
#'   `crypt_read_x25519_key()` and `crypt_ec_key()` with `d` return a key of
#'   class `c("crypt_key", "crypt_ecdsa")` or `c("crypt_key",
#'   "crypt_x25519")`; the public forms are class `crypt_pubkey`. The
#'   Diffie-Hellman functions return the shared secret as a raw vector: 32,
#'   48 or 66 bytes for the NIST curves, 32 for X25519. `crypt_ecdsa_parse()`
#'   returns `list(r, s)` and `crypt_ecdsa_write()` the DER signature.
#'   `as.list()` on an EC key gives `data` with `curve`, `x`, `y` and, for a
#'   private key, `secret`; on an X25519 key, `x` and, private, `d`.
#'
#' @section Compared with openssl:
#' `crypt_ecdsa_parse()` returns raw vectors rather than `bignum`s, and
#' `as.list()` gives coordinates as raw vectors. There is no Ed25519: the
#' bundled library has no EdDSA. There is no default key.
#'
#' @examples
#' alice <- crypt_ec_keygen("P-256")
#' bob <- crypt_ec_keygen("P-256")
#' identical(crypt_ec_dh(alice, bob$pubkey), crypt_ec_dh(bob, alice$pubkey))
#'
#' sig <- crypt_signature_create(charToRaw("hi"), crypt_sha256, alice)
#' crypt_signature_verify(charToRaw("hi"), sig, crypt_sha256, alice$pubkey)
#' str(crypt_ecdsa_parse(sig))
#'
#' a <- crypt_x25519_keygen()
#' b <- crypt_x25519_keygen()
#' identical(crypt_x25519_diffie_hellman(a, b$pubkey),
#'           crypt_x25519_diffie_hellman(b, a$pubkey))
#'
#' @name crypt_ec_keys
NULL

curve_type <- function(curve, call) {
  types <- c("P-256" = "p256", "P-384" = "p384", "P-521" = "p521")
  if (!is.character(curve) || length(curve) != 1L || !curve %in% names(types)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`curve` must be \"P-256\", \"P-384\" or \"P-521\".",
      call = call
    )
  }
  unname(types[[curve]])
}

curve_bytes <- c(p256 = 32L, p384 = 48L, p521 = 66L, x25519 = 32L)

generate_key <- function(type, call) {
  res <- .Call(zucrypt_pkey_generate, type, 0)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = type, call = call)
  }
  new_key(res$value)
}

import_key <- function(type, private, data, call) {
  res <- .Call(zucrypt_pkey_import, type, private, data)
  if (res$status != 0L) {
    name <- names(zuc_status_codes())[match(res$status, zuc_status_codes())]
    if (identical(name, "ZUC_ERR_INVALID_ARGUMENT")) {
      zucrypt_abort(
        "zucrypt_invalid_argument",
        sprintf(paste0("The %s key material is not valid: a point not on ",
                       "the curve, a scalar out of range, or the wrong ",
                       "length."), type),
        algorithm = type,
        call = call
      )
    }
    abort_native(res$status, algorithm = type, call = call)
  }
  new_key(res$value)
}

export_key <- function(x, public_only, call) {
  res <- .Call(zucrypt_pkey_export, x, public_only)
  if (res$status != 0L) {
    abort_native(res$status, call = call)
  }
  res$value
}

# Left-pad an unsigned big-endian integer to `n` bytes, or refuse it.
fixed_width <- function(x, n, arg, type, call) {
  check_raw(x, arg, algorithm = type, call = call)
  x <- x[cumsum(x != as.raw(0)) > 0]
  if (length(x) > n) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      sprintf("`%s` is longer than the curve's %d bytes.", arg, n),
      algorithm = type,
      call = call
    )
  }
  c(raw(n - length(x)), x)
}

#' @rdname crypt_ec_keys
#' @export
crypt_ec_keygen <- function(curve = c("P-256", "P-384", "P-521")) {
  call <- sys.call()
  if (missing(curve)) curve <- "P-256"
  generate_key(curve_type(curve, call), call)
}

#' @rdname crypt_ec_keys
#' @export
crypt_ec_key <- function(curve, x, y, d = NULL) {
  call <- sys.call()
  type <- curve_type(curve, call)
  n <- curve_bytes[[type]]
  x <- fixed_width(x, n, "x", type, call)
  y <- fixed_width(y, n, "y", type, call)
  pub <- import_key(type, FALSE, c(as.raw(4), x, y), call)
  if (is.null(d)) {
    return(pub)
  }
  key <- import_key(type, TRUE, fixed_width(d, n, "d", type, call), call)
  # The point is computed from d; it must be the one given.
  if (!identical(export_key(key, TRUE, call), c(as.raw(4), x, y))) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`x` and `y` are not the public point of `d`.",
      algorithm = type,
      call = call
    )
  }
  key
}

ec_as_list <- function(x, info, call) {
  priv <- inherits(x, "crypt_key")
  if (info$type == "x25519") {
    data <- list(x = export_key(x, TRUE, call))
    if (priv) data$d <- export_key(x, FALSE, call)
  } else {
    n <- curve_bytes[[info$type]]
    point <- export_key(x, TRUE, call)
    data <- list(curve = curve_names[[info$type]],
                 x = point[1L + seq_len(n)],
                 y = point[1L + n + seq_len(n)])
    if (priv) data$secret <- export_key(x, FALSE, call)
  }
  out <- list(type = key_type_name(info$type), size = info$bits)
  if (priv) out$pubkey <- public_of(x, call)
  out$data <- data
  out
}

agree <- function(key, peer, call) {
  res <- .Call(zucrypt_pkey_agree, key, peer)
  if (res$status != 0L) {
    name <- names(zuc_status_codes())[match(res$status, zuc_status_codes())]
    if (identical(name, "ZUC_ERR_INVALID_ARGUMENT")) {
      zucrypt_abort(
        "zucrypt_invalid_argument",
        paste0("Key agreement needs a private key and a peer on the same ",
               "curve, and a peer point that yields a usable secret."),
        call = call
      )
    }
    abort_native(res$status, algorithm = "ecdh", call = call)
  }
  res$value
}

#' @rdname crypt_ec_keys
#' @export
crypt_ec_dh <- function(key, peerkey, password = NULL) {
  call <- sys.call()
  no_password(password, call)
  key <- crypt_read_key(key)
  peerkey <- crypt_read_pubkey(peerkey)
  if (!inherits(key, "crypt_ecdsa") || !inherits(peerkey, "crypt_ecdsa")) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`key` and `peerkey` must be keys on P-256, P-384 or P-521.",
      call = call
    )
  }
  agree(key, peerkey, call)
}

#' @rdname crypt_ec_keys
#' @export
crypt_x25519_keygen <- function() {
  generate_key("x25519", sys.call())
}

#' @rdname crypt_ec_keys
#' @export
crypt_read_x25519_key <- function(x) {
  call <- sys.call()
  check_raw(x, "x", algorithm = "x25519", call = call)
  import_key("x25519", TRUE, x, call)
}

#' @rdname crypt_ec_keys
#' @export
crypt_read_x25519_pubkey <- function(x) {
  call <- sys.call()
  check_raw(x, "x", algorithm = "x25519", call = call)
  import_key("x25519", FALSE, x, call)
}

#' @rdname crypt_ec_keys
#' @export
crypt_x25519_diffie_hellman <- function(key, pubkey) {
  call <- sys.call()
  key <- crypt_read_key(key)
  pubkey <- crypt_read_pubkey(pubkey)
  if (!inherits(key, "crypt_x25519") || !inherits(pubkey, "crypt_x25519")) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`key` and `pubkey` must be X25519 keys.",
      call = call
    )
  }
  agree(key, pubkey, call)
}

# --- ECDSA signatures in DER (RFC 3279 section 2.2.3) -------------------

#' @rdname crypt_ec_keys
#' @export
crypt_ecdsa_parse <- function(sig) {
  call <- sys.call()
  check_raw(sig, "sig", algorithm = "ecdsa", call = call)
  v <- tryCatch(der_integers(sig), error = function(e) NULL)
  if (is.null(v) || length(v) != 2L || sig[[1]] != as.raw(0x30)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`sig` is not a DER ECDSA signature.",
      algorithm = "ecdsa",
      call = call
    )
  }
  list(r = v[[1]], s = v[[2]])
}

#' @rdname crypt_ec_keys
#' @export
crypt_ecdsa_write <- function(r, s) {
  call <- sys.call()
  check_raw(r, "r", algorithm = "ecdsa", call = call)
  check_raw(s, "s", algorithm = "ecdsa", call = call)
  der_sequence(list(der_integer(r), der_integer(s)))
}

# DER to the r || s the backend takes, each half `n` bytes; NULL when the
# DER is not a signature of that size, so the caller can report it as one
# that does not verify.
ecdsa_raw <- function(sig, n) {
  v <- tryCatch(der_integers(sig), error = function(e) NULL)
  if (is.null(v) || length(v) != 2L || !length(sig) ||
        sig[[1]] != as.raw(0x30) || any(lengths(v) > n)) {
    return(NULL)
  }
  if (!identical(crypt_ecdsa_write(v[[1]], v[[2]]), sig)) {
    return(NULL)
  }
  c(raw(n - length(v[[1]])), v[[1]], raw(n - length(v[[2]])), v[[2]])
}

ecdsa_der <- function(raw_sig) {
  n <- length(raw_sig) %/% 2L
  crypt_ecdsa_write(raw_sig[seq_len(n)], raw_sig[n + seq_len(n)])
}
