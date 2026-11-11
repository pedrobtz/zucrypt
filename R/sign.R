#' Signatures and RSA Encryption
#'
#' @description
#' `crypt_signature_create()` signs data with a private RSA or EC key, and
#' `crypt_signature_verify()` checks the signature with the public key.
#' `crypt_rsa_encrypt()` encrypts a short message to a public key, and
#' `crypt_rsa_decrypt()` decrypts it with the private key. The names,
#' arguments and defaults follow `openssl`, with `pss` and `oaep_hash` added.
#'
#' A signature covers a digest: `hash` is applied to `data` and the digest is
#' signed, so `hash = crypt_sha256` gives an RSA-SHA256 signature. With
#' `hash = NULL`, `data` must already be a SHA-1 or SHA-2 digest. PKCS#1
#' v1.5 signatures are deterministic. PSS signatures (`pss = TRUE`, RFC 8017
#' section 8.1) are randomised, use MGF1 with the same digest, and a salt as
#' long as the digest; verification requires that salt length.
#'
#' With a key on P-256, P-384 or P-521 the signature is ECDSA, encoded in DER
#' as openssl encodes it; [crypt_ecdsa_parse()] gives its `r` and `s`.
#' ECDSA signatures are randomised unless `deterministic = TRUE`, which
#' derives the nonce from the key and digest as RFC 6979 specifies.
#' Verification accepts only the canonical DER encoding.
#'
#' RSA encryption is for short secrets such as keys: a 2048-bit key with
#' OAEP over SHA-1 takes at most 214 bytes. OAEP (`oaep = TRUE`, RFC 8017
#' section 7.1) is the padding to use. `oaep_hash` picks the digest for both
#' its label hash and MGF1: `"sha1"`, as openssl uses, or `"sha256"`,
#' `"sha384"` or `"sha512"`. PKCS#1 v1.5 padding (`oaep = FALSE`, the
#' openssl default) is legacy: a decryptor that reveals whether padding was
#' valid can be attacked to decrypt messages (Bleichenbacher, 1998). It is
#' here for formats that specify it.
#'
#' @param data A raw vector, or a path or connection to read one from. For
#'   `crypt_rsa_encrypt()` and `crypt_rsa_decrypt()`, a raw vector.
#' @param hash A digest function such as [crypt_sha256()], or `NULL` when
#'   `data` is already a digest. The default, `crypt_sha1`, is openssl's; use
#'   `crypt_sha256` for anything new.
#' @param key A private key from [crypt_read_key()], or anything
#'   `crypt_read_key()` reads.
#' @param pubkey A public key from [crypt_read_pubkey()], a private key
#'   (whose public half is used), or anything `crypt_read_pubkey()` reads.
#' @param password Not supported yet; must be `NULL`.
#' @param sig The signature, a raw vector.
#' @param pss `TRUE` for RSASSA-PSS, `FALSE` (the default) for PKCS#1 v1.5.
#'   RSA keys only.
#' @param deterministic `TRUE` for RFC 6979 deterministic ECDSA. EC keys
#'   only.
#' @param oaep `TRUE` for OAEP, `FALSE` (the default) for PKCS#1 v1.5.
#' @param oaep_hash The OAEP digest: `"sha1"` (the default), `"sha256"`,
#'   `"sha384"` or `"sha512"`. Ignored unless `oaep = TRUE`.
#'
#' @return `crypt_signature_create()` returns the signature, a raw vector as
#'   long as the modulus. `crypt_signature_verify()` returns `TRUE`, or
#'   signals `zucrypt_auth_error`. `crypt_rsa_encrypt()` returns the
#'   ciphertext and `crypt_rsa_decrypt()` the plaintext, as raw vectors.
#'
#' @section Errors:
#' A signature that does not verify, and a ciphertext that does not decrypt,
#' are `zucrypt_auth_error`, whatever the reason. A message too long for the
#' key is `zucrypt_bad_length`.
#'
#' @section Compared with openssl:
#' `pss`, `deterministic` and `oaep_hash` are additions. There is no default key: openssl
#' reads `~/.ssh`. PKCS#1 v1.5 decryption of an invalid ciphertext is an
#' error here; OpenSSL 3 returns random bytes instead (implicit rejection).
#'
#' @examples
#' key <- crypt_rsa_keygen(2048)
#' msg <- charToRaw("hello")
#'
#' sig <- crypt_signature_create(msg, crypt_sha256, key)
#' crypt_signature_verify(msg, sig, crypt_sha256, key$pubkey)
#'
#' sig <- crypt_signature_create(msg, crypt_sha256, key, pss = TRUE)
#' crypt_signature_verify(msg, sig, crypt_sha256, key$pubkey, pss = TRUE)
#'
#' secret <- crypt_rand_bytes(32)
#' ct <- crypt_rsa_encrypt(secret, key$pubkey, oaep = TRUE,
#'                         oaep_hash = "sha256")
#' identical(crypt_rsa_decrypt(ct, key, oaep = TRUE, oaep_hash = "sha256"),
#'           secret)
#'
#' @name crypt_rsa_crypto
NULL

digest_name <- function(md, call) {
  name <- c("20" = "sha1", "32" = "sha256", "48" = "sha384",
            "64" = "sha512")[as.character(length(md))]
  if (!is.raw(md) || is.na(name)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      paste0("`hash` must give, or `data` be, a SHA-1 or SHA-2 digest ",
             "(20, 32, 48 or 64 bytes)."),
      call = call
    )
  }
  unname(name)
}

apply_hash <- function(data, hash, call) {
  if (is.null(hash)) {
    return(data)
  }
  if (!is.function(hash)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`hash` must be a digest function such as crypt_sha256, or NULL.",
      call = call
    )
  }
  as.vector(unclass(hash(data)))
}

check_flag <- function(x, arg, call) {
  if (!is.logical(x) || length(x) != 1L || is.na(x)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      sprintf("`%s` must be TRUE or FALSE.", arg),
      call = call
    )
  }
  x
}

#' @rdname crypt_rsa_crypto
#' @export
crypt_signature_create <- function(data, hash = crypt_sha1, key,
                                   password = NULL, pss = FALSE,
                                   deterministic = FALSE) {
  call <- sys.call()
  check_flag(pss, "pss", call)
  check_flag(deterministic, "deterministic", call)
  md <- apply_hash(key_input(data, "data", call), hash, call)
  digest <- digest_name(md, call)
  no_password(password, call)
  key <- private_key_arg(key, "key", call)
  pkey_info(key, call)
  scheme <- signature_scheme(key, pss, deterministic, call)
  res <- .Call(zucrypt_pkey_sign, key, scheme, digest, md)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = scheme, call = call)
  }
  if (inherits(key, "crypt_ecdsa")) ecdsa_der(res$value) else res$value
}

# The scheme a key signs with, and the options that apply to it.
signature_scheme <- function(key, pss, deterministic, call) {
  if (inherits(key, "crypt_rsa")) {
    if (deterministic) {
      zucrypt_abort("zucrypt_invalid_argument",
                    "`deterministic` applies to EC keys only.", call = call)
    }
    return(if (pss) "rsa-pss" else "rsa-pkcs1v15-sign")
  }
  if (inherits(key, "crypt_ecdsa")) {
    if (pss) {
      zucrypt_abort("zucrypt_invalid_argument",
                    "`pss` applies to RSA keys only.", call = call)
    }
    return(if (deterministic) "ecdsa-deterministic" else "ecdsa")
  }
  zucrypt_abort(
    "zucrypt_invalid_argument",
    "X25519 keys agree on secrets and do not sign; there is no Ed25519.",
    call = call
  )
}

#' @rdname crypt_rsa_crypto
#' @export
crypt_signature_verify <- function(data, sig, hash = crypt_sha1, pubkey,
                                   pss = FALSE) {
  call <- sys.call()
  check_flag(pss, "pss", call)
  md <- apply_hash(key_input(data, "data", call), hash, call)
  digest <- digest_name(md, call)
  sig <- key_input(sig, "sig", call)
  pubkey <- public_key_arg(pubkey, "pubkey", call)
  info <- pkey_info(pubkey, call)
  scheme <- signature_scheme(pubkey, pss, FALSE, call)
  if (inherits(pubkey, "crypt_ecdsa")) {
    # Deterministic and randomised ECDSA verify alike.
    sig <- ecdsa_raw(sig, curve_bytes[[info$type]])
    if (is.null(sig)) {
      zucrypt_abort(
        "zucrypt_auth_error",
        "The signature is not a canonical DER ECDSA signature for this key.",
        algorithm = "ecdsa",
        call = call
      )
    }
  }
  res <- .Call(zucrypt_pkey_verify, pubkey, scheme, digest, md, sig)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = scheme, call = call)
  }
  TRUE
}

check_rsa <- function(key, call) {
  if (!inherits(key, "crypt_rsa")) {
    zucrypt_abort("zucrypt_invalid_argument",
                  "RSA encryption needs an RSA key.", call = call)
  }
}

rsa_scheme <- function(oaep, oaep_hash, call) {
  check_flag(oaep, "oaep", call)
  if (!oaep) {
    return(list(scheme = "rsa-pkcs1v15-crypt", hash = NULL))
  }
  if (!is.character(oaep_hash) || length(oaep_hash) != 1L ||
        !oaep_hash %in% c("sha1", "sha256", "sha384", "sha512")) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`oaep_hash` must be \"sha1\", \"sha256\", \"sha384\" or \"sha512\".",
      algorithm = "rsa-oaep",
      call = call
    )
  }
  list(scheme = "rsa-oaep", hash = oaep_hash)
}

#' @rdname crypt_rsa_crypto
#' @export
crypt_rsa_encrypt <- function(data, pubkey, oaep = FALSE,
                              oaep_hash = "sha1") {
  call <- sys.call()
  s <- rsa_scheme(oaep, oaep_hash, call)
  check_raw(data, "data", algorithm = s$scheme, call = call)
  pubkey <- public_key_arg(pubkey, "pubkey", call)
  pkey_info(pubkey, call)
  check_rsa(pubkey, call)
  res <- .Call(zucrypt_pkey_crypt, pubkey, s$scheme, s$hash, data, TRUE)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = s$scheme, call = call)
  }
  res$value
}

#' @rdname crypt_rsa_crypto
#' @export
crypt_rsa_decrypt <- function(data, key, password = NULL, oaep = FALSE,
                              oaep_hash = "sha1") {
  call <- sys.call()
  s <- rsa_scheme(oaep, oaep_hash, call)
  check_raw(data, "data", algorithm = s$scheme, call = call)
  no_password(password, call)
  key <- private_key_arg(key, "key", call)
  pkey_info(key, call)
  check_rsa(key, call)
  res <- .Call(zucrypt_pkey_crypt, key, s$scheme, s$hash, data, FALSE)
  if (res$status != 0L) {
    abort_native(res$status, algorithm = s$scheme, call = call)
  }
  res$value
}
