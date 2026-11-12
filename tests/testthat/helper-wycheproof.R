# Project Wycheproof vectors (#70): the shipped subset in
# fixtures/wycheproof.tsv, or, when ZUCRYPT_WYCHEPROOF names it, every case
# zucrypt can express (tools/wycheproof/wycheproof.tsv.gz, written by
# tools/make-wycheproof.py, kept out of the tarball). A path that does not
# exist is an error, never a quiet fall back to the subset.
WYCHEPROOF_FULL_COUNT <- 6004L
wycheproof_full <- function() nzchar(Sys.getenv("ZUCRYPT_WYCHEPROOF"))
wycheproof_vectors <- function() {
  path <- Sys.getenv("ZUCRYPT_WYCHEPROOF")
  if (!nzchar(path)) path <- test_path("fixtures", "wycheproof.tsv")
  if (!file.exists(path)) stop("ZUCRYPT_WYCHEPROOF names a missing file: ", path)
  utils::read.delim(path, colClasses = "character", na.strings = NULL)
}

# Run one case through the public functions. Returns list(accepted, right):
# `accepted` is FALSE when zucrypt refused it with one of its own
# conditions; `right` says whether an accepted case produced Wycheproof's
# output. Any other error propagates, and fails the test that called this.
wycheproof_case <- function(r, keys) {
  h <- function(x) if (nzchar(x)) unhex(x) else raw(0)
  refused <- function(e) list(accepted = FALSE, right = NA)
  key_from <- function(hex, private) {
    id <- paste(private, hex)
    if (is.null(keys[[id]])) {
      keys[[id]] <- tryCatch(
        if (private) crypt_read_key(h(hex)) else crypt_read_pubkey(h(hex)),
        zucrypt_error = function(e) e
      )
    }
    k <- keys[[id]]
    if (inherits(k, "zucrypt_error")) stop(k)
    k
  }
  hash_fn <- list(sha1 = crypt_sha1, sha256 = crypt_sha256,
                  sha384 = crypt_sha384, sha512 = crypt_sha512)
  tryCatch(switch(
    r$family,
    gcm = {
      aad <- if (nzchar(r$aad)) h(r$aad) else NULL
      pt <- crypt_aes_gcm_decrypt(h(r$ct), h(r$key), iv = h(r$iv),
                                  tag = h(r$tag), aad = aad)
      enc <- crypt_aes_gcm_encrypt(h(r$msg), h(r$key), iv = h(r$iv), aad = aad)
      list(accepted = TRUE,
           right = identical(as.vector(pt), h(r$msg)) &&
             identical(as.vector(enc), h(r$ct)) &&
             identical(attr(enc, "tag"), h(r$tag)))
    },
    hmac = {
      mac <- crypt_hmac(h(r$msg), h(r$key), r$hash)
      tag <- h(r$tag)
      # Wycheproof's truncated tags are a prefix of the full MAC; a tag that
      # is not that prefix is a refusal by the caller's comparison.
      ok <- length(tag) <= length(mac) && crypt_equal(mac[seq_along(tag)], tag)
      list(accepted = ok, right = if (ok) TRUE else NA)
    },
    ecdsa = , `rsa-pkcs1-sig` = , `rsa-pss` = {
      pub <- key_from(r$key, FALSE)
      ok <- crypt_signature_verify(h(r$msg), h(r$ct), hash_fn[[r$hash]], pub,
                                   pss = identical(r$family, "rsa-pss"))
      list(accepted = isTRUE(ok), right = if (isTRUE(ok)) TRUE else NA)
    },
    `rsa-oaep` = {
      pt <- crypt_rsa_decrypt(h(r$ct), key_from(r$key, TRUE), oaep = TRUE,
                              oaep_hash = r$hash)
      list(accepted = TRUE, right = identical(pt, h(r$msg)))
    },
    `rsa-pkcs1-crypt` = {
      pt <- crypt_rsa_decrypt(h(r$ct), key_from(r$key, TRUE))
      list(accepted = TRUE, right = identical(pt, h(r$msg)))
    },
    ecdh = {
      # The scalar is an ASN.1 INTEGER's bytes: a leading zero for a high
      # bit, or fewer bytes than the curve; zucrypt imports exactly the
      # curve's size.
      n <- c(p256 = 32L, p384 = 48L, p521 = 66L)[[r$hash]]
      d <- h(r$key)
      while (length(d) > n && d[1] == as.raw(0)) d <- d[-1]
      if (length(d) < n) d <- c(raw(n - length(d)), d)
      key <- zucrypt:::import_key(r$hash, TRUE, d, quote(crypt_ec_dh()))
      s <- crypt_ec_dh(key, crypt_read_pubkey(h(r$msg)))
      list(accepted = TRUE, right = identical(s, h(r$ct)))
    },
    x25519 = {
      s <- crypt_x25519_diffie_hellman(crypt_read_x25519_key(h(r$key)),
                                       crypt_read_x25519_pubkey(h(r$msg)))
      list(accepted = TRUE, right = identical(s, h(r$ct)))
    },
    stop("unknown Wycheproof family: ", r$family)
  ), zucrypt_error = refused)
}
