#!/usr/bin/env Rscript
## The expected bytes for tools/alloc-exercise.R (#115), written to
## tools/alloc-expected.tsv.
##
## The allocation-failure sweep runs the workload once per injected failure,
## and a run that survives must have produced the right bytes, not merely
## bytes. The sweep cannot load openssl -- its allocations would be in the
## window -- so the answers are computed here, once, by outside
## implementations, and committed:
##
##   openssl   digests, HMACs, AES-CBC, the AES-GCM ciphertext, the RSA
##             PKCS#1 v1.5 signature, an RSA-OAEP ciphertext to decrypt, and
##             the PEM encoding of the RSA key; it also verifies the ECDSA
##             signature below
##   hashlib   PBKDF2 (Python's standard library)
##   zucrypt   the AES-GCM tag and the deterministic ECDSA signature, which
##             openssl cannot produce (its GCM returns no tag; it has no
##             RFC 6979 signing); both are checked against published vectors
##             in test-aead.R and test-ec.R, and the signature is verified by
##             openssl here
##
##   Rscript tools/alloc-expected.R           # rewrite tools/alloc-expected.tsv
##   Rscript tools/alloc-expected.R --check   # recompute and compare

OUT <- file.path("tools", "alloc-expected.tsv")

## The workload's inputs, defined once in tools/alloc-inputs.R.
source(file.path("tools", "alloc-inputs.R"))
pkgload::load_all(".", quiet = TRUE)  # this checkout, not an installed copy
inputs <- alloc_inputs()

tohex <- function(x) paste(format(x), collapse = "")

expected <- function() {
  d <- inputs$data
  k <- inputs$key
  rows <- list()
  add <- function(name, value, oracle) {
    rows[[length(rows) + 1L]] <<- data.frame(name = name,
                                             hex = tohex(value),
                                             oracle = oracle)
  }
  for (a in c("sha1", "sha256", "sha384", "sha512")) {
    f <- getExportedValue("openssl", a)
    add(paste0("hash_", a), as.raw(f(d)), "openssl")
    add(paste0("hmac_", a), as.raw(f(d, key = k)), "openssl")
  }
  # openssl pads; the data is whole blocks, so its first 4096 bytes are the
  # unpadded ciphertext.
  cbc <- openssl::aes_cbc_encrypt(d, k, inputs$iv)
  add("aes_cbc", cbc[seq_along(d)], "openssl")
  gcm <- openssl::aes_gcm_encrypt(d, k, inputs$nonce)
  add("aes_gcm_ciphertext", as.raw(gcm)[seq_along(d)], "openssl")
  ours <- crypt_aes_gcm_encrypt(d, k, inputs$nonce, aad = inputs$iv)
  stopifnot(identical(as.vector(ours), as.raw(gcm)[seq_along(d)]))
  add("aes_gcm_tag", attr(ours, "tag"), "zucrypt (test-aead.R vectors)")

  rsa <- do.call(crypt_rsa_key, unname(inputs$rsa_parts))
  pem <- crypt_write_pem(rsa)
  their_key <- openssl::read_key(pem)
  add("rsa_pem", charToRaw(openssl::write_pem(their_key)), "openssl")
  add("rsa_pkcs1v15_sha256",
      openssl::signature_create(d, openssl::sha256, key = their_key),
      "openssl")
  add("rsa_oaep_sha1_ciphertext",
      openssl::rsa_encrypt(k, their_key$pubkey, oaep = TRUE),
      "openssl (OAEP-SHA1; decrypted by the workload)")

  p256 <- with(inputs$ec_p256, crypt_ec_key(curve, x, y, d))
  sig <- crypt_signature_create(d, crypt_sha256, p256, deterministic = TRUE)
  their_pub <- openssl::read_pubkey(crypt_write_pem(p256$pubkey))
  stopifnot(openssl::signature_verify(d, sig, openssl::sha256, their_pub))
  add("ecdsa_p256_deterministic", sig,
      "zucrypt, verified by openssl (test-ec.R: RFC 6979)")

  py <- system2("python3", c("-I", "-c", shQuote(sprintf(
    "import hashlib;print(hashlib.pbkdf2_hmac('sha256',bytes.fromhex('%s'),bytes.fromhex('%s'),2,40).hex())",
    tohex(k), tohex(inputs$iv)
  ))), stdout = TRUE)
  add("pbkdf2_sha256", as.raw(strtoi(substring(py, seq(1, 79, 2),
                                               seq(2, 80, 2)), 16L)),
      "python hashlib")
  do.call(rbind, rows)
}

rows <- expected()
if ("--check" %in% commandArgs(trailingOnly = TRUE)) {
  # The randomised OAEP ciphertext differs every run; the rest must match.
  old <- utils::read.delim(OUT, colClasses = "character")
  keep <- rows$name != "rsa_oaep_sha1_ciphertext"
  stopifnot(identical(old$name, rows$name),
            identical(old$hex[keep], rows$hex[keep]))
  cat(sprintf("%s: %d rows reproduce\n", OUT, sum(keep)))
} else {
  utils::write.table(rows, OUT, sep = "\t", quote = FALSE, row.names = FALSE)
  cat(sprintf("wrote %d rows to %s\n", nrow(rows), OUT))
}
