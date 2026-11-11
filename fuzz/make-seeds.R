#!/usr/bin/env Rscript
## The fuzz corpus's seeds (#94), from the test fixtures:
##
##   corpus/pkey/     every key encoding the readers take, private and
##                    public, from tests/testthat/fixtures; each prefixed
##                    with the harness's flag byte
##   corpus/gcm/      the AES-GCM vectors of aead.tsv, laid out as
##                    fuzz_gcm.c reads them
##   corpus/verify/   a few messages under each scheme and digest
##
## and the regress-* seeds, which encode what a past bug looked like, so the
## replay on every OS catches it coming back:
##
##   regress-93-*     RSA keys over 4096 bits (#93), refused alike
##   regress-141-*    RSA keys under 1024 bits or not in whole bytes (#141)
##   regress-91-*     the malformed DER of #91, offered to the key reader
##
##   Rscript fuzz/make-seeds.R      (from the repository root)

pkgload::load_all(".", quiet = TRUE)
fx <- file.path("tests", "testthat", "fixtures")
out <- file.path("fuzz", "corpus")
u <- function(x) {
  if (!nzchar(x)) return(raw(0))
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}
put <- function(dir, name, bytes) {
  dir.create(file.path(out, dir), recursive = TRUE, showWarnings = FALSE)
  writeBin(bytes, file.path(out, dir, name))
}

## --- pkey ----------------------------------------------------------------
key_seeds <- function(name, key) {
  pub <- key$pubkey
  put("pkey", paste0(name, "-private-der"), c(as.raw(1), crypt_write_der(key)))
  put("pkey", paste0(name, "-private-pem"),
      c(as.raw(1), charToRaw(crypt_write_pem(key))))
  put("pkey", paste0(name, "-public-der"), c(as.raw(0), crypt_write_der(pub)))
  put("pkey", paste0(name, "-public-pem"),
      c(as.raw(0), charToRaw(crypt_write_pem(pub))))
}
rsa <- utils::read.delim(file.path(fx, "rsa-keys.tsv"), colClasses = "character")
for (i in seq_len(nrow(rsa))) {
  parts <- lapply(rsa[i, c("n", "e", "d", "p", "q", "dp", "dq", "qi")], u)
  key <- do.call(crypt_rsa_key, unname(parts))
  key_seeds(rsa$id[i], key)
  put("pkey", paste0(rsa$id[i], "-private-pkcs1-pem"),
      c(as.raw(1), charToRaw(crypt_write_pkcs1(key))))
}
ec <- utils::read.delim(file.path(fx, "ec-keys.tsv"), colClasses = "character")
for (i in seq_len(nrow(ec))) {
  r <- ec[i, ]
  if (!nzchar(r$d)) next
  key <- if (r$curve == "X25519") {
    crypt_read_x25519_key(u(r$d))
  } else {
    crypt_ec_key(r$curve, u(r$x), u(r$y), u(r$d))
  }
  key_seeds(r$id, key)
}
lim <- utils::read.delim(file.path(fx, "rsa-limit.tsv"), colClasses = "character")
for (i in seq_len(nrow(lim))) {
  r <- lim[i, ]
  if (!(r$bits %in% c("512", "1000", "1028", "2047", "4096", "4104"))) next
  flag <- as.raw(startsWith(r$encoding, "private"))
  name <- switch(r$bits,
    "4096" = r$id,
    "4104" = paste0("regress-93-", r$id),
    paste0("regress-141-", r$id)
  )
  put("pkey", name, c(flag, u(r$data)))
}
for (h in c(seq_too_long = "307f020105020107", s_truncated = "3006020105020307",
            trailing = "3006020105020107dead", indefinite = "30800201050201070000")) {
  put("pkey", paste0("regress-91-", names(h)), c(as.raw(0), u(h)))
}

## --- gcm -------------------------------------------------------------------
aead <- utils::read.delim(file.path(fx, "aead.tsv"), colClasses = "character")
for (i in seq_len(nrow(aead))) {
  r <- aead[i, ]
  key <- u(r$key)
  iv <- u(r$iv)
  if (length(iv) != 12L) next
  aad <- u(r$aad)
  key[[1]] <- if (length(key) == 32L) key[[1]] | as.raw(0x80) else key[[1]] & as.raw(0x7f)
  put("gcm", r$id, c(key, iv, as.raw(length(aad)), aad, as.raw(i),
                     u(r$tag), u(r$input)))
}

## --- verify ----------------------------------------------------------------
for (ctl in 0:8) {
  put("verify", sprintf("scheme-%d", ctl),
      c(as.raw(ctl), as.raw(ctl * 37), charToRaw("message to sign")))
}
put("verify", "empty-message", as.raw(c(2, 0)))

cat("seeds:", vapply(c("pkey", "gcm", "verify"),
                     function(d) length(list.files(file.path(out, d))),
                     integer(1)), "\n")
