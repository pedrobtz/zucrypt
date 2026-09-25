#!/usr/bin/env Rscript

## Generates tests/testthat/fixtures/kat.tsv, the known-answer vectors the
## test suite runs against, plus the MANIFEST.tsv recording where each one
## came from.
##
##   Rscript tools/make-kat.R            write the fixtures
##   Rscript tools/make-kat.R --check    regenerate and compare, changing nothing
##
## Maintainer tooling. Nothing is generated at test time: the fixtures are
## committed, and the suite reads them offline.
##
## The vectors below are published values, transcribed from the documents
## named in the `source` column. Transcription is exactly where this can go
## wrong, so --check does not merely diff the file: where the `openssl`
## package is installed it recomputes every vector with a completely
## independent implementation and compares. That is the design's requirement
## that compatibility be shown against another implementation, not against
## ourselves -- a self round trip would pass just as happily with a wrong
## constant on both sides.

FIXTURES <- file.path("tests", "testthat", "fixtures")

## --- the vectors ----------------------------------------------------------

## FIPS 180-2 / RFC 3174 / RFC 6234 sample messages.
MSG_ABC <- "abc"
MSG_448 <- "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

hash_vectors <- function() {
  rbind(
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = "", output = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
               source = "FIPS 180-2 / RFC 3174, empty message"),
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = hex(MSG_ABC),
               output = "a9993e364706816aba3e25717850c26c9cd0d89d",
               source = "FIPS 180-2 A.1"),
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = hex(MSG_448),
               output = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
               source = "FIPS 180-2 A.2"),

    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = "",
               output = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               source = "FIPS 180-2, empty message"),
    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = hex(MSG_ABC),
               output = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
               source = "FIPS 180-2 B.1"),
    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = hex(MSG_448),
               output = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
               source = "FIPS 180-2 B.2"),

    data.frame(family = "hash", algorithm = "sha384", key = "", iv = "",
               input = "",
               output = paste0("38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743",
                               "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
               source = "FIPS 180-2, empty message"),
    data.frame(family = "hash", algorithm = "sha384", key = "", iv = "",
               input = hex(MSG_ABC),
               output = paste0("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163",
                               "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
               source = "FIPS 180-2 D.1"),

    data.frame(family = "hash", algorithm = "sha512", key = "", iv = "",
               input = "",
               output = paste0("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc",
                               "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f",
                               "63b931bd47417a81a538327af927da3e"),
               source = "FIPS 180-2, empty message"),
    data.frame(family = "hash", algorithm = "sha512", key = "", iv = "",
               input = hex(MSG_ABC),
               output = paste0("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2",
                               "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd",
                               "454d4423643ce80e2a9ac94fa54ca49f"),
               source = "FIPS 180-2 C.1")
  )
}

hmac_vectors <- function() {
  k1 <- strrep("0b", 20)
  jefe <- hex("Jefe")
  hi <- hex("Hi There")
  what <- hex("what do ya want for nothing?")

  rbind(
    ## RFC 2202 test cases 1 and 2 (HMAC-SHA-1).
    data.frame(family = "hmac", algorithm = "sha1", key = k1, iv = "",
               input = hi, output = "b617318655057264e28bc0b6fb378c8ef146be00",
               source = "RFC 2202 test case 1"),
    data.frame(family = "hmac", algorithm = "sha1", key = jefe, iv = "",
               input = what, output = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
               source = "RFC 2202 test case 2"),

    ## RFC 4231 test cases 1 and 2.
    data.frame(family = "hmac", algorithm = "sha256", key = k1, iv = "",
               input = hi,
               output = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
               source = "RFC 4231 test case 1"),
    data.frame(family = "hmac", algorithm = "sha384", key = k1, iv = "",
               input = hi,
               output = paste0("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6",
                               "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
               source = "RFC 4231 test case 1"),
    data.frame(family = "hmac", algorithm = "sha512", key = k1, iv = "",
               input = hi,
               output = paste0("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec278",
                               "7ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4",
                               "be9d914eeb61f1702e696c203a126854"),
               source = "RFC 4231 test case 1"),
    data.frame(family = "hmac", algorithm = "sha256", key = jefe, iv = "",
               input = what,
               output = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
               source = "RFC 4231 test case 2"),
    data.frame(family = "hmac", algorithm = "sha512", key = jefe, iv = "",
               input = what,
               output = paste0("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd6",
                               "10270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fd",
                               "caeab1a34d4a6b4b636e070a38bce737"),
               source = "RFC 4231 test case 2")
  )
}

## NIST SP 800-38A appendix F. The same four plaintext blocks throughout.
## Only the CBC vectors: ECB left in design revision 3 (#29), and its three
## F.1 vectors with it.
PT <- paste0("6bc1bee22e409f96e93d7e117393172a",
             "ae2d8a571e03ac9c9eb76fac45af8e51",
             "30c81c46a35ce411e5fbc1191a0a52ef",
             "f69f2445df4f9b17ad2b417be66c3710")
IV <- "000102030405060708090a0b0c0d0e0f"
K128 <- "2b7e151628aed2a6abf7158809cf4f3c"
K192 <- "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
K256 <- "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

aes_vectors <- function() {
  rbind(
    data.frame(family = "aes-cbc", algorithm = "aes128", key = K128, iv = IV,
               input = PT,
               output = paste0("7649abac8119b246cee98e9b12e9197d",
                               "5086cb9b507219ee95db113a917678b2",
                               "73bed6b8e3c1743b7116e69e22229516",
                               "3ff1caa1681fac09120eca307586e1a7"),
               source = "NIST SP 800-38A F.2.1 (CBC-AES128.Encrypt)"),
    data.frame(family = "aes-cbc", algorithm = "aes192", key = K192, iv = IV,
               input = PT,
               output = paste0("4f021db243bc633d7178183a9fa071e8",
                               "b4d9ada9ad7dedf4e5e738763f69145a",
                               "571b242012fb7ae07fa9baac3df102e0",
                               "08b0e27988598881d920a9e64f5615cd"),
               source = "NIST SP 800-38A F.2.3 (CBC-AES192.Encrypt)"),
    data.frame(family = "aes-cbc", algorithm = "aes256", key = K256, iv = IV,
               input = PT,
               output = paste0("f58c4c04d6e5f1ba779eabfb5f7bfbd6",
                               "9cfc4e967edb808d679f777bc6702c7d",
                               "39f23369a9d9bacfa530e26304231461",
                               "b2eb05e2c39be9fcda6c19078c6a9d1b"),
               source = "NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt)")
  )
}

## --- helpers --------------------------------------------------------------

hex <- function(x) paste(format(as.raw(utf8ToInt(x)), width = 2), collapse = "")

unhex <- function(x) {
  if (!nzchar(x)) return(raw(0))
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}

all_vectors <- function() {
  out <- rbind(hash_vectors(), hmac_vectors(), aes_vectors())
  out$id <- sprintf("%s-%s-%02d", out$family, out$algorithm,
                    ave(seq_len(nrow(out)), out$family, out$algorithm,
                        FUN = seq_along))
  out[, c("id", "family", "algorithm", "key", "iv", "input", "output", "source")]
}

## Recompute every vector with openssl, which shares no code with the backend
## this package vendors. A wrong transcription fails here rather than looking
## like a backend bug later.
cross_check <- function(v) {
  if (!requireNamespace("openssl", quietly = TRUE)) {
    message("openssl is not installed: skipping the independent cross-check.")
    return(invisible(0L))
  }
  checked <- 0L
  skipped <- 0L
  for (i in seq_len(nrow(v))) {
    row <- v[i, ]
    input <- unhex(row$input)
    got <- switch(
      row$family,
      hash = switch(row$algorithm,
                    sha1 = openssl::sha1(input),
                    sha256 = openssl::sha256(input),
                    sha384 = openssl::sha384(input),
                    sha512 = openssl::sha512(input)),
      hmac = switch(row$algorithm,
                    sha1 = openssl::sha1(input, key = unhex(row$key)),
                    sha256 = openssl::sha256(input, key = unhex(row$key)),
                    sha384 = openssl::sha384(input, key = unhex(row$key)),
                    sha512 = openssl::sha512(input, key = unhex(row$key))),
      "aes-cbc" = openssl::aes_cbc_encrypt(input, key = unhex(row$key),
                                           iv = unhex(row$iv)),
      NULL
    )
    if (is.null(got)) {
      skipped <<- skipped + 1L
      next
    }
    if (row$family == "aes-cbc") {
      ## openssl pads; compare only the blocks the vector covers.
      got <- got[seq_len(length(input))]
    }
    got <- paste(format(as.raw(got), width = 2), collapse = "")
    if (!identical(got, row$output)) {
      stop(sprintf("cross-check FAILED for %s\n  openssl:   %s\n  fixture:   %s",
                   row$id, got, row$output), call. = FALSE)
    }
    checked <- checked + 1L
  }
  message(sprintf("cross-checked %d of %d vectors against openssl (%d skipped).",
                  checked, nrow(v), skipped))
  invisible(checked)
}

write_fixtures <- function(v, dir) {
  dir.create(dir, recursive = TRUE, showWarnings = FALSE)
  utils::write.table(v[, c("id", "family", "algorithm", "key", "iv", "input",
                           "output")],
                     file.path(dir, "kat.tsv"),
                     sep = "\t", quote = FALSE, row.names = FALSE)
  manifest <- data.frame(file = "kat.tsv", id = v$id, source = v$source,
                         generator = "tools/make-kat.R")
  utils::write.table(manifest, file.path(dir, "MANIFEST.tsv"),
                     sep = "\t", quote = FALSE, row.names = FALSE)
}

## --- main -----------------------------------------------------------------

main <- function(args) {
  check <- "--check" %in% args
  v <- all_vectors()
  cross_check(v)

  if (!check) {
    write_fixtures(v, FIXTURES)
    message(sprintf("wrote %s/kat.tsv (%d vectors) and MANIFEST.tsv",
                    FIXTURES, nrow(v)))
    return(invisible(TRUE))
  }

  tmp <- tempfile("kat-check-")
  write_fixtures(v, tmp)
  ok <- TRUE
  for (f in c("kat.tsv", "MANIFEST.tsv")) {
    a <- file.path(FIXTURES, f)
    if (!file.exists(a)) {
      message("MISSING ", a); ok <- FALSE; next
    }
    if (!identical(readLines(a, warn = FALSE),
                   readLines(file.path(tmp, f), warn = FALSE))) {
      message("DIFFERS ", a); ok <- FALSE
    }
  }
  unlink(tmp, recursive = TRUE)
  if (!ok) {
    stop("fixtures do not match this generator; re-run without --check",
         call. = FALSE)
  }
  message("fixtures match the generator.")
  invisible(TRUE)
}

main(commandArgs(trailingOnly = TRUE))
