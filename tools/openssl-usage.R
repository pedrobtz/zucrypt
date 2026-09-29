#!/usr/bin/env Rscript
## Which openssl functions do its CRAN reverse dependencies actually call?
##
## This is the measurement behind the tranche order in .agents/roadmap.md
## (Stages 13-17) and the "N of openssl's exports" claim the migration article
## makes (design.md section 7.1). Maintainer-only and network-bound, like
## tools/vendor/fetch: it downloads each reverse dependency's R/ and NAMESPACE
## from the CRAN GitHub mirror into a scratch directory and counts, per
## exported openssl function, how many packages use it -- through
## `openssl::f()`, `importFrom(openssl, f)`, or a bare `f(` under
## `import(openssl)`.
##
##   Rscript tools/openssl-usage.R [scratch-dir]
##
## Results are dated in the roadmap; re-run before restating the claim.

args <- commandArgs(trailingOnly = TRUE)
scratch <- if (length(args)) args[[1]] else file.path(tempdir(), "openssl-usage")
dir.create(scratch, showWarnings = FALSE, recursive = TRUE)

if (!requireNamespace("openssl", quietly = TRUE)) stop("install openssl first")
ex <- sort(getNamespaceExports("openssl"))
ex <- ex[!startsWith(ex, ".")]

db  <- tools::CRAN_package_db()
rev <- tools::package_dependencies("openssl", db,
  which = c("Imports", "Depends", "LinkingTo"), reverse = TRUE)[[1]]
message(length(rev), " CRAN packages import or depend on openssl ",
        as.character(packageVersion("openssl")))

fetch <- function(pkg) {
  d <- file.path(scratch, pkg)
  if (dir.exists(file.path(d, "R"))) return(TRUE)
  tgz <- file.path(scratch, paste0(pkg, ".tgz"))
  url <- sprintf("https://github.com/cran/%s/archive/refs/heads/master.tar.gz", pkg)
  ok <- tryCatch({ download.file(url, tgz, quiet = TRUE, mode = "wb"); TRUE },
                 error = function(e) FALSE, warning = function(w) FALSE)
  if (!ok) { message("  miss ", pkg); return(FALSE) }
  files <- untar(tgz, list = TRUE)
  keep <- files[grepl("/(NAMESPACE|R/[^/]+)$", files)]
  dir.create(d, showWarnings = FALSE)
  untar(tgz, files = keep, exdir = d, extras = "--strip-components=1")
  unlink(tgz)
  TRUE
}
invisible(vapply(rev, fetch, logical(1)))

read_all <- function(d) {
  files <- c(file.path(d, "NAMESPACE"), list.files(file.path(d, "R"), full.names = TRUE))
  files <- files[file.exists(files)]
  txt <- unlist(lapply(files, readLines, warn = FALSE, encoding = "UTF-8"))
  txt <- iconv(txt, "UTF-8", "ASCII", sub = " ")   # names are ASCII; nothing else matters
  paste(txt, collapse = "\n")
}

use <- list()
for (pkg in rev) {
  d <- file.path(scratch, pkg)
  if (!dir.exists(d)) next
  txt <- read_all(d)
  hits <- sub("openssl:::?", "", regmatches(txt, gregexpr("openssl:::?[A-Za-z0-9_.]+", txt))[[1]])
  for (x in regmatches(txt, gregexpr("importFrom\\(\\s*\"?openssl\"?\\s*,[^)]*\\)", txt))[[1]]) {
    inner <- sub("\\)$", "", sub("importFrom\\(\\s*\"?openssl\"?\\s*,", "", x))
    hits <- c(hits, trimws(gsub("\"", "", strsplit(inner, ",")[[1]])))
  }
  if (grepl("import\\(\\s*\"?openssl\"?\\s*\\)", txt)) {
    for (f in ex) if (grepl(paste0("(^|[^A-Za-z0-9_.])", f, "\\("), txt)) hits <- c(hits, f)
  }
  use[[pkg]] <- intersect(unique(hits), ex)
}

n_call <- sum(lengths(use) > 0)
cnt <- sort(table(unlist(use)), decreasing = TRUE)
cat(sprintf("%d packages scanned, %d call at least one openssl function\n\n", length(use), n_call))
cat(sprintf("%-28s %4s %6s\n", "function", "pkgs", "share"))
for (f in names(cnt)) cat(sprintf("%-28s %4d %5.0f%%\n", f, cnt[[f]], 100 * cnt[[f]] / n_call))
unused <- setdiff(ex, names(cnt))
cat("\nexports no reverse dependency calls (", length(unused), "):\n", sep = "")
cat(strwrap(paste(unused, collapse = "  "), 78, prefix = "  "), sep = "\n")

## The roadmap's tranches, cumulative. Keep in step with roadmap.md Stages 13-17.
tranches <- list(
  "Stage 13: digests, HMAC, Base64, randomness" =
    c("sha1", "sha2", "sha224", "sha256", "sha384", "sha512", "sha3", "md5", "ripemd160",
      "multihash", "base64_encode", "base64_decode", "rand_bytes", "rand_num"),
  "Stage 14: AES modes, padding, KDFs" =
    c("aes_cbc_encrypt", "aes_cbc_decrypt", "aes_ctr_encrypt", "aes_ctr_decrypt",
      "aes_gcm_encrypt", "aes_gcm_decrypt", "aes_keygen"),
  "Stage 15: key objects, PEM and DER, RSA, envelopes" =
    c("read_key", "read_pubkey", "read_pem", "write_pem", "write_der", "write_pkcs1",
      "write_ssh", "write_openssh_pem", "rsa_keygen", "rsa_encrypt", "rsa_decrypt",
      "signature_create", "signature_verify", "fingerprint", "encrypt_envelope",
      "decrypt_envelope", "bignum"),
  "Stage 16: EC keys, ECDSA, ECDH, X25519" =
    c("ec_keygen", "ec_dh", "ecdsa_parse", "ecdsa_write", "x25519_keygen",
      "x25519_diffie_hellman", "read_x25519_key", "read_x25519_pubkey"),
  "Stage 17: certificates" =
    c("read_cert", "read_cert_bundle", "cert_verify", "read_p7b"))

cum <- character()
cat("\nPackages whose detected usage falls within the subset, cumulative\n",
    "(name matching only: not compatible arguments, key formats or a run):\n", sep = "")
for (nm in names(tranches)) {
  cum <- c(cum, tranches[[nm]])
  served <- sum(vapply(use, function(h) length(h) > 0 && all(h %in% cum), logical(1)))
  cat(sprintf("  %-52s %3d of %d (%3.0f%%)\n", nm, served, n_call, 100 * served / n_call))
}
cat("\nDetected usage outside the subset after Stage 17:\n")
for (p in names(use)) {
  miss <- setdiff(use[[p]], cum)
  if (length(use[[p]]) && length(miss)) cat(sprintf("  %-22s %s\n", p, paste(miss, collapse = ", ")))
}
