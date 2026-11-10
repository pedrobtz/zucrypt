#!/usr/bin/env Rscript
## RSA keys straddling the backend's 4096-bit limit (#93), written to
## tests/testthat/fixtures/rsa-limit.tsv, with their MANIFEST.tsv rows.
##
## The backend refuses RSA keys over PSA_VENDOR_RSA_MAX_KEY_BITS (4096). The
## suite reads keys of 4088, 4096, 4104 and 8192 bits in every encoding both
## readers take, so that a key over the limit is refused with the
## same class whichever reader and encoding reached it. The keys are made by
## openssl, the outside oracle for the key encodings, and stored as hex so
## the suite needs neither openssl nor an RSA key generation at run time.
##
## The straddle is a byte either side of the limit, not a bit: openssl
## rounds an odd size down (4097 gives 4096), so it cannot make the 4095- or
## 4097-bit keys a bit-level straddle would need. Each size is still drawn
## until its modulus is exactly that long.
##
##   Rscript tools/make-rsa-limit-kat.R          # rewrite the fixture
##   Rscript tools/make-rsa-limit-kat.R --check  # parse every row with openssl

FIXTURES <- file.path("tests", "testthat", "fixtures")
OUT <- file.path(FIXTURES, "rsa-limit.tsv")
GENERATOR <- "tools/make-rsa-limit-kat.R"
BITS <- c(4088L, 4096L, 4104L, 8192L)

tohex <- function(x) paste(format(x), collapse = "")
unhex <- function(h) {
  as.raw(strtoi(substring(h, seq(1, nchar(h), 2), seq(2, nchar(h), 2)), 16L))
}

exact_key <- function(bits) {
  repeat {
    key <- openssl::rsa_keygen(bits)
    if (as.list(key)$size == bits) return(key)
  }
}

# openssl writes PKCS#1 as PEM only; its DER is the PEM's base64 body.
pem_body <- function(pem) {
  lines <- strsplit(pem, "\n")[[1]]
  openssl::base64_decode(paste(lines[!startsWith(lines, "-----")],
                               collapse = ""))
}

encodings <- function(key) {
  pub <- key$pubkey
  list(
    private_pkcs8_der = openssl::write_der(key),
    private_pkcs1_der = pem_body(openssl::write_pkcs1(key)),
    private_pkcs8_pem = charToRaw(openssl::write_pem(key)),
    public_spki_der   = openssl::write_der(pub),
    public_pkcs1_der  = pem_body(openssl::write_pkcs1(pub)),
    public_spki_pem   = charToRaw(openssl::write_pem(pub))
  )
}

check <- function() {
  rows <- utils::read.delim(OUT, colClasses = "character")
  for (i in seq_len(nrow(rows))) {
    r <- rows[i, ]
    bytes <- unhex(r$data)
    private <- startsWith(r$encoding, "private")
    pem <- endsWith(r$encoding, "_pem")
    if (grepl("pkcs1_der", r$encoding)) {
      # openssl reads PKCS#1 only as PEM, so the DER goes back into one.
      label <- if (private) "RSA PRIVATE KEY" else "RSA PUBLIC KEY"
      input <- sprintf("-----BEGIN %s-----\n%s\n-----END %s-----\n", label,
                       trimws(openssl::base64_encode(bytes, linebreaks = TRUE)),
                       label)
      pem <- TRUE
    } else {
      input <- if (pem) rawToChar(bytes) else bytes
    }
    key <- if (private) {
      openssl::read_key(input, der = !pem)
    } else {
      openssl::read_pubkey(input, der = !pem)
    }
    if (as.list(key)$size != as.integer(r$bits)) {
      stop(sprintf("%s: openssl reads %d bits, the row says %s",
                   r$id, as.list(key)$size, r$bits))
    }
  }
  cat(sprintf("rsa-limit.tsv: %d rows, every one read by openssl at its size\n",
              nrow(rows)))
}

generate <- function() {
  rows <- list()
  for (bits in BITS) {
    enc <- encodings(exact_key(bits))
    for (name in names(enc)) {
      rows[[length(rows) + 1L]] <- data.frame(
        id = sprintf("rsa%d-%s", bits, gsub("_", "-", name)),
        bits = as.character(bits),
        encoding = name,
        data = tohex(enc[[name]])
      )
    }
  }
  rows <- do.call(rbind, rows)
  utils::write.table(rows, OUT, sep = "\t", quote = FALSE, row.names = FALSE)

  manifest_file <- file.path(FIXTURES, "MANIFEST.tsv")
  manifest <- utils::read.delim(manifest_file, colClasses = "character")
  manifest <- manifest[manifest$file != "rsa-limit.tsv", ]
  manifest <- rbind(manifest, data.frame(
    file = "rsa-limit.tsv",
    id = rows$id,
    source = sprintf("openssl %s, RSA-%s (%s), the 4096-bit backend limit",
                     openssl::openssl_config()$version, rows$bits,
                     rows$encoding),
    generator = GENERATOR
  ))
  utils::write.table(manifest, manifest_file, sep = "\t", quote = FALSE,
                     row.names = FALSE)
  cat(sprintf("wrote %d rows to %s\n", nrow(rows), OUT))
}

if ("--check" %in% commandArgs(trailingOnly = TRUE)) check() else generate()
