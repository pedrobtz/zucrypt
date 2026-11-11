#!/usr/bin/env Rscript
## RSA keys straddling the size rule, 1024 to 4096 bits in whole bytes (#93,
## #141), written to tests/testthat/fixtures/rsa-limit.tsv, with their
## MANIFEST.tsv rows.
##
## The backend refuses RSA keys over PSA_VENDOR_RSA_MAX_KEY_BITS (4096) and
## keys whose modulus is not a whole number of bytes; zucrypt refuses keys
## under 1024 bits. The suite reads keys of each size in BITS, in every
## encoding both readers take, so that a key outside the rule is refused with
## the same class and message whichever reader and encoding reached it, and
## one inside it is read at its size. The keys are made by openssl, the
## outside oracle for the key encodings, and stored as hex so the suite needs
## neither openssl nor an RSA key generation at run time.
##
## At the top the straddle is a byte either side of the limit, not a bit:
## openssl rounds an odd size down (4097 gives 4096), so it cannot make the
## 4095- or 4097-bit keys a bit-level straddle would need. Each size is still
## drawn until its modulus is exactly that long. A size already in the
## fixture keeps its key; only missing sizes are drawn.
##
##   Rscript tools/make-rsa-limit-kat.R          # add the missing sizes
##   Rscript tools/make-rsa-limit-kat.R --check  # parse every row with openssl

FIXTURES <- file.path("tests", "testthat", "fixtures")
OUT <- file.path(FIXTURES, "rsa-limit.tsv")
GENERATOR <- "tools/make-rsa-limit-kat.R"
BITS <- c(512L, 1000L, 1016L, 1024L, 1028L, 2047L, 2048L,
          4088L, 4096L, 4104L, 8192L)

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
  old <- if (file.exists(OUT)) {
    utils::read.delim(OUT, colClasses = "character")
  } else {
    data.frame(id = character(), bits = character(), encoding = character(),
               data = character())
  }
  rows <- list(old[old$bits %in% BITS, ])
  for (bits in setdiff(BITS, as.integer(old$bits))) {
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
  rows <- rows[order(as.integer(rows$bits), seq_len(nrow(rows))), ]
  utils::write.table(rows, OUT, sep = "\t", quote = FALSE, row.names = FALSE)

  manifest_file <- file.path(FIXTURES, "MANIFEST.tsv")
  manifest <- utils::read.delim(manifest_file, colClasses = "character")
  # A kept row keeps its provenance: the openssl that wrote it.
  ours <- manifest$file == "rsa-limit.tsv"
  kept <- manifest[ours & manifest$id %in% rows$id, ]
  fresh <- rows[!rows$id %in% kept$id, ]
  manifest <- rbind(manifest[!ours, ], kept, data.frame(
    file = rep("rsa-limit.tsv", nrow(fresh)),
    id = fresh$id,
    source = sprintf("openssl %s, RSA-%s (%s), the 1024 to 4096-bit rule",
                     openssl::openssl_config()$version, fresh$bits,
                     fresh$encoding),
    generator = rep(GENERATOR, nrow(fresh))
  ))
  utils::write.table(manifest, manifest_file, sep = "\t", quote = FALSE,
                     row.names = FALSE)
  cat(sprintf("wrote %d rows to %s\n", nrow(rows), OUT))
}

if ("--check" %in% commandArgs(trailingOnly = TRUE)) check() else generate()
