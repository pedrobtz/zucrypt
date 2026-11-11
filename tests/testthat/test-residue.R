# No secret is left in memory the backend frees (#137). The harness arms a
# scan in the adapter's allocator (zuc_live.h): every block the backend
# allocates during one operation is searched for a piece of the private key
# when it is freed. Each piece is taken from the key's own fields, raw for
# DER and as the base64 characters that encode it for PEM, which is the
# form the PEM writer and reader hold it in.

test_that("writing and reading a private key leaves no secret in freed memory", {
  rsa <- crypt_read_key(rsa_fixture_key(rsa_vectors()$key[1]))
  keys <- list(
    rsa = list(key = rsa, secret = as.list(rsa)$data$d),
    p256 = crypt_ec_keygen("P-256"),
    p384 = crypt_ec_keygen("P-384"),
    p521 = crypt_ec_keygen("P-521"),
    x25519 = crypt_x25519_keygen()
  )
  found <- character(0)
  checked <- 0L
  for (name in names(keys)) {
    k <- keys[[name]]
    if (inherits(k, "crypt_key")) {
      d <- as.list(k)$data
      k <- list(key = k, secret = if (is.null(d$secret)) d$d else d$secret)
    }
    # A slice from inside the secret, away from its edges: at least 24
    # bytes, since the shortest secret (P-256, X25519) is 32.
    secret <- k$secret[5:(length(k$secret) - 4L)]
    der <- crypt_write_der(k$key)
    for (format in 1:4) {
      # The DER of this format's encoding (formats 1 and 3 are DER, 2 and
      # 4 their PEM), for the base64 needle.
      ders <- tryCatch(
        native_residue(der, TRUE, paste0("write", format - (format %% 2L == 0L)))$output,
        error = function(e) NULL
      )
      if (is.null(ders)) next          # no PKCS#1 encoding of an X25519 key
      needles <- list(raw = secret[1:24])
      if (format %% 2 == 0) needles$base64 <- base64_needle(ders, secret)
      for (n in names(needles)) {
        hits <- native_residue(der, TRUE, paste0("write", format), needles[[n]])$hits
        checked <- checked + 1L
        if (!identical(hits, 0L)) found <- c(found, sprintf("%s write%d %s: %d", name, format, n, hits))
        # And reading that encoding back.
        enc <- native_residue(der, TRUE, paste0("write", format))$output
        hits <- native_residue(enc, TRUE, "parse", needles[[n]])$hits
        checked <- checked + 1L
        if (!identical(hits, 0L)) found <- c(found, sprintf("%s parse%d %s: %d", name, format, n, hits))
      }
    }
  }
  expect_gt(checked, 40L)
  expect_identical(found, character(0))
})

test_that("the residue scan finds a secret that is left behind", {
  # The positive control: a block freed with the needle in it is found, and
  # the same block wiped first is not. Without it, a scan that looked at
  # nothing would pass the test above.
  expect_identical(.Call(zucrypt:::zucrypt_test_residue_control), 1L)
})
