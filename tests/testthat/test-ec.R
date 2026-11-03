# Elliptic-curve keys, ECDSA, ECDH and X25519 (Stage 16a, #81).
#
# Published vectors fix what is deterministic: RFC 6979's signatures,
# RFC 7748's and RFC 5903's shared secrets. Randomised ECDSA and key
# generation are cross-verified with openssl.

hash_fun <- function(name) {
  switch(name, sha1 = crypt_sha1, sha256 = crypt_sha256,
         sha384 = crypt_sha384, sha512 = crypt_sha512)
}

raw_sig <- function(der, n) {
  p <- crypt_ecdsa_parse(der)
  c(raw(n - length(p$r)), p$r, raw(n - length(p$s)), p$s)
}

test_that("every EC vector reproduces from the RFC's keys", {
  v <- ec_vectors()
  expect_gt(nrow(v), 0L)
  for (i in seq_len(nrow(v))) {
    row <- v[i, ]
    key <- ec_fixture_key(row$key)
    out <- unhex(row$output)
    if (row$operation == "agree") {
      peer <- ec_fixture_key(row$peer)
      if (inherits(key, "crypt_x25519")) {
        got <- crypt_x25519_diffie_hellman(key, peer$pubkey)
        back <- crypt_x25519_diffie_hellman(peer, key$pubkey)
      } else {
        got <- crypt_ec_dh(key, peer$pubkey)
        back <- crypt_ec_dh(peer, key$pubkey)
      }
      expect_identical(got, out, info = row$id)
      expect_identical(back, out, info = row$id)
      next
    }
    msg <- unhex(row$input)
    n <- length(out) %/% 2L
    der <- crypt_ecdsa_write(out[seq_len(n)], out[n + seq_len(n)])
    expect_true(crypt_signature_verify(msg, der, hash_fun(row$hash),
                                       key$pubkey), info = row$id)
    if (row$operation == "sign-deterministic") {
      sig <- crypt_signature_create(msg, hash_fun(row$hash), key,
                                    deterministic = TRUE)
      expect_identical(raw_sig(sig, n), out, info = row$id)
    }
  }
})

test_that("every EC encoding matches openssl's, byte for byte", {
  skip_if_not_installed("openssl")
  for (k in list(crypt_ec_keygen("P-256"), crypt_ec_keygen("P-384"),
                 crypt_ec_keygen("P-521"), crypt_x25519_keygen())) {
    theirs <- openssl::read_key(crypt_write_pem(k))
    expect_identical(crypt_write_pem(k), openssl::write_pem(theirs))
    expect_identical(crypt_write_der(k), openssl::write_der(theirs))
    expect_identical(crypt_write_pem(k$pubkey),
                     openssl::write_pem(theirs$pubkey))
    expect_identical(crypt_write_der(k$pubkey),
                     openssl::write_der(theirs$pubkey))
    if (inherits(k, "crypt_ecdsa")) {
      expect_identical(crypt_write_pkcs1(k), openssl::write_pkcs1(theirs))
    }
  }
})

test_that("each package reads the EC keys the other writes", {
  skip_if_not_installed("openssl")
  for (curve in c("P-256", "P-384", "P-521")) {
    theirs <- openssl::ec_keygen(curve)
    ours <- crypt_read_key(openssl::write_pem(theirs))
    expect_identical(crypt_write_der(ours), openssl::write_der(theirs))
    expect_identical(crypt_write_der(crypt_read_key(openssl::write_der(theirs))),
                     openssl::write_der(theirs))
    pub <- crypt_read_pubkey(openssl::write_pem(theirs$pubkey))
    expect_identical(crypt_write_der(pub), openssl::write_der(theirs$pubkey))
  }
  theirs <- openssl::x25519_keygen()
  ours <- crypt_read_key(openssl::write_pem(theirs))
  expect_identical(crypt_write_der(ours), openssl::write_der(theirs))
  expect_identical(
    crypt_write_der(crypt_read_pubkey(openssl::write_pem(theirs$pubkey))),
    openssl::write_der(theirs$pubkey)
  )
})

test_that("ECDSA and ECDH cross-verify with openssl on every curve", {
  skip_if_not_installed("openssl")
  msg <- charToRaw("cross")
  for (curve in c("P-256", "P-384", "P-521")) {
    key <- crypt_ec_keygen(curve)
    theirs <- openssl::read_key(crypt_write_pem(key))
    ours <- crypt_signature_create(msg, crypt_sha256, key)
    expect_true(openssl::signature_verify(msg, ours, openssl::sha256,
                                          theirs$pubkey), info = curve)
    other <- openssl::signature_create(msg, openssl::sha256, theirs)
    expect_true(crypt_signature_verify(msg, other, crypt_sha256, key$pubkey),
                info = curve)
    peer <- openssl::ec_keygen(curve)
    expect_identical(
      crypt_ec_dh(key, crypt_read_pubkey(openssl::write_pem(peer$pubkey))),
      openssl::ec_dh(theirs, peer$pubkey),
      info = curve
    )
  }
  a <- crypt_x25519_keygen()
  b <- openssl::x25519_keygen()
  expect_identical(
    crypt_x25519_diffie_hellman(a, crypt_read_pubkey(openssl::write_pem(b$pubkey))),
    openssl::x25519_diffie_hellman(openssl::read_key(crypt_write_pem(a)),
                                   b$pubkey)
  )
})

test_that("ECDSA is randomised by default and deterministic on request", {
  key <- crypt_ec_keygen("P-256")
  msg <- charToRaw("m")
  expect_false(identical(crypt_signature_create(msg, crypt_sha256, key),
                         crypt_signature_create(msg, crypt_sha256, key)))
  expect_identical(
    crypt_signature_create(msg, crypt_sha256, key, deterministic = TRUE),
    crypt_signature_create(msg, crypt_sha256, key, deterministic = TRUE)
  )
})

test_that("a bad ECDSA signature is zucrypt_auth_error, whatever is wrong", {
  key <- crypt_ec_keygen("P-256")
  msg <- charToRaw("m")
  sig <- crypt_signature_create(msg, crypt_sha256, key)
  p <- crypt_ecdsa_parse(sig)
  flipped <- p$s
  flipped[[length(flipped)]] <- xor(flipped[[length(flipped)]], as.raw(1))
  # A leading zero the canonical encoding would not have: the same integers,
  # a different encoding, refused.
  padded <- c(as.raw(0x30), as.raw(length(sig) - 1L), as.raw(0x02),
              as.raw(length(p$r) + 1L), as.raw(0), p$r,
              sig[(4L + length(p$r) + 1L):length(sig)])
  for (bad in list(crypt_ecdsa_write(p$r, flipped), sig[-length(sig)],
                   raw(0), as.raw(1:8), padded,
                   crypt_ecdsa_write(p$r, as.raw(rep(0xff, 40))))) {
    expect_error(crypt_signature_verify(msg, bad, crypt_sha256, key),
                 class = "zucrypt_auth_error")
  }
  expect_error(crypt_signature_verify(charToRaw("n"), sig, crypt_sha256, key),
               class = "zucrypt_auth_error")
  expect_error(
    crypt_signature_verify(msg, sig, crypt_sha256, crypt_ec_keygen("P-256")),
    class = "zucrypt_auth_error"
  )
})

test_that("an EC key round-trips through its coordinates", {
  for (curve in c("P-256", "P-384", "P-521")) {
    key <- crypt_ec_keygen(curve)
    l <- as.list(key)
    expect_identical(l$type, "ecdsa")
    expect_identical(l$data$curve, curve)
    n <- c("P-256" = 32L, "P-384" = 48L, "P-521" = 66L)[[curve]]
    expect_length(l$data$x, n)
    expect_length(l$data$secret, n)
    rebuilt <- crypt_ec_key(curve, l$data$x, l$data$y, l$data$secret)
    expect_identical(crypt_write_der(rebuilt), crypt_write_der(key))
    pub <- crypt_ec_key(curve, l$data$x, l$data$y)
    expect_s3_class(pub, "crypt_pubkey")
    expect_identical(crypt_write_der(pub), crypt_write_der(key$pubkey))
  }
  x <- crypt_x25519_keygen()
  l <- as.list(x)
  expect_identical(crypt_write_der(crypt_read_x25519_key(l$data$d)),
                   crypt_write_der(x))
  expect_identical(crypt_write_der(crypt_read_x25519_pubkey(l$data$x)),
                   crypt_write_der(x$pubkey))
})

test_that("points off the curve and mismatched keys are refused", {
  l <- as.list(crypt_ec_keygen("P-256"))$data
  y <- l$y
  y[[32]] <- xor(y[[32]], as.raw(1))
  expect_error(crypt_ec_key("P-256", l$x, y), class = "zucrypt_invalid_argument")
  expect_error(crypt_ec_key("P-256", l$x, y, l$secret),
               class = "zucrypt_invalid_argument")
  other <- as.list(crypt_ec_keygen("P-256"))$data
  expect_error(crypt_ec_key("P-256", other$x, other$y, l$secret),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_ec_key("P-256", c(as.raw(1), l$x), l$y),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_ec_key("P-224", l$x, l$y),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_ec_dh(crypt_ec_keygen("P-256"), crypt_ec_keygen("P-384")),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_read_x25519_key(as.raw(1:31)),
               class = "zucrypt_invalid_argument")
})

test_that("an X25519 peer that yields an all-zero secret is refused", {
  # RFC 7748 section 6.1. 0 is a point of small order.
  zero <- tryCatch(crypt_read_x25519_pubkey(raw(32)), error = identity)
  if (!inherits(zero, "error")) {
    expect_error(crypt_x25519_diffie_hellman(crypt_x25519_keygen(), zero),
                 class = "zucrypt_invalid_argument")
  } else {
    expect_s3_class(zero, "zucrypt_invalid_argument")
  }
})

test_that("each key does only what its type does", {
  ec <- crypt_ec_keygen("P-256")
  x <- crypt_x25519_keygen()
  rsa <- crypt_rsa_keygen(1024)
  msg <- charToRaw("m")
  expect_error(crypt_signature_create(msg, crypt_sha256, x),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_signature_create(msg, crypt_sha256, ec, pss = TRUE),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_signature_create(msg, crypt_sha256, rsa,
                                      deterministic = TRUE),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_rsa_encrypt(msg, ec), class = "zucrypt_invalid_argument")
  expect_error(crypt_ec_dh(rsa, ec), class = "zucrypt_invalid_argument")
  expect_error(crypt_x25519_diffie_hellman(ec, x),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_write_pkcs1(ec$pubkey))
  expect_error(crypt_write_pkcs1(x))
})

test_that("crypt_ecdsa_parse() and _write() agree with openssl's", {
  skip_if_not_installed("openssl")
  key <- crypt_ec_keygen("P-384")
  sig <- crypt_signature_create(charToRaw("m"), crypt_sha384, key)
  ours <- crypt_ecdsa_parse(sig)
  theirs <- openssl::ecdsa_parse(sig)
  expect_identical(ours$r, as.raw(theirs$r))
  expect_identical(ours$s, as.raw(theirs$s))
  expect_identical(crypt_ecdsa_write(ours$r, ours$s),
                   openssl::ecdsa_write(theirs$r, theirs$s))
  expect_error(crypt_ecdsa_parse(as.raw(1:4)), class = "zucrypt_invalid_argument")
})

test_that("zuc_pkey_*() keep the EC contract zucrypt.h states", {
  got <- native_ec_contract()
  for (n in c("generate", "import_point", "sign", "verify", "agree")) {
    expect_identical(got[[n]], "ZUC_OK", info = n)
  }
  for (n in c("export_point", "agree_symmetric", "x25519_zero_wiped")) {
    expect_identical(got[[n]], "TRUE", info = n)
  }
  for (n in c("off_curve", "scalar_zero", "sign_x25519", "pss_on_ec",
              "agree_other_curve", "x25519_zero")) {
    expect_identical(got[[n]], "ZUC_ERR_INVALID_ARGUMENT", info = n)
  }
  expect_identical(got[["verify_short"]], "ZUC_ERR_AUTH")
  for (n in c("encrypt_ec", "pkcs1_public_ec", "pkcs1_x25519")) {
    expect_identical(got[[n]], "ZUC_ERR_UNSUPPORTED", info = n)
  }
})

test_that("EC keys print their size and type", {
  expect_identical(capture.output(print(crypt_ec_keygen("P-384"))),
                   "[384-bit ecdsa private key]")
  expect_identical(capture.output(print(crypt_x25519_keygen()$pubkey)),
                   "[255-bit x25519 public key]")
})
