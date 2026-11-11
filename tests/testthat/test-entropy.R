test_that("a failing entropy source is reported as such by every key operation (#140)", {
  # The oracle is the same call with a working source: under a failing one,
  # each operation either gives that same answer (it needed no randomness)
  # or raises zucrypt_entropy_error. Any other class misreports the failure;
  # decryption that says "forged" or agreement that says "bad peer" sends
  # the caller after the wrong party.
  rsa <- rsa_fixture_key("rfc7515-a2")
  p256 <- ec_fixture_key("rfc5903-p256-i")
  peer <- ec_fixture_key("rfc5903-p256-r")$pubkey
  alice <- ec_fixture_key("rfc7748-alice")
  bob <- ec_fixture_key("rfc7748-bob")$pubkey
  msg <- charToRaw("abc")
  oaep_ct <- crypt_rsa_encrypt(msg, rsa$pubkey, oaep = TRUE)
  pkcs1_ct <- crypt_rsa_encrypt(msg, rsa$pubkey)
  rsa_sig <- crypt_signature_create(msg, crypt_sha256, rsa)
  ec_sig <- crypt_signature_create(msg, crypt_sha256, p256)

  ops <- list(
    rsa_decrypt_oaep = function() crypt_rsa_decrypt(oaep_ct, rsa, oaep = TRUE),
    rsa_decrypt_pkcs1 = function() crypt_rsa_decrypt(pkcs1_ct, rsa),
    ec_dh = function() crypt_ec_dh(p256, peer),
    x25519_dh = function() crypt_x25519_diffie_hellman(alice, bob),
    rsa_sign = function() crypt_signature_create(msg, crypt_sha256, rsa),
    rsa_verify = function() {
      crypt_signature_verify(msg, rsa_sig, crypt_sha256, rsa$pubkey)
    },
    ec_verify = function() {
      crypt_signature_verify(msg, ec_sig, crypt_sha256, p256$pubkey)
    },
    rsa_encrypt = function() {
      length(crypt_rsa_encrypt(msg, rsa$pubkey, oaep = TRUE))
    },
    ec_sign = function() {
      length(crypt_signature_create(msg, crypt_sha256, p256)) > 0
    }
  )
  for (key in list(rsa, p256, alice)) {
    for (w in list(crypt_write_der, crypt_write_pem, crypt_write_pkcs1)) {
      for (k in list(key, key$pubkey)) {
        ops[[length(ops) + 1L]] <- local({
          w <- w
          k <- k
          function() w(k)
        })
      }
    }
    # The public half of a private key, derived under the failing source.
    ops[[length(ops) + 1L]] <- local({
      key <- key
      function() crypt_write_der(key$pubkey)
    })
  }

  expected <- lapply(ops, function(f) tryCatch(f(), error = identity))
  native_random_fail(TRUE)
  got <- tryCatch(
    lapply(ops, function(f) tryCatch(f(), error = identity)),
    finally = native_random_fail(FALSE)
  )
  entropy <- 0L
  for (i in seq_along(ops)) {
    label <- names(ops)[i]
    if (is.null(label) || !nzchar(label)) label <- paste("write", i)
    if (inherits(got[[i]], "zucrypt_entropy_error")) {
      entropy <- entropy + 1L
      next
    }
    expect_identical(got[[i]], expected[[i]], label = label)
  }
  for (label in c("rsa_decrypt_oaep", "rsa_decrypt_pkcs1", "ec_dh",
                  "x25519_dh", "rsa_sign")) {
    expect_s3_class(got[[label]], "zucrypt_entropy_error")
  }
  # The control: the source really failed for some of them.
  expect_gte(entropy, 5L)
})
