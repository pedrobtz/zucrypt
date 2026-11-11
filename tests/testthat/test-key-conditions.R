test_that("key conditions carry the key's type and the user's function (#143)", {
  # Design section 11: a handler may branch on `algorithm`. Code written
  # when RSA was the only key type said "rsa" for every key; a condition
  # about a key now carries that key's type, and NA when there is no key.
  keys <- list(
    rsa = rsa_fixture_key("rfc7515-a2"),
    p256 = ec_fixture_key("rfc6979-p256"),
    p384 = ec_fixture_key("rfc6979-p384"),
    p521 = ec_fixture_key("rfc6979-p521"),
    x25519 = ec_fixture_key("rfc7748-alice")
  )
  caught <- function(expr) tryCatch(expr, zucrypt_error = function(e) e)
  expect_condition_fields <- function(e, class, algorithm, fn, info) {
    expect_s3_class(e, class)
    expect_identical(e$algorithm, algorithm, info = info)
    expect_identical(conditionCall(e), call(fn), info = info)
  }
  msg <- charToRaw("abc")

  for (type in names(keys)) {
    k <- keys[[type]]
    e <- caught(crypt_write_pem(k, password = "x"))
    expect_condition_fields(e, "zucrypt_unsupported_algorithm", type,
                            "crypt_write_pem", paste(type, "pem password"))
    e <- caught(crypt_write_pkcs1(k, password = "x"))
    expect_condition_fields(e, "zucrypt_unsupported_algorithm", type,
                            "crypt_write_pkcs1", paste(type, "pkcs1 password"))
    # A public key where a private one is needed names the argument and
    # the function the user called, not crypt_read_key()'s `file`.
    e <- caught(crypt_signature_create(msg, crypt_sha256, k$pubkey))
    expect_condition_fields(e, "zucrypt_invalid_argument", type,
                            "crypt_signature_create", paste(type, "sign"))
    expect_match(conditionMessage(e), "`key`.*public key")
    e <- caught(crypt_read_key(k$pubkey))
    expect_condition_fields(e, "zucrypt_invalid_argument", type,
                            "crypt_read_key", paste(type, "read_key"))
    expect_match(conditionMessage(e), "`file`.*public key")
  }

  e <- caught(crypt_write_pkcs1(keys$x25519))
  expect_condition_fields(e, "zucrypt_unsupported_algorithm", "x25519",
                          "crypt_write_pkcs1", "x25519 pkcs1")
  e <- caught(crypt_rsa_decrypt(as.raw(rep(1, 256)), keys$rsa$pubkey))
  expect_condition_fields(e, "zucrypt_invalid_argument", "rsa",
                          "crypt_rsa_decrypt", "decrypt with public")
  expect_match(conditionMessage(e), "`key`.*public key")
  for (type in c("p256", "p384", "p521")) {
    k <- keys[[type]]
    e <- caught(crypt_ec_dh(k$pubkey, k))
    expect_condition_fields(e, "zucrypt_invalid_argument", type,
                            "crypt_ec_dh", paste(type, "dh"))
    expect_match(conditionMessage(e), "`key`.*public key")
    e <- caught(crypt_ec_dh(k, k, password = "x"))
    expect_condition_fields(e, "zucrypt_unsupported_algorithm", NA_character_,
                            "crypt_ec_dh", paste(type, "dh password"))
  }
  e <- caught(crypt_x25519_diffie_hellman(keys$x25519$pubkey, keys$x25519))
  expect_condition_fields(e, "zucrypt_invalid_argument", "x25519",
                          "crypt_x25519_diffie_hellman", "x25519 dh")
  expect_match(conditionMessage(e), "`key`.*public key")

  # Input that is not a key has no type.
  e <- caught(crypt_read_key(as.raw(1:10)))
  expect_condition_fields(e, "zucrypt_invalid_argument", NA_character_,
                          "crypt_read_key", "read_key garbage")
  e <- caught(crypt_read_pubkey(as.raw(1:10)))
  expect_condition_fields(e, "zucrypt_invalid_argument", NA_character_,
                          "crypt_read_pubkey", "read_pubkey garbage")
  e <- caught(crypt_signature_create(as.raw(1:3), function(x) x, keys$p256))
  expect_condition_fields(e, "zucrypt_invalid_argument", NA_character_,
                          "crypt_signature_create", "digest length")
})
