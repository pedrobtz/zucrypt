# RSA keys, signatures and encryption (Stage 15a, #80).
#
# Published vectors fix what is deterministic (RFC 7515 A.2's signature,
# RFC 7516 A.1 and A.2's decryptions). Everything randomised -- key
# generation, PSS, OAEP, PKCS#1 v1.5 encryption -- is cross-verified: what
# we produce, openssl or Python's cryptography accepts, and what they
# produce, we accept. A self round trip never counts on its own.

hash_fun <- function(name) {
  switch(name, sha1 = crypt_sha1, sha256 = crypt_sha256,
         sha384 = crypt_sha384, sha512 = crypt_sha512)
}

test_that("every RSA vector reproduces from the key's integers", {
  v <- rsa_vectors()
  expect_gt(nrow(v), 0L)
  for (i in seq_len(nrow(v))) {
    row <- v[i, ]
    key <- rsa_fixture_key(row$key)
    input <- unhex(row$input)
    output <- unhex(row$output)
    pss <- row$scheme == "pss"
    oaep <- row$scheme == "oaep"
    if (row$operation == "sign") {
      sig <- crypt_signature_create(input, hash_fun(row$hash), key)
      expect_identical(sig, output, info = row$id)
    }
    if (row$operation %in% c("sign", "verify")) {
      expect_true(crypt_signature_verify(input, output, hash_fun(row$hash),
                                         key$pubkey, pss = pss),
                  info = row$id)
    }
    if (row$operation == "decrypt") {
      got <- crypt_rsa_decrypt(output, key, oaep = oaep,
                               oaep_hash = if (oaep) row$hash else "sha1")
      expect_identical(got, input, info = row$id)
    }
  }
})

test_that("a key round-trips through its integers", {
  key <- rsa_fixture_key("rfc7515-a2")
  parts <- as.list(key)
  expect_identical(parts$type, "rsa")
  expect_identical(parts$size, 2048)
  expect_named(parts$data, c("e", "n", "p", "q", "d", "dp", "dq", "qi"))
  expect_identical(parts$data$e, as.raw(c(1, 0, 1)))
  rebuilt <- do.call(crypt_rsa_key, unname(parts$data[c(
    "n", "e", "d", "p", "q", "dp", "dq", "qi")]))
  expect_identical(crypt_write_der(rebuilt), crypt_write_der(key))
  pub <- crypt_rsa_key(parts$data$n, parts$data$e)
  expect_s3_class(pub, "crypt_pubkey")
  expect_identical(as.list(pub)$data, parts$data[c("e", "n")])
  expect_identical(crypt_write_der(pub), crypt_write_der(key$pubkey))
})

test_that("a key must be all private integers or none", {
  p <- as.list(rsa_fixture_key("rfc7515-a2"))$data
  expect_error(crypt_rsa_key(p$n, p$e, p$d), class = "zucrypt_invalid_argument")
  expect_error(crypt_rsa_key("n", p$e), class = "zucrypt_invalid_argument")
  # Inconsistent integers are refused by the backend's key checks.
  bad <- p$q
  bad[[length(bad)]] <- xor(bad[[length(bad)]], as.raw(2))
  expect_error(crypt_rsa_key(p$n, p$e, p$d, p$p, bad, p$dp, p$dq, p$qi),
               class = "zucrypt_invalid_argument")
})

test_that("every encoding matches openssl's, byte for byte", {
  skip_if_not_installed("openssl")
  key <- rsa_fixture_key("rfc7515-a2")
  theirs <- openssl::read_key(crypt_write_pem(key))
  expect_identical(crypt_write_pem(key), openssl::write_pem(theirs))
  expect_identical(crypt_write_pkcs1(key), openssl::write_pkcs1(theirs))
  expect_identical(crypt_write_der(key), openssl::write_der(theirs))
  expect_identical(crypt_write_pem(key$pubkey),
                   openssl::write_pem(theirs$pubkey))
  expect_identical(crypt_write_pkcs1(key$pubkey),
                   openssl::write_pkcs1(theirs$pubkey))
  expect_identical(crypt_write_der(key$pubkey),
                   openssl::write_der(theirs$pubkey))
})

test_that("each package reads every encoding the other writes", {
  skip_if_not_installed("openssl")
  theirs <- openssl::rsa_keygen(2048)
  ref <- openssl::write_der(theirs)
  for (enc in list(openssl::write_pem(theirs), openssl::write_pkcs1(theirs),
                   openssl::write_der(theirs))) {
    expect_identical(crypt_write_der(crypt_read_key(enc)), ref)
  }
  pref <- openssl::write_der(theirs$pubkey)
  for (enc in list(openssl::write_pem(theirs$pubkey),
                   openssl::write_pkcs1(theirs$pubkey), pref,
                   openssl::write_pem(theirs))) {
    expect_identical(crypt_write_der(crypt_read_pubkey(enc)), pref)
  }
  ours <- crypt_rsa_keygen(2048)
  ref <- crypt_write_der(ours)
  for (enc in list(crypt_write_pem(ours), crypt_write_pkcs1(ours), ref)) {
    expect_identical(openssl::write_der(openssl::read_key(enc)), ref)
  }
})

test_that("keys are read from a file, a connection and PEM text", {
  key <- crypt_rsa_keygen(1024)
  path <- tempfile(fileext = ".pem")
  on.exit(unlink(path), add = TRUE)
  expect_identical(crypt_write_pem(key, path), path)
  ref <- crypt_write_der(key)
  expect_identical(crypt_write_der(crypt_read_key(path)), ref)
  expect_identical(crypt_write_der(crypt_read_key(file(path))), ref)
  expect_identical(crypt_write_der(crypt_read_key(crypt_write_pem(key))), ref)
  expect_identical(crypt_write_der(crypt_read_key(key)), ref)
})

test_that("signatures cross-verify with openssl", {
  skip_if_not_installed("openssl")
  key <- crypt_rsa_keygen(2048)
  theirs <- openssl::read_key(crypt_write_pem(key))
  msg <- charToRaw("cross")
  # Not SHA-1: an OpenSSL configured to refuse SHA-1 signatures, as the
  # sanitizer containers' is, fails openssl's side of the comparison. The
  # SHA-1 path is the same code with another digest.
  for (h in c("sha256", "sha384", "sha512")) {
    ours <- crypt_signature_create(msg, hash_fun(h), key)
    other <- openssl::signature_create(msg, getExportedValue("openssl", h),
                                       theirs)
    expect_identical(ours, other, info = h)
    expect_true(openssl::signature_verify(
      msg, ours, getExportedValue("openssl", h), theirs$pubkey))
    expect_true(crypt_signature_verify(msg, other, hash_fun(h), key$pubkey))
  }
})

test_that("PSS is randomised, and verifies only as PSS", {
  key <- crypt_rsa_keygen(2048)
  msg <- charToRaw("pss")
  a <- crypt_signature_create(msg, crypt_sha256, key, pss = TRUE)
  b <- crypt_signature_create(msg, crypt_sha256, key, pss = TRUE)
  expect_false(identical(a, b))
  expect_true(crypt_signature_verify(msg, a, crypt_sha256, key, pss = TRUE))
  expect_error(crypt_signature_verify(msg, a, crypt_sha256, key),
               class = "zucrypt_auth_error")
  v15 <- crypt_signature_create(msg, crypt_sha256, key)
  expect_error(crypt_signature_verify(msg, v15, crypt_sha256, key, pss = TRUE),
               class = "zucrypt_auth_error")
})

test_that("hash = NULL signs a digest the caller made", {
  key <- crypt_rsa_keygen(1024)
  msg <- charToRaw("pre-hashed")
  expect_identical(
    crypt_signature_create(crypt_sha256(msg), NULL, key),
    crypt_signature_create(msg, crypt_sha256, key)
  )
  expect_error(crypt_signature_create(as.raw(1:16), NULL, key),
               class = "zucrypt_invalid_argument")
})

test_that("a bad signature is zucrypt_auth_error, whatever is wrong", {
  key <- crypt_rsa_keygen(1024)
  msg <- charToRaw("m")
  sig <- crypt_signature_create(msg, crypt_sha256, key)
  flipped <- sig
  flipped[[1]] <- xor(flipped[[1]], as.raw(1))
  # The last is an integer above the modulus, which the backend refuses as
  # bad input rather than a bad signature: it must still read as one.
  for (bad in list(flipped, sig[-1], c(sig, as.raw(0)), raw(0),
                   as.raw(rep(0xff, length(sig))))) {
    expect_error(crypt_signature_verify(msg, bad, crypt_sha256, key),
                 class = "zucrypt_auth_error")
  }
  expect_error(crypt_signature_verify(charToRaw("n"), sig, crypt_sha256, key),
               class = "zucrypt_auth_error")
  expect_error(crypt_signature_verify(msg, sig, crypt_sha384, key),
               class = "zucrypt_auth_error")
  other <- crypt_rsa_keygen(1024)
  err <- expect_error(crypt_signature_verify(msg, sig, crypt_sha256, other),
                      class = "zucrypt_auth_error")
  expect_identical(conditionCall(err), quote(crypt_signature_verify()))
})

test_that("encryption cross-decrypts with openssl, OAEP and v1.5", {
  skip_if_not_installed("openssl")
  key <- crypt_rsa_keygen(2048)
  theirs <- openssl::read_key(crypt_write_pem(key))
  secret <- as.raw(1:32)
  for (oaep in c(TRUE, FALSE)) {
    ct <- crypt_rsa_encrypt(secret, key$pubkey, oaep = oaep)
    expect_identical(openssl::rsa_decrypt(ct, theirs, oaep = oaep), secret)
    ct <- openssl::rsa_encrypt(secret, theirs$pubkey, oaep = oaep)
    expect_identical(crypt_rsa_decrypt(ct, key, oaep = oaep), secret)
  }
})

test_that("OAEP takes each hash, and decrypts only with the same one", {
  key <- crypt_rsa_keygen(2048)
  secret <- crypt_rand_bytes(32)
  for (h in c("sha1", "sha256", "sha384", "sha512")) {
    ct <- crypt_rsa_encrypt(secret, key, oaep = TRUE, oaep_hash = h)
    expect_length(ct, 256L)
    expect_identical(crypt_rsa_decrypt(ct, key, oaep = TRUE, oaep_hash = h),
                     secret)
  }
  ct <- crypt_rsa_encrypt(secret, key, oaep = TRUE, oaep_hash = "sha256")
  expect_error(crypt_rsa_decrypt(ct, key, oaep = TRUE),
               class = "zucrypt_auth_error")
  # Not asserted: that PKCS#1 v1.5 refuses an OAEP ciphertext. About one in
  # 256 OAEP encodings happens to look like valid v1.5 padding and decodes
  # to garbage -- the weakness that makes v1.5 legacy -- so the expectation
  # would fail by chance.
  expect_error(crypt_rsa_encrypt(secret, key, oaep = TRUE, oaep_hash = "md5"),
               class = "zucrypt_invalid_argument")
})

test_that("decryption failures are one class, and a long message is refused", {
  key <- crypt_rsa_keygen(1024)
  ct <- crypt_rsa_encrypt(as.raw(1:8), key, oaep = TRUE)
  flipped <- ct
  flipped[[10]] <- xor(flipped[[10]], as.raw(1))
  # A wrong length, nothing, and an integer above the modulus fail under
  # either padding. A flipped ciphertext is checked under OAEP only: under
  # PKCS#1 v1.5 the garbage it decrypts to passes the padding check about
  # once in 65,536.
  expect_error(crypt_rsa_decrypt(flipped, key, oaep = TRUE),
               class = "zucrypt_auth_error")
  for (bad in list(ct[-1], raw(0), as.raw(rep(0xff, 128)))) {
    for (oaep in c(TRUE, FALSE)) {
      expect_error(crypt_rsa_decrypt(bad, key, oaep = oaep),
                   class = "zucrypt_auth_error")
    }
  }
  # 1024 bits with OAEP-SHA1 leaves room for 86 bytes.
  expect_length(crypt_rsa_encrypt(as.raw(1:86), key, oaep = TRUE), 128L)
  expect_error(crypt_rsa_encrypt(as.raw(1:87), key, oaep = TRUE),
               class = "zucrypt_bad_length")
})

test_that("zuc_pkey_*() keep the contract zucrypt.h states", {
  got <- native_pkey_contract(charToRaw(crypt_write_pem(crypt_rsa_keygen(2048))))
  for (n in c("parse", "sign", "verify", "encrypt")) {
    expect_identical(got[[n]], "ZUC_OK", info = n)
  }
  for (n in c("sig_flipped", "sig_short", "pss_as_pkcs1", "decrypt_garbage")) {
    expect_identical(got[[n]], "ZUC_ERR_AUTH", info = n)
  }
  expect_identical(got[["sign_with_public"]], "ZUC_ERR_INVALID_ARGUMENT")
  expect_identical(got[["decrypt_public"]], "ZUC_ERR_INVALID_ARGUMENT")
  expect_identical(got[["digest_length"]], "ZUC_ERR_BAD_LENGTH")
  expect_identical(got[["sign_gcm"]], "ZUC_ERR_UNSUPPORTED")
  expect_identical(got[["write_small"]], "ZUC_ERR_BAD_LENGTH")
  for (n in c("decrypt_wiped", "write_wiped", "free_null")) {
    expect_identical(got[[n]], "TRUE", info = n)
  }
})

test_that("key generation takes 1024 to 4096 bits, and randomness", {
  key <- crypt_rsa_keygen(1024)
  expect_s3_class(key, "crypt_key")
  expect_identical(as.list(key)$size, 1024)
  expect_false(identical(crypt_write_der(key),
                         crypt_write_der(crypt_rsa_keygen(1024))))
  for (bad in list(512, 1023.5, 4097, 8192, "2048", NA)) {
    expect_error(crypt_rsa_keygen(bad), class = "zucrypt_invalid_argument")
  }
  native_random_fail(TRUE)
  err <- tryCatch(crypt_rsa_keygen(1024), error = identity,
                  finally = native_random_fail(FALSE))
  expect_s3_class(err, "zucrypt_entropy_error")
})

test_that("what is not an RSA key is refused, and says which way", {
  expect_error(crypt_read_key(as.raw(1:64)), class = "zucrypt_invalid_argument")
  expect_error(crypt_read_key("not a file"), class = "zucrypt_invalid_argument")
  expect_error(crypt_read_key(42), class = "zucrypt_invalid_argument")
  expect_error(
    crypt_read_key("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
    class = "zucrypt_invalid_argument"
  )
  # A public key is not a private key.
  pub <- crypt_write_pem(crypt_rsa_keygen(1024)$pubkey)
  expect_error(crypt_read_key(pub), class = "zucrypt_invalid_argument")
  expect_error(crypt_read_key(pub, password = "x"),
               class = "zucrypt_unsupported_algorithm")
  skip_if_not_installed("openssl")
  ec <- openssl::ec_keygen()
  expect_error(crypt_read_key(openssl::write_pem(ec)),
               class = "zucrypt_unsupported_algorithm")
  expect_error(crypt_read_pubkey(openssl::write_pem(ec$pubkey)),
               class = "zucrypt_unsupported_algorithm")
})

test_that("a saved key is refused, and a key keeps its class when used", {
  key <- crypt_rsa_keygen(1024)
  path <- tempfile(fileext = ".rds")
  on.exit(unlink(path), add = TRUE)
  saveRDS(key, path)
  stale <- readRDS(path)
  expect_error(crypt_write_pem(stale), class = "zucrypt_invalid_argument")
  expect_error(crypt_signature_create(as.raw(1), crypt_sha256, stale),
               class = "zucrypt_invalid_argument")
  crypt_write_der(key)
  crypt_signature_create(as.raw(1), crypt_sha256, key)
  expect_identical(class(key), c("crypt_key", "crypt_rsa"))
})

test_that("printing a key shows its size and type, never its material", {
  key <- rsa_fixture_key("rfc7515-a2")
  out <- capture.output(print(key))
  expect_identical(out, "[2048-bit rsa private key]")
  expect_identical(capture.output(print(key$pubkey)),
                   "[2048-bit rsa public key]")
})

test_that("crypt_sha*() mirror openssl's digests and HMACs on raw input", {
  skip_if_not_installed("openssl")
  x <- charToRaw("abc")
  k <- charToRaw("key")
  for (h in c("sha1", "sha256", "sha384", "sha512")) {
    theirs <- getExportedValue("openssl", h)
    expect_identical(hash_fun(h)(x), theirs(x), info = h)
    expect_identical(hash_fun(h)(x, key = k), theirs(x, key = k), info = h)
  }
  expect_error(crypt_sha256("abc"), class = "zucrypt_invalid_argument")
})
