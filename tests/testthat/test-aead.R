# crypt_aes_gcm_encrypt() / _decrypt() and zuc_aead_*() (#10, Stage 14a).
#
# The published vectors fix the bytes; the authentication gate of design.md
# section 12 fixes the contract: every alteration fails with
# zucrypt_auth_error and releases no plaintext, in C and in R.

test_that("every published GCM vector reproduces, both directions", {
  v <- aead_vectors()
  expect_gt(nrow(v), 0L)
  for (i in seq_len(nrow(v))) {
    a <- gcm_args(v[i, ])
    ct <- crypt_aes_gcm_encrypt(a$input, a$key, a$iv, aad = a$aad)
    expect_identical(as.vector(ct), a$output, info = v$id[i])
    expect_identical(attr(ct, "tag"), a$tag, info = v$id[i])
    expect_identical(attr(ct, "iv"), a$iv, info = v$id[i])
    pt <- crypt_aes_gcm_decrypt(a$output, a$key, a$iv, a$tag, aad = a$aad)
    expect_identical(pt, a$input, info = v$id[i])
  }
})

test_that("decryption reads the nonce and tag from the ciphertext", {
  key <- as.raw(1:16)
  ct <- crypt_aes_gcm_encrypt(charToRaw("hello"), key)
  expect_length(attr(ct, "iv"), 12L)
  expect_length(attr(ct, "tag"), 16L)
  expect_identical(crypt_aes_gcm_decrypt(ct, key), charToRaw("hello"))
  # The plaintext comes back without attributes.
  expect_null(attributes(crypt_aes_gcm_decrypt(ct, key)))
})

test_that("the default nonce is fresh for every message", {
  key <- as.raw(1:32)
  a <- crypt_aes_gcm_encrypt(charToRaw("same"), key)
  b <- crypt_aes_gcm_encrypt(charToRaw("same"), key)
  expect_false(identical(attr(a, "iv"), attr(b, "iv")))
  expect_false(identical(as.vector(a), as.vector(b)))
})

test_that("empty plaintext and empty associated data are valid", {
  key <- raw(16)
  ct <- crypt_aes_gcm_encrypt(raw(0), key, raw(12))
  expect_identical(as.vector(ct), raw(0))
  expect_identical(attr(ct, "tag"), unhex("58e2fccefa7e3061367f1d57a4e7455a"))
  expect_identical(crypt_aes_gcm_decrypt(ct, key), raw(0))
  # raw(0) as associated data is the same as none.
  expect_identical(
    attr(crypt_aes_gcm_encrypt(raw(0), key, raw(12), aad = raw(0)), "tag"),
    attr(ct, "tag")
  )
})

test_that("every alteration fails with zucrypt_auth_error (design §12)", {
  key <- as.raw(1:32)
  aad <- charToRaw("header")
  ct <- crypt_aes_gcm_encrypt(charToRaw("a secret message"), key, aad = aad)
  flip <- function(x, i = 1L) {
    x[i] <- xor(x[i], as.raw(1))
    x
  }
  expect_auth <- function(expr) {
    err <- expect_error(expr, class = "zucrypt_auth_error")
    expect_s3_class(err, "zucrypt_error")
    expect_identical(conditionCall(err), quote(crypt_aes_gcm_decrypt()))
    expect_identical(err$algorithm, "aes-256-gcm")
    # Neither the message nor anything else carries the plaintext.
    expect_false(grepl("secret", conditionMessage(err), fixed = TRUE))
  }
  expect_auth(crypt_aes_gcm_decrypt(flip(ct), key, aad = aad))
  expect_auth(crypt_aes_gcm_decrypt(ct, key, tag = flip(attr(ct, "tag")),
                                    aad = aad))
  expect_auth(crypt_aes_gcm_decrypt(ct, key, aad = flip(aad)))
  expect_auth(crypt_aes_gcm_decrypt(ct, key, iv = flip(attr(ct, "iv")),
                                    aad = aad))
  expect_auth(crypt_aes_gcm_decrypt(ct, flip(key), aad = aad))
  # Truncated: the right prefix of the right tag.
  expect_auth(crypt_aes_gcm_decrypt(ct, key, tag = attr(ct, "tag")[1:15],
                                    aad = aad))
  expect_auth(crypt_aes_gcm_decrypt(ct, key, tag = raw(0), aad = aad))
  # Associated data left out, or added.
  expect_auth(crypt_aes_gcm_decrypt(ct, key))
  plain <- crypt_aes_gcm_encrypt(charToRaw("x"), key)
  expect_auth(crypt_aes_gcm_decrypt(plain, key, aad = aad))
  # A shortened ciphertext.
  short <- ct[-length(ct)]
  attributes(short) <- attributes(ct)[c("iv", "tag")]
  expect_auth(crypt_aes_gcm_decrypt(short, key, aad = aad))
})

test_that("zuc_aead_*() keep the contract zucrypt.h states", {
  got <- native_aead_contract()
  ok <- c("encrypt", "decrypt", "inplace_encrypt", "inplace_decrypt",
          "null_data_0", "null_aad_0")
  for (n in ok) expect_identical(got[[n]], "ZUC_OK", info = n)
  auth <- c("tampered_ciphertext", "tampered_tag", "tampered_aad",
            "tampered_nonce", "truncated_tag", "wrong_key")
  for (n in auth) expect_identical(got[[n]], "ZUC_ERR_AUTH", info = n)
  truthy <- c("roundtrip", "wiped_on_failure", "inplace_matches",
              "overlap_untouched")
  for (n in truthy) expect_identical(got[[n]], "TRUE", info = n)
  expect_identical(got[["partial_overlap"]], "ZUC_ERR_OVERLAP")
  expect_identical(got[["null_key"]], "ZUC_ERR_INVALID_ARGUMENT")
  expect_identical(got[["bad_key_length"]], "ZUC_ERR_BAD_LENGTH")
  expect_identical(got[["bad_nonce_length"]], "ZUC_ERR_BAD_LENGTH")
  expect_identical(got[["short_tag_encrypt"]], "ZUC_ERR_BAD_LENGTH")
  for (n in c("not_an_aead", "hash_refuses_gcm", "hmac_refuses_gcm",
              "pbkdf2_refuses_gcm")) {
    expect_identical(got[[n]], "ZUC_ERR_UNSUPPORTED", info = n)
  }
  expect_identical(got[["pbkdf2_zero_iterations"]], "ZUC_ERR_INVALID_ARGUMENT")
})

test_that("keys, nonces and types are checked before anything runs", {
  data <- charToRaw("data")
  for (n in c(0L, 15L, 17L, 31L, 33L)) {
    expect_error(crypt_aes_gcm_encrypt(data, raw(n), raw(12)),
                 class = "zucrypt_bad_length")
  }
  for (n in c(0L, 8L, 11L, 13L, 16L)) {
    expect_error(crypt_aes_gcm_encrypt(data, raw(16), raw(n)),
                 class = "zucrypt_bad_length")
  }
  expect_error(crypt_aes_gcm_encrypt("data", raw(16)),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_aes_gcm_encrypt(data, "key"),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_aes_gcm_encrypt(data, raw(16), aad = "x"),
               class = "zucrypt_invalid_argument")
  # A ciphertext with no iv or tag attribute and none given.
  expect_error(crypt_aes_gcm_decrypt(data, raw(16)),
               class = "zucrypt_invalid_argument")
  expect_error(crypt_aes_gcm_decrypt(data, raw(16), raw(12)),
               class = "zucrypt_invalid_argument")
})

test_that("inputs are left unchanged", {
  key <- as.raw(1:16)
  iv <- as.raw(1:12)
  data <- charToRaw("leave me alone")
  aad <- charToRaw("and me")
  keep <- list(key, iv, data, aad)
  ct <- crypt_aes_gcm_encrypt(data, key, iv, aad)
  ct_copy <- ct
  crypt_aes_gcm_decrypt(ct, key, aad = aad)
  expect_identical(list(key, iv, data, aad), keep)
  expect_identical(ct, ct_copy)
})

test_that("ciphertext equals openssl's, past one interrupt chunk", {
  skip_if_not_installed("openssl")
  # Deterministic bytes, so R's RNG is neither used nor disturbed.
  bytes <- function(n, k) as.raw((seq_len(n) * k + n) %% 256L)
  for (n in c(1L, 15L, 16L, 17L, 1000L, 65537L, 1024L * 1024L + 3L)) {
    data <- bytes(n, 31L)
    key <- bytes(32L, 7L)
    iv <- bytes(12L, 13L)
    ours <- crypt_aes_gcm_encrypt(data, key, iv)
    theirs <- openssl::aes_gcm_encrypt(data, key, iv)
    expect_identical(as.vector(ours), as.vector(theirs), info = n)
    expect_identical(crypt_aes_gcm_decrypt(ours, key), data, info = n)
  }
})

test_that("the argument order mirrors openssl::aes_gcm_encrypt()", {
  skip_if_not_installed("openssl")
  ours <- names(formals(crypt_aes_gcm_encrypt))
  theirs <- names(formals(openssl::aes_gcm_encrypt))
  expect_identical(ours[seq_along(theirs)], theirs)
  ours <- names(formals(crypt_aes_gcm_decrypt))
  theirs <- names(formals(openssl::aes_gcm_decrypt))
  expect_identical(ours[seq_along(theirs)], theirs)
})
