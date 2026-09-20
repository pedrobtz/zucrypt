# The public interface: that it computes the right answers, does not touch its
# inputs, and handles the empty cases the design calls out.

test_that("the public functions reproduce every published vector", {
  # The same fixtures the adapter is tested against, now through the R
  # surface. Running them twice is the point: the wrappers do argument
  # handling and buffer allocation of their own, and a bug there would not
  # show up in the native harness.
  for (v in split(kat_vectors("hash"), seq_len(nrow(kat_vectors("hash"))))) {
    expect_identical(tohex(crypt_hash(unhex(v$input), v$algorithm)), v$output,
                     info = v$id)
  }
  for (v in split(kat_vectors("hmac"), seq_len(nrow(kat_vectors("hmac"))))) {
    expect_identical(
      tohex(crypt_hmac(unhex(v$input), unhex(v$key), v$algorithm)),
      v$output, info = v$id)
  }
  cbc <- kat_vectors("aes-cbc")
  for (v in split(cbc, seq_len(nrow(cbc)))) {
    expect_identical(
      tohex(crypt_aes_cbc_encrypt(unhex(v$input), unhex(v$key), unhex(v$iv))),
      v$output, info = v$id)
    expect_identical(
      tohex(crypt_aes_cbc_decrypt(unhex(v$output), unhex(v$key), unhex(v$iv))),
      v$input, info = v$id)
  }
})

test_that("inputs are byte-identical after every call", {
  # Native code must never write into an R vector it was handed. R would not
  # complain, and the damage would land in whatever else shares that vector.
  data <- as.raw(seq.int(0L, 255L))
  key <- as.raw(rep(0x2b, 32))
  iv <- as.raw(seq.int(0L, 15L))
  data0 <- data; key0 <- key; iv0 <- iv

  invisible(crypt_hash(data))
  invisible(crypt_hmac(data, key))
  invisible(crypt_equal(data, data))
  invisible(crypt_aes_cbc_encrypt(data, key, iv))
  invisible(crypt_aes_cbc_decrypt(data, key, iv))

  expect_identical(data, data0)
  expect_identical(key, key0)
  expect_identical(iv, iv0)
})

test_that("results are freshly allocated, not views on the input", {
  data <- as.raw(rep(0x01, 32))
  out <- crypt_aes_cbc_encrypt(data, as.raw(rep(0x02, 16)), raw(16))
  out[1] <- as.raw(0xff)
  expect_identical(data, as.raw(rep(0x01, 32)))
})

test_that("empty input is valid for digests and HMAC", {
  expect_length(crypt_hash(raw(0)), 32L)
  expect_length(crypt_hash(raw(0), "sha1"), 20L)
  expect_length(crypt_hmac(raw(0), raw(0)), 32L)

  v <- kat_vectors("hash")
  empty <- v[v$input == "", ]
  for (i in seq_len(nrow(empty))) {
    expect_identical(tohex(crypt_hash(raw(0), empty$algorithm[i])),
                     empty$output[i])
  }
})

test_that("empty CBC input returns empty, but only after validation", {
  key <- as.raw(rep(0x2b, 16))
  expect_identical(crypt_aes_cbc_encrypt(raw(0), key, raw(16)), raw(0))
  expect_identical(crypt_aes_cbc_decrypt(raw(0), key, raw(16)), raw(0))

  # Zero length does not excuse a bad key or IV: the design says the empty
  # result comes *after* parameter validation succeeds.
  expect_error(crypt_aes_cbc_encrypt(raw(0), raw(15), raw(16)),
               class = "zucrypt_bad_length")
  expect_error(crypt_aes_cbc_encrypt(raw(0), key, raw(8)),
               class = "zucrypt_bad_length")
})

test_that("crypt_equal() is length-aware and value-correct", {
  a <- crypt_hash(charToRaw("message"))
  expect_true(crypt_equal(a, a))
  expect_true(crypt_equal(raw(0), raw(0)))
  expect_false(crypt_equal(a, crypt_hash(charToRaw("other"))))
  # Unequal lengths are FALSE rather than an error: length is not secret.
  expect_false(crypt_equal(a, raw(0)))
  expect_false(crypt_equal(a, a[1:10]))
})

test_that("a round trip returns the original bytes at several key lengths", {
  data <- as.raw(rep(seq.int(0L, 15L), times = 8))
  iv <- as.raw(rep(0x7f, 16))
  for (n in c(16L, 24L, 32L)) {
    key <- as.raw(rep(0x11, n))
    ct <- crypt_aes_cbc_encrypt(data, key, iv)
    expect_identical(crypt_aes_cbc_decrypt(ct, key, iv), data)
    # And a different IV must give different ciphertext, or the IV is being
    # ignored somewhere.
    expect_false(identical(ct, crypt_aes_cbc_encrypt(data, key, raw(16))))
  }
})

test_that("input larger than one interrupt chunk is handled correctly", {
  # The native entry points process input in 1 MiB chunks so an interrupt can
  # be answered. Crossing that boundary must not change the answer, and the
  # CBC path in particular must chain across chunks.
  n <- 1024L * 1024L + 1024L
  data <- as.raw(rep(seq.int(0L, 255L), length.out = n))
  key <- as.raw(rep(0x2b, 16))
  iv <- as.raw(seq.int(0L, 15L))

  expect_length(crypt_hash(data), 32L)
  # A hash of the same bytes computed in two halves through the harness must
  # match the wrapper's chunked answer.
  expect_identical(crypt_hash(data), native_hash("sha256", data,
                                                 c(n %/% 2L, n - n %/% 2L)))

  ct <- crypt_aes_cbc_encrypt(data, key, iv)
  expect_identical(crypt_aes_cbc_decrypt(ct, key, iv), data)
  # Chunking must not restart the chaining: one call through the adapter with
  # no chunking has to agree.
  expect_identical(ct, native_aes("cbc", TRUE, key, iv, data))
})

test_that("crypt_info() reports the build, from the compiled library", {
  info <- crypt_info()
  expect_named(info, c("version", "abi_version", "algorithms", "vendored",
                       "build_flags"))
  expect_s3_class(info$version, "package_version")
  expect_type(info$abi_version, "integer")
  expect_identical(info$algorithms, c("sha1", "sha256", "sha384", "sha512"))
  expect_s3_class(info$vendored, "data.frame")
  expect_identical(info$vendored$source, "TF-PSA-Crypto")
  expect_match(info$vendored$version, "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  expect_false(info$build_flags$hardware_acceleration)

  # src/zuc_random.c's preprocessor chain has no arm that selects nothing:
  # every platform lands on a named source. An empty string would mean the
  # chain fell through and the backend links against a function that cannot
  # produce bytes.
  expect_true(info$build_flags$random_backend %in%
                c("rand_s", "arc4random_buf", "getrandom", "/dev/urandom"))

  # Whatever it advertises must actually work.
  for (alg in info$algorithms) {
    expect_true(length(crypt_hash(raw(0), alg)) > 0L)
  }
})
