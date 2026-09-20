# The ABI validation gate (roadmap Stage 4).
#
# This is not Office support and must not become it: no constants, no block
# keys, no salts. It is the generic shape of the iterative derivation those
# formats specify, run through the C table, and compared against an
# independent implementation written in R. The point is to find out whether
# the incremental and chaining interfaces actually suit the real consumer
# *before* the ABI is frozen, when changing them is still free.

# The same loop in R, using zucrypt's own public functions rather than the
# table. Independent in the sense that matters here: a missing hash_reset, or
# a reset that is not equivalent to a fresh context, would make the two
# disagree.
derive_in_r <- function(seed, spins, algorithm = "sha512") {
  digest <- zucrypt::crypt_hash(seed, algorithm)
  for (i in seq_len(spins) - 1L) {
    counter <- as.raw(bitwAnd(bitwShiftR(i, c(0L, 8L, 16L, 24L)), 255L))
    digest <- zucrypt::crypt_hash(c(counter, digest), algorithm)
  }
  digest
}

test_that("the derivation loop agrees with an independent implementation", {
  seed <- charToRaw("a password verifier, notionally")

  for (algorithm in c("sha1", "sha256", "sha512")) {
    for (spins in c(0L, 1L, 2L, 10L, 100L)) {
      expect_identical(
        derive_key(seed, spins, algorithm),
        derive_in_r(seed, spins, algorithm),
        info = paste(algorithm, spins)
      )
    }
  }
})

test_that("the loop survives a realistic spin count on one reused context", {
  # The real formats use 100,000. Running that here would be slow for no
  # extra information: what is being tested is that one context can be reset
  # and reused indefinitely, which 5,000 iterations demonstrates as well as
  # 100,000 does.
  seed <- charToRaw("verifier")
  got <- derive_key(seed, 5000L, "sha512")
  expect_length(got, 64L)
  expect_identical(got, derive_key(seed, 5000L, "sha512"))
  # A different spin count must give a different answer, or the loop is not
  # actually iterating.
  expect_false(identical(got, derive_key(seed, 4999L, "sha512")))
})

test_that("segmented CBC resets the chaining state at every boundary", {
  key <- as.raw(rep(0x2b, 32))
  iv <- as.raw(seq.int(0L, 15L))
  data <- as.raw(rep(seq.int(0L, 15L), times = 16))   # 256 bytes

  for (segment in c(16L, 32L, 64L, 128L)) {
    encrypted <- decrypt_segments(data, key, iv, segment, encrypt = TRUE)

    # Each segment must equal an independent encryption of that segment from
    # the same IV. That is what the Agile profiles specify, and it is what an
    # API hiding the IV inside a streaming operation could not express.
    starts <- seq(1L, length(data), by = segment)
    expected <- unlist(lapply(starts, function(s) {
      chunk <- data[s:min(s + segment - 1L, length(data))]
      zucrypt::crypt_aes_cbc_encrypt(chunk, key, iv)
    }))
    expect_identical(encrypted, expected, info = paste("segment", segment))

    # And it round trips.
    expect_identical(decrypt_segments(encrypted, key, iv, segment), data,
                     info = paste("segment", segment))
  }
})

test_that("a segmented stream differs from one continuous CBC stream", {
  # If it did not, the reset would be doing nothing and every assertion above
  # would be passing for the wrong reason.
  key <- as.raw(rep(0x2b, 16))
  iv <- as.raw(rep(0x01, 16))
  data <- as.raw(rep(0xff, 128))

  segmented <- decrypt_segments(data, key, iv, 32L, encrypt = TRUE)
  continuous <- zucrypt::crypt_aes_cbc_encrypt(data, key, iv)
  expect_false(identical(segmented, continuous))
  # The first segment is the one place they must agree.
  expect_identical(segmented[1:32], continuous[1:32])
})
