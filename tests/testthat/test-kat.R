# Known-answer tests, from committed published vectors.
#
# The vectors are in fixtures/kat.tsv with their provenance in
# fixtures/MANIFEST.tsv, and tools/make-kat.R --check recomputes every one of
# them against openssl -- a completely independent implementation. That is the
# design's requirement (section 12): a self round trip proves the library
# agrees with itself, which it would also do with a wrong constant on both
# sides.

test_that("every published digest vector reproduces", {
  v <- kat_vectors("hash")
  expect_gt(nrow(v), 0L)

  for (i in seq_len(nrow(v))) {
    got <- native_hash(v$algorithm[i], unhex(v$input[i]))
    expect_identical(tohex(got), v$output[i],
                     info = paste(v$id[i], v$algorithm[i]))
  }
})

test_that("every published HMAC vector reproduces", {
  v <- kat_vectors("hmac")
  expect_gt(nrow(v), 0L)

  for (i in seq_len(nrow(v))) {
    got <- native_hmac(v$algorithm[i], unhex(v$key[i]), unhex(v$input[i]))
    expect_identical(tohex(got), v$output[i],
                     info = paste(v$id[i], v$algorithm[i]))
  }
})

test_that("every published AES vector reproduces, both directions", {
  v <- kat_vectors(c("aes-cbc", "aes-ecb"))
  expect_gt(nrow(v), 0L)

  for (i in seq_len(nrow(v))) {
    mode <- if (v$family[i] == "aes-cbc") "cbc" else "ecb"
    key <- unhex(v$key[i])
    iv <- if (nzchar(v$iv[i])) unhex(v$iv[i]) else raw(16)
    pt <- unhex(v$input[i])

    ct <- native_aes(mode, TRUE, key, iv, pt)
    expect_identical(tohex(ct), v$output[i], info = paste(v$id[i], "encrypt"))

    # Decryption is a separate code path with its own chaining bookkeeping,
    # not the inverse of the line above.
    back <- native_aes(mode, FALSE, key, iv, unhex(v$output[i]))
    expect_identical(tohex(back), v$input[i], info = paste(v$id[i], "decrypt"))
  }
})

test_that("incremental digests equal one-shot at every split point", {
  v <- kat_vectors("hash")

  for (i in seq_len(nrow(v))) {
    data <- unhex(v$input[i])
    for (plan in split_plans(length(data))) {
      got <- native_hash(v$algorithm[i], data, plan)
      expect_identical(tohex(got), v$output[i],
                       info = paste(v$id[i], "splits:",
                                    paste(plan, collapse = "+")))
    }
  }
})

test_that("incremental HMAC equals one-shot at every split point", {
  v <- kat_vectors("hmac")

  for (i in seq_len(nrow(v))) {
    data <- unhex(v$input[i])
    for (plan in split_plans(length(data))) {
      got <- native_hmac(v$algorithm[i], unhex(v$key[i]), data, plan)
      expect_identical(tohex(got), v$output[i],
                       info = paste(v$id[i], "splits:",
                                    paste(plan, collapse = "+")))
    }
  }
})

test_that("a longer message crosses the internal buffer boundary", {
  # The published vectors are all shorter than one compression block, so on
  # their own they never exercise the buffering the incremental path does.
  data <- as.raw(rep(seq.int(0L, 255L), length.out = 1000L))

  for (alg in c("sha1", "sha256", "sha384", "sha512")) {
    reference <- native_hash(alg, data)
    for (plan in list(c(1L, 999L), c(63L, 937L), c(64L, 936L), c(65L, 935L),
                      c(127L, 873L), c(128L, 872L), c(500L, 500L),
                      rep(100L, 10L))) {
      expect_identical(native_hash(alg, data, plan), reference,
                       info = paste(alg, paste(plan, collapse = "+")))
    }
  }
})
