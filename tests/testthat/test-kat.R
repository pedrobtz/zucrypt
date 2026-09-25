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
  v <- kat_vectors("aes-cbc")
  expect_gt(nrow(v), 0L)

  for (i in seq_len(nrow(v))) {
    key <- unhex(v$key[i])
    iv <- unhex(v$iv[i])
    pt <- unhex(v$input[i])

    ct <- native_aes("cbc", TRUE, key, iv, pt)
    expect_identical(tohex(ct), v$output[i], info = paste(v$id[i], "encrypt"))

    # Decryption is a separate code path with its own chaining bookkeeping,
    # not the inverse of the line above.
    back <- native_aes("cbc", FALSE, key, iv, unhex(v$output[i]))
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
  # The published multi-block vectors are one-million-byte runs of a single
  # byte, which cross every boundary but with uniform content. This uses
  # varied bytes at lengths that straddle each block size.
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

test_that("large inputs agree with OpenSSL through the public functions", {
  # design.md section 12: compatibility with an independent implementation,
  # not with ourselves. The published vectors pin the algorithms; this pins
  # the chunking in src/zucrypt_crypt.c (1 MiB between interrupt checks) and
  # the incremental path it drives, at sizes no published vector covers --
  # one short of and past a block, 64 KiB + 1, and four whole chunks.
  skip_if_not_installed("openssl")

  key <- as.raw(seq_len(100L) %% 256L)   # longer than the SHA-1/256 block
  sizes <- c(1000L, 65537L, 4L * 1024L * 1024L)
  ref <- list(sha1 = openssl::sha1, sha256 = openssl::sha256,
              sha384 = openssl::sha384, sha512 = openssl::sha512)

  for (n in sizes) {
    data <- as.raw((seq_len(n) * 7L) %% 251L)
    for (alg in names(ref)) {
      expect_identical(crypt_hash(data, alg), as.raw(ref[[alg]](data)),
                       info = paste(alg, n))
      expect_identical(crypt_hmac(data, key, alg),
                       as.raw(ref[[alg]](data, key = key)),
                       info = paste("hmac", alg, n))
    }
  }

  # AES-CBC across chunk boundaries. openssl pads, so compare the blocks the
  # input covers; they are identical because padding only appends.
  data <- as.raw((seq_len(4L * 1024L * 1024L) * 13L) %% 251L)
  iv <- as.raw(seq_len(16L))
  for (bits in c(128L, 192L, 256L)) {
    k <- as.raw(seq_len(bits %/% 8L) + 40L)
    ours <- crypt_aes_cbc_encrypt(data, k, iv)
    theirs <- openssl::aes_cbc_encrypt(data, key = k, iv = iv)
    expect_identical(ours, as.raw(theirs)[seq_along(data)], info = bits)
  }
})
