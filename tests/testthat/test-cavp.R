# NIST CAVP vectors (#67), through both surfaces: the R functions and the
# adapter through the zucrypt_test_* harness.
#
# fixtures/cavp.tsv is a subset that ships. With ZUCRYPT_CAVP naming
# tools/cavp/cavp.tsv.gz, every vector runs: aes-paths.yaml does that on each
# AES implementation, and tools/ci/platform.sh on macOS and Windows. Both
# files are written by tools/make-cavp.py from the archives NIST publishes,
# checked by SHA-256; CAVP is the outside oracle.

test_that("the full CAVP set is all there when it is asked for", {
  skip_if_not(cavp_full())
  # The gate rule: a job that ran no vectors must not pass.
  expect_identical(nrow(cavp_vectors()), CAVP_FULL_COUNT)
})

test_that("SHAVS ShortMsg and LongMsg digests reproduce", {
  v <- cavp_vectors("hash")
  expect_gt(nrow(v), 0L)
  r_side <- c_side <- stats::setNames(character(nrow(v)), v$id)
  for (i in seq_len(nrow(v))) {
    data <- unhex(v$input[i])
    n <- length(data)
    r_side[i] <- tohex(crypt_hash(data, v$algorithm[i]))
    # The incremental path, split one short of a block and unevenly after.
    k <- min(n, 63L)
    plan <- if (n == 0L) integer(0) else c(k, (n - k) %/% 2L,
                                           n - k - (n - k) %/% 2L)
    c_side[i] <- tohex(native_hash(v$algorithm[i], data, plan))
  }
  # One comparison per surface, named by vector id: a failure lists the ids.
  want <- stats::setNames(v$output, v$id)
  expect_identical(r_side, want)
  expect_identical(c_side, want)
})

test_that("SHAVS Monte Carlo chains reproduce through one reused context", {
  v <- cavp_vectors("hash-monte")
  expect_gt(nrow(v), 0L)
  for (alg in unique(v$algorithm)) {
    w <- v[v$algorithm == alg, , drop = FALSE]
    w <- w[order(w$id), , drop = FALSE]
    # The C chain starts at checkpoint 0 and runs every listed checkpoint,
    # all n * 1000 digests through one handle.
    expect_true(endsWith(w$id[1], "-000"), info = alg)
    got <- native_sha_monte(alg, unhex(w$input[1]), nrow(w))
    d <- length(got) / nrow(w)
    for (j in seq_len(nrow(w))) {
      expect_identical(tohex(got[(j - 1) * d + seq_len(d)]), w$output[j],
                       info = w$id[j])
    }
  }

  # The R surface, from each checkpoint's own seed. Every 25th checkpoint
  # of the full set, to stay inside the time budget; the C chain above has
  # checked them all.
  r <- if (cavp_full()) v[as.integer(substring(v$id, nchar(v$id) - 2)) %% 25L == 0L, ] else v
  for (i in seq_len(nrow(r))) {
    md <- rep(list(unhex(r$input[i])), 3L)
    for (k in seq_len(1000L)) {
      md <- list(md[[2]], md[[3]], crypt_hash(c(md[[1]], md[[2]], md[[3]]),
                                              r$algorithm[i]))
    }
    expect_identical(tohex(md[[3]]), r$output[i], info = r$id[i])
  }
})

test_that("HMACVS tags reproduce at every key and tag length", {
  v <- cavp_vectors("hmac")
  expect_gt(nrow(v), 0L)
  r_side <- c_side <- stats::setNames(character(nrow(v)), v$id)
  for (i in seq_len(nrow(v))) {
    key <- unhex(v$key[i])
    data <- unhex(v$input[i])
    n <- length(data)
    # A truncated tag is the leading Tlen bytes of the full one.
    tlen <- nchar(v$output[i])
    r_side[i] <- substr(tohex(crypt_hmac(data, key, v$algorithm[i])), 1L, tlen)
    c_side[i] <- substr(tohex(native_hmac(v$algorithm[i], key, data,
                                          c(n %/% 3L, n - n %/% 3L))),
                        1L, tlen)
  }
  want <- stats::setNames(v$output, v$id)
  expect_identical(r_side, want)
  expect_identical(c_side, want)
})

test_that("AESAVS CBC known answers and MMT reproduce in both directions", {
  v <- cavp_vectors("cbc")
  expect_gt(nrow(v), 0L)
  r_side <- c_side <- stats::setNames(character(nrow(v)), v$id)
  for (i in seq_len(nrow(v))) {
    key <- unhex(v$key[i])
    iv <- unhex(v$iv[i])
    data <- unhex(v$input[i])
    enc <- v$algorithm[i] == "encrypt"
    f <- if (enc) crypt_aes_cbc_encrypt_nopad else crypt_aes_cbc_decrypt_nopad
    r_side[i] <- tohex(f(data, key, iv))
    # One block per call through one handle: the chaining state carries.
    plan <- rep(16L, length(data) %/% 16L)
    c_side[i] <- tohex(native_aes("cbc", enc, key, iv, data, plan))
  }
  want <- stats::setNames(v$output, v$id)
  expect_identical(r_side, want)
  expect_identical(c_side, want)
})

test_that("AESAVS CBC Monte Carlo reproduces, chained in C and per row in R", {
  v <- cavp_vectors("cbc-mct")
  expect_gt(nrow(v), 0L)
  stems <- sub("-[0-9]{3}$", "", v$id)
  for (s in unique(stems)) {
    w <- v[stems == s, , drop = FALSE]
    w <- w[order(w$id), , drop = FALSE]
    enc <- w$algorithm[1] == "encrypt"
    expect_true(endsWith(w$id[1], "-000"), info = s)
    got <- native_cbc_mct(enc, unhex(w$key[1]), unhex(w$iv[1]),
                          unhex(w$input[1]), nrow(w))
    kl <- nchar(w$key[1]) / 2L
    row <- kl + 48L
    for (j in seq_len(nrow(w))) {
      r <- got[(j - 1L) * row + seq_len(row)]
      expect_identical(
        c(tohex(r[seq_len(kl)]), tohex(r[kl + 1:16]), tohex(r[kl + 16 + 1:16]),
          tohex(r[kl + 32 + 1:16])),
        c(w$key[j], w$iv[j], w$input[j], w$output[j]),
        info = w$id[j]
      )
    }
  }

  # The R surface: 1000 one-block calls from a row's own start values, the
  # chaining carried by passing the previous output block as the next IV.
  # Every 25th checkpoint of the full set; the C chain has checked them all.
  r <- if (cavp_full()) v[as.integer(substring(v$id, nchar(v$id) - 2)) %% 25L == 0L, ] else v
  for (i in seq_len(nrow(r))) {
    enc <- r$algorithm[i] == "encrypt"
    f <- if (enc) crypt_aes_cbc_encrypt_nopad else crypt_aes_cbc_decrypt_nopad
    key <- unhex(r$key[i])
    iv <- unhex(r$iv[i])
    chain <- iv
    input <- unhex(r$input[i])
    prev <- NULL
    for (j in 0:999) {
      # Decryption chains on the ciphertext block, encryption on the output.
      out <- f(input, key, chain)
      chain <- if (enc) out else input
      nxt <- if (j == 0L) iv else prev
      prev <- out
      input <- nxt
    }
    expect_identical(tohex(out), r$output[i], info = r$id[i])
  }
})
