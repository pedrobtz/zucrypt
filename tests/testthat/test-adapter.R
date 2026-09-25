# Adapter behaviour that the published vectors do not reach: chaining state,
# resets, overlap, the status table and the struct_size contract.

test_that("CBC chaining continues across calls and a reset restores the IV", {
  v <- kat_vectors("aes-cbc", "aes128")[1, ]
  key <- unhex(v$key); iv <- unhex(v$iv); pt <- unhex(v$input)

  # Two half-length calls with the state retained equal one full call. This
  # is the property the whole explicit-chaining design rests on.
  whole <- native_aes("cbc", TRUE, key, iv, pt)
  halves <- native_aes("cbc", TRUE, key, iv, pt,
                       splits = c(32L, 32L), reset_each = FALSE)
  expect_identical(halves, whole)

  # And resetting to the IV before each chunk does *not* equal one call --
  # if it did, the reset would be doing nothing and the test above would be
  # passing for the wrong reason.
  segmented <- native_aes("cbc", TRUE, key, iv, pt,
                          splits = c(32L, 32L), reset_each = TRUE)
  expect_false(identical(segmented, whole))

  # Each segment must equal an independent encryption of that segment from
  # the same IV, which is exactly what a segmented document format needs.
  first <- native_aes("cbc", TRUE, key, iv, pt[1:32])
  second <- native_aes("cbc", TRUE, key, iv, pt[33:64])
  expect_identical(segmented, c(first, second))
})

test_that("CBC decryption chains on the ciphertext, not the plaintext", {
  v <- kat_vectors("aes-cbc", "aes256")[1, ]
  key <- unhex(v$key); iv <- unhex(v$iv); ct <- unhex(v$output)

  whole <- native_aes("cbc", FALSE, key, iv, ct)
  halves <- native_aes("cbc", FALSE, key, iv, ct, splits = c(16L, 48L))
  expect_identical(halves, whole)
  expect_identical(tohex(whole), v$input)
})

test_that("exact in-place AES is supported and correct", {
  v <- kat_vectors("aes-cbc", "aes128")[1, ]
  key <- unhex(v$key); iv <- unhex(v$iv)

  expect_identical(tohex(native_aes_inplace(TRUE, key, iv, unhex(v$input))),
                   v$output)
  # The decrypt path has to save the next chaining value before overwriting
  # the input it lives in; in place is the only way that goes wrong.
  expect_identical(tohex(native_aes_inplace(FALSE, key, iv, unhex(v$output))),
                   v$input)
})

test_that("partial overlap is refused rather than silently corrupted", {
  v <- kat_vectors("aes-cbc", "aes128")[1, ]
  key <- unhex(v$key); iv <- unhex(v$iv); pt <- unhex(v$input)

  for (shift in c(1L, 15L, 16L, 48L)) {
    expect_identical(native_aes_overlap(key, iv, pt, shift), "ZUC_ERR_OVERLAP",
                     info = paste("shift", shift))
  }
  # Zero shift is exact in-place, which is supported.
  expect_identical(native_aes_overlap(key, iv, pt, 0L), "ZUC_OK")
})

test_that("a reset digest context is indistinguishable from a fresh one", {
  v <- kat_vectors("hash", "sha256")
  target <- v[v$input != "", ][1, ]

  got <- native_hash_reset("sha256", charToRaw("discarded content"),
                           unhex(target$input))
  expect_identical(tohex(got), target$output)
})

test_that("a reset HMAC context keeps its key", {
  v <- kat_vectors("hmac", "sha256")[1, ]

  got <- native_hmac_reset("sha256", unhex(v$key),
                           charToRaw("discarded content"), unhex(v$input))
  expect_identical(tohex(got), v$output)
})

test_that("constant-time comparison answers correctly", {
  a <- charToRaw("the same bytes")
  expect_true(native_equal(a, a))
  expect_true(native_equal(raw(0), raw(0)))

  b <- a; b[1] <- as.raw(0x00)
  expect_false(native_equal(a, b))
  b <- a; b[length(b)] <- as.raw(0x00)
  expect_false(native_equal(a, b))

  # Length is the caller's business and is not hidden, so unequal lengths are
  # a usage error at this layer rather than a FALSE.
  expect_error(native_equal(a, a[1:3]))
})

test_that("every status enumerator has a name and a message", {
  codes <- native_status_codes()
  expect_true(length(codes) >= 9L)
  expect_true("ZUC_OK" %in% names(codes))
  expect_identical(unname(codes[["ZUC_OK"]]), 0L)
  # No negative value, so `if (st)` means "not success" in C.
  expect_true(all(codes >= 0L))

  for (i in seq_along(codes)) {
    s <- native_status(codes[[i]])
    expect_identical(unname(s[["name"]]), names(codes)[i])
    expect_true(nzchar(s[["message"]]))
  }

  # And a value that is not an enumerator at all still answers, because a
  # caller reporting an error must never fail while doing so.
  s <- native_status(9999L)
  expect_true(nzchar(s[["name"]]))
  expect_true(nzchar(s[["message"]]))
})

test_that("algorithm identity, size and availability agree", {
  algs <- native_algs()
  expect_identical(algs$name, c("sha1", "sha256", "sha384", "sha512"))
  expect_identical(algs$size, c(20L, 32L, 48L, 64L))
  expect_true(all(algs$available))

  # Anything reporting available must actually produce its published vector,
  # at the length it claims.
  for (i in seq_along(algs$name)) {
    got <- native_hash(algs$name[i], charToRaw("abc"))
    expect_length(got, algs$size[i])
  }
})

test_that("zuc_get_info() honours the caller's struct_size", {
  sizes <- native_required_sizes()
  expect_true(sizes[["required"]] > 0L)
  expect_true(sizes[["current"]] >= sizes[["required"]])

  # At or above the required prefix is served; below it is refused. A
  # consumer built against an older header has the shorter struct, and
  # writing past its end would smash its stack rather than ours.
  expect_identical(native_info_size(sizes[["current"]]), "ZUC_OK")
  expect_identical(native_info_size(sizes[["required"]]), "ZUC_OK")
  expect_identical(native_info_size(sizes[["required"]] - 1L), "ZUC_ERR_ABI")
  expect_identical(native_info_size(0L), "ZUC_ERR_ABI")
})

test_that("empty input is valid for digests and HMAC", {
  v <- kat_vectors("hash")
  empty <- v[v$input == "", ]
  expect_gt(nrow(empty), 0L)
  for (i in seq_len(nrow(empty))) {
    expect_identical(tohex(native_hash(empty$algorithm[i], raw(0))),
                     empty$output[i])
  }
  # An empty HMAC key is legal -- RFC 2104 sets no lower bound -- and must
  # not be confused with a missing one.
  expect_length(native_hmac("sha256", raw(0), raw(0)), 32L)
})

test_that("empty AES input is a no-op after validation", {
  key <- unhex(kat_vectors("aes-cbc", "aes128")$key[1])
  expect_identical(native_aes("cbc", TRUE, key, raw(16), raw(0)), raw(0))
})

test_that("a non-block-multiple length is refused", {
  key <- unhex(kat_vectors("aes-cbc", "aes128")$key[1])
  for (n in c(1L, 15L, 17L, 31L)) {
    expect_error(native_aes("cbc", TRUE, key, raw(16), raw(n)),
                 "ZUC_ERR_BAD_LENGTH")
  }
})

test_that("only 16, 24 and 32-byte AES keys are accepted", {
  for (n in c(0L, 1L, 8L, 15L, 17L, 23L, 25L, 31L, 33L, 64L)) {
    expect_error(native_aes("cbc", TRUE, raw(n), raw(16), raw(16)),
                 "ZUC_ERR_BAD_LENGTH", info = paste("key length", n))
  }
  for (n in c(16L, 24L, 32L)) {
    expect_length(native_aes("cbc", TRUE, raw(n), raw(16), raw(16)), 16L)
  }
})

test_that("an unknown algorithm name is refused, with no partial matching", {
  for (name in c("sha", "sha2", "sha-256", "SHA256", "sha256 ", "md5",
                 "sha224", "")) {
    expect_error(native_hash(name, raw(0)), "unknown algorithm",
                 info = name)
  }
})

test_that("a call outside an initialised window is ZUC_ERR_NOT_READY", {
  # The harness drops the reference R_init_zucrypt holds, calls every
  # backend-touching constructor and one-shot, then takes the reference back.
  # Tearing the backend down destroys every key, so nothing else may be live:
  # collect first, so no finalizer-owned context from an earlier test is.
  gc()
  got <- native_not_ready()

  expect_identical(got[["shutdown"]], "ZUC_OK")
  expect_identical(got[["init"]], "ZUC_OK")
  calls <- setdiff(names(got), c("shutdown", "init"))
  expect_length(calls, 6L)
  for (call in calls) {
    expect_identical(got[[call]], "ZUC_ERR_NOT_READY", info = call)
  }

  # And the backend is back: the R functions work afterwards.
  expect_identical(
    tohex(crypt_hash(charToRaw("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  )
})

test_that("64 live handles of each kind coexist (#30)", {
  # The static key store failed at the 17th live AES handle, and reported it
  # as ZUC_ERR_MEMORY. The dynamic store is bounded by memory alone.
  got <- native_live_handles(64L)
  expect_identical(got$aes_created, 64L)
  expect_identical(got$hmac_created, 64L)
  expect_identical(got$aes_new, "ZUC_OK")
  expect_identical(got$hmac_new, "ZUC_OK")
  # With all 128 keys live, a one-shot that needs a key of its own still works.
  expect_identical(got$hmac_compute, "ZUC_OK")
  expect_identical(got$aes_cbc_encrypt, "ZUC_OK")

  # Well past the old limit, and everything is freed again afterwards: a
  # second round must not start where the first left off.
  again <- native_live_handles(1000L)
  expect_identical(again$aes_created, 1000L)
  expect_identical(again$hmac_created, 1000L)
})
