# Native contexts are released on every path out of a crypt_* call,
# including the ones that longjmp.
#
# design.md section 11 and the family's rule: a context that must survive
# R_CheckUserInterrupt() is owned by an external pointer with a finalizer,
# because an interrupt jumps past every free() beneath it. Until Stage 8
# nothing executed that path (#35). The adapter counts live handles
# (src/zuc_live.h), so a leak is a number rather than a guess.

test_that("successful calls leave no live context", {
  gc()
  before <- live_contexts()
  key <- as.raw(rep(1L, 32))
  crypt_hash(charToRaw("abc"))
  crypt_hmac(charToRaw("abc"), key)
  crypt_aes_cbc_decrypt_nopad(
    crypt_aes_cbc_encrypt_nopad(raw(32), key, raw(16)),
    key,
    raw(16)
  )
  # Released eagerly, not by the collector: no gc() before this check.
  expect_identical(live_contexts(), before)
})

test_that("a native failure leaves no live context", {
  gc()
  before <- live_contexts()
  # An unsupported algorithm name never reaches C (R refuses it), so use a
  # failure the adapter itself reports: an AES key of the wrong length is
  # validated in R too, so this goes through the harness instead.
  expect_error(
    native_aes("cbc", TRUE, raw(17), raw(16), raw(16)),
    "ZUC_ERR_BAD_LENGTH"
  )
  expect_identical(live_contexts(), before)
})

test_that("a failure at every step of a call leaves no live context (#116)", {
  # Each fallible step in turn: the handle's own storage, the backend setup
  # after it, the key import and, for HMAC, the setup after the import, then
  # every allocation the updates make. Each must raise the memory class and
  # release what it built at once (no gc() before the count), and the next
  # call must work. A constructor that forgets to free on a failure path
  # leaves its storage counted as live (src/zuc_live.h).
  key <- as.raw(rep(1L, 32))
  iv <- raw(16)
  data <- as.raw(rep_len(0:255, 2L * 1048576L + 32L)) # three chunks
  path <- tempfile()
  on.exit(unlink(path), add = TRUE)
  writeBin(data, path)
  calls <- list(
    hash = function() crypt_hash(data),
    hmac = function() crypt_hmac(data, key),
    aes = function() crypt_aes_cbc_encrypt_nopad(data, key, iv),
    stream = function() crypt_hash(file(path))
  )
  # The construction steps alone: the storage and the setup for a digest;
  # the storage, three key-store allocations and the setup for an HMAC; the
  # storage and two key-store allocations for AES.
  at_least <- c(hash = 2L, hmac = 5L, aes = 3L, stream = 2L)
  gc()
  before <- live_contexts()
  for (name in names(calls)) {
    want <- calls[[name]]()
    fired <- sweep_steps(calls[[name]], function(n, cnd) {
      info <- paste(name, "step", n)
      expect_s3_class(cnd, "zucrypt_memory_error")
      expect_identical(live_contexts(), before, info = info)
      expect_identical(calls[[name]](), want, info = info)
    })
    expect_gte(fired, at_least[[name]])
  }
})

test_that("an R error after the first chunk leaves the context to its finalizer (#116)", {
  # The error lands where an interrupt would, after a chunk, with the
  # context owned only by its external pointer: the live count at that
  # moment is one above the baseline, and the collection brings it back.
  key <- as.raw(rep(1L, 32))
  iv <- raw(16)
  data <- as.raw(rep_len(0:255, 3L * 1048576L))
  path <- tempfile()
  on.exit(unlink(path), add = TRUE)
  writeBin(data, path)
  calls <- list(
    hash = function() crypt_hash(data),
    hmac = function() crypt_hmac(data, key),
    aes = function() crypt_aes_cbc_encrypt_nopad(data, key, iv),
    stream = function() crypt_hmac(file(path), key)
  )
  on.exit(chunk_error_at(0), add = TRUE)
  gc()
  before <- live_contexts()
  for (name in names(calls)) {
    want <- calls[[name]]()
    chunk_error_at(1)
    expect_error(calls[[name]](), "injected error after a chunk")
    expect_identical(chunk_error_at(0), before + 1, info = name)
    gc()
    expect_identical(live_contexts(), before, info = name)
    expect_identical(calls[[name]](), want, info = name)
  }
})

test_that("an interrupted call frees its context once collected", {
  skip_on_cran() # 64 MiB inputs, and timing-dependent by construction
  gc()
  before <- live_contexts()

  # 64 chunks of 1 MiB between interrupt checks: far longer than the limits
  # below on any machine this runs on, so the limit trips inside the loop,
  # with a context live and owned only by its external pointer.
  data <- as.raw(rep_len(0:255, 64L * 1024L * 1024L))
  key <- as.raw(rep(0x2bL, 32))
  iv <- raw(16)
  calls <- list(
    hash = function() crypt_hash(data, "sha512"),
    hmac = function() crypt_hmac(data, key, "sha512"),
    aes = function() crypt_aes_cbc_encrypt_nopad(data, key, iv)
  )

  for (name in names(calls)) {
    cut_short <- FALSE
    for (limit in c(0.01, 0.05, 0.2)) {
      if (interrupted_by_time_limit(calls[[name]], limit)) {
        cut_short <- TRUE
        break
      }
    }
    # Not a skip: a machine fast enough to finish 64 MiB of SHA-512 in 0.2 s
    # would mean this test proves nothing, and that should be seen.
    expect_true(cut_short, info = name)

    # The context was stranded by the longjmp; the finalizer releases it.
    gc()
    expect_identical(live_contexts(), before, info = name)
  }
})

test_that("connection input leaves no live context, however it ends", {
  # #11: the stream's context lives in an external pointer across R-level
  # calls, so each way out of digest_connection() is a separate path.
  path <- tempfile()
  writeBin(as.raw(rep_len(0:255, 3L * 1048576L)), path)
  on.exit(unlink(path))
  key <- as.raw(rep(1L, 32))

  gc()
  before <- live_contexts()
  crypt_hash(file(path))
  crypt_hmac(file(path), key)
  # Released eagerly on success: no gc() before this check.
  expect_identical(live_contexts(), before)

  # A text-mode connection is refused before any context exists.
  con <- file(path, "r")
  expect_error(crypt_hash(con), class = "zucrypt_invalid_argument")
  close(con)
  expect_identical(live_contexts(), before)
})

test_that("an interrupted connection hash frees its context once collected", {
  skip_on_cran() # a 64 MiB file, and timing-dependent by construction
  path <- tempfile()
  writeBin(as.raw(rep_len(0:255, 64L * 1024L * 1024L)), path)
  on.exit(unlink(path))
  key <- as.raw(rep(0x2bL, 32))
  calls <- list(
    hash = function() crypt_hash(file(path), "sha512"),
    hmac = function() crypt_hmac(file(path), key, "sha512")
  )

  gc()
  before <- live_contexts()
  for (name in names(calls)) {
    cut_short <- FALSE
    for (limit in c(0.01, 0.05, 0.2)) {
      if (interrupted_by_time_limit(calls[[name]], limit)) {
        cut_short <- TRUE
        break
      }
    }
    expect_true(cut_short, info = name)
    gc()
    expect_identical(live_contexts(), before, info = name)
  }
})

test_that("key objects release their handles when collected", {
  gc()
  before <- live_contexts()
  keys <- lapply(1:4, function(i) crypt_rsa_keygen(1024))
  pubs <- lapply(keys, function(k) k$pubkey)
  expect_gte(live_contexts(), before + 8L)
  rm(keys, pubs)
  gc()
  expect_identical(live_contexts(), before)
})
