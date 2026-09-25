# Native contexts are released on every path out of a crypt_* call,
# including the ones that longjmp.
#
# design.md section 11 and the family's rule: a context that must survive
# R_CheckUserInterrupt() is owned by an external pointer with a finalizer,
# because an interrupt jumps past every free() beneath it. Until Stage 8
# nothing executed that path (#35). The adapter counts live handles
# (src/zuc_live.h), so a leak is a number rather than a guess.

live_contexts <- function() .Call(zucrypt:::zucrypt_test_live_contexts)

# Run `f()` under an elapsed-time limit short enough to trip inside its
# chunk loop, whose R_CheckUserInterrupt() enforces setTimeLimit(). Returns
# TRUE if the call was cut short, FALSE if it finished first. The limit is
# always lifted again: transient limits last until R returns to top level,
# which inside a test run is never.
interrupted_by_time_limit <- function(f, limit) {
  setTimeLimit(elapsed = limit, transient = TRUE)
  on.exit(setTimeLimit(elapsed = Inf), add = TRUE)
  tryCatch(
    {
      f()
      FALSE
    },
    error = function(e) grepl("time limit", conditionMessage(e))
  )
}

test_that("successful calls leave no live context", {
  gc()
  before <- live_contexts()
  key <- as.raw(rep(1L, 32))
  crypt_hash(charToRaw("abc"))
  crypt_hmac(charToRaw("abc"), key)
  crypt_aes_cbc_decrypt(crypt_aes_cbc_encrypt(raw(32), key, raw(16)),
                        key, raw(16))
  # Released eagerly, not by the collector: no gc() before this check.
  expect_identical(live_contexts(), before)
})

test_that("a native failure leaves no live context", {
  gc()
  before <- live_contexts()
  # An unsupported algorithm name never reaches C (R refuses it), so use a
  # failure the adapter itself reports: an AES key of the wrong length is
  # validated in R too, so this goes through the harness instead.
  expect_error(native_aes("cbc", TRUE, raw(17), raw(16), raw(16)),
               "ZUC_ERR_BAD_LENGTH")
  expect_identical(live_contexts(), before)
})

test_that("an interrupted call frees its context once collected", {
  skip_on_cran()   # 64 MiB inputs, and timing-dependent by construction
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
    aes  = function() crypt_aes_cbc_encrypt(data, key, iv)
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
