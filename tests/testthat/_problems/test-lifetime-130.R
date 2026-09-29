# Extracted from test-lifetime.R:130

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "zucrypt", path = "..")
attach(test_env, warn.conflicts = FALSE)

# prequel ----------------------------------------------------------------------
live_contexts <- function() .Call(zucrypt:::zucrypt_test_live_contexts)
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

# test -------------------------------------------------------------------------
skip_on_cran()
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
