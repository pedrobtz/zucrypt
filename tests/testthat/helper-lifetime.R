# Helpers for test-lifetime.R, here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

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

# Deterministic failure points (#116). fail_at(n) arms the adapter's failure
# countdown: the nth fallible step from now (a handle's storage, a backend
# allocation, a marked backend call) fails as an allocation failure, and
# fail_at(0) disarms it, returning how many steps the arming had left (0 when
# it fired). chunk_error_at(n) makes the C chunk loops raise an R error after
# their nth chunk; chunk_error_at(0) disarms it and returns the live count at
# the moment it fired (-1 if it did not).
fail_at <- function(n) .Call(zucrypt:::zucrypt_test_fail_at, as.numeric(n))
chunk_error_at <- function(n) {
  .Call(zucrypt:::zucrypt_test_chunk_error, as.numeric(n))
}

# Fail each step of `f()` in turn, from the first, until `f()` finishes
# before the armed step. For every step that fired, `check(condition)` is
# called with what `f()` raised (NULL if it returned). Returns the number of
# steps that fired. The countdown is disarmed whatever happens.
sweep_steps <- function(f, check, max = 200L) {
  on.exit(fail_at(0), add = TRUE)
  for (n in seq_len(max)) {
    fail_at(n)
    cnd <- tryCatch(
      {
        f()
        NULL
      },
      error = function(e) e
    )
    if (fail_at(0) != 0) {
      return(n - 1L)
    }
    check(n, cnd)
  }
  stop("sweep_steps(): more than ", max, " steps")
}
