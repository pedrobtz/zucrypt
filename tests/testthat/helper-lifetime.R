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
