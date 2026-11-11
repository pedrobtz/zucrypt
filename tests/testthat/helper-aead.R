# Helpers for test-aead.R, here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

gcm_args <- function(row) {
  list(
    key = unhex(row$key),
    iv = unhex(row$iv),
    aad = if (nzchar(row$aad)) unhex(row$aad),
    input = unhex(row$input),
    output = unhex(row$output),
    tag = unhex(row$tag)
  )
}
