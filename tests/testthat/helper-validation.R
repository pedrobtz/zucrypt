# Helpers for test-validation.R, here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

expect_zucrypt_error <- function(expr, class) {
  cond <- tryCatch(expr, zucrypt_error = function(e) e)
  expect_s3_class(cond, class)
  expect_s3_class(cond, "zucrypt_error")
  expect_s3_class(cond, "error")
  cond
}

lying <- function(x, n) {
  structure(x, class = "zucrypt_test_lying", lie = as.integer(n))
}

# lying()'s length() method. Registered when the helpers load: length()
# dispatches through the S3 method table, not the calling environment.
registerS3method(
  "length",
  "zucrypt_test_lying",
  function(x) attr(x, "lie"),
  envir = globalenv()
)
