test_that("crypt_info() reports the package and the vendored backend", {
  info <- crypt_info()

  expect_type(info, "list")
  expect_named(info, c("version", "vendored", "random_backend"))

  expect_s3_class(info$version, "package_version")
  expect_identical(info$version, utils::packageVersion("zucrypt"))

  expect_s3_class(info$vendored, "data.frame")
  expect_named(info$vendored, c("source", "version"))
  expect_identical(info$vendored$source, "tf-psa-crypto")
  # A version, not an empty string: the C routine returns a compile-time
  # literal, so an empty answer means the macro was not defined and the build
  # silently reported nothing.
  expect_match(info$vendored$version, "^[0-9]+\\.[0-9]+\\.[0-9]+$")
})

test_that("a random backend was selected at compile time", {
  # src/zuc_random.c's preprocessor chain has no default arm that does
  # nothing: every platform lands on a named source. An empty string here
  # would mean the chain fell through and the backend links against a
  # function that cannot produce bytes.
  backend <- crypt_info()$random_backend
  expect_type(backend, "character")
  expect_length(backend, 1L)
  expect_true(nzchar(backend))
  expect_true(backend %in% c("rand_s", "arc4random_buf", "getrandom",
                             "/dev/urandom"))
})
