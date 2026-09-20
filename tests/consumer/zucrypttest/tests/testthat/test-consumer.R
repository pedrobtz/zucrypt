# The shape-one consumer contract: LinkingTo for headers, Imports plus a real
# importFrom() so the namespace loads, and the table resolved lazily on first
# use.

test_that("the table resolves from a consumer package", {
  expect_true(api_available())
})

test_that("every table entry behaves", {
  # exercise_table() returns a character vector of failures so one run
  # reports all of them. A pointer that was never assigned is
  # indistinguishable from a working one until something calls it, and the
  # table is filled field by field in zucrypt_api.c -- exactly the shape of
  # code where one line goes missing.
  failures <- exercise_table()
  expect_identical(failures, character(0),
                   info = paste(failures, collapse = "; "))
})

test_that("an unsupported ABI version is refused, not served", {
  current <- zucrypt::crypt_info()$abi_version
  for (wrong in c(current + 1L, current + 99L, 4242L)) {
    expect_true(abi_rejects_wrong_version(wrong), info = paste("version", wrong))
  }
  # And the version this consumer was built against is served, or the test
  # above would pass for the wrong reason.
  expect_false(abi_rejects_wrong_version(current))
})

test_that("the consumer sees the same backend zucrypt reports", {
  linked <- linked_backend()
  reported <- zucrypt::crypt_info()$vendored
  expect_identical(unname(linked[["name"]]), reported$source)
  expect_identical(unname(linked[["version"]]), reported$version)
})
