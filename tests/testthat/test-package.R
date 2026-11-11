# Package-level invariants. Nothing here tests cryptography -- there is none
# yet -- but both assertions are ones that only ever go red for a real reason,
# and the naming one starts guarding the family convention (design.md section 3)
# before the first export exists rather than after.

test_that("every export follows the family's crypt_ prefix", {
  exports <- getNamespaceExports("zucrypt")
  exports <- setdiff(exports, ".__NAMESPACE__.")
  expect_true(
    all(grepl("^crypt_", exports)),
    info = paste(exports[!grepl("^crypt_", exports)], collapse = ", ")
  )
})

test_that("DESCRIPTION carries no skeleton placeholders", {
  fields <- c("Title", "Description", "Authors@R", "URL", "BugReports")
  meta <- vapply(
    fields,
    function(f) as.character(utils::packageDescription("zucrypt", fields = f)),
    character(1)
  )

  expect_false(anyNA(meta))
  expect_false(any(grepl(
    "What the [Pp]ackage [Dd]oes|First.*Last|example\\.com",
    meta
  )))
})

test_that("test files hold only test_that() calls", {
  # A definition at a test file's top level is invisible to testthat's
  # parallel workers and runs in a random place under shuffle = TRUE, which
  # broke ten tests before it was caught. Helpers go in helper-*.R.
  files <- list.files(test_path(), pattern = "^test-.*[.]R$", full.names = TRUE)
  expect_gt(length(files), 0L)
  stray <- character(0)
  for (f in files) {
    for (e in parse(f, keep.source = FALSE)) {
      if (!(is.call(e) && identical(e[[1]], as.name("test_that")))) {
        stray <- c(stray, paste0(basename(f), ": ", deparse(e)[1]))
      }
    }
  }
  expect_identical(stray, character(0))
})
