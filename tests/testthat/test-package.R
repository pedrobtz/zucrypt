# Package-level invariants. Nothing here tests cryptography -- there is none
# yet -- but both assertions are ones that only ever go red for a real reason,
# and the naming one starts guarding the family convention (design.md section 3)
# before the first export exists rather than after.

test_that("every export follows the family's crypt_ prefix", {
  exports <- getNamespaceExports("zucrypt")
  exports <- setdiff(exports, ".__NAMESPACE__.")
  expect_true(all(grepl("^crypt_", exports)),
              info = paste(exports[!grepl("^crypt_", exports)], collapse = ", "))
})

test_that("DESCRIPTION carries no skeleton placeholders", {
  fields <- c("Title", "Description", "Authors@R", "URL", "BugReports")
  meta <- vapply(
    fields,
    function(f) as.character(utils::packageDescription("zucrypt", fields = f)),
    character(1)
  )

  expect_false(anyNA(meta))
  expect_false(any(grepl("What the [Pp]ackage [Dd]oes|First.*Last|example\\.com", meta)))
})
