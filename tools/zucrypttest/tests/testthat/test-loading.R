# Load-order, extended from zucrypt's own Stage 1 test to include a consumer.
#
# Three libraries with cryptographic symbols end up in one process here:
# zucrypt's vendored backend, the consumer's own shared object linking nothing
# but resolving into it, and openssl's system libcrypto. If any of them could
# bind to another's symbols, which of them wins would depend on load order --
# so every order is tried, and each library is then *used*, because a wrong
# binding shows up in a call and not in dlopen().

run_in_fresh_r <- function(lines) {
  script <- tempfile(fileext = ".R")
  on.exit(unlink(script), add = TRUE)
  writeLines(lines, script)
  out <- suppressWarnings(system2(
    file.path(R.home("bin"), "Rscript"),
    c("--vanilla", shQuote(script)),
    stdout = TRUE, stderr = TRUE
  ))
  list(output = out, status = attr(out, "status"))
}

test_that("zucrypt, zucrypttest and openssl coexist in every load order", {
  skip_if_not_installed("openssl")

  libs <- paste0(".libPaths(c(",
                 paste(shQuote(.libPaths()), collapse = ", "), "))")
  packages <- c("zucrypt", "zucrypttest", "openssl")
  orders <- list(
    packages,
    rev(packages),
    c("openssl", "zucrypt", "zucrypttest"),
    c("zucrypttest", "openssl", "zucrypt"),
    c("zucrypt", "openssl", "zucrypttest"),
    c("openssl", "zucrypttest", "zucrypt")
  )

  for (order in orders) {
    res <- run_in_fresh_r(c(
      libs,
      sprintf("library(%s)", order),
      # openssl still answers from the system libcrypto...
      'stopifnot(identical(as.character(openssl::sha256("abc")),',
      '  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))',
      # ...zucrypt from its own vendored backend...
      'stopifnot(identical(',
      '  paste(format(zucrypt::crypt_hash(charToRaw("abc"))), collapse = ""),',
      '  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))',
      # ...and the consumer through the table, which is a third path into the
      # same code.
      'stopifnot(length(zucrypttest::exercise_table()) == 0L)',
      'cat("OK\\n")'
    ))
    label <- paste(order, collapse = " then ")
    expect_true("OK" %in% res$output,
                info = paste(label, "|", paste(res$output, collapse = " | ")))
  }
})
