# Load-order tests. design.md section 4: zucrypt carries its own crypto, and
# openssl links the system libcrypto into the same process. If either could
# bind to the other's symbols, the damage would depend on which loaded first
# -- so both orders are tested, and openssl is exercised afterwards rather
# than merely loaded, because a broken binding shows up in a call, not in
# dlopen().
#
# The work happens in a separate R process: within one session a package can
# only be loaded once, so testing an order at all requires a fresh one.

skip_if_no_openssl <- function() {
  skip_if_not_installed("openssl")
  # A fresh R process can only `library(zucrypt)` if zucrypt is installed.
  # Under devtools::load_all() it is not, and the subprocess would fail for
  # that reason rather than for anything this test is about. Meta/package.rds
  # is written by R's install step and by nothing else, so it distinguishes
  # the two without asking about any file the test itself cares about.
  skip_if(!nzchar(system.file("Meta", "package.rds", package = "zucrypt")),
          "not an installed layout")
}

run_in_fresh_r <- function(code) {
  script <- tempfile(fileext = ".R")
  on.exit(unlink(script), add = TRUE)
  writeLines(code, script)
  out <- suppressWarnings(system2(
    file.path(R.home("bin"), "Rscript"),
    c("--vanilla", shQuote(script)),
    stdout = TRUE, stderr = TRUE
  ))
  list(output = out, status = attr(out, "status") %||% 0L)
}

`%||%` <- function(x, y) if (is.null(x)) y else x

test_that("zucrypt and openssl coexist, loaded in either order", {
  skip_if_no_openssl()

  libs <- shQuote(.libPaths())
  libs <- paste0(".libPaths(c(", paste(libs, collapse = ", "), "))")

  for (order in list(c("zucrypt", "openssl"), c("openssl", "zucrypt"))) {
    res <- run_in_fresh_r(c(
      libs,
      sprintf("library(%s)", order[1]),
      sprintf("library(%s)", order[2]),
      # openssl still computes the right answer through the system libcrypto
      'stopifnot(identical(as.character(openssl::sha256("abc")),',
      '  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))',
      # and zucrypt still answers from its own backend
      'stopifnot(nzchar(zucrypt::crypt_info()$vendored$version))',
      'cat("OK\\n")'
    ))
    expect_identical(res$status, 0L,
                     info = paste(c(order, res$output), collapse = " | "))
    expect_true("OK" %in% res$output,
                info = paste(c(order, res$output), collapse = " | "))
  }
})
