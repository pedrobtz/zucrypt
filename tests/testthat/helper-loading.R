# Helpers for test-loading.R, here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

skip_if_no_openssl <- function() {
  skip_if_not_installed("openssl")
  # A fresh R process can only `library(zucrypt)` if zucrypt is installed.
  # Under devtools::load_all() it is not, and the subprocess would fail for
  # that reason rather than for anything this test is about. Meta/package.rds
  # is written by R's install step and by nothing else, so it distinguishes
  # the two without asking about any file the test itself cares about.
  skip_if(
    !nzchar(system.file("Meta", "package.rds", package = "zucrypt")),
    "not an installed layout"
  )
}

run_in_fresh_r <- function(code) {
  script <- tempfile(fileext = ".R")
  on.exit(unlink(script), add = TRUE)
  writeLines(code, script)
  out <- suppressWarnings(system2(
    file.path(R.home("bin"), "Rscript"),
    c("--vanilla", shQuote(script)),
    stdout = TRUE,
    stderr = TRUE
  ))
  list(output = out, status = attr(out, "status") %||% 0L)
}

`%||%` <- function(x, y) if (is.null(x)) y else x
