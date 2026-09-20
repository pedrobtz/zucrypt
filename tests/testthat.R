# This file is the standard testthat runner, with one deviation: the whole run
# is conditional on testthat being installed.
#
# R-CMD-check.yaml turns on the `nosuggests` leg, which is CRAN's NOSUGGESTS
# flavor -- the package is checked with none of its Suggests available. An
# unguarded `library(testthat)` is an ERROR there and nowhere else, which is
# precisely the failure mode that leg exists to catch. Skipping the tests is
# the correct behaviour: a package must check without its suggested packages,
# not test without them.
#
# Where should you do additional test configuration?
# Learn more about the roles of various files in:
# * https://r-pkgs.org/testing-design.html#sec-tests-files-overview
# * https://testthat.r-lib.org/articles/special-files.html

if (requireNamespace("testthat", quietly = TRUE)) {
  library(testthat)
  library(zucrypt)

  test_check("zucrypt")
}
