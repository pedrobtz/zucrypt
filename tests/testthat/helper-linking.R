# Helpers for auditing the installed LinkingTo surface.

# Is this a real installed layout, or devtools::load_all()? Decided from a
# file that has nothing to do with the artifacts under test, so that "there
# is nothing to test here" can never be confused with "the thing under test
# is missing" -- which is the only failure these tests exist to detect.
#
# Meta/package.rds is written by R's install step and by nothing else. It has
# to be something outside inst/: under load_all() system.file() resolves
# against the source tree's inst/, so anything installed *from* inst/ -- the
# header, say -- is found there too.
skip_if_not_installed_layout <- function() {
  skip_if(!nzchar(system.file("Meta", "package.rds", package = "zucrypt")),
          "not an installed layout")
}

installed_path <- function(...) {
  skip_if_not_installed_layout()
  file.path(system.file(package = "zucrypt"), ...)
}

# Where the archive lives, resolved exactly the way a consumer resolves it.
#
# This mirrors zuxlsx's configure line for its sibling archives: try
# lib/<r_arch> first, fall back to plain lib. This package installs under
# R_ARCH, as zukomp does, but zuxml still installs arch-neutral and a
# consumer's configure copes with either, so the helper resolves the way that
# configure does; test-linking.R separately asserts where the archive is.
#
# Assuming lib/<r_arch> here is what failed on Windows: .Platform$r_arch is
# "x64" there and empty on Linux and macOS, so a single-path helper passes on
# two platforms out of three while testing the wrong thing on all of them.
installed_lib_dir <- function() {
  root <- installed_path()
  arch <- .Platform$r_arch
  if (nzchar(arch) && dir.exists(file.path(root, "lib", arch))) {
    return(file.path(root, "lib", arch))
  }
  file.path(root, "lib")
}

archive_path <- function() file.path(installed_lib_dir(), "libzucrypt.a")

# Symbols of the installed static archive. nm over an archive interleaves a
# "member.o:" line before each member's symbols; those are not symbols, so
# only lines carrying a symbol type are kept.
archive_symbols <- function() {
  nm <- Sys.which("nm")
  skip_if(!nzchar(nm), "nm is not available on this platform")

  # Not a skip: by the time we are here the installed layout exists, so a
  # missing archive is a failure of the install, which is what this audits.
  archive <- archive_path()
  expect_true(file.exists(archive))

  out <- suppressWarnings(
    system2(nm, c("-g", shQuote(archive)), stdout = TRUE, stderr = FALSE)
  )
  skip_if(!is.character(out) || length(out) == 0L, "nm produced no output")
  grep("^[0-9a-fA-F ]*\\s[A-Za-z]\\s", out, value = TRUE)
}

# Of those, the ones the archive defines rather than needs from elsewhere.
archive_defined <- function() {
  grep("\\sU\\s", archive_symbols(), value = TRUE, invert = TRUE)
}

# Text of the installed public header -- the copy a LinkingTo consumer
# actually sees, not the one in the source tree.
installed_header <- function(name = "zucrypt.h") {
  path <- system.file("include", name, package = "zucrypt")
  skip_if(!nzchar(path) || !file.exists(path), paste0(name, " is not installed"))
  readLines(path, warn = FALSE)
}

# The same header with C comments removed. The hygiene rules are about what
# the header *declares*: a comment saying "no PSA type appears here" is worth
# keeping, a declaration mentioning one is not.
installed_header_code <- function(name = "zucrypt.h") {
  text <- paste(installed_header(name), collapse = "\n")
  text <- gsub("/\\*.*?\\*/", " ", text)
  text <- gsub("//[^\n]*", " ", text)
  strsplit(text, "\n", fixed = TRUE)[[1L]]
}
