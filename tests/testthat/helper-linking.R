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

# R_ARCH is empty on every single-architecture platform, so this is plain
# "lib" there. The archive is architecture-specific object code, so a
# multi-architecture install would have to give each one its own directory.
installed_lib_dir <- function() {
  arch <- .Platform$r_arch
  installed_path(if (nzchar(arch)) file.path("lib", arch) else "lib")
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
