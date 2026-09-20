# Symbol-audit helpers. In a helper file rather than at the top of test-abi.R
# because testthat's parallel workers source helper-*.R but do not share a
# test file's file-scope definitions.

# Path of the loaded zucrypt shared object.
zucrypt_dll_path <- function() {
  dll <- getLoadedDLLs()[["zucrypt"]]
  skip_if(is.null(dll), "zucrypt DLL is not loaded")
  path <- dll[["path"]]
  skip_if(!file.exists(path), "zucrypt shared object not found on disk")
  path
}

# Symbols the installed shared object *exports* -- what another loaded library
# could bind to -- as nm reports them.
#
# The flags are not interchangeable, and getting them wrong is how this test
# passes for the wrong reason or fails for none:
#
#   ELF     `nm -D` reads .dynsym. Plain `nm` reads .symtab, which still holds
#           every hidden mbedtls_* symbol; auditing that would report a leak
#           where there is none, since a hidden symbol is not bindable.
#   Mach-O  `nm -gU` is global, defined-only. There is no separate dynamic
#           table to ask for.
#
# Windows is skipped rather than approximated. A PE DLL exports only what an
# export table names, each module has its own namespace, and two independently
# vendored copies cannot bind to one another there at all (design.md section
# 4) -- so the property this audits is a property of the format, not of our
# build flags.
exported_symbols <- function() {
  nm <- Sys.which("nm")
  skip_if(!nzchar(nm), "nm is not available on this platform")
  skip_on_os("windows")

  path <- zucrypt_dll_path()
  args <- if (Sys.info()[["sysname"]] == "Darwin") {
    c("-gU", shQuote(path))
  } else {
    c("-D", "--defined-only", shQuote(path))
  }

  syms <- suppressWarnings(
    system2(nm, args, stdout = TRUE, stderr = FALSE)
  )
  skip_if(!is.character(syms) || length(syms) == 0L, "nm produced no output")
  syms
}

# Is this build instrumented? covr sets R_COVR for the test run, and
# coverage.yaml's native: true compiles with gcov, whose runtime is linked
# into the shared object and exports symbols of its own.
#
# It matters for exactly one assertion -- the exact set of exported symbols --
# and not for the banned-name audits, which keep running everywhere. An
# earlier attempt filtered the runtime out by name prefix and failed: libgcov
# exports `mangle_path`, and enumerating another runtime's symbol names is a
# game with no end. What can be said precisely is "this build is instrumented,
# so its exported set is not the shipping one", so that is what is said.
is_instrumented_build <- function() {
  identical(Sys.getenv("R_COVR"), "true") ||
    identical(Sys.getenv("_R_CHECK_COVERAGE_"), "true")
}
