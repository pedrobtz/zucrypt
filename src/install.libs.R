## Installs the shared object, and beside it the LinkingTo surface that a
## consumer linking libzucrypt.a needs: the archive itself, and the licence
## of the backend compiled into it.
##
## Defining this file makes R stop installing the shared object by itself, so
## the first block is not optional boilerplate -- without it the package
## installs with no compiled code at all. (Writing R Extensions 1.2.1.1.)
##
## The layout follows zukomp's, which is the family's convergence target
## (design.md section 8.3, #33).

install_or_stop <- function(from, to, what, name = NULL) {
  dir.create(to, recursive = TRUE, showWarnings = FALSE)
  ## file.copy() returns a logical per source and never signals, so an
  ## unchecked call is how a package installs with a piece silently missing.
  target <- if (is.null(name)) to else file.path(to, name)
  ok <- file.copy(from, target, overwrite = TRUE)
  if (length(ok) == 0L || !all(ok)) {
    stop("zucrypt: failed to install ", what, " into ", to)
  }
  invisible(TRUE)
}

libs <- file.path(R_PACKAGE_DIR, paste0("libs", R_ARCH))
## Checked like everything else here: Sys.glob() returning nothing is exactly
## the "no compiled code at all" failure described above, and an unchecked
## copy of zero files succeeds quietly.
install_or_stop(Sys.glob(paste0("*", SHLIB_EXT)), libs, "the shared object")
if (file.exists("symbols.rds")) {
  install_or_stop("symbols.rds", libs, "symbols.rds")
}

## The archive is architecture-specific object code, so it installs under
## R_ARCH the way the shared object does. R_ARCH is empty on single-arch
## Unix, so this is plain <pkg>/lib there. It is not empty on Windows: R kept
## the sub-architecture layout when it dropped 32-bit Windows, so R_ARCH is
## "/x64" and the archive lands in <pkg>/lib/x64. Consumers resolve it with
## system.file("lib", .Platform$r_arch, package = "zucrypt") first and plain
## "lib" second, which zuxlsx's configure already does for its siblings.
lib <- file.path(R_PACKAGE_DIR, paste0("lib", R_ARCH))
install_or_stop("libzucrypt.a", lib,
                "libzucrypt.a (src/Makevars should have built it)")

## The backend's licence, from the same vendored tree the archive was
## compiled from. This is an obligation, not tidiness: a binary zucrypt, and
## every consumer that links libzucrypt.a into its own shared object,
## redistributes Apache-2.0 object code, and Apache-2.0 section 4(a) requires
## the licence text to travel with it. Nothing outside inst/ is installed, so
## without this the text would reach the source tarball and stop there.
install_or_stop(file.path("vendor", "tf-psa-crypto", "LICENSE"),
                file.path(R_PACKAGE_DIR, "licenses"),
                "TF-PSA-Crypto's LICENSE", name = "tf-psa-crypto-LICENSE")

## No upstream header is copied here, and that is the deliberate departure
## from zukomp and zuxml, whose archives are raw miniz and Expat with
## miniz.h/expat.h installed beside them. A consumer of those has to reproduce
## the provider's define set or its declarations describe a different library.
## PSA's headers are worse: sizes and key-identifier types are generated from
## the configuration. So a consumer of libzucrypt.a sees inst/include/zucrypt.h
## and nothing else, and there is no define for it to match. R's own "inst"
## step copies that header into R_PACKAGE_DIR/include.
