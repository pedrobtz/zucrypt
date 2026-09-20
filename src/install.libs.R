## Installs the shared object, and beside it the LinkingTo surface that a
## consumer linking libzucrypt.a needs.
##
## Defining this file makes R stop installing the shared object by itself, so
## the first block is not optional boilerplate -- without it the package
## installs with no compiled code at all. (Writing R Extensions 1.2.1.1.)

libs <- file.path(R_PACKAGE_DIR, paste0("libs", R_ARCH))
dir.create(libs, recursive = TRUE, showWarnings = FALSE)
file.copy(Sys.glob(paste0("*", SHLIB_EXT)), libs, overwrite = TRUE)
if (file.exists("symbols.rds")) {
  file.copy("symbols.rds", libs, overwrite = TRUE)
}

## The archive is architecture-specific object code but installs to a single
## architecture-neutral path, which is what the design asks for and what every
## current platform needs. It would have to move under R_ARCH before zucrypt
## could support a multi-architecture installation again.
lib <- file.path(R_PACKAGE_DIR, "lib")
dir.create(lib, recursive = TRUE, showWarnings = FALSE)
if (!file.copy("libzucrypt.a", lib, overwrite = TRUE)) {
  stop("zucrypt: failed to install libzucrypt.a; src/Makevars should have built it")
}

## No upstream header is copied here, and that is the deliberate departure
## from zukomp and zuxml, whose archives are raw miniz and Expat with
## miniz.h/expat.h installed beside them. A consumer of those has to reproduce
## the provider's define set or its declarations describe a different library.
## PSA's headers are worse: sizes and key-identifier types are generated from
## the configuration. So a consumer of libzucrypt.a sees inst/include/zucrypt.h
## and nothing else, and there is no define for it to match. R's own "inst"
## step copies that header into R_PACKAGE_DIR/include, merging with whatever
## this script put there rather than replacing it.
