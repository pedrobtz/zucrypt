# Check the installed zucrypt is this checkout (revdep.yaml).
d <- utils::packageDescription("zucrypt")
if (!is.null(d$RemoteType)) {
  stop("zucrypt was installed from ", d$RemoteType, " (", d$RemoteSha,
       "), not from this checkout")
}
lib <- system.file("lib", .Platform$r_arch, package = "zucrypt")
if (!nzchar(lib)) lib <- system.file("lib", package = "zucrypt")
stopifnot(file.exists(file.path(lib, "libzucrypt.a")))
cat("zucrypt", format(d$Version), "from this checkout; archive in", lib, "\n")
