# Install what zuxlsx needs to build and run its tests, other than zucrypt
# (revdep.yaml uses setup-r-dependencies; tools/ci/platform.sh, which has
# no such step for a second package, uses this). Argument: zuxlsx's path.
path <- commandArgs(trailingOnly = TRUE)[[1]]
d <- read.dcf(file.path(path, "DESCRIPTION"))
fields <- intersect(c("Depends", "Imports", "LinkingTo", "Suggests"), colnames(d))
pkgs <- unlist(lapply(d[1, fields], function(x) strsplit(x, ",")[[1]]))
pkgs <- trimws(sub("\\(.*", "", pkgs))
pkgs <- setdiff(c(pkgs[nzchar(pkgs)], "testthat", "withr"), c("R", "zucrypt"))
need <- setdiff(pkgs, rownames(installed.packages()))
if (length(need)) {
  install.packages(need, repos = c(CRAN = "https://cloud.r-project.org"))
}
cat("zuxlsx's dependencies:", paste(pkgs, collapse = ", "), "\n")
