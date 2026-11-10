# Run zuxlsx's decryption tests against the installed zucrypt (revdep.yaml).
res <- testthat::test_dir(
  ".revdep/zuxlsx/tests/testthat",
  package = "zuxlsx",
  load_package = "installed",
  filter = "agile",
  reporter = "summary",
  stop_on_failure = FALSE
)
df <- as.data.frame(res)
n <- sum(df$passed) + sum(df$failed)
cat(sprintf("discovered %d assertions in %d files\n", n, nrow(df)))
if (nrow(df) == 0L || n == 0L) {
  stop("no zuxlsx decryption tests ran: the job proved nothing")
}
if (sum(df$failed) > 0L || any(df$error)) {
  stop("zuxlsx's decryption tests failed against this zucrypt")
}
