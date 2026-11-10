# The table consumer fixture's tests (consumer.yaml), from the repository
# root; tools/zucrypttest must be installed first.
setwd("tools/zucrypttest")
res <- testthat::test_local(stop_on_failure = FALSE, reporter = "summary")
df <- as.data.frame(res)
n <- sum(df$passed) + sum(df$failed)
cat(sprintf("discovered %d assertions in %d files\n", n, nrow(df)))
if (nrow(df) == 0L || n == 0L) {
  stop("no tests were discovered: the fixture proved nothing")
}
if (sum(df$failed) > 0L || any(df$error)) {
  stop("consumer fixture failed")
}
