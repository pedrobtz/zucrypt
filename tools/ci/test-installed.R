# Run the test suite against the installed package (aes-paths.yaml).
res <- as.data.frame(testthat::test_local(".", load_package = "installed",
                                          reporter = "summary",
                                          stop_on_failure = FALSE))
cat(sprintf("%d expectations passed\n", sum(res$passed)))
if (sum(res$passed) == 0L) stop("no tests ran")
if (sum(res$failed) > 0L || any(res$error)) stop("tests failed")
