# Helpers for test-connection.R, here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

chunk <- 1048576L

write_temp <- function(bytes) {
  path <- tempfile()
  writeBin(bytes, path)
  path
}

open_connections <- function() nrow(showConnections(all = FALSE))
