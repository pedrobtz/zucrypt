# Fixture access and native-harness wrappers.
#
# In a helper file because testthat's parallel workers source helper-*.R but
# do not share a test file's file scope, so a definition at the top of
# test-kat.R is found in some shuffled orders and not others.

# The committed known-answer vectors. Read from the installed fixtures, never
# regenerated at test time: tools/make-kat.R writes them, and its --check mode
# recomputes every one against openssl. See fixtures/MANIFEST.tsv.
kat_vectors <- function(family = NULL, algorithm = NULL) {
  path <- test_path("fixtures", "kat.tsv")
  v <- utils::read.delim(path, colClasses = "character")
  if (!is.null(family)) v <- v[v$family %in% family, , drop = FALSE]
  if (!is.null(algorithm)) v <- v[v$algorithm %in% algorithm, , drop = FALSE]
  v
}

unhex <- function(x) {
  if (!nzchar(x)) return(raw(0))
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}

tohex <- function(x) paste(format(x, width = 2), collapse = "")

# Split points that exercise the incremental path at every boundary that has
# ever hidden a bug: nothing, one byte, one short of a block, exactly a block,
# one past it, and an uneven tail. Returned as a list of chunk-size vectors
# summing to `n`.
split_plans <- function(n, block = 64L) {
  if (n == 0L) return(list(integer(0), 0L, c(0L, 0L)))
  candidates <- unique(c(1L, block - 1L, block, block + 1L, 2L * block,
                         n %/% 2L, n - 1L))
  candidates <- candidates[candidates > 0L & candidates < n]
  plans <- list(n)                       # one chunk
  for (first in candidates) {
    plans[[length(plans) + 1L]] <- c(first, n - first)
  }
  # A zero-length update in the middle must be a no-op, not a state change.
  plans[[length(plans) + 1L]] <- c(0L, n, 0L)
  # Byte at a time, for short inputs only -- this is the strongest check and
  # the slowest, so it is bounded rather than skipped.
  if (n <= 64L) plans[[length(plans) + 1L]] <- rep(1L, n)
  plans
}

# Thin wrappers over the permanently-compiled harness. Using ::: on our own
# package: these are registered native symbols, deliberately not exported.
native_hash <- function(algorithm, data, splits = integer(0)) {
  .Call(zucrypt:::zucrypt_test_hash, algorithm, data, as.integer(splits))
}
native_hmac <- function(algorithm, key, data, splits = integer(0)) {
  .Call(zucrypt:::zucrypt_test_hmac, algorithm, key, data, as.integer(splits))
}
native_hash_reset <- function(algorithm, first, second) {
  .Call(zucrypt:::zucrypt_test_hash_reset, algorithm, first, second)
}
native_hmac_reset <- function(algorithm, key, first, second) {
  .Call(zucrypt:::zucrypt_test_hmac_reset, algorithm, key, first, second)
}
native_aes <- function(mode, encrypt, key, iv, data, splits = integer(0),
                       reset_each = FALSE) {
  .Call(zucrypt:::zucrypt_test_aes, mode, encrypt, key, iv, data,
        as.integer(splits), reset_each)
}
native_aes_inplace <- function(encrypt, key, iv, data) {
  .Call(zucrypt:::zucrypt_test_aes_inplace, encrypt, key, iv, data)
}
native_aes_overlap <- function(key, iv, data, offset) {
  .Call(zucrypt:::zucrypt_test_aes_overlap, key, iv, data, as.integer(offset))
}
native_equal <- function(a, b) .Call(zucrypt:::zucrypt_test_equal, a, b)
native_algs <- function() .Call(zucrypt:::zucrypt_test_algs)
native_status <- function(code) {
  .Call(zucrypt:::zucrypt_test_status, as.integer(code))
}
native_info_size <- function(size) {
  .Call(zucrypt:::zucrypt_test_info_size, as.integer(size))
}
native_required_sizes <- function() .Call(zucrypt:::zucrypt_test_required_sizes)
native_status_codes <- function() .Call(zucrypt:::zucrypt_status_codes)
native_not_ready <- function() .Call(zucrypt:::zucrypt_test_not_ready)
native_live_handles <- function(n) {
  .Call(zucrypt:::zucrypt_test_live_handles, as.integer(n))
}
