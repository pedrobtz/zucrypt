# Randomized differential testing against openssl (#68): the seed and the
# count. ZUCRYPT_DIFF_SEED and ZUCRYPT_DIFF_N override the defaults, which
# keep R CMD check quick; aes-paths.yaml runs a large count with a fresh,
# logged seed. Every failure message names the seed and the iteration, so
# `ZUCRYPT_DIFF_SEED=<seed> ZUCRYPT_DIFF_N=<n>` reproduces it.
diff_seed <- function() {
  s <- Sys.getenv("ZUCRYPT_DIFF_SEED")
  if (nzchar(s)) as.integer(s) else 20261112L
}
diff_n <- function(default) {
  n <- Sys.getenv("ZUCRYPT_DIFF_N")
  if (nzchar(n)) max(1L, as.integer(n)) else default
}

# Run `code` under set.seed(seed) and put the caller's RNG state back
# afterwards (withr is not in Suggests).
with_diff_seed <- function(seed, code) {
  had <- exists(".Random.seed", envir = globalenv(), inherits = FALSE)
  old <- if (had) get(".Random.seed", envir = globalenv())
  on.exit(
    if (had) assign(".Random.seed", old, envir = globalenv())
    else rm(".Random.seed", envir = globalenv()),
    add = TRUE
  )
  set.seed(seed)
  force(code)
}

# A length biased towards where bugs live: 0, 1, a block either side, the
# 1 MiB interrupt chunk either side (rarely: it is large), else uniform.
diff_length <- function(block = 64L, max = 5000L) {
  chunk <- 1048576L
  switch(
    sample(6L, 1L, prob = c(1, 1, 3, 3, 0.15, 6)),
    0L,
    1L,
    block * sample(0:4, 1L) + sample(-1:1, 1L) %% (block + 1L),
    max(0L, block * sample(1:8, 1L) + sample(c(-1L, 0L, 1L), 1L)),
    chunk + sample(c(-1L, 0L, 1L), 1L),
    sample.int(max + 1L, 1L) - 1L
  )
}
diff_bytes <- function(n) {
  if (n == 0L) raw(0) else as.raw(sample.int(256L, n, replace = TRUE) - 1L)
}
# The harness's split plan: chunk sizes summing to `n`, from up to six
# random cut points. A repeated cut is a zero-length update, which must be a
# no-op.
diff_splits <- function(n) {
  if (n == 0L) return(integer(0))
  cuts <- sort(sample.int(n + 1L, sample(0:6, 1L), replace = TRUE) - 1L)
  diff(c(0L, cuts, n))
}
diff_where <- function(seed, i, what) {
  sprintf("seed %d, iteration %d: %s", seed, i, what)
}
