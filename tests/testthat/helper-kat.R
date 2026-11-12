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

# Hex, or the fixture's repeat notation "HH*N": byte HH, N times -- how the
# one-million-'a' messages and the 131-byte HMAC keys are written without
# megabytes of hex. Kept identical to unhex() in tools/make-kat.R.
unhex <- function(x) {
  if (!nzchar(x)) return(raw(0))
  if (grepl("^[0-9a-f]{2}\\*[0-9]+$", x)) {
    parts <- strsplit(x, "*", fixed = TRUE)[[1L]]
    return(rep(as.raw(strtoi(parts[1L], 16L)), as.integer(parts[2L])))
  }
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
native_random_contract <- function() {
  .Call(zucrypt:::zucrypt_test_random_contract)
}
native_random_enosys <- function(on) {
  .Call(zucrypt:::zucrypt_test_random_enosys, isTRUE(on))
}
native_random_fail <- function(on) {
  invisible(.Call(zucrypt:::zucrypt_test_random_fail, isTRUE(on)))
}
native_random_script <- function(steps, len = 64L) {
  .Call(zucrypt:::zucrypt_test_random_script, as.character(steps),
        as.integer(len))
}
native_rand_fill <- function(x) .Call(zucrypt:::zucrypt_test_rand_fill, x)
native_live_handles <- function(n) {
  .Call(zucrypt:::zucrypt_test_live_handles, as.integer(n))
}

# The AEAD and KDF fixtures (Stage 14a), each with its own columns.
aead_vectors <- function() {
  utils::read.delim(test_path("fixtures", "aead.tsv"), colClasses = "character")
}
kdf_vectors <- function() {
  utils::read.delim(test_path("fixtures", "kdf.tsv"), colClasses = "character")
}
native_aead_contract <- function() {
  .Call(zucrypt:::zucrypt_test_aead_contract)
}

# The RSA fixtures (Stage 15a): keys as their integers, and vectors.
rsa_vectors <- function() {
  utils::read.delim(test_path("fixtures", "rsa.tsv"), colClasses = "character")
}
rsa_fixture_key <- function(id) {
  k <- utils::read.delim(test_path("fixtures", "rsa-keys.tsv"),
                         colClasses = "character")
  k <- k[k$id == id, ]
  args <- lapply(k[c("n", "e", "d", "p", "q", "dp", "dq", "qi")], unhex)
  do.call(crypt_rsa_key, unname(args))
}
native_pkey_contract <- function(pem) {
  .Call(zucrypt:::zucrypt_test_pkey_contract, pem)
}

# The EC fixtures (Stage 16a).
ec_vectors <- function() {
  utils::read.delim(test_path("fixtures", "ec.tsv"), colClasses = "character")
}
ec_fixture_key <- function(id) {
  k <- utils::read.delim(test_path("fixtures", "ec-keys.tsv"),
                         colClasses = "character")
  k <- k[k$id == id, ]
  if (k$curve == "X25519") {
    return(crypt_read_x25519_key(unhex(k$d)))
  }
  crypt_ec_key(k$curve, unhex(k$x), unhex(k$y), unhex(k$d))
}
native_ec_contract <- function() .Call(zucrypt:::zucrypt_test_ec_contract)

# NIST CAVP vectors (#67): the shipped subset in fixtures/cavp.tsv, or, when
# ZUCRYPT_CAVP names it, every vector (tools/cavp/cavp.tsv.gz, written by
# tools/make-cavp.py, kept out of the tarball). A path that does not exist is
# an error, never a quiet fall back to the subset.
CAVP_FULL_COUNT <- 5110L
cavp_full <- function() nzchar(Sys.getenv("ZUCRYPT_CAVP"))
cavp_vectors <- function(family = NULL) {
  path <- Sys.getenv("ZUCRYPT_CAVP")
  if (!nzchar(path)) path <- test_path("fixtures", "cavp.tsv")
  if (!file.exists(path)) stop("ZUCRYPT_CAVP names a missing file: ", path)
  v <- utils::read.delim(path, colClasses = "character", na.strings = NULL)
  if (!is.null(family)) v <- v[v$family == family, , drop = FALSE]
  v
}
native_sha_monte <- function(algorithm, seed, n) {
  .Call(zucrypt:::zucrypt_test_sha_monte, algorithm, seed, as.integer(n))
}
native_cbc_mct <- function(encrypt, key, iv, text, n) {
  .Call(zucrypt:::zucrypt_test_cbc_mct, encrypt, key, iv, text, as.integer(n))
}
native_residue <- function(key, private_key, op, needle = raw()) {
  .Call(zucrypt:::zucrypt_test_residue, key, private_key, op, needle)
}

# The base64 characters that encode `secret` inside `der`, as they appear in
# the unwrapped body of the PEM of `der` (#137): a run of whole 3-byte groups
# lying inside the secret, so the 4-character groups depend on it alone.
base64_needle <- function(der, secret, nchar = 24L) {
  pos <- NULL
  for (i in seq_len(length(der) - length(secret) + 1L)) {
    if (identical(der[i:(i + length(secret) - 1L)], secret)) {
      pos <- i - 1L
      break
    }
  }
  stopifnot(!is.null(pos))
  first <- ((pos + 2L) %/% 3L) * 3L       # the first group inside the secret
  stopifnot(first + nchar / 4L * 3L <= pos + length(secret))
  b64 <- base64_encode_raw(der)
  start <- first %/% 3L * 4L + 1L
  charToRaw(substr(b64, start, start + nchar - 1L))
}

base64_encode_raw <- function(x) {
  # RFC 4648 base64, so the needle does not trust the code under test.
  tbl <- c(LETTERS, letters, 0:9, "+", "/")
  pad <- (3L - length(x) %% 3L) %% 3L
  v <- as.integer(x)
  v <- c(v, integer(pad))
  out <- character(length(v) / 3L * 4L)
  for (g in seq_len(length(v) / 3L)) {
    n <- v[3L * g - 2L] * 65536L + v[3L * g - 1L] * 256L + v[3L * g]
    out[4L * g - 3:0] <- tbl[c(n %/% 262144L, n %/% 4096L %% 64L,
                               n %/% 64L %% 64L, n %% 64L) + 1L]
  }
  if (pad) out[length(out) - seq_len(pad) + 1L] <- "="
  paste(out, collapse = "")
}
native_alias <- function(rsa_der) .Call(zucrypt:::zucrypt_test_alias, rsa_der)
