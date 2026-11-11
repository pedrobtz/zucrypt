# Helpers for test-ec.R and test-rsa.R (hash_fun), here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

hash_fun <- function(name) {
  switch(
    name,
    sha1 = crypt_sha1,
    sha256 = crypt_sha256,
    sha384 = crypt_sha384,
    sha512 = crypt_sha512
  )
}

raw_sig <- function(der, n) {
  p <- crypt_ecdsa_parse(der)
  c(raw(n - length(p$r)), p$r, raw(n - length(p$s)), p$s)
}

# --- crypt_ecdsa_parse() reads strict DER (#91) --------------------------
#
# The oracle is an independent model of the DER rules for
# SEQUENCE { INTEGER r, INTEGER s } (X.690 8.1.3, 8.3, 10.1), written here
# rather than shared with R/pkey.R: definite minimal lengths, both INTEGERs
# present and inside the input, non-negative, minimally encoded, and no
# byte after the SEQUENCE. It returns list(r, s) as unsigned magnitudes, or
# NULL when the input is not such a signature.
der_model <- function(b) {
  b <- as.integer(b)
  pos <- 1L
  length_at <- function() {
    if (pos > length(b)) {
      return(NULL)
    }
    first <- b[[pos]]
    pos <<- pos + 1L
    if (first < 0x80) {
      return(first)
    }
    k <- first - 0x80
    if (k == 0L || k > 4L || pos + k - 1L > length(b)) {
      return(NULL)
    }
    bytes <- b[pos:(pos + k - 1L)]
    pos <<- pos + k
    n <- sum(bytes * 256^((k - 1L):0))
    if (bytes[[1]] == 0L || n < 0x80) {
      return(NULL)
    } # not minimal
    n
  }
  integer_at <- function(end) {
    if (pos > end || b[[pos]] != 0x02) {
      return(NULL)
    }
    pos <<- pos + 1L
    n <- length_at()
    if (is.null(n) || n == 0L || pos + n - 1L > end) {
      return(NULL)
    }
    v <- b[pos:(pos + n - 1L)]
    pos <<- pos + n
    if (v[[1]] >= 0x80) {
      return(NULL)
    } # negative
    if (n > 1L && v[[1]] == 0L && v[[2]] < 0x80) {
      return(NULL)
    } # padded
    if (n > 1L && v[[1]] == 0L) {
      v <- v[-1L]
    }
    as.raw(v)
  }
  if (!length(b) || b[[1]] != 0x30) {
    return(NULL)
  }
  pos <- 2L
  n <- length_at()
  if (is.null(n) || pos + n - 1L != length(b)) {
    return(NULL)
  }
  end <- length(b)
  r <- integer_at(end)
  if (is.null(r)) {
    return(NULL)
  }
  s <- integer_at(end)
  if (is.null(s) || pos != end + 1L) {
    return(NULL)
  }
  list(r = r, s = s)
}

parse_or_null <- function(b) {
  tryCatch(crypt_ecdsa_parse(b), zucrypt_invalid_argument = function(e) NULL)
}
