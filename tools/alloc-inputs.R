## The inputs tools/alloc-exercise.R works on, and tools/alloc-expected.R
## computes its answers from: defined once, so the two cannot drift. Fixed
## keys only, never generated ones -- key generation searches for primes, so
## its allocation count differs from run to run, and every sweep position
## would shift with it.
alloc_inputs <- function(fixtures = file.path("tests", "testthat", "fixtures")) {
  unhex <- function(x) {
    as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
  }
  rsa <- utils::read.delim(file.path(fixtures, "rsa-keys.tsv"),
                           colClasses = "character")
  rsa <- rsa[rsa$id == "rfc7515-a2", ]
  ec <- utils::read.delim(file.path(fixtures, "ec-keys.tsv"),
                          colClasses = "character")
  row <- function(id) ec[ec$id == id, ]
  p256 <- row("rfc6979-p256")
  iv <- as.raw(seq.int(0L, 15L))
  list(
    data = as.raw(rep(seq.int(0L, 255L), length.out = 4096L)),
    key = as.raw(rep(0x2b, 32)),
    iv = iv,
    nonce = iv[1:12],
    rsa_parts = lapply(rsa[c("n", "e", "d", "p", "q", "dp", "dq", "qi")],
                       unhex),
    ec_p256 = list(curve = p256$curve, x = unhex(p256$x), y = unhex(p256$y),
                   d = unhex(p256$d)),
    x25519_alice = unhex(row("rfc7748-alice")$d),
    x25519_bob = unhex(row("rfc7748-bob")$x),
    unhex = unhex
  )
}
