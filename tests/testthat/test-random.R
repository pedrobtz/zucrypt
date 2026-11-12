# crypt_rand_bytes() and zuc_random_bytes() (#9).
#
# Randomness cannot be tested for correctness, only for obvious brokenness:
# the right length, distinct draws, not a constant, independent of R's RNG.
# Anything stronger belongs to the operating system. What can be tested
# exactly is the contract around it: arguments, the not-ready window, and
# that a failing source is an error and never bytes.

test_that("the requested number of raw bytes comes back", {
  for (n in c(1, 2, 15, 16, 17, 32, 1000)) {
    x <- crypt_rand_bytes(n)
    expect_type(x, "raw")
    expect_length(x, n)
  }
  expect_length(crypt_rand_bytes(5L), 5L)
  # openssl's default.
  expect_length(crypt_rand_bytes(), 1L)
})

test_that("n = 0 gives raw(0)", {
  expect_identical(crypt_rand_bytes(0), raw(0))
})

test_that("two draws differ, and a draw is not a constant", {
  # 2^-256 is the chance of a false failure in each expectation.
  a <- crypt_rand_bytes(32)
  b <- crypt_rand_bytes(32)
  expect_false(identical(a, b))
  expect_gt(length(unique(a)), 1L)
})

test_that("a draw spanning chunks is filled to the end", {
  # The entry point fills 1 MiB at a time. A loop that stopped after the
  # first chunk would leave the tail as allocated -- zero on most systems.
  n <- 1024 * 1024 + 64
  x <- crypt_rand_bytes(n)
  expect_length(x, n)
  expect_gt(length(unique(x[(n - 63):n])), 1L)
  # And every byte value turns up: a constant or a stuck bit would not.
  expect_length(unique(x), 256L)
})

test_that("R's RNG is neither used nor disturbed", {
  set.seed(42)
  a <- crypt_rand_bytes(16)
  set.seed(42)
  b <- crypt_rand_bytes(16)
  expect_false(identical(a, b))

  set.seed(42)
  before <- get(".Random.seed", envir = globalenv())
  invisible(crypt_rand_bytes(64))
  expect_identical(get(".Random.seed", envir = globalenv()), before)
})

test_that("an invalid n is refused before any native call", {
  for (bad in list(-1, 1.5, NA, NA_integer_, Inf, NaN, c(1, 2), numeric(0),
                   "16", TRUE, 2^53, list(16))) {
    expect_error(crypt_rand_bytes(bad), class = "zucrypt_invalid_argument")
  }
})

test_that("a failing source raises zucrypt_entropy_error, never bytes", {
  native_random_fail(TRUE)
  e <- tryCatch(crypt_rand_bytes(16), error = identity,
                finally = native_random_fail(FALSE))
  expect_s3_class(e, "zucrypt_entropy_error")
  expect_s3_class(e, "zucrypt_error")
  expect_identical(conditionCall(e), quote(crypt_rand_bytes()))
  # The switch is off again, and the source works.
  expect_length(crypt_rand_bytes(16), 16L)
})

test_that("zuc_random_bytes() keeps the contract zucrypt.h states", {
  got <- native_random_contract()
  expect_identical(got[["null_0"]], "ZUC_OK")
  expect_identical(got[["null_16"]], "ZUC_ERR_INVALID_ARGUMENT")
  expect_identical(got[["ok_16"]], "ZUC_OK")
  expect_identical(got[["failing_16"]], "ZUC_ERR_ENTROPY")
  # A failed draw zeroes the whole buffer, so it cannot pass for random.
  expect_identical(got[["wiped"]], "TRUE")
  expect_identical(got[["after_failure"]], "ZUC_OK")
})

test_that("the name and signature mirror openssl::rand_bytes()", {
  skip_if_not_installed("openssl")
  expect_identical(formals(crypt_rand_bytes),
                   formals(openssl::rand_bytes))
  # Same type and length; the bytes themselves cannot be compared.
  expect_identical(typeof(crypt_rand_bytes(8)),
                   typeof(openssl::rand_bytes(8)))
  expect_identical(length(crypt_rand_bytes(0)),
                   length(openssl::rand_bytes(0)))
})

test_that("getrandom() refused by the kernel falls back to /dev/urandom (#144)", {
  # glibc 2.25 or later on a kernel before 3.17 (a modern container on a
  # CentOS 7 host) has getrandom() fail with ENOSYS, and a seccomp filter
  # can make it EPERM. Either used to be ZUC_ERR_ENTROPY on every draw. The
  # harness makes getrandom() report ENOSYS; it is a no-op, and says so, on
  # a build that does not use getrandom().
  if (!native_random_enosys(TRUE)) {
    skip("this build does not draw from getrandom()")
  }
  got <- tryCatch(
    list(a = crypt_rand_bytes(64), b = crypt_rand_bytes(64),
         key = crypt_ec_keygen("P-256"),
         backend = crypt_info()$build_flags$random_backend),
    finally = native_random_enosys(FALSE)
  )
  expect_length(got$a, 64L)
  expect_false(identical(got$a, got$b))
  expect_false(all(got$a == as.raw(0)))
  expect_s3_class(got$key, "crypt_key")
  expect_identical(got$backend, "/dev/urandom (getrandom() unavailable)")
  # Switched back, the build reports its own source again.
  expect_identical(crypt_info()$build_flags$random_backend, "getrandom")
})

test_that("forked children draw their own bytes, nonces and keys (#98)", {
  # Randomness comes from the operating system on every call, with no DRBG
  # state for fork() to copy. A buffered source or a DRBG brought back by a
  # configuration change would give two parallel::mcparallel() workers the
  # same bytes, and two randomised ECDSA signatures the same nonce, which
  # reveals the private key. The oracle is the r of each signature: it is
  # determined by the nonce alone.
  skip_on_os("windows")
  key <- ec_fixture_key("rfc6979-p256")
  msg <- charToRaw("one message, signed in two processes")
  draw <- function() {
    sig <- crypt_signature_create(msg, crypt_sha256, key)
    list(
      bytes = crypt_rand_bytes(32),
      r = crypt_ecdsa_parse(sig)$r,
      ok = crypt_signature_verify(msg, sig, crypt_sha256, key$pubkey),
      rsa = crypt_write_der(crypt_rsa_keygen(1024)$pubkey)
    )
  }
  jobs <- list(parallel::mcparallel(draw()), parallel::mcparallel(draw()))
  parent <- draw()
  got <- parallel::mccollect(jobs, wait = TRUE)
  expect_length(got, 2L)
  for (g in got) expect_type(g, "list")
  a <- got[[1]]
  b <- got[[2]]
  expect_false(identical(a$bytes, b$bytes))
  expect_false(identical(a$bytes, parent$bytes))
  expect_false(identical(b$bytes, parent$bytes))
  expect_false(identical(a$r, b$r))
  expect_false(identical(a$r, parent$r))
  expect_false(identical(a$rsa, b$rsa))
  # The signatures are valid: the children really signed.
  expect_true(a$ok)
  expect_true(b$ok)
})

test_that("getrandom()'s short reads, EINTR and errors are each handled (#119)", {
  # A real kernel returns short or is interrupted only now and then, so the
  # harness scripts the next calls. The buffer starts as 0xAA: a filled
  # 64-byte buffer keeps a few such bytes by chance (a quarter on average,
  # eight or more about once in 10^9), a buffer the loop failed to finish
  # keeps every byte it did not write.
  skip_if(is.null(native_random_script(character(0))),
          "this build does not draw from getrandom()")
  left <- function(r) sum(r[[2]] == as.raw(0xAA))

  # Short reads: the loop asks again until every byte has arrived.
  r <- native_random_script(c("1", "5", "7", "11"))
  expect_identical(r[[1]], "ZUC_OK")
  expect_identical(r[[3]], 0L)
  expect_lt(left(r), 8L)

  # Interrupted once, and twice between short reads: retried, not failed.
  for (steps in list("EINTR", c("3", "EINTR", "EINTR", "9"))) {
    r <- native_random_script(steps)
    expect_identical(r[[1]], "ZUC_OK", info = paste(steps, collapse = " "))
    expect_identical(r[[3]], 0L)
    expect_lt(left(r), 8L)
  }

  # A permanent error, at once or after a short read: ZUC_ERR_ENTROPY, and
  # nothing drawn before it is left in the buffer.
  for (steps in list("EIO", c("10", "EIO"))) {
    r <- native_random_script(steps)
    expect_identical(r[[1]], "ZUC_ERR_ENTROPY",
                     info = paste(steps, collapse = " "))
    expect_identical(r[[2]], raw(64))
  }

  # The call itself refused (a seccomp filter's EPERM, an old kernel's
  # ENOSYS) after a short read: the rest comes from /dev/urandom.
  for (steps in list(c("4", "EPERM"), c("4", "ENOSYS"))) {
    r <- native_random_script(steps)
    expect_identical(r[[1]], "ZUC_OK", info = paste(steps, collapse = " "))
    expect_lt(left(r), 8L)
  }
  # And the harness put getrandom() back.
  expect_identical(crypt_info()$build_flags$random_backend, "getrandom")
})
