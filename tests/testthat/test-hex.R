# crypt_hex() (#59): lower-case hex, two digits a byte, converted in C.

test_that("every byte value encodes to its two lower-case digits", {
  # The reference is built with sprintf(), which shares nothing with the C
  # table: a swapped nibble or an upper-case digit shows up here.
  all_bytes <- as.raw(0:255)
  expect_identical(crypt_hex(all_bytes),
                   paste(sprintf("%02x", 0:255), collapse = ""))
})

test_that("digests encode to the published hex vectors", {
  # The fixtures store every expected digest as lower-case hex, so they are
  # an oracle for the conversion as much as for the hash.
  for (v in split(kat_vectors("hash"), seq_len(nrow(kat_vectors("hash"))))) {
    expect_identical(crypt_hex(crypt_hash(unhex(v$input), v$algorithm)),
                     v$output, info = v$id)
  }
  for (v in split(kat_vectors("hmac"), seq_len(nrow(kat_vectors("hmac"))))) {
    expect_identical(
      crypt_hex(crypt_hmac(unhex(v$input), unhex(v$key), v$algorithm)),
      v$output, info = v$id)
  }
})

test_that("it agrees with openssl's hex for a digest", {
  skip_if_not_installed("openssl")
  x <- charToRaw("the quick brown fox")
  # openssl's as.character() keeps its "hash" class; the digits are the test.
  expect_identical(crypt_hex(crypt_hash(x, "sha256")),
                   unclass(as.character(openssl::sha256(x))))
})

test_that("the result is one plain string of twice the input's length", {
  x <- as.raw(c(0x00, 0x0f, 0xa0, 0xff))
  out <- crypt_hex(x)
  expect_identical(out, "000fa0ff")
  expect_null(attributes(out))
  expect_identical(nchar(crypt_hex(as.raw(rep(1, 1000)))), 2000L)
})

test_that("empty input is the empty string", {
  expect_identical(crypt_hex(raw(0)), "")
})

test_that("the input is not modified", {
  x <- as.raw(0:31)
  crypt_hex(x)
  expect_identical(x, as.raw(0:31))
})

test_that("anything but a raw vector is refused, by class", {
  for (bad in list("abc", 1:3, NULL, list(as.raw(1)), c(a = 1))) {
    expect_error(crypt_hex(bad), class = "zucrypt_invalid_argument")
  }
  e <- tryCatch(crypt_hex("abc"), error = identity)
  expect_identical(conditionCall(e), quote(crypt_hex()))
})
