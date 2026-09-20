# Every validation rule in design.md section 7, asserted on the condition
# *class* and its native_status field rather than on message text. Messages
# are allowed to be reworded; the class is the contract a caller branches on.

expect_zucrypt_error <- function(expr, class) {
  cond <- tryCatch(expr, zucrypt_error = function(e) e)
  expect_s3_class(cond, class)
  expect_s3_class(cond, "zucrypt_error")
  expect_s3_class(cond, "error")
  cond
}

test_that("character input is refused rather than silently converted", {
  # The rule that matters most: a string is never a file name, never a
  # password, and never a byte sequence with a guessed encoding.
  expect_zucrypt_error(crypt_hash("abc"), "zucrypt_invalid_argument")
  expect_zucrypt_error(crypt_hmac("abc", raw(4)), "zucrypt_invalid_argument")
  expect_zucrypt_error(crypt_hmac(raw(4), "key"), "zucrypt_invalid_argument")
  expect_zucrypt_error(crypt_equal("a", raw(1)), "zucrypt_invalid_argument")
  expect_zucrypt_error(
    crypt_aes_cbc_encrypt("abc", raw(16), raw(16)), "zucrypt_invalid_argument")
})

test_that("other non-raw types are refused too", {
  for (value in list(1L, 1.5, TRUE, NULL, list(), as.factor("a"))) {
    expect_zucrypt_error(crypt_hash(value), "zucrypt_invalid_argument")
  }
})

test_that("an unknown algorithm is an error, with no partial matching", {
  for (name in c("sha", "sha2", "sha-256", "SHA256", "md5", "sha224", "")) {
    cond <- expect_zucrypt_error(crypt_hash(raw(0), name),
                                 "zucrypt_unsupported_algorithm")
    expect_identical(cond$algorithm, name)
  }
})

test_that("the algorithm argument must be a single name", {
  expect_zucrypt_error(crypt_hash(raw(0), c("sha256", "sha512")),
                       "zucrypt_invalid_argument")
  expect_zucrypt_error(crypt_hash(raw(0), character(0)),
                       "zucrypt_invalid_argument")
  expect_zucrypt_error(crypt_hash(raw(0), NA_character_),
                       "zucrypt_invalid_argument")
  expect_zucrypt_error(crypt_hash(raw(0), 256L), "zucrypt_invalid_argument")
})

test_that("AES key lengths other than 16, 24 and 32 are refused", {
  for (n in c(0L, 1L, 8L, 15L, 17L, 23L, 25L, 31L, 33L, 64L)) {
    expect_zucrypt_error(crypt_aes_cbc_encrypt(raw(16), raw(n), raw(16)),
                         "zucrypt_bad_length")
    expect_zucrypt_error(crypt_aes_cbc_decrypt(raw(16), raw(n), raw(16)),
                         "zucrypt_bad_length")
  }
})

test_that("an IV that is not exactly 16 bytes is refused", {
  for (n in c(0L, 8L, 15L, 17L, 32L)) {
    expect_zucrypt_error(crypt_aes_cbc_encrypt(raw(16), raw(16), raw(n)),
                         "zucrypt_bad_length")
  }
})

test_that("data that is not a whole number of blocks is refused", {
  for (n in c(1L, 15L, 17L, 31L, 33L)) {
    expect_zucrypt_error(crypt_aes_cbc_encrypt(raw(n), raw(16), raw(16)),
                         "zucrypt_bad_length")
    expect_zucrypt_error(crypt_aes_cbc_decrypt(raw(n), raw(16), raw(16)),
                         "zucrypt_bad_length")
  }
})

test_that("validation happens before anything is computed", {
  # A bad key with good data must report the key, not a backend failure, and
  # must not depend on the data at all.
  cond <- expect_zucrypt_error(
    crypt_aes_cbc_encrypt(raw(1), raw(15), raw(0)), "zucrypt_bad_length")
  expect_true(is.na(cond$native_status))
})

test_that("no condition message contains key or plaintext bytes", {
  # design.md section 11: an error message goes to the console, to logs and
  # into bug reports. Arguments here are exactly the values that must not.
  secret <- as.raw(rep(0xAB, 15))
  cond <- expect_zucrypt_error(
    crypt_aes_cbc_encrypt(raw(16), secret, raw(16)), "zucrypt_bad_length")
  expect_false(grepl("ab", conditionMessage(cond), fixed = TRUE))
  expect_false(grepl("AB", conditionMessage(cond), fixed = TRUE))
  # The length is named, which is not secret and is what makes the message
  # actionable.
  expect_match(conditionMessage(cond), "15")
})

test_that("the status-to-class map is keyed on enumerator names from C", {
  codes <- zucrypt:::zuc_status_codes()
  map <- zucrypt:::zuc_status_class

  # Every class the map produces must be reachable from a real enumerator...
  expect_true(all(names(map) %in% names(codes)))
  # ...every failing enumerator must have a class...
  failing <- setdiff(names(codes), "ZUC_OK")
  expect_true(all(failing %in% names(map)))
  # ...and success must not.
  expect_false("ZUC_OK" %in% names(map))
  expect_true(all(startsWith(unname(map), "zucrypt_")))
})

test_that("an unmapped native status still raises a catchable condition", {
  # The one place the mapping can be broken is the one place an uncatchable
  # stop() would be worst.
  cond <- tryCatch(zucrypt:::abort_native(4242L), zucrypt_error = function(e) e)
  expect_s3_class(cond, "zucrypt_internal_error")
  expect_identical(cond$native_status, 4242L)
})
