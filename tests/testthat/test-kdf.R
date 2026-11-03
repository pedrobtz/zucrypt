# crypt_pbkdf2() and zuc_pbkdf2_hmac() (#12, Stage 14a).

test_that("every published PBKDF2 vector reproduces", {
  v <- kdf_vectors()
  expect_gt(nrow(v), 0L)
  for (i in seq_len(nrow(v))) {
    want <- unhex(v$output[i])
    got <- crypt_pbkdf2(unhex(v$password[i]), unhex(v$salt[i]),
                        iterations = as.numeric(v$iterations[i]),
                        length = length(want), algorithm = v$algorithm[i])
    expect_identical(got, want, info = v$id[i])
  }
})

test_that("a shorter output is a prefix of a longer one", {
  long <- crypt_pbkdf2(charToRaw("pw"), charToRaw("salt"), 3, length = 100)
  expect_length(long, 100L)
  expect_identical(
    crypt_pbkdf2(charToRaw("pw"), charToRaw("salt"), 3, length = 7),
    long[1:7]
  )
})

test_that("an empty password and an empty salt are valid", {
  # Python's hashlib.pbkdf2_hmac("sha256", b"", b"", 1, 20).
  expect_identical(
    tohex(crypt_pbkdf2(raw(0), raw(0), 1, length = 20)),
    "f7ce0b653d2d72a4108cf5abe912ffdd777616db"
  )
})

test_that("the default is 32 bytes of PBKDF2-HMAC-SHA256", {
  expect_identical(
    crypt_pbkdf2(charToRaw("passwd"), charToRaw("salt"), 1),
    unhex(kdf_vectors()$output[kdf_vectors()$id == "pbkdf2-sha256-01"])[1:32]
  )
})

test_that("invalid arguments are refused before anything runs", {
  pw <- charToRaw("pw")
  salt <- charToRaw("salt")
  for (bad in list(0, -1, 1.5, NA, NaN, Inf, 2^32, c(1, 2), "1000", NULL)) {
    expect_error(crypt_pbkdf2(pw, salt, bad), class = "zucrypt_invalid_argument")
  }
  expect_error(crypt_pbkdf2(pw, salt), "iterations")
  for (bad in list(0, -1, 2.5, NA, c(16, 32), "32")) {
    expect_error(crypt_pbkdf2(pw, salt, 1, length = bad),
                 class = "zucrypt_invalid_argument")
  }
  expect_error(crypt_pbkdf2("pw", salt, 1), class = "zucrypt_invalid_argument")
  expect_error(crypt_pbkdf2(pw, "salt", 1), class = "zucrypt_invalid_argument")
  expect_error(crypt_pbkdf2(pw, salt, 1, algorithm = "aes-gcm"),
               class = "zucrypt_unsupported_algorithm")
  expect_error(crypt_pbkdf2(pw, salt, 1, algorithm = "sha"),
               class = "zucrypt_unsupported_algorithm")
})

test_that("conditions never carry the password", {
  err <- tryCatch(crypt_pbkdf2(charToRaw("hunter2"), raw(0), 0),
                  error = identity)
  expect_s3_class(err, "zucrypt_invalid_argument")
  expect_identical(conditionCall(err), quote(crypt_pbkdf2()))
  expect_false(grepl("hunter2", conditionMessage(err), fixed = TRUE))
})
