# Connection input to crypt_hash() and crypt_hmac() (#11): a file or any
# other connection, read in 1 MiB chunks and never held whole in memory.

test_that("a file hashes to the digest of its bytes, across chunk boundaries", {
  # The raw-vector path is pinned by the published vectors, so agreeing with
  # it at sizes around the chunk length pins the connection path's chunking.
  for (n in c(0L, 1L, 63L, chunk - 1L, chunk, chunk + 1L, 3L * chunk + 17L)) {
    bytes <- as.raw(seq_len(n) %% 251L)
    path <- write_temp(bytes)
    for (alg in crypt_info()$algorithms) {
      expect_identical(crypt_hash(file(path), alg), crypt_hash(bytes, alg),
                       info = paste(n, alg))
    }
    unlink(path)
  }
})

test_that("an empty file hashes to the digest of nothing", {
  path <- write_temp(raw(0))
  on.exit(unlink(path))
  expect_identical(crypt_hex(crypt_hash(file(path))),
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
})

test_that("a file's digest agrees with openssl reading the same file", {
  skip_if_not_installed("openssl")
  bytes <- as.raw(seq_len(2L * chunk + 5L) %% 256L)
  path <- write_temp(bytes)
  on.exit(unlink(path))
  expect_identical(crypt_hex(crypt_hash(file(path), "sha512")),
                   unclass(as.character(openssl::sha512(file(path)))))
})

test_that("an HMAC over a connection equals the HMAC over its bytes", {
  bytes <- as.raw(seq_len(chunk + 100L) %% 256L)
  path <- write_temp(bytes)
  on.exit(unlink(path))
  key <- as.raw(seq_len(100L))   # longer than the SHA-256 block
  for (alg in crypt_info()$algorithms) {
    expect_identical(crypt_hmac(file(path), key, alg),
                     crypt_hmac(bytes, key, alg), info = alg)
  }
})

test_that("an unopened connection is opened in binary mode and closed again", {
  path <- write_temp(as.raw(0:255))
  on.exit(unlink(path))
  before <- open_connections()
  crypt_hash(file(path))
  crypt_hmac(file(path), as.raw(1:4))
  expect_identical(open_connections(), before)
})

test_that("an open connection is read from where it stands and left open", {
  bytes <- as.raw(seq_len(1000L) %% 256L)
  path <- write_temp(bytes)
  con <- file(path, "rb")
  on.exit({
    close(con)
    unlink(path)
  })
  readBin(con, "raw", 10L)
  expect_identical(crypt_hash(con), crypt_hash(bytes[-(1:10)]))
  expect_true(isOpen(con))
})

test_that("in-memory and compressed connections hash what they yield", {
  bytes <- as.raw(seq_len(5000L) %% 256L)
  # rawConnection() is created open, so it is the caller's to close.
  rc <- rawConnection(bytes)
  expect_identical(crypt_hash(rc), crypt_hash(bytes))
  close(rc)

  path <- tempfile(fileext = ".gz")
  on.exit(unlink(path))
  gz <- gzfile(path, "wb")
  writeBin(bytes, gz)
  close(gz)
  expect_identical(crypt_hash(gzfile(path)), crypt_hash(bytes))
})

test_that("a text-mode or unreadable connection is refused, by class", {
  path <- write_temp(as.raw(0:255))
  on.exit(unlink(path))

  con <- file(path, "r")
  expect_error(crypt_hash(con), class = "zucrypt_invalid_argument")
  close(con)

  out <- file(tempfile(), "wb")
  expect_error(crypt_hmac(out, as.raw(1)), class = "zucrypt_invalid_argument")
  close(out)
})

test_that("a missing file is a connection error, and leaks no connection", {
  before <- open_connections()
  e <- tryCatch(crypt_hash(file(file.path(tempdir(), "no-such-file"))),
                error = identity)
  expect_s3_class(e, "zucrypt_connection_error")
  expect_s3_class(e, "zucrypt_error")
  expect_identical(conditionCall(e), quote(crypt_hash()))
  expect_identical(open_connections(), before)
})

test_that("a character value is still never a file name", {
  path <- write_temp(as.raw(0:255))
  on.exit(unlink(path))
  expect_error(crypt_hash(path), class = "zucrypt_invalid_argument")
  expect_error(crypt_hmac(path, as.raw(1)), class = "zucrypt_invalid_argument")
})

test_that("the algorithm and key are validated before the connection is read", {
  con <- rawConnection(as.raw(1:10))
  on.exit(close(con))
  expect_error(crypt_hash(con, "md5"), class = "zucrypt_unsupported_algorithm")
  expect_error(crypt_hmac(con, "key"), class = "zucrypt_invalid_argument")
  # Nothing was consumed by the refused calls.
  expect_identical(crypt_hash(con), crypt_hash(as.raw(1:10)))
})

test_that("a finished stream cannot be updated or finished again", {
  res <- .Call(zucrypt:::zucrypt_hash_stream_new, "sha256")
  expect_identical(res$status, 0L)
  stream <- res$value
  expect_identical(.Call(zucrypt:::zucrypt_stream_update, stream, as.raw(1:3)), 0L)
  expect_identical(.Call(zucrypt:::zucrypt_stream_finish, stream)$value,
                   crypt_hash(as.raw(1:3)))

  bad <- zuc_status_codes()[["ZUC_ERR_INVALID_ARGUMENT"]]
  expect_identical(.Call(zucrypt:::zucrypt_stream_update, stream, raw(1)), bad)
  expect_identical(.Call(zucrypt:::zucrypt_stream_finish, stream)$status, bad)
})

test_that("an unfinished non-blocking connection is refused by every reader (#145)", {
  skip_on_cran()
  for (name in names(readers <- connection_readers())) {
    con <- half_open_socket(charToRaw("first-half-"))
    e <- tryCatch(readers[[name]](con), error = identity)
    # Nothing is returned: a signature over a prefix is the bug.
    expect_s3_class(e, "zucrypt_connection_error")
    expect_s3_class(e, "zucrypt_error")
  }
})

test_that("every reader refuses a text-mode connection and an unopenable one (#145)", {
  path <- write_temp(as.raw(0:255))
  on.exit(unlink(path))
  for (name in names(readers <- connection_readers())) {
    con <- file(path, "r")
    e <- tryCatch(readers[[name]](con), error = identity)
    close(con)
    expect_s3_class(e, "zucrypt_invalid_argument")

    before <- open_connections()
    e <- tryCatch(
      expect_no_warning(
        readers[[name]](file(file.path(tempdir(), "no-such-file")))
      ),
      error = identity
    )
    expect_s3_class(e, "zucrypt_connection_error")
    expect_identical(open_connections(), before)
  }
})

test_that("every reader leaves an open connection open and closes one it opened (#145)", {
  k <- crypt_ec_keygen("P-256")
  path <- write_temp(charToRaw(crypt_write_pem(k)))
  on.exit(unlink(path))
  for (name in names(readers <- connection_readers())) {
    before <- open_connections()
    try(readers[[name]](file(path)), silent = TRUE)
    expect_identical(open_connections(), before)

    con <- file(path, "rb")
    try(readers[[name]](con), silent = TRUE)
    expect_true(isOpen(con))
    close(con)
  }
})

test_that("a key path that is a directory is refused by class, without warnings (#145)", {
  expect_no_warning(
    expect_error(crypt_read_key(tempdir()), class = "zucrypt_invalid_argument")
  )
  expect_no_warning(
    expect_error(crypt_read_pubkey(tempdir()), class = "zucrypt_invalid_argument")
  )
})
