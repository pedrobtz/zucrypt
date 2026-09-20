# Size and boundary behaviour.
#
# Everything here is about inputs larger than the published vectors, which are
# all shorter than one compression block. These are slower than the rest of
# the suite, so they are bounded rather than open-ended: a few megabytes is
# enough to cross every internal boundary the code has.

test_that("multi-megabyte input agrees across one-shot and incremental", {
  # 4 MiB crosses the 1 MiB interrupt chunk in src/zucrypt_crypt.c four times,
  # so the chunked wrapper and the unchunked adapter must still agree.
  n <- 4L * 1024L * 1024L
  data <- as.raw(rep(seq.int(0L, 255L), length.out = n))

  for (algorithm in c("sha1", "sha256", "sha512")) {
    one_shot <- native_hash(algorithm, data)
    expect_identical(crypt_hash(data, algorithm), one_shot,
                     info = algorithm)
    # And through the incremental path at chunk sizes that do and do not
    # divide the interrupt chunk.
    expect_identical(native_hash(algorithm, data, c(1048576L, n - 1048576L)),
                     one_shot, info = paste(algorithm, "aligned split"))
    expect_identical(native_hash(algorithm, data, c(1048575L, n - 1048575L)),
                     one_shot, info = paste(algorithm, "unaligned split"))
  }
})

test_that("multi-megabyte CBC chains correctly across interrupt chunks", {
  n <- 4L * 1024L * 1024L
  data <- as.raw(rep(seq.int(0L, 255L), length.out = n))
  key <- as.raw(rep(0x2b, 32))
  iv <- as.raw(seq.int(0L, 15L))

  # The adapter processes the whole buffer in one call; the wrapper splits it
  # into 1 MiB chunks. If the chaining state were reset or dropped between
  # chunks these would differ from the first megabyte onwards.
  expect_identical(crypt_aes_cbc_encrypt(data, key, iv),
                   native_aes("cbc", TRUE, key, iv, data))
  expect_identical(crypt_aes_cbc_decrypt(crypt_aes_cbc_encrypt(data, key, iv),
                                         key, iv),
                   data)
})

test_that("processing a large input does not allocate per block", {
  # The native entry points write into one preallocated output vector and
  # loop in the C layer. If a future change moved the loop into R, or
  # reallocated per chunk, this is where it would show -- and nowhere else,
  # because the answers would still be correct.
  skip_if(!capabilities("profmem"),
          "this R was not built with memory profiling")

  n <- 4L * 1024L * 1024L
  data <- as.raw(rep(seq.int(0L, 255L), length.out = n))
  key <- as.raw(rep(0x2b, 32))
  iv <- as.raw(seq.int(0L, 15L))

  log <- tempfile(fileext = ".out")
  on.exit(unlink(log), add = TRUE)

  # Threshold at 64 KiB: well above anything incidental, well below the 1 MiB
  # chunk, so a per-chunk allocation would be recorded and a scalar would not.
  utils::Rprofmem(log, threshold = 65536)
  digest <- crypt_hash(data)
  ciphertext <- crypt_aes_cbc_encrypt(data, key, iv)
  utils::Rprofmem(NULL)

  records <- readLines(log, warn = FALSE)
  large <- grep("^[0-9]+ :", records, value = TRUE)

  expect_length(digest, 32L)
  expect_length(ciphertext, n)
  # One allocation for the ciphertext, and room for a couple of incidentals.
  # Four 1 MiB chunks allocating each would be at least four more.
  expect_lt(length(large), 4L)
})
