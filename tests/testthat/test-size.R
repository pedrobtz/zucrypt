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
  expect_identical(crypt_aes_cbc_encrypt_nopad(data, key, iv),
                   native_aes("cbc", TRUE, key, iv, data))
  expect_identical(crypt_aes_cbc_decrypt_nopad(crypt_aes_cbc_encrypt_nopad(data, key, iv),
                                         key, iv),
                   data)
})

test_that("a last chunk of one byte is processed on every in-memory path (#100)", {
  # src/zucrypt_crypt.c loops over in-memory input 1 MiB at a time. Either
  # side of the chunk, and at one byte, the last chunk is a single byte (or
  # block): a loop bound off by one drops it. The oracles are one unchunked
  # adapter call and, where it is installed, openssl.
  chunk <- 1048576L
  key <- as.raw(1:20)
  have_openssl <- requireNamespace("openssl", quietly = TRUE)
  for (n in c(1L, chunk - 1L, chunk, chunk + 1L)) {
    data <- as.raw(rep_len(c(0:255, 7L), n))
    for (algorithm in c("sha1", "sha256", "sha512")) {
      info <- paste(algorithm, n)
      expect_identical(crypt_hash(data, algorithm),
                       native_hash(algorithm, data), info = info)
      expect_identical(crypt_hmac(data, key, algorithm),
                       native_hmac(algorithm, key, data), info = info)
      if (have_openssl) {
        f <- getExportedValue("openssl", algorithm)
        expect_identical(crypt_hash(data, algorithm), as.vector(f(data)),
                         info = info)
        expect_identical(crypt_hmac(data, key, algorithm),
                         as.vector(f(data, key = key)), info = info)
      }
    }
  }

  # CBC works in blocks, so its straddle is a block either side.
  aes_key <- as.raw(rep(0x2b, 32))
  iv <- as.raw(0:15)
  for (n in c(16L, chunk - 16L, chunk, chunk + 16L)) {
    info <- paste("n =", n)
    data <- as.raw(rep_len(c(0:255, 7L), n))
    ct <- crypt_aes_cbc_encrypt_nopad(data, aes_key, iv)
    expect_identical(ct, native_aes("cbc", TRUE, aes_key, iv, data),
                     info = info)
    expect_identical(crypt_aes_cbc_decrypt_nopad(ct, aes_key, iv), data,
                     info = info)
    if (have_openssl) {
      # openssl pads; its first n bytes are the unpadded encryption.
      theirs <- openssl::aes_cbc_encrypt(data, aes_key, iv)
      expect_identical(ct, as.vector(theirs)[seq_len(n)], info = info)
    }
  }

  # Random bytes: the fill loop runs over a buffer pre-filled with a
  # sentinel. A byte left unfilled is the sentinel in every draw; a filled
  # one is the sentinel in all four with probability 2^-32.
  for (n in c(1L, chunk - 1L, chunk, chunk + 1L)) {
    last <- vapply(1:4, function(i) {
      native_rand_fill(rep(as.raw(0xAA), n))[n]
    }, raw(1))
    expect_false(all(last == as.raw(0xAA)), info = paste("n =", n))
    expect_length(native_rand_fill(raw(n)), n)
    expect_length(crypt_rand_bytes(n), n)
  }
})

test_that("a large input makes no per-chunk R heap allocation (#118)", {
  # The native entry points write into one preallocated output vector and
  # loop in the C layer. If a future change moved the loop into R, or
  # reallocated an R vector per chunk, this is where it would show -- and
  # nowhere else, because the answers would still be correct. Rprofmem()
  # sees R's heap only; the backend's own allocations are the next test's.
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
  ciphertext <- crypt_aes_cbc_encrypt_nopad(data, key, iv)
  utils::Rprofmem(NULL)

  records <- readLines(log, warn = FALSE)
  large <- grep("^[0-9]+ :", records, value = TRUE)

  expect_length(digest, 32L)
  expect_length(ciphertext, n)
  # One allocation for the ciphertext, and room for a couple of incidentals.
  # Four 1 MiB chunks allocating each would be at least four more.
  expect_lt(length(large), 4L)
})

test_that("the backend's copies of a large input are bounded by the chunk (#118)", {
  # PSA copies each update's input (and a cipher's output) into a buffer of
  # its own, through psa_crypto_local_input_alloc(), against callers that
  # share buffers with an attacker. Those copies are native, so Rprofmem()
  # cannot see them; the adapter's allocator counts them instead
  # (zuc_int_alloc_stats(), zuc_live.h). The loop hands the backend 1 MiB
  # at a time, so no copy is larger than that whatever the input, and the
  # copies number a few per chunk, not one per block.
  alloc_stats <- function() .Call(zucrypt:::zucrypt_test_alloc_stats)
  chunk <- 1048576
  n <- 4L * 1024L * 1024L
  data <- as.raw(rep(seq.int(0L, 255L), length.out = n))
  key <- as.raw(rep(0x2b, 32))
  iv <- as.raw(seq.int(0L, 15L))

  calls <- list(
    hash = function() crypt_hash(data),
    hmac = function() crypt_hmac(data, key),
    cbc = function() crypt_aes_cbc_encrypt_nopad(data, key, iv)
  )
  for (name in names(calls)) {
    calls[[name]]() # first use initialises the backend
    alloc_stats()
    calls[[name]]()
    stats <- alloc_stats()
    # The largest copy is one chunk: the counter sees the backend at all,
    # and the input is never copied whole.
    expect_equal(stats[[3]], chunk, label = paste(name, "largest block"))
    # 4 chunks at a few blocks each; per-block copies would be 2^16 or more.
    expect_lt(stats[[1]], 32, label = paste(name, "blocks"))
    # Input (and, for a cipher, output) once each, plus small change.
    expect_lt(stats[[2]], 2 * n + 65536, label = paste(name, "bytes"))
  }
})
