# The archive consumption mode: zucrypt's adapter and backend linked
# statically out of the installed libzucrypt.a, with zucrypt's namespace never
# loaded. See ../../NAMESPACE for why there is no importFrom to make that true.
#
# Every expected value here is a published vector or comes from an
# implementation that shares no code with zucrypt, so a wrong answer cannot
# hide behind agreement with zucrypt.so -- the two are the same source code.

unhex <- function(x) {
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}
tohex <- function(x) paste(format(x, width = 2), collapse = "")

test_that("the linked archive reports its backend and the ABI it was built for", {
  b <- linked_backend()
  expect_identical(b$name, "TF-PSA-Crypto")
  # Shape only: the pinned version is asserted in zucrypt's own test-abi.R,
  # and tools/check-linking.sh compares this string with the one zucrypt.so
  # reports from the same installation.
  expect_match(b$version, "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  # The library and the header it was compiled against agree.
  expect_identical(b$abi_version, b$header_abi_version)
})

test_that("digests reproduce FIPS 180-2", {
  abc <- charToRaw("abc")
  expect_identical(
    tohex(archive_hash(abc, "sha256")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  expect_identical(
    tohex(archive_hash(abc, "sha512")),
    paste0("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))
  expect_identical(
    tohex(archive_hash(charToRaw(strrep("a", 1e6)), "sha1")),
    "34aa973cd4c4daa4f61eeb2bdbad27316534016f")
})

test_that("HMAC reproduces RFC 4231, including a key longer than the block", {
  expect_identical(
    tohex(archive_hmac(charToRaw("Hi There"), as.raw(rep(0x0b, 20)), "sha256")),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  expect_identical(
    tohex(archive_hmac(
      charToRaw("Test Using Larger Than Block-Size Key - Hash Key First"),
      as.raw(rep(0xaa, 131)), "sha256")),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
})

test_that("CBC reproduces NIST SP 800-38A F.2.1 and restarts at segments", {
  key <- unhex("2b7e151628aed2a6abf7158809cf4f3c")
  iv <- unhex("000102030405060708090a0b0c0d0e0f")
  pt <- unhex(paste0("6bc1bee22e409f96e93d7e117393172a",
                     "ae2d8a571e03ac9c9eb76fac45af8e51"))
  ct <- unhex(paste0("7649abac8119b246cee98e9b12e9197d",
                     "5086cb9b507219ee95db113a917678b2"))

  # One segment covering everything is plain CBC.
  expect_identical(archive_segments(pt, key, iv, 32L, encrypt = TRUE), ct)
  expect_identical(archive_segments(ct, key, iv, 32L), pt)

  # 16-byte segments restart from the IV, so each block is the first block
  # of an independent CBC stream: both equal F.2.1's first block.
  twice <- c(pt[1:16], pt[1:16])
  expect_identical(archive_segments(twice, key, iv, 16L, encrypt = TRUE),
                   c(ct[1:16], ct[1:16]))
})

test_that("the derivation loop reproduces msoffcrypto-tool", {
  # The same vector tools/zucrypttest checks through the registered table,
  # written into both fixtures by tools/make-derivation-kat.py.
  kat <- utils::read.delim(test_path("fixtures", "derivation.tsv"),
                           colClasses = "character")
  expect_gt(nrow(kat), 0L)
  for (i in seq_len(nrow(kat))) {
    got <- archive_derive(unhex(kat$seed[i]), as.integer(kat$spin_count[i]),
                          kat$algorithm[i])
    expect_identical(tohex(got), kat$output[i], info = kat$id[i])
  }
})

test_that("zucrypt's namespace is never loaded by using the archive", {
  # The claim the whole shape rests on: no run-time dependency. Everything
  # above ran without zucrypt; if it had pulled the namespace in, this is
  # where it would show. tools/check-linking.sh goes further and runs these
  # tests with zucrypt removed from the library path entirely.
  expect_false("zucrypt" %in% loadedNamespaces())
})

test_that("the archive draws random bytes from its own source", {
  # Added after ABI 1 (zucrypt#9). Randomness has no vector; the checks are
  # the length and that two draws differ.
  a <- archive_random(32)
  b <- archive_random(32)
  expect_length(a, 32L)
  expect_false(identical(a, b))
  expect_identical(archive_random(0), raw(0))
})

test_that("the archive's AES-GCM reproduces the specification and refuses tampering", {
  # Added after ABI 1 (Stage 14a). GCM specification test case 3.
  hex <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2),
                                             seq(2, nchar(x), 2)), 16L))
  key <- hex("feffe9928665731c6d6a8f9467308308")
  iv <- hex("cafebabefacedbaddecaf888")
  pt <- hex(paste0("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d",
                   "8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657",
                   "ba637b391aafd255"))
  out <- archive_gcm_encrypt(key, iv, pt)
  expect_identical(out[[1]][1:4], hex("42831ec2"))
  expect_identical(out[[2]], hex("4d5c2af327cd64a62cf35abd2ba6fab4"))
  expect_identical(archive_gcm_decrypt_status(key, iv, out[[1]], out[[2]]),
                   "ZUC_OK")
  tag <- out[[2]]
  tag[1] <- xor(tag[1], as.raw(1))
  expect_identical(archive_gcm_decrypt_status(key, iv, out[[1]], tag),
                   "ZUC_ERR_AUTH")
})

test_that("the archive's PBKDF2 reproduces RFC 6070", {
  expect_identical(
    archive_pbkdf2(charToRaw("password"), charToRaw("salt"), 1, 20),
    as.raw(c(0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
             0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6))
  )
})

test_that("the archive reads an RSA key, signs and verifies (RFC 7515 A.2)", {
  # Added after ABI 1 (Stage 15a). The RFC's key is committed beside this
  # test as PEM, because this fixture must run without zucrypt installed.
  pem <- readBin(test_path("rfc7515-a2.pem"), "raw",
                 file.size(test_path("rfc7515-a2.pem")))
  # SHA-256 of the RFC's JWS Signing Input.
  digest <- as.raw(c(
    0xc8, 0x8a, 0x34, 0x84, 0x7b, 0x4f, 0xfb, 0x12, 0xa9, 0x32, 0x6e, 0x54,
    0x0f, 0x14, 0x4b, 0x3d, 0xcc, 0x4d, 0x55, 0x15, 0xf1, 0x87, 0x01, 0xe7,
    0xd6, 0xe0, 0xee, 0x78, 0x66, 0xc9, 0xc7, 0x05
  ))
  sig <- archive_rsa_sign(pem, digest)
  # PKCS#1 v1.5 is deterministic: the RFC's signature begins 112, 46, 33,
  # 137 and is 256 bytes.
  expect_length(sig, 256L)
  expect_identical(sig[1:4], as.raw(c(112, 46, 33, 137)))
})

test_that("the archive's X25519 reproduces RFC 7748 section 6.1", {
  # Added after ABI 1 (Stage 16a).
  hex <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2),
                                             seq(2, nchar(x), 2)), 16L))
  a <- hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  B <- hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  expect_identical(
    archive_x25519(a, B),
    hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
  )
})
