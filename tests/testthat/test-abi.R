# Symbol isolation. design.md sections 3 and 4: zucrypt vendors a crypto
# library into the same process as other packages that vendor their own, and
# on Linux beside the system libcrypto that zuhttp links. Nothing upstream may
# be exported, or those copies can bind to each other and a call into "our"
# SHA-256 can land in someone else's.
#
# This is invisible to R CMD check, and it is not a property of the source: it
# is a property of $(C_VISIBILITY) in src/Makevars still being applied. That
# is exactly the kind of thing that survives until someone needs one symbol
# exported for a debugging session.

test_that("the shared object exports nothing but R_init_zucrypt", {
  syms <- exported_symbols()
  names <- sub("^.*[[:space:]]", "", syms)
  # Instrumented builds -- coverage.yaml's native: true today, the sanitizer
  # jobs at Stage 5 -- export their own runtime. Those are the toolchain's,
  # not ours, and they cannot collide with another package's vendored crypto.
  names <- drop_instrumentation(names)
  names <- sub("^_", "", names)          # Mach-O's leading underscore
  expect_identical(sort(names), "R_init_zucrypt")
})

test_that("no upstream backend symbol is exported", {
  syms <- exported_symbols()
  for (pattern in c("mbedtls_", "psa_", "PSA_")) {
    expect_length(grep(pattern, syms, fixed = TRUE, value = TRUE), 0L)
  }
})

test_that("no OpenSSL-ABI name is exported", {
  # zuhttp links the system libcrypto on Linux, in the same process. A
  # coincidental name match there is not a build error, it is a call arriving
  # in the wrong implementation.
  syms <- exported_symbols()
  banned <- c("SHA1_Init", "SHA1_Update", "SHA1_Final",
              "SHA256_Init", "SHA256_Update", "SHA256_Final",
              "SHA512_Init", "AES_encrypt", "AES_decrypt",
              "AES_set_encrypt_key", "HMAC", "HMAC_Init_ex")
  for (name in banned) {
    expect_length(grep(paste0("\\b_?", name, "\\b"), syms, value = TRUE), 0L)
  }
  expect_length(grep("\\bEVP_", syms, value = TRUE), 0L)
})

test_that("the backend is compiled in at the pinned version", {
  # Must match version_string in tools/vendor/manifest.tsv. tools/ is not
  # installed, so tools/vendor/verify cross-checks this literal from the
  # other side -- the same arrangement zukomp uses for miniz.
  vendored <- crypt_info()$vendored
  expect_identical(vendored$source, "TF-PSA-Crypto")
  expect_identical(vendored$version, "1.1.1")
})
