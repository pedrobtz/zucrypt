# The LinkingTo surface, audited on the installed package.
#
# This is the shape zuxlsx consumes: LinkingTo only, no Imports, a configure
# script resolving system.file("lib") and linking inst/lib/libzucrypt.a. None
# of it is visible to R CMD check, and all of it breaks silently -- an archive
# that quietly stopped being installed looks exactly like one that installs
# fine until a consumer tries to link it.

test_that("the archive and the header are installed side by side", {
  skip_if_not_installed_layout()

  expect_true(file.exists(archive_path()))
  expect_gt(file.size(archive_path()), 0)

  # R's own "inst" step copies inst/include/ into the installed package,
  # merging with whatever src/install.libs.R already put there rather than
  # replacing it. If that ever stops being true, the header vanishes and a
  # consumer fails at compile time with no explanation.
  expect_true(file.exists(system.file("include", "zucrypt.h",
                                      package = "zucrypt")))
})

test_that("the archive defines every public entry point", {
  entry_points <- c(
    "zuc_init", "zuc_shutdown", "zuc_get_info",
    "zuc_status_string", "zuc_status_name",
    "zuc_alg_name", "zuc_alg_by_name", "zuc_alg_available", "zuc_alg_size",
    "zuc_hash_compute", "zuc_hash_new", "zuc_hash_update", "zuc_hash_finish",
    "zuc_hash_reset", "zuc_hash_free",
    "zuc_hmac_compute", "zuc_hmac_new", "zuc_hmac_update", "zuc_hmac_finish",
    "zuc_hmac_reset", "zuc_hmac_free",
    "zuc_aes_new", "zuc_aes_free",
    "zuc_aes_cbc_set_state", "zuc_aes_cbc_get_state",
    "zuc_aes_cbc_encrypt", "zuc_aes_cbc_decrypt",
    "zuc_aes_ecb_encrypt", "zuc_aes_ecb_decrypt",
    "zuc_equal", "zuc_secure_zero"
  )
  defined <- archive_defined()

  for (name in entry_points) {
    expect_length(grep(paste0("\\b_?", name, "$"), defined, value = TRUE), 1L)
  }
})

test_that("the archive contains no R glue", {
  # The archive is linked into a consumer's own shared object. An R symbol in
  # here is a duplicate at best, and at worst a second R_init_ that R would
  # call for the wrong package.
  defined <- archive_defined()
  for (pattern in c("R_init_", "zucrypt_", "Rf_", "R_registerRoutines")) {
    expect_length(grep(pattern, defined, value = TRUE), 0L)
  }
})

test_that("no upstream header is installed beside ours", {
  skip_if_not_installed_layout()

  # The deliberate departure from zukomp and zuxml, which install miniz.h and
  # expat.h. PSA's headers are generated against a specific configuration, so
  # a consumer seeing them would have to reproduce our build to be describing
  # the same library. It sees zucrypt.h and nothing else.
  installed <- list.files(system.file("include", package = "zucrypt"),
                          recursive = TRUE)
  expect_identical(sort(installed), c("zucrypt-r.h", "zucrypt.h"))
})

test_that("zucrypt-r.h is the only header that knows about R", {
  # The split is the contract: an archive consumer includes zucrypt.h and
  # links no R at all, and a table consumer includes zucrypt-r.h, which adds
  # the one thing that unavoidably knows about R -- how to reach the table.
  r_header <- installed_header_code("zucrypt-r.h")
  expect_gt(length(grep("R_GetCCallable", r_header, fixed = TRUE)), 0L)
  expect_gt(length(grep("zucrypt.h", installed_header("zucrypt-r.h"),
                        fixed = TRUE)), 0L)

  # And it defines the accessor as `static inline`, not plain `static`: a
  # header-defined plain static is an unused-function error in every consumer
  # translation unit that includes the header without calling it, which is a
  # build failure in their tree and warning-free in ours.
  expect_length(grep("^static inline const zucrypt_api_v1 \\*zucrypt_api",
                     r_header), 1L)
  expect_length(grep("^static const zucrypt_api_v1", r_header), 0L)
})

test_that("the registered callable is named as the header expects", {
  # zucrypt-r.h resolves this literal. If the provider ever registers a
  # different name -- which is the documented way to version a layout change
  # in a non-table type -- the header has to change with it, and this fails
  # until it does.
  r_header <- installed_header_code("zucrypt-r.h")
  expect_length(grep('"zucrypt_get_api"', r_header, fixed = TRUE), 1L)
})

test_that("the public header leaks no backend vocabulary", {
  header <- installed_header_code()
  for (pattern in c("mbedtls", "psa_", "PSA_", "MBEDTLS_", "tf-psa", "TF_PSA")) {
    expect_length(grep(pattern, header, fixed = TRUE, value = TRUE), 0L)
  }
})

test_that("the public header leaks no R vocabulary", {
  # zucrypt.h only. zucrypt-r.h is R-specific by design and is exempt --
  # which is why the two are separate files rather than one with an #ifdef.
  header <- installed_header_code()
  for (pattern in c("R.h", "Rinternals.h", "SEXP", "Rf_", "R_xlen_t")) {
    expect_length(grep(pattern, header, fixed = TRUE, value = TRUE), 0L)
  }
})

test_that("the public header carries its guard, C++ wrapper and ABI version", {
  header <- installed_header()
  expect_length(grep("^#ifndef ZUCRYPT_H$", header), 1L)
  expect_length(grep('^extern "C" \\{$', header), 1L)
  expect_length(grep("define ZUCRYPT_ABI_VERSION", header), 1L)
  # Only these two system headers, per design section 3.
  includes <- grep("^#include", header, value = TRUE)
  expect_setequal(includes, c("#include <stddef.h>", "#include <stdint.h>"))
})
