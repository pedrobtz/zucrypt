# Buffers that share memory (#138). zucrypt.h promises, for AEAD and CBC,
# that the output may be the input exactly and that any other overlap is
# ZUC_ERR_OVERLAP, reported before anything is written. For the other
# one-shot functions, which promise nothing, the harness checks the weaker
# property every caller may rely on: with the output moved onto an input,
# the call gives the answer it gives with separate buffers, or refuses with
# ZUC_ERR_OVERLAP and writes nothing.

test_that("every aliasing of a written buffer is refused or harmless", {
  rsa <- crypt_write_der(crypt_read_key(rsa_fixture_key(rsa_vectors()$key[1])))
  failures <- native_alias(rsa)
  expect_gt(attr(failures, "cases"), 60L)
  expect_identical(as.vector(failures), character(0))
})
