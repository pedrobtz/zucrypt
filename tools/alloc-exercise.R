#!/usr/bin/env Rscript

## Driver for alloc-failure.yml: exercises the paths that allocate, and
## nothing else.
##
## The workflow runs this once per injected allocation failure, so it has to
## be short -- the sweep multiplies its cost -- and it has to be narrow, so a
## failure is attributable. The whole test suite would be neither.
##
## What is being checked is a sentence in design.md section 11 that nothing
## else reaches: "destroy partial contexts after any failed initialization".
## Nothing in an ordinary suite makes malloc fail, so that code is executed
## zero times. ASan and valgrind check what happens to memory that *was*
## allocated; gctorture forces collections rather than failures; rchk reasons
## about PROTECT rather than a NULL return.
##
## expect-pattern in the workflow is what makes this "behaved" rather than
## "did not crash": surviving a failed allocation while returning a truncated
## digest would pass a crash test and be worse than crashing.

suppressMessages(library(zucrypt))

data <- as.raw(rep(seq.int(0L, 255L), length.out = 4096L))
key <- as.raw(rep(0x2b, 32))
iv <- as.raw(seq.int(0L, 15L))

## Each of these allocates a native context and frees it, which is the
## lifecycle the sweep is aimed at. Run for every digest, because each one
## takes a different branch through the backend's setup.
for (algorithm in crypt_info()$algorithms) {
  digest <- crypt_hash(data, algorithm)
  stopifnot(is.raw(digest), length(digest) > 0L)

  tag <- crypt_hmac(data, key, algorithm)
  stopifnot(is.raw(tag), length(tag) == length(digest))
}

## The AES context allocates twice -- one key per cipher mode -- so a failure
## of the second is the case where a partially built context has to be taken
## apart rather than returned.
ciphertext <- crypt_aes_cbc_encrypt(data, key, iv)
stopifnot(identical(crypt_aes_cbc_decrypt(ciphertext, key, iv), data))

stopifnot(crypt_equal(crypt_hash(data), crypt_hash(data)))

cat("ok\n")
