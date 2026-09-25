#!/usr/bin/env Rscript

## Driver for alloc-failure.yaml: exercises the paths that allocate, and
## nothing else.
##
##   R_ENABLE_JIT=0 Rscript tools/alloc-exercise.R --baseline   the prefix only
##   R_ENABLE_JIT=0 Rscript tools/alloc-exercise.R              prefix + workload
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
## Why a prefix, and why the JIT is off. The sweep starts at the "startup
## floor", the allocation count of the baseline command. The first swept run
## of this script (2026-09-25, 3,264 allocations after a plain R startup)
## crashed 61 times, and every one was inside R rather than zucrypt: 52 in
## the byte-code compiler JIT-compiling the loop below, 9 in TRE regex and
## gzfile under utils::packageVersion(), which crypt_info() calls. R does not
## survive every allocation failure in its own internals, and that is not
## what this job is for. So everything before the workload -- attaching the
## package, crypt_info(), building the inputs -- is the prefix, which the
## baseline runs too, putting it under the floor; and R_ENABLE_JIT=0 keeps
## the compiler out of the window. What is left in the window is the crypt_*
## calls themselves: R's argument checks and result vectors, and the adapter.
##
## expect-pattern in the workflow is what makes this "behaved" rather than
## "did not crash": surviving a failed allocation while returning a truncated
## digest would pass a crash test and be worse than crashing.

baseline <- identical(commandArgs(trailingOnly = TRUE), "--baseline")

## --- prefix: run by the baseline too, so it sits under the floor ----------

suppressMessages(library(zucrypt))
algorithms <- crypt_info()$algorithms
data <- as.raw(rep(seq.int(0L, 255L), length.out = 4096L))
key <- as.raw(rep(0x2b, 32))
iv <- as.raw(seq.int(0L, 15L))

if (baseline) quit(save = "no")

## --- workload: what the sweep fails allocations in -------------------------

## Each of these allocates a native context and frees it, which is the
## lifecycle the sweep is aimed at. Every digest, because each one takes a
## different branch through the backend's setup.
for (algorithm in algorithms) {
  digest <- crypt_hash(data, algorithm)
  stopifnot(is.raw(digest), length(digest) > 0L)

  tag <- crypt_hmac(data, key, algorithm)
  stopifnot(is.raw(tag), length(tag) == length(digest))
}

## One key per AES context now (#30), in a key store that allocates as it
## grows -- so a failure can land in the context, in the store, or in the
## backend's cipher setup, and each has to come back as ZUC_ERR_MEMORY.
ciphertext <- crypt_aes_cbc_encrypt(data, key, iv)
stopifnot(identical(crypt_aes_cbc_decrypt(ciphertext, key, iv), data))

stopifnot(crypt_equal(crypt_hash(data), crypt_hash(data)))

cat("ok\n")
