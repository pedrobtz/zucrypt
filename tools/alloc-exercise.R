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
## Every result is checked against fixed bytes (#115). A run that survives
## a failed allocation must have produced the right answer, not just an
## answer: a truncated digest or a ciphertext under the wrong key would pass
## a crash test and be worse than crashing. The answers are in
## tools/alloc-expected.tsv, computed by openssl and Python's hashlib
## (tools/alloc-expected.R); a round trip alone would miss a fault shared by
## encryption and decryption. An operation that fails prints its condition's
## class and message and exits 1, which expect-pattern must match; a wrong
## result exits 3 and matches nothing, so the sweep reports it as silent.
## Every namespace the workload touches is loaded in the prefix, and the run
## exits 4 if the window loaded another, since a failure there would be in
## loading code, not in zucrypt.

baseline <- identical(commandArgs(trailingOnly = TRUE), "--baseline")

## --- prefix: run by the baseline too, so it sits under the floor ----------

suppressMessages(library(zucrypt))
source(file.path("tools", "alloc-inputs.R"))
inp <- alloc_inputs()
unhex <- inp$unhex
data <- inp$data
key <- inp$key
iv <- inp$iv
algorithms <- crypt_info()$algorithms

want_rows <- utils::read.delim(file.path("tools", "alloc-expected.tsv"),
                               colClasses = "character")
want <- stats::setNames(lapply(want_rows$hex, unhex), want_rows$name)

## The EC keys are built here, in the prefix, so that the sweep's window
## holds only the operations below. Measured on macOS, 2026-11-03: building
## a P-256 key from its coordinates is about 7,600 allocations, deterministic
## signing 7,500, verification 36,000, P-256 ECDH 21,000 and X25519 3,200 --
## the backend's bignum code allocates as it goes. The window keeps signing
## and X25519, which between them pass through every EC path of the adapter
## (key import, sign, agree, the allocation watch); verification and P-256
## ECDH would multiply the sweep's length by five for the same adapter code.
p256 <- with(inp$ec_p256, crypt_ec_key(curve, x, y, d))
alice <- crypt_read_x25519_key(inp$x25519_alice)
bob <- crypt_read_x25519_pubkey(inp$x25519_bob)

## One failure-free pass of the helpers, so nothing the window calls is
## loaded or compiled for the first time inside it.
check <- function(what, got, expected) {
  if (!identical(got, expected)) {
    cat(what, ": WRONG RESULT, ", length(got), " bytes\n", sep = "")
    quit(status = 3, save = "no")
  }
}
## Both arguments are forced inside the handler: `expected` is lazy, and an
## expected value computed by a crypt_* call (crypt_write_der(rsa) below)
## would otherwise fail outside it, printing R's bare "Error in" rather than
## the class. The first sweep (2026-11-10) reported two such correct
## ZUC_ERR_MEMORY refusals as silent for exactly that reason.
run <- function(what, expr, expected = NULL) {
  got <- tryCatch(list(expr, expected), error = function(e) e)
  if (inherits(got, "error")) {
    cat(what, ": ", class(got)[1], ": ", conditionMessage(got), "\n", sep = "")
    quit(status = 1, save = "no")
  }
  if (!is.null(got[[2]])) check(what, got[[1]], got[[2]])
  invisible(got[[1]])
}
run("prefix", crypt_hash(raw(1)), crypt_hash(raw(1)))
namespaces <- sort(loadedNamespaces())

if (baseline) quit(save = "no")

## --- workload: what the sweep fails allocations in -------------------------

## Each of these allocates a native context and frees it, which is the
## lifecycle the sweep is aimed at. Every digest, because each one takes a
## different branch through the backend's setup.
for (a in algorithms) {
  run(paste("hash", a), crypt_hash(data, a), want[[paste0("hash_", a)]])
  run(paste("hmac", a), crypt_hmac(data, key, a), want[[paste0("hmac_", a)]])
}

## One key per AES context now (#30), in a key store that allocates as it
## grows -- so a failure can land in the context, in the store, or in the
## backend's cipher setup, and each has to come back as ZUC_ERR_MEMORY.
ct <- run("aes-cbc encrypt", crypt_aes_cbc_encrypt_nopad(data, key, iv),
          want$aes_cbc)
run("aes-cbc decrypt", crypt_aes_cbc_decrypt_nopad(want$aes_cbc, key, iv),
    data)
run("equal", crypt_equal(want$aes_cbc, ct), TRUE)

## AES-GCM and PBKDF2 (Stage 14a). Neither keeps a handle, but each imports a
## volatile key or builds a derivation in the backend per call, so a failure
## can land in the key store, the AEAD setup or the derivation's HMAC, and
## must come back as ZUC_ERR_MEMORY, never as a wrong ciphertext or key.
sealed <- run("aes-gcm encrypt",
              crypt_aes_gcm_encrypt(data, key, inp$nonce, aad = iv))
check("aes-gcm ciphertext", as.vector(sealed), want$aes_gcm_ciphertext)
check("aes-gcm tag", attr(sealed, "tag"), want$aes_gcm_tag)
run("aes-gcm decrypt", crypt_aes_gcm_decrypt(sealed, key, aad = iv), data)
run("pbkdf2", crypt_pbkdf2(key, iv, iterations = 2, length = 40),
    want$pbkdf2_sha256)

## RSA (Stage 15a): building, encoding and reading a key, both signature
## schemes and OAEP. Every bignum the backend allocates is in the window.
rsa <- run("rsa key", do.call(crypt_rsa_key, unname(inp$rsa_parts)))
pem <- run("rsa pem", crypt_write_pem(rsa))
check("rsa pem", charToRaw(pem), want$rsa_pem)
run("rsa read", crypt_write_der(crypt_read_key(pem)), crypt_write_der(rsa))
run("rsa pkcs1 sign", crypt_signature_create(data, crypt_sha256, rsa),
    want$rsa_pkcs1v15_sha256)
run("rsa pkcs1 verify",
    crypt_signature_verify(data, want$rsa_pkcs1v15_sha256, crypt_sha256, rsa),
    TRUE)
pss <- run("rsa pss sign",
           crypt_signature_create(data, crypt_sha256, rsa, pss = TRUE))
run("rsa pss verify",
    crypt_signature_verify(data, pss, crypt_sha256, rsa, pss = TRUE), TRUE)
run("rsa oaep decrypt",
    crypt_rsa_decrypt(want$rsa_oaep_sha1_ciphertext, rsa, oaep = TRUE), key)
sealed_key <- run("rsa oaep encrypt",
                  crypt_rsa_encrypt(key, rsa, oaep = TRUE,
                                    oaep_hash = "sha256"))
run("rsa oaep round trip",
    crypt_rsa_decrypt(sealed_key, rsa, oaep = TRUE, oaep_hash = "sha256"), key)

## EC (Stage 16a): deterministic ECDSA, whose bytes openssl verified when
## they were recorded, and X25519, checked against RFC 7748. See the prefix
## for what is left out of the window, and why.
run("ecdsa sign",
    crypt_signature_create(data, crypt_sha256, p256, deterministic = TRUE),
    want$ecdsa_p256_deterministic)
run("x25519", crypt_x25519_diffie_hellman(alice, bob),
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))

if (!identical(sort(loadedNamespaces()), namespaces)) {
  cat("the workload loaded a namespace:",
      setdiff(loadedNamespaces(), namespaces), "\n")
  quit(status = 4, save = "no")
}
cat("ok\n")
