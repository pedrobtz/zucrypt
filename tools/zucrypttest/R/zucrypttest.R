# Thin R wrappers over the fixture's C code. All the interesting work is in
# src/probe.c, which is the part that has to compile and link against
# zucrypt's headers.

api_available <- function() .Call(zucrypttest_api_available)

abi_rejects_wrong_version <- function(version) {
  .Call(zucrypttest_abi_reject, as.integer(version))
}

# Returns a character vector of failures. Empty means every table entry
# behaved. A vector, not a stop(), so one run reports everything wrong at
# once instead of the first thing.
exercise_table <- function() .Call(zucrypttest_exercise)

# The Office-style iterative key derivation: H_0 = hash(seed),
# H_n = hash(int32le(n - 1) || H_{n-1}). One reused incremental context.
derive_key <- function(seed, spins, algorithm = "sha512") {
  stopifnot(is.raw(seed), is.numeric(spins), spins >= 0)
  .Call(zucrypttest_derive, seed, as.integer(spins), algorithm)
}

# CBC where the chaining state is reset to `iv` at every segment boundary,
# which is what the Agile profiles specify.
decrypt_segments <- function(data, key, iv, segment, encrypt = FALSE) {
  stopifnot(is.raw(data), is.raw(key), is.raw(iv))
  .Call(zucrypttest_segments, data, key, iv, as.integer(segment),
        isTRUE(encrypt))
}

linked_backend <- function() .Call(zucrypttest_backend)
