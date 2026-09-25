# The R side of the error model (design.md section 3 and section 11). C
# returns status codes and never calls Rf_error() below the outermost .Call;
# R turns a status into a condition.
#
# The *class* is the contract. Messages are one line and may be reworded;
# anything a caller branches on is a class or a field of the condition
# object. And no message ever contains a key, a password, an IV or any
# plaintext -- an R error goes to the console, into logs, and into bug
# reports, and this package's arguments are exactly the values that must not
# arrive there.

zucrypt_abort <- function(class,
                          message,
                          algorithm = NA_character_,
                          native_status = NA_integer_,
                          call = sys.call(-1L)) {
  cond <- structure(
    class = c(class, "zucrypt_error", "error", "condition"),
    list(
      message = message,
      call = call,
      algorithm = algorithm,
      native_status = native_status
    )
  )
  stop(cond)
}

# zuc_status values by C enumerator name. Fetched from C rather than written
# as literals here, so that renumbering the enum cannot silently remap a
# condition class -- nothing would fail, and a caller would start catching the
# wrong one. Cached because the answer is a compile-time constant.
zuc_status_codes <- local({
  cache <- NULL
  function() {
    if (is.null(cache)) cache <<- .Call(zucrypt_status_codes)
    cache
  }
})

# The status-to-class map, keyed by enumerator name for the same reason.
# ZUC_OK is deliberately absent: success must never reach zucrypt_abort().
zuc_status_class <- c(
  ZUC_ERR_INVALID_ARGUMENT = "zucrypt_invalid_argument",
  ZUC_ERR_UNSUPPORTED      = "zucrypt_unsupported_algorithm",
  ZUC_ERR_BAD_LENGTH       = "zucrypt_bad_length",
  ZUC_ERR_OVERLAP          = "zucrypt_invalid_argument",
  ZUC_ERR_MEMORY           = "zucrypt_memory_error",
  ZUC_ERR_BACKEND          = "zucrypt_backend_error",
  ZUC_ERR_ABI              = "zucrypt_abi_mismatch",
  ZUC_ERR_INTERNAL         = "zucrypt_internal_error",
  # R_init_zucrypt initialises the backend and never releases it, so from R
  # this can only be a bug -- hence internal, not a class of its own.
  ZUC_ERR_NOT_READY        = "zucrypt_internal_error"
)

# Raise the condition a native status maps to. Called only with a failing
# status; a success reaching here is itself an internal error.
abort_native <- function(status, algorithm = NA_character_,
                         call = sys.call(-1L)) {
  codes <- zuc_status_codes()
  name <- names(codes)[match(status, codes)]

  if (is.na(name) || identical(name, "ZUC_OK")) {
    # A status the C layer can return that this map has never heard of. It
    # is still an error, and it still gets a class, because the alternative
    # is an uncatchable stop() in the one place the mapping is broken.
    zucrypt_abort(
      "zucrypt_internal_error",
      sprintf("The native layer returned an unmapped status (%d).", status),
      algorithm = algorithm, native_status = status, call = call
    )
  }

  class <- unname(zuc_status_class[name])
  if (is.na(class)) {
    class <- "zucrypt_internal_error"
  }
  zucrypt_abort(
    class,
    sprintf("The cryptographic backend reported %s.", name),
    algorithm = algorithm, native_status = status, call = call
  )
}

# --- argument validation ----------------------------------------------------
#
# All of it happens in R, before any native call. Two reasons. The messages
# can name the argument, which C cannot do; and a rule enforced in R is a
# rule that is visible in R's own documentation and testable without the
# harness.

check_raw <- function(x, arg, call = sys.call(-1L)) {
  if (!is.raw(x)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      sprintf(paste0("`%s` must be a raw vector, not %s. ",
                     "Use charToRaw() to convert a string deliberately; ",
                     "this package never guesses an encoding, and never ",
                     "treats a string as a file name."),
              arg, class(x)[1]),
      call = call
    )
  }
  invisible(x)
}

check_algorithm <- function(algorithm, call = sys.call(-1L)) {
  if (!is.character(algorithm) || length(algorithm) != 1L ||
      is.na(algorithm)) {
    zucrypt_abort(
      "zucrypt_invalid_argument",
      "`algorithm` must be a single, non-missing algorithm name.",
      call = call
    )
  }
  known <- available_algorithms()
  if (!algorithm %in% known) {
    # Exact match only. No partial matching and no match.arg(), so that
    # "sha" never silently becomes "sha1" and a typo cannot pick a weaker
    # digest than the caller asked for.
    zucrypt_abort(
      "zucrypt_unsupported_algorithm",
      sprintf("Unknown algorithm %s. Available: %s.",
              encodeString(algorithm, quote = '"'),
              paste(known, collapse = ", ")),
      algorithm = algorithm,
      call = call
    )
  }
  invisible(algorithm)
}

check_aes_key <- function(key, call = sys.call(-1L)) {
  check_raw(key, "key", call = call)
  if (!length(key) %in% c(16L, 24L, 32L)) {
    zucrypt_abort(
      "zucrypt_bad_length",
      sprintf(paste0("`key` must be 16, 24 or 32 bytes (AES-128, AES-192 or ",
                     "AES-256), not %d. This function takes a key, never a ",
                     "password: deriving one is the caller's responsibility."),
              length(key)),
      call = call
    )
  }
  invisible(key)
}

check_aes_iv <- function(iv, call = sys.call(-1L)) {
  check_raw(iv, "iv", call = call)
  if (length(iv) != 16L) {
    zucrypt_abort(
      "zucrypt_bad_length",
      sprintf("`iv` must be exactly 16 bytes, not %d.", length(iv)),
      call = call
    )
  }
  invisible(iv)
}

check_block_multiple <- function(data, call = sys.call(-1L)) {
  check_raw(data, "data", call = call)
  if (length(data) %% 16L != 0L) {
    zucrypt_abort(
      "zucrypt_bad_length",
      sprintf(paste0("`data` must be a multiple of 16 bytes, not %d. ",
                     "No padding is added or removed; if your format uses ",
                     "PKCS#7, apply it yourself."),
              length(data)),
      call = call
    )
  }
  invisible(data)
}
