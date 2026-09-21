# The exact set of names crypt_hash() and crypt_hmac() accept.
#
# Reported by the compiled library rather than written down in R, so it cannot
# disagree with what the build can actually do -- an algorithm configured out
# of the backend disappears from here without anyone editing this file.
#
# Not exported. design.md section 7 fixes the R surface at six functions, and
# this is reachable through crypt_info()$algorithms, which is where a user
# should be looking anyway.
# Cached, like zuc_status_codes() in R/conditions.R: the answer is fixed at
# compile time, and check_algorithm() runs on every crypt_hash() and
# crypt_hmac() call. Uncached this was a native call per call, which is the
# whole per-call cost doubled for a loop that hashes many small inputs --
# which is exactly the shape of the Office derivation this package exists to
# support.
available_algorithms <- local({
  cache <- NULL
  function() {
    if (is.null(cache)) cache <<- .Call(zucrypt_algorithms)
    cache
  }
})

#' Report what this build of zucrypt contains
#'
#' Describes the installed package: its version, the C ABI it publishes, the
#' algorithms it provides, and the vendored cryptographic backend it was
#' compiled against.
#'
#' Everything here is read from the compiled library, never from
#' `tools/vendor/manifest.tsv`. The manifest is maintainer tooling and is not
#' installed, so it could only describe the tree a build was made *from* --
#' which is the one thing a user holding a binary package cannot check.
#'
#' @return A list with elements:
#'   \describe{
#'     \item{`version`}{the `zucrypt` package version, as a `package_version`.}
#'     \item{`abi_version`}{the C ABI version published to `LinkingTo`
#'       consumers, as an integer. `0` while the interface is still moving;
#'       it becomes `1` at the first release.}
#'     \item{`algorithms`}{the digest algorithms this build provides, which
#'       is exactly the set `crypt_hash()` and `crypt_hmac()` accept.}
#'     \item{`vendored`}{a data frame with one row per vendored source, giving
#'       its `source` name and the `version` the compiled library reports.}
#'     \item{`build_flags`}{a named list of compile-time choices worth being
#'       able to see from R: the operating-system random source that was
#'       selected, and whether hardware acceleration is compiled in.}
#'   }
#'
#' @examples
#' info <- crypt_info()
#' info$version
#' info$algorithms
#' info$vendored
#'
#' @export
crypt_info <- function() {
  backend <- .Call(zucrypt_backend_info)

  list(
    version = utils::packageVersion("zucrypt"),
    abi_version = backend[["abi_version"]],
    algorithms = available_algorithms(),
    vendored = data.frame(
      source = backend[["backend_name"]],
      version = backend[["backend_version"]],
      stringsAsFactors = FALSE
    ),
    build_flags = list(
      random_backend = backend[["random_backend"]],
      # Off everywhere, deliberately: MBEDTLS_HAVE_ASM, AESNI and AESCE are
      # set only by upstream's default configuration, which
      # src/zuc_crypto_config.h replaces. Every platform runs the same C and
      # produces the same bytes. See .agents/stage-1-spike.md.
      hardware_acceleration = FALSE
    )
  )
}
