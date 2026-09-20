#' Report what this build of zucrypt contains
#'
#' Describes the installed package: its own version, and the vendored
#' cryptographic backend it was compiled against.
#'
#' Everything reported here is read from the compiled library, never from
#' `tools/vendor/manifest.tsv`. The manifest is maintainer tooling and is not
#' installed, so it can only describe the tree a build *was made from* -- which
#' is the one thing a user with a binary package cannot check.
#'
#' @section Stage of development:
#' This is a placeholder. The full `crypt_info()` described in the design
#' returns `abi_version`, the supported `algorithms` and `build_flags` as well,
#' and those arrive with the functions they describe. Nothing in this list will
#' change meaning when they do.
#'
#' @return A list with elements:
#'   \describe{
#'     \item{`version`}{the `zucrypt` package version, as a `package_version`.}
#'     \item{`vendored`}{a data frame with one row per vendored source, giving
#'       its `source` name and the `version` the compiled library reports.}
#'     \item{`random_backend`}{the operating-system random source selected at
#'       compile time. No function in this version of the package consumes
#'       randomness; the backend requires the source to exist at link time.}
#'   }
#'
#' @examples
#' info <- crypt_info()
#' info$version
#' info$vendored
#'
#' @export
crypt_info <- function() {
  backend <- .Call(zucrypt_backend_info)

  list(
    version = utils::packageVersion("zucrypt"),
    vendored = data.frame(
      source = "tf-psa-crypto",
      version = unname(backend[["backend_version"]]),
      stringsAsFactors = FALSE
    ),
    random_backend = unname(backend[["random_backend"]])
  )
}
