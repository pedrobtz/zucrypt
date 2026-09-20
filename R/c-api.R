#' Using zucrypt from C
#'
#' @description
#' zucrypt publishes its primitives to other packages twice, because the
#' `zu*` family consumes siblings in two different ways. Both deliver the
#' same library; they differ in what the consumer has to carry.
#'
#' @section Shape one, the registered function table:
#' For a package that can carry an `Imports:`. Nothing is linked: R's
#' registered C-callable mechanism hands over a single versioned table of
#' function pointers.
#'
#' ```
#' # DESCRIPTION
#' Imports:   zucrypt
#' LinkingTo: zucrypt
#' ```
#'
#' ```
#' # NAMESPACE -- a real import, not just the Imports: field
#' importFrom(zucrypt, crypt_info)
#' ```
#'
#' ```c
#' #include <zucrypt-r.h>
#'
#' const zucrypt_api_v1 *api = zucrypt_api();
#' if (api == NULL) {
#'     /* zucrypt is missing, or too old for the ABI this was built against */
#' }
#' uint8_t out[ZUC_MAX_DIGEST_SIZE];
#' size_t n;
#' zuc_status st = api->hash_compute(ZUC_ALG_SHA256, data, len,
#'                                   out, sizeof out, &n);
#' ```
#'
#' **`LinkingTo:` alone is not enough, and neither is `Imports:` alone.**
#' `LinkingTo:` supplies the headers and links nothing. `Imports:` without a
#' real `importFrom()` in `NAMESPACE` does not load zucrypt's namespace, and
#' an unloaded namespace has no registered callable to find. `zucrypt_api()`
#' resolves lazily on first use rather than from your `R_init_`, which
#' sidesteps the remaining ordering problem, but the import directive is
#' still required.
#'
#' @section Shape two, the static archive:
#' For a package that cannot carry an `Imports:` -- `zuxlsx` links its
#' siblings statically and has no runtime dependency on them by design.
#'
#' ```
#' # DESCRIPTION
#' LinkingTo: zucrypt
#' ```
#'
#' A `configure` and `configure.win` resolve
#' `system.file("lib", .Platform$r_arch, package = "zucrypt")`, falling back
#' to `system.file("lib", package = "zucrypt")`, and substitute the result
#' into `src/Makevars.in` as a **single-quoted** `PKG_LIBS` entry -- a library
#' path containing a space, which is the norm on Windows, otherwise reaches
#' the linker as two arguments. Then include `<zucrypt.h>` and call the
#' functions directly.
#'
#' This shape owns the backend's lifetime: call `zuc_init()` before anything
#' else and `zuc_shutdown()` when finished. It is reference counted, so
#' nesting is safe.
#'
#' Two consequences worth stating plainly. Your shared object contains its own
#' copy of the backend, kept private by hidden visibility. And upgrading
#' zucrypt does nothing for you until your package is reinstalled -- including
#' a security fix -- so report the version you actually linked, by calling
#' `zuc_get_info()` rather than reading a macro.
#'
#' @section What the interface promises:
#' * Every function returns a `zuc_status`. None raises an R error, allocates
#'   an R object, or calls back into R. No status is negative, so `if (st)`
#'   means "not success".
#' * An object the library allocated is destroyed only by a library function.
#'   No buffer you pass is retained after the call returns.
#' * `inst/include/zucrypt.h` compiles standalone as C99 against `<stddef.h>`
#'   and `<stdint.h>`, and names no backend type. You never have to reproduce
#'   this package's build configuration.
#' * Fields are appended to the table, never removed or reordered. A layout
#'   change to any other type in the header renames the registered callable
#'   instead, so an old consumer fails at `R_GetCCallable()` rather than
#'   reading a structure that has moved.
#' * Main thread only, in this version.
#'
#' @section Stability:
#' `ZUCRYPT_ABI_VERSION` is `r zucrypt::crypt_info()$abi_version` in this
#' build. It is `0` while the interface is still moving; the compatibility
#' promise begins when it reaches `1` at the first release.
#'
#' @seealso [crypt_info()], which reports the ABI version, the backend and the
#'   algorithms this build provides.
#'
#' @name zucrypt_c_api
#' @aliases zucrypt-c-api
NULL
