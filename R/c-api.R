#' Using zucrypt from C
#'
#' @description
#' zucrypt publishes its primitives to other packages twice, because the
#' `zu*` family consumes siblings in two different ways. Both deliver the
#' same library; they differ in what the consumer has to carry, and in how
#' stable they are: the static archive is the primary shape, and the
#' registered table is experimental. See the Stability section.
#'
#' @section Shape one, the registered function table (experimental):
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
#'     /* zucrypt does not implement the ABI version this was built against */
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
#' **`NULL` means a version mismatch, and nothing else.** When zucrypt is not
#' installed or not loaded, `R_GetCCallable()` does not return `NULL`: it
#' raises an R error, which longjmps out of your C code. Resolve the table
#' before you acquire anything such a jump would strand.
#'
#' A table field added after the one you built against may be missing from
#' an older zucrypt: test with `ZUCRYPT_API_HAS(api, field)` before calling
#' it.
#'
#' @section Shape two, the static archive (primary):
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
#' The archive is installed to `lib/` plus the R sub-architecture -- plain
#' `lib/` on Linux and macOS, `lib/x64/` on Windows -- which is why the lookup
#' above tries the sub-architecture first. The licence of the backend
#' compiled into it is installed as `licenses/tf-psa-crypto-LICENSE`; a
#' binary of your package redistributes that code, so ship the notice too.
#'
#' This shape owns the backend's lifetime: call `zuc_init()` before anything
#' else and `zuc_shutdown()` when finished. It is reference counted, so
#' nesting is safe. A call outside that window returns `ZUC_ERR_NOT_READY`.
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
#' * Each AES and HMAC handle holds one key in a key store that grows on
#'   demand, so the number of live handles is bounded only by memory.
#' * Main thread only, in this version.
#'
#' @section Stability:
#' The three surfaces are at different stages:
#'
#' * **The six `crypt_*()` R functions** are stable.
#' * **The static archive** -- `zucrypt.h`, `libzucrypt.a` and where it is
#'   installed -- is *provisional* in 0.1.0 and becomes frozen ABI 1 in
#'   0.2.0, once its first consumer (`zuxlsx`'s decryption of password
#'   protected workbooks) has linked it. Until then a change is possible, and
#'   every one is recorded in `NEWS.md`.
#' * **The registered table** (`zucrypt-r.h`) is *experimental*: no package
#'   uses it yet. It may change in any release until one does, again with
#'   every change recorded in `NEWS.md`.
#'
#' `ZUCRYPT_ABI_VERSION` is `1`. Once frozen, within a major version:
#' functions and table fields may be added; nothing is removed, reordered or
#' given a new meaning; enumerator values are permanent, so an algorithm
#' compiled out of a build keeps its number and reports itself unavailable;
#' and a `ZUC_*_REQUIRED_SIZE` macro never grows, so a consumer built against
#' an older header keeps working without being rebuilt.
#'
#' A layout change to a type that `struct_size` cannot see renames the
#' registered callable instead, so an old consumer fails at
#' `R_GetCCallable()` rather than reading a structure that has moved.
#'
#' Not promised: the numeric value of a backend status behind
#' `ZUC_ERR_BACKEND`, the contents of an opaque handle, and thread safety
#' beyond the main thread.
#'
#' @seealso [crypt_info()], which reports the ABI version, the backend and the
#'   algorithms this build provides.
#'
#' @name zucrypt_c_api
#' @aliases zucrypt-c-api
NULL
