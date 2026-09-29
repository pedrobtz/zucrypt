# Using zucrypt from C

zucrypt’s digests, HMAC, AES-CBC, constant-time comparison and secure
erasure are available to other packages’ compiled code, with no R round
trip. This page is for a package author deciding whether to depend on it
that way, and how. The reference is
[`?zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)
and the two headers; this page is the decision and the wiring.

Neither the `openssl` nor the `sodium` R package publishes a C interface
for other packages. A package that needs SHA-256 or AES in its own C
code has otherwise had to vendor a library itself or require system
libssl.

## Two shapes, one question

zucrypt publishes the same functions twice, because R packages consume
each other in two ways. Which one fits is decided by a single question:
**can your package carry `Imports: zucrypt`?**

|  | Static archive | Registered table |
|----|----|----|
| For a package that | cannot, or will not, carry `Imports:` | can carry `Imports:` |
| `DESCRIPTION` | `LinkingTo: zucrypt` | `Imports: zucrypt` and `LinkingTo: zucrypt` |
| Header | `<zucrypt.h>` | `<zucrypt-r.h>` (includes `zucrypt.h`) |
| Code comes from | `libzucrypt.a`, linked into *your* shared object at install | zucrypt’s own `zucrypt.so`, at run time |
| zucrypt needed at run time | no | yes |
| Backend lifetime | yours: `zuc_init()` / `zuc_shutdown()` | zucrypt’s |
| Security fixes arrive | when *your* package is reinstalled | when zucrypt is updated |
| Stability | **frozen, ABI 1** | *experimental* |

The static archive is the primary shape. `zuxlsx`, which decrypts
password-protected Excel workbooks, uses it: the ABI was frozen after
zuxlsx’s decryption code was written against it and passed on Linux,
macOS and Windows. The table works, and a fixture calls every entry on
every push, but no package uses it yet, so it may still change.

## The static archive

### `DESCRIPTION`

    LinkingTo: zucrypt

`LinkingTo` puts `zucrypt.h` on your include path. It does not link
anything: R has no mechanism for one package to link another’s object
code. That part is `configure`’s.

### `configure` and `configure.win`

The archive is installed to `lib` plus R’s sub-architecture inside
zucrypt’s installation, which is `lib/x64/` on Windows and `lib/`
elsewhere. Ask for the arch-specific directory first and fall back to
the plain one:

``` sh
#!/bin/sh
set -eu
: "${R_HOME:?configure must be run by R CMD INSTALL, which sets R_HOME}"
RSCRIPT="${R_HOME}/bin/Rscript"

lib_dir() {
  "${RSCRIPT}" --vanilla -e "arch <- .Platform\$r_arch; d <- if (nzchar(arch)) system.file('lib', arch, package = '$1') else ''; if (!nzchar(d)) d <- system.file('lib', package = '$1'); cat(d)"
}

ZUCRYPT_LIB=$(lib_dir zucrypt)
if [ -z "${ZUCRYPT_LIB}" ] || [ ! -f "${ZUCRYPT_LIB}/libzucrypt.a" ]; then
  echo "configure: zucrypt's libzucrypt.a was not found; install zucrypt." >&2
  exit 1
fi

sed -e "s|@ZUCRYPT_LIB@|${ZUCRYPT_LIB}|g" src/Makevars.in > src/Makevars
```

`configure.win` is the same script writing `src/Makevars.win`. Check for
the file, not for a version: an older zucrypt that predates the archive
has no way to say so.

### `src/Makevars.in`

``` make
PKG_CFLAGS = $(C_VISIBILITY)
PKG_LIBS = '@ZUCRYPT_LIB@/libzucrypt.a'
```

The single quotes matter. The path comes from
[`system.file()`](https://rdrr.io/r/base/system.file.html), so it sits
under an R library, and on Windows that library is usually under a
profile directory with a space in its name. Unquoted, the linker
receives two arguments, neither of which exists. `$(C_VISIBILITY)` keeps
your own symbols out of your shared object’s export table; the archive’s
are hidden already.

Add `src/Makevars` and `src/Makevars.win` to `.gitignore`: they are
generated on every install.

### Owning the backend’s lifetime

With the archive, the backend is compiled into your package, so you
start it and stop it:

``` c
#include <R.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>
#include <zucrypt.h>

static zuc_status init_status = ZUC_ERR_NOT_READY;

void attribute_visible R_init_mypkg(DllInfo *dll)
{
    /* register your routines here */
    init_status = zuc_init();          /* remembered, never raised */
}

void attribute_visible R_unload_mypkg(DllInfo *dll)
{
    if (init_status == ZUC_OK) {
        zuc_shutdown();
        init_status = ZUC_ERR_NOT_READY;
    }
}
```

`R_init_` must not raise an R error, so a failed `zuc_init()` is
recorded and reported by the entry point that needs the backend.

R calls `R_unload_mypkg()` only when the DLL is unloaded, and with
`useDynLib` in `NAMESPACE` that happens only if your namespace asks for
it. Without the following, `zuc_shutdown()` never runs:

``` r

.onUnload <- function(libpath) {
  library.dynam.unload("mypkg", libpath)
}
```

### Calling it

`zucrypt.h` compiles as C99 against `<stddef.h>` and `<stdint.h>` alone;
it names no backend type, so you never have to reproduce zucrypt’s build
configuration. Every function returns a `zuc_status`; turn it into a
message with `zuc_status_name()` and never compare it with a number you
wrote down.

A one-shot digest:

``` c
uint8_t out[ZUC_MAX_DIGEST_SIZE];
size_t len = 0;
zuc_status st = zuc_hash_compute(ZUC_ALG_SHA256, data, data_len,
                                 out, sizeof out, &len);
```

An incremental one, reused across many inputs, which is how an iterated
key derivation should be written. This is the loop from zucrypt’s own
archive fixture, which checks it against an independent implementation:

``` c
zuc_hash *h = NULL;
uint8_t digest[ZUC_MAX_DIGEST_SIZE], counter[4];
size_t size = zuc_alg_size(alg), n = 0;

zuc_status st = zuc_hash_new(alg, &h);
if (st == ZUC_OK) st = zuc_hash_update(h, seed, seed_len);
if (st == ZUC_OK) st = zuc_hash_finish(h, digest, sizeof digest, &n);
for (int i = 0; i < spins && st == ZUC_OK; i++) {
    counter[0] = (uint8_t) i;          /* little-endian, by construction */
    counter[1] = (uint8_t) (i >> 8);
    counter[2] = (uint8_t) (i >> 16);
    counter[3] = (uint8_t) (i >> 24);
    st = zuc_hash_reset(h);
    if (st == ZUC_OK) st = zuc_hash_update(h, counter, sizeof counter);
    if (st == ZUC_OK) st = zuc_hash_update(h, digest, size);
    if (st == ZUC_OK) st = zuc_hash_finish(h, digest, sizeof digest, &n);
}
zuc_hash_free(h);
zuc_secure_zero(digest, sizeof digest);   /* key material */
```

AES-CBC keeps its chaining state in the handle, so a format that
restarts the chain at segment boundaries sets it per segment:

``` c
zuc_aes *aes = NULL;
zuc_status st = zuc_aes_new(key, key_len, &aes);   /* 16, 24 or 32 bytes */
for (size_t off = 0; off < total && st == ZUC_OK; off += seg) {
    st = zuc_aes_cbc_set_state(aes, segment_iv(off));  /* 16 bytes */
    if (st == ZUC_OK) st = zuc_aes_cbc_decrypt(aes, in + off, seg_len(off),
                                               out + off);
}
zuc_aes_free(aes);
```

CBC adds and strips no padding and authenticates nothing. Verify a MAC
with `zuc_equal()`, in constant time, before you decrypt.

### Rules worth knowing

- **Allocate your R result first.** A handle is plain C memory. If an R
  error or an interrupt check can longjmp while a handle is live, the
  handle leaks, and it holds key material. Either allocate every `SEXP`
  you need before creating handles and make no R calls until they are
  freed, or own each handle with an external pointer and a finalizer.
- **Buffers:** a pointer may be `NULL` exactly when its length is 0.
- **Threads:** main thread only, in this version.
- **Handles are bounded only by memory.** Each AES and HMAC handle holds
  one key in a key store that grows on demand.
- **Report what you linked.** Call `zuc_get_info()` at run time for the
  backend and its version; a macro says what you compiled against, not
  what is in your shared object.

## The registered table

### `DESCRIPTION` and `NAMESPACE`

    Imports: zucrypt
    LinkingTo: zucrypt

and in `NAMESPACE`, a real import directive:

    importFrom(zucrypt, crypt_info)

The import is not decoration. *Writing R Extensions* documents C
callables as available once the providing package’s namespace is loaded,
and `Imports:` alone does not promise to load it. Import something, even
if your R code never calls it.

### Calling it

``` c
#include <string.h>
#include <zucrypt-r.h>

SEXP mypkg_sha256(SEXP x)
{
    const zucrypt_api_v1 *api = zucrypt_api();   /* resolved once, cached */
    uint8_t out[ZUC_MAX_DIGEST_SIZE];
    size_t len = 0;
    zuc_status st;

    if (api == NULL) {
        Rf_error("mypkg: zucrypt does not implement ABI %d", ZUCRYPT_ABI_VERSION);
    }
    st = api->hash_compute(ZUC_ALG_SHA256, RAW(x), (size_t) XLENGTH(x),
                           out, sizeof out, &len);
    if (st != ZUC_OK) {
        Rf_error("mypkg: %s", api->status_name(st));
    }
    SEXP res = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t) len));
    memcpy(RAW(res), out, len);
    UNPROTECT(1);
    return res;
}
```

`zucrypt_api()` resolves lazily, on first use, not in your `R_init_`, so
the order in which R loads the two DLLs does not matter. It returns
`NULL` only for an ABI version zucrypt does not implement. If zucrypt is
not installed at all, `R_GetCCallable()` raises an R error instead,
which longjmps. So resolve the table before you acquire anything a
longjmp would strand.

A field appended to the table in a later release is tested before use:

``` c
if (ZUCRYPT_API_HAS(api, secure_zero)) api->secure_zero(buf, n);
```

zucrypt owns the backend’s lifetime in this shape: do not call
`zuc_init()` or `zuc_shutdown()`.

## What is promised

The static archive is **frozen as ABI 1** from zucrypt 0.1.0. Within
major version 1:

- functions may be added; nothing is removed, renamed, or given a
  different signature or meaning;
- fields may be appended to a struct that carries a `struct_size`, and a
  `ZUC_*_REQUIRED_SIZE` never grows, so a package built against an older
  header keeps working without being rebuilt;
- enumerator values are permanent. An algorithm compiled out of a build
  keeps its number and reports itself unavailable. `zuc_alg` values are
  grouped in reserved ranges (digests, other MACs, ciphers, key
  derivation, key families, signatures), so later families never
  renumber;
- a layout change to a type `struct_size` cannot see renames the
  registered callable instead, so an old consumer fails at
  `R_GetCCallable()` rather than reading a structure that has moved.

Not promised: the numeric value of a backend error behind
`ZUC_ERR_BACKEND`, the contents of an opaque handle, and thread safety
beyond the main thread. The table’s shape may change until a package
other than a fixture uses it; every change is recorded in `NEWS.md`.

## Security updates

With the table, updating zucrypt updates the code your package calls.

With the archive, it does not. The backend was compiled into your shared
object when your package was installed, and it stays there until your
package is reinstalled or rebuilt. When zucrypt ships a security fix,
release your package too, so that CRAN rebuilds it, and say in your
documentation that you link zucrypt statically. [The vendored
backend](https://pedrobtz.github.io/zucrypt/articles/backend.md) covers
how zucrypt tracks upstream.

## Working examples

Both shapes have a complete consumer package in zucrypt’s repository,
built and tested on Linux, macOS and Windows on every push:

- [`tools/zucryptlink`](https://github.com/pedrobtz/zucrypt/tree/main/tools/zucryptlink):
  the static archive. Its `configure`, `Makevars.in`,
  `R_init_`/`R_unload_` and `.onUnload()` are the ones quoted above.
  `tools/check-linking.sh` installs it into a library path containing a
  space, checks that no backend symbol is exported, runs it beside
  `zucrypt.so` in both load orders, runs it with zucrypt uninstalled,
  and unloads and reloads it.
- [`tools/zucrypttest`](https://github.com/pedrobtz/zucrypt/tree/main/tools/zucrypttest):
  the table. It calls every entry, because a function pointer that was
  never assigned looks like a working one until something calls it.
