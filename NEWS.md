# zucrypt 0.1.0

First release. A narrow set of cryptographic primitives over raw vectors,
backed by a vendored, pinned crypto library, published to R and to C.

## R interface

Six functions, and deliberately no more:

* `crypt_hash()` and `crypt_hmac()` — SHA-1, SHA-256, SHA-384 and SHA-512
  digests and keyed digests. Raw vectors in, raw vectors out; a character
  value is never given a guessed encoding and never treated as a file name.
  Algorithm names match exactly, with no partial matching and no fallback.
* `crypt_equal()` — constant-time comparison. Unequal lengths return `FALSE`
  rather than pretending the length is secret.
* `crypt_aes_cbc_encrypt()` and `crypt_aes_cbc_decrypt()` — AES-128/192/256
  in CBC mode, with no padding and **no authentication**. Interoperability
  tools for formats that specify unauthenticated CBC, not a way to encrypt
  something of your own.
* `crypt_info()` — what this build contains, read from the compiled library.

Failures are R conditions classed
`c(<specific>, "zucrypt_error", "error", "condition")`, mapped from the C
status by enumerator name rather than by number. No message ever contains a
key, an IV or plaintext.

## C interface

Both shapes the `zu*` family consumes siblings by, with the ABI frozen at
`ZUCRYPT_ABI_VERSION 1`:

* A registered function table, `inst/include/zucrypt-r.h`, for a package that
  can carry an `Imports:`. Resolved lazily through `zucrypt_api()`.
* A static archive, `inst/lib/libzucrypt.a`, for a package that cannot —
  `LinkingTo:` only, no runtime dependency, and the consumer owns the
  backend's lifetime through `zuc_init()`/`zuc_shutdown()`.

`inst/include/zucrypt.h` compiles standalone as C99 against `<stddef.h>` and
`<stdint.h>`, and names no backend type: a consumer never has to reproduce
this package's build configuration. Within major version 1, functions and
table fields may be added and nothing is removed, reordered, or given a new
meaning; see `?zucrypt_c_api`.

## Backend

Vendored TF-PSA-Crypto 1.1.1, an LTS release, trimmed to 109 files — the
dependency closure of the 18 sources that carry a symbol under this package's
configuration. Installation needs a C99 compiler and nothing else: no system
cryptographic library, no CMake, no Python or Perl, and no network access.
Hardware acceleration is disabled on every platform, so every platform
produces the same bytes.

Upstream symbols are hidden. The installed shared object exports exactly one
symbol, `R_init_zucrypt`, so an independently vendored copy of the same
library in another package cannot bind to this one, and no OpenSSL-ABI name
is exported beside the `libcrypto` other packages link.

## Supported platforms

Checked on every push: Linux, macOS (ARM64) and Windows; R release, oldrel-1
and 4.1; CRAN's clang-23 and GCC-16 containers; the no-Suggests flavour; LTO;
rchk and gctorture; ASan, UBSan, valgrind and GCC's `-fanalyzer`. Weekly: a
32-bit and a musl build, and a sweep that fails every allocation in turn.

Correctness is checked against published vectors — FIPS 180-2, RFC 2202, RFC
4231 and NIST SP 800-38A — every one of which is also recomputed with OpenSSL,
an implementation sharing no code with the vendored backend.

## Not in this release

Deliberate omissions, each waiting on a concrete consumer rather than on
effort: authenticated encryption, password-based key derivation (PBKDF2,
HKDF, Argon2), random byte generation, signatures, key serialization, file
hashing and connection wrappers. There is no `encrypt_file(password = )`, and
there will not be one without a specified authenticated format, a nonce policy
and a key derivation step.

Office/Excel decryption is not here either. It belongs to
[zuxlsx](https://github.com/pedrobtz/zuxlsx), which consumes this package.
