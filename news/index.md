# Changelog

## zucrypt 0.1.0

First release. A narrow set of cryptographic primitives over raw
vectors, backed by a vendored, pinned crypto library, published to R and
to C.

### R interface

Six functions, and deliberately no more:

- [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
  and
  [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md)
  — SHA-1, SHA-256, SHA-384 and SHA-512 digests and keyed digests. Raw
  vectors in, raw vectors out; a character value is never given a
  guessed encoding and never treated as a file name. Algorithm names
  match exactly, with no partial matching and no fallback.
- [`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md)
  — constant-time comparison. Unequal lengths return `FALSE` rather than
  pretending the length is secret.
- [`crypt_aes_cbc_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md)
  and
  [`crypt_aes_cbc_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md)
  — AES-128/192/256 in CBC mode, with no padding and **no
  authentication**. Interoperability tools for formats that specify
  unauthenticated CBC, not a way to encrypt something of your own.
- [`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
  — what this build contains, read from the compiled library.

Failures are R conditions classed
`c(<specific>, "zucrypt_error", "error", "condition")`, mapped from the
C status by enumerator name rather than by number. No message ever
contains a key, an IV or plaintext.

### C interface

Both shapes the `zu*` family consumes siblings by, at
`ZUCRYPT_ABI_VERSION 1`, with different stability
([`?zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)):

- A static archive, `libzucrypt.a`, installed to `lib/` plus the R
  sub-architecture (`lib/x64/` on Windows), for a package that cannot
  carry an `Imports:` — `LinkingTo:` only, no runtime dependency, and
  the consumer owns the backend’s lifetime through
  `zuc_init()`/`zuc_shutdown()`. This is the primary shape. It is
  **provisional** in 0.1.0 and is frozen in 0.2.0, once its first
  consumer has linked it.
- A registered function table, `inst/include/zucrypt-r.h`, for a package
  that can carry an `Imports:`. Resolved lazily through `zucrypt_api()`;
  test an appended field with `ZUCRYPT_API_HAS()`. **Experimental**
  until a package uses it.

`inst/include/zucrypt.h` compiles standalone as C99 against `<stddef.h>`
and `<stdint.h>`, and names no backend type: a consumer never has to
reproduce this package’s build configuration.

Settled before any consumer linked the ABI (design revision 3):

- AES-ECB is not provided. Its one use was Office Standard encryption,
  which `zuxlsx` does not implement.
- The backend’s key store grows on demand, so the number of live AES and
  HMAC handles is bounded only by memory. The static store it replaces
  allowed 16 live AES handles per process and reported the 17th as an
  allocation failure.
- `ZUC_ERR_NOT_READY` (9) is returned by a call made before `zuc_init()`
  or after the last `zuc_shutdown()`.
- `zuc_info` gains `hardware_acceleration`, appended after the required
  prefix, and `crypt_info()$build_flags$hardware_acceleration` now reads
  it from the compiled library.
- TF-PSA-Crypto’s licence is installed as
  `licenses/tf-psa-crypto-LICENSE`, since the archive carries its object
  code into every consumer.

### Backend

Vendored TF-PSA-Crypto 1.1.1, an LTS release, trimmed to 109 files — the
dependency closure of the 18 sources that carry a symbol under this
package’s configuration. Installation needs a C99 compiler and nothing
else: no system cryptographic library, no CMake, no Python or Perl, and
no network access. Hardware acceleration is disabled on every platform,
so every platform produces the same bytes.

Upstream symbols are hidden. The installed shared object exports exactly
one symbol, `R_init_zucrypt`, so an independently vendored copy of the
same library in another package cannot bind to this one, and no
OpenSSL-ABI name is exported beside the `libcrypto` other packages link.

### Supported platforms

Checked on every push: Linux, macOS (ARM64) and Windows; R release,
oldrel-1 and 4.1; CRAN’s clang-23 and GCC-16 containers; the no-Suggests
flavour; LTO; rchk and gctorture; ASan, UBSan, valgrind and GCC’s
`-fanalyzer`. Weekly: i386, musl and aarch64 builds that run the test
suite and fail on a WARNING, and a sweep that fails each allocation the
`crypt_*()` calls make, one run per allocation — about 250 of them, of
which some 77 land in zucrypt’s own code — checking that each surfaces
as an error rather than a crash or a wrong answer.

Correctness is checked against published vectors — FIPS 180-2, RFC 2202,
RFC 4231, RFC 6234 and NIST SP 800-38A, including the one-million-byte
messages and HMAC keys longer than the block — every one of which is
also recomputed with OpenSSL, an implementation sharing no code with the
vendored backend. Inputs up to 4 MiB are compared with OpenSSL directly,
and the iterated hash Office agile encryption uses is checked against
msoffcrypto-tool.

### Not in this release

Deliberate omissions, each waiting on a concrete consumer rather than on
effort: authenticated encryption, password-based key derivation (PBKDF2,
HKDF, Argon2), random byte generation, signatures, key serialization,
file hashing and connection wrappers. There is no
`encrypt_file(password = )`, and there will not be one without a
specified authenticated format, a nonce policy and a key derivation
step.

Office/Excel decryption is not here either. It belongs to
[zuxlsx](https://github.com/pedrobtz/zuxlsx), which consumes this
package.
