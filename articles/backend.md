# The vendored backend

This page is for whoever has to decide whether zucrypt is acceptable in
their environment: a CRAN or security reviewer, or a package author
about to depend on it. It says what cryptographic code is compiled into
the package, where it came from, how to reproduce it, how security fixes
reach you, and what the tests do and do not establish.

The short version: zucrypt compiles a small, pinned part of one upstream
library, [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto),
from source. It uses no system cryptographic library. That removes an
installation requirement, and it hands this package a duty the operating
system would otherwise carry: **code compiled into an R package is not
patched when the system is.**

## What is in the package

The backend is **TF-PSA-Crypto 1.1.1**, the Mbed TLS project’s
cryptography library. The 1.1 line is a long-term support branch,
maintained with Mbed TLS 4.1 LTS until March 2029. No Mbed TLS file is
vendored. In the 4.x architecture TF-PSA-Crypto *is* the cryptography
library; Mbed TLS adds only X.509 and TLS, and this package builds
neither.

It is not the whole library. Of upstream’s 77 buildable C sources,
zucrypt compiles the **20** that contain code under its configuration,
plus the headers those include: 113 files and about 2.7 MB of source,
including upstream’s `LICENSE`. The upstream archive is 55 MB unpacked,
most of it tests.

|                          | Measured on macOS x86-64, R release |
|--------------------------|-------------------------------------|
| Vendored tree            | 113 files, 2.7 MB                   |
| Source tarball           | 532 KB                              |
| Installed `zucrypt.so`   | 266 KB                              |
| Installed `libzucrypt.a` | 606 KB                              |

The tree lives in `src/vendor/tf-psa-crypto/`, flattened to `inc/` and
`lib/`, because upstream’s own paths exceed the 100-byte limit on
tarball paths. Nothing else about the files changes.

## The configuration

Upstream’s configuration header is replaced entirely by
`src/zuc_crypto_config.h`, so what is enabled is exactly what that file
lists:

| Define | Why |
|----|----|
| `PSA_WANT_ALG_SHA_1`, `_SHA_256`, `_SHA_384`, `_SHA_512` | The digests [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md) offers. SHA-1 for compatibility with existing formats, never as a default |
| `PSA_WANT_ALG_HMAC`, `PSA_WANT_KEY_TYPE_HMAC` | [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md) |
| `PSA_WANT_ALG_CBC_NO_PADDING`, `PSA_WANT_KEY_TYPE_AES` | [`crypt_aes_cbc_encrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md) and [`crypt_aes_cbc_decrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md) |
| `MBEDTLS_PSA_CRYPTO_C` | The PSA API everything above goes through |
| `MBEDTLS_PSA_KEY_STORE_DYNAMIC` | A key store that grows with the number of live handles, rather than failing at a fixed slot count |
| `MBEDTLS_AESNI_C`, `MBEDTLS_AESCE_C`, `MBEDTLS_HAVE_ASM` | Hardware AES where the CPU has it (below) |
| `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` | Randomness from the operating system rather than a vendored DRBG and entropy module |

That is the whole list. **Not enabled:** public-key cryptography of any
kind, authenticated encryption, key derivation, other hash functions
(MD5, SHA-224, SHA-3), PKCS#7 padding, X.509, TLS and persistent key
storage. The build asks upstream for exactly these features through its
own configuration mechanism. When the configuration was settled, a probe
confirmed that MD5 and SHA-224 report “not supported” in the backend
rather than working by accident, and the package’s tests confirm that
any algorithm name it does not list is refused.

**Randomness.** No operation in this profile consumes random bytes; CBC
takes its IV from the caller. The backend still links a random-number
entry point, and zucrypt supplies it from the operating system
(`rand_s`, `arc4random_buf`, `getrandom` or `/dev/urandom`, chosen at
compile time), never from R’s random number generator.

**Hardware AES.** AES uses AES-NI on x86 and the Cryptography Extension
on 64-bit Arm where the CPU has them, detected at run time, and falls
back to upstream’s table-based software AES otherwise. Every path
produces the same bytes; the published vectors check that on every
platform CI reaches. Upstream’s security policy says the software path
can leak the key through cache timing to an attacker who can observe it.
zucrypt documents that rather than refusing to run;
[`?crypt_aes_cbc_nopad`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md)
explains when it matters.

## Checking what you have

[`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
reads everything it reports from the compiled library, not from a file
shipped beside it:

``` r

library(zucrypt)
info <- crypt_info()
info$vendored
#>          source version
#> 1 TF-PSA-Crypto   1.1.1
info$build_flags
#> $random_backend
#> [1] "getrandom"
#> 
#> $aes_implementation
#> [1] "aesni"
#> 
#> $hardware_acceleration
#> [1] TRUE
```

`vendored` is the version compiled in. A manifest describes the tree a
build was made from, and a user with a binary package cannot verify
that; the compiled library can say what it is. `aes_implementation` is
`"aesni"`, `"aesce"` or `"software"`, the path this machine actually
uses.

## Provenance and reproduction

`tools/vendor/manifest.tsv` records the upstream repository, release
tag, commit, archive URL and its SHA-256, the licence, the exact list of
defines and the patches. `tools/vendor/checksums.sha256` records every
vendored file. From a clone of the repository:

``` sh
sh tools/vendor/fetch    # download the release archive, check its SHA-256,
                         # trim it to the keep list, apply the patches
sh tools/vendor/verify   # offline: tree, checksums, keep list, object list,
                         # defines and path lengths all agree
```

Running `fetch` against the pinned release reproduces `src/vendor/` byte
for byte. That was rehearsed, not assumed: afterwards `git status` shows
no change. Installation itself downloads nothing and needs no CMake,
Python or Perl, because upstream’s release archive ships its generated
sources. A C99 compiler is the only requirement.

The trim is derived, not chosen by hand. Compile all 77 upstream sources
under this configuration, keep those whose object defines a symbol, and
take the header closure of those. The method and its results are
recorded with the repository, and `verify` fails if the keep list and
the build’s object list disagree.

## The patches

`src/vendor/` is never edited in place. Two changes are applied as
patches from `tools/patches/tf-psa-crypto/`, each with its reason in its
header:

- **`0001-avoid-zero-size-pubkey-array.patch`.** With no public-key
  algorithm enabled, an upstream header declares a zero-size array,
  which is not ISO C and which `-Wpedantic` rejects. The patch changes
  the array’s minimum size from 0 to 1 in a structure this build never
  uses. It should go when upstream fixes the header.
- **`0002-drop-diagnostic-pragmas.patch`.** Removes two upstream
  `#pragma GCC diagnostic ignored` blocks that R CMD check reports.
  Neither warning fires under the flags CRAN compiles with. The code
  they surround, including the constant-time functions and the
  zeroisation barrier, is unchanged.

## How a security fix reaches you

This is the part most often misunderstood.

1.  **Noticing.** A weekly job, `vendor-upstream.yaml`, watches
    TF-PSA-Crypto’s releases on the 1.1 LTS line and opens an issue in
    this repository when one appears. It watches releases, not
    advisories; the advisory is read from the release notes.
2.  **Updating.** The manifest’s pinned release changes, `fetch`
    re-derives the tree, each patch is checked for whether it still
    applies and is still needed, `verify` and the full CI run follow,
    and a zucrypt release goes to CRAN.
3.  **Reaching you.** It depends on how you use zucrypt:
    - **From R, or through the registered C table,** you get the fix
      when you update zucrypt.
    - **Through the static archive,** as `zuxlsx` does, the backend is
      compiled *into your package*. Updating zucrypt changes nothing
      until **your package is reinstalled or rebuilt** against the new
      archive. CRAN rebuilds binaries when a package is updated, not
      when a package it links to is. A package that links the archive
      should say so in its own documentation, and should release when
      zucrypt ships a security fix.

## What the testing establishes

Every algorithm is checked against **published known-answer vectors**:
FIPS 180-2 and RFC 6234 for the digests, including multi-block and
one-million-byte inputs; RFC 2202 and RFC 4231 for HMAC, including keys
longer than the block; NIST SP 800-38A for AES-CBC at all three key
sizes. Each vector is committed with its source, and
`tools/make-kat.R --check` recomputes every one with the `openssl` R
package, an implementation that shares no code with this backend.

Beyond the vectors: - inputs up to 4 MiB are compared with `openssl`
directly; - one-shot and incremental results agree at every split
point; - the Office key-derivation loop is checked against a vector
whose independent source is msoffcrypto-tool; - a weekly sweep fails
allocations inside the backend and requires a clean error rather than a
wrong answer; - the suite runs under the address and undefined-behaviour
sanitizers, valgrind and `gctorture`, and on i386, musl and aarch64.

**What it does not establish.** This package has not been independently
audited. The tests show that the configured algorithms give the right
answers and fail cleanly; they do not show that the backend is free of
side channels beyond what upstream documents. Upstream’s own test suite
is not vendored or run here: zucrypt relies on upstream for the
correctness of the library as a whole and tests the subset it builds.
And R keeps its own copies of raw vectors, so zucrypt can wipe the
native buffers it owns but cannot promise that a key has left the
process’s memory.

## Licence

TF-PSA-Crypto is distributed under Apache-2.0 (upstream offers
Apache-2.0 or GPL-2.0-or-later; zucrypt takes it under Apache-2.0). Its
licence text is vendored with the source and installed with the package,
beside the static archive, as `licenses/tf-psa-crypto-LICENSE`.
`inst/COPYRIGHTS` lists the copyright holders. zucrypt’s own code is
MIT-licensed.
