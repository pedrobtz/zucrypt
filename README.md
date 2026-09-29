
<!-- README.md is generated from README.Rmd. Please edit that file, then
     run devtools::build_readme(). CI (readme.yaml) re-renders it and fails
     on any difference, so the output below cannot drift from the code:
     it once printed a digest that was not SHA-256 of its input (#36). -->

# zucrypt

<!-- badges: start -->

[![Lifecycle: stable](https://img.shields.io/badge/lifecycle-stable-brightgreen.svg)](https://lifecycle.r-lib.org/articles/stages.html#stable)
[![R-CMD-check](https://github.com/pedrobtz/zucrypt/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/zucrypt/actions/workflows/R-CMD-check.yaml)
[![coverage](https://raw.githubusercontent.com/pedrobtz/zucrypt/main/.github/badges/coverage.svg)](https://github.com/pedrobtz/zucrypt/actions/workflows/coverage.yaml)
<!-- badges: end -->

zucrypt provides a focused set of cryptographic functions for R, backed by a
bundled library: message digests, HMAC, unauthenticated AES-CBC,
constant-time comparison and secure erasure, over raw vectors. The backend is a vendored,
pinned subset of [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto),
the Mbed TLS project’s cryptography library — 113 files of it, configured down
to the algorithms above and nothing else. Installing the package needs a C99
compiler and nothing else: no system cryptographic library, no Java, no
Python, and no network access during installation.

The same primitives are published to other packages’ compiled code twice: as a
registered C function table for consumers that can carry an `Imports:`, and
as a static archive (`libzucrypt.a`) for consumers that cannot.

Today that is the whole surface.
[openssl](https://cran.r-project.org/package=openssl) and
[sodium](https://cran.r-project.org/package=sodium) cover far more ground,
and a package that needs keys, signatures, certificates or authenticated
encryption should use them. Later releases are planned to add randomness,
Base64 and familiar `openssl`-style interfaces for hashing and HMAC, then
authenticated encryption and key derivation. Those are plans, not features
of this version. Office/Excel decryption lives in
[zuxlsx](https://github.com/pedrobtz/zuxlsx), which is the first consumer of
the archive, not here.

## Usage

Bytes in, bytes out. Raw vectors only — a character value is never guessed at,
never treated as a file name, and never given an encoding on your behalf.

``` r
library(zucrypt)

digest <- crypt_hash(charToRaw("the quick brown fox"))
digest
#>  [1] 9e cb 36 56 13 41 d1 8e b6 54 84 e8 33 ef ea 61 ed c7 4b 84 cf 5e 6a e1 b8
#> [26] 1c 63 53 3e 25 fc 8f

# Hex is an explicit conversion at the call site, not a default.
crypt_hex(digest)
#> [1] "9ecb36561341d18eb65484e833efea61edc74b84cf5e6ae1b81c63533e25fc8f"

# A keyed digest, and the right way to check one.
key <- as.raw(rep(0x0b, 32))
tag <- crypt_hmac(charToRaw("Hi There"), key)
crypt_equal(tag, crypt_hmac(charToRaw("Hi There"), key))
#> [1] TRUE
```

Use `crypt_equal()` rather than `identical()` whenever one side is a secret:
an ordinary comparison stops at the first differing byte, so how long it takes
measures how much of the expected value an attacker has guessed.

`crypt_info()` reports what the installed build actually contains, read from
the compiled library rather than from anything written down in R:

``` r
info <- crypt_info()
info$algorithms
#> [1] "sha1"   "sha256" "sha384" "sha512"
info$vendored
#>          source version
#> 1 TF-PSA-Crypto   1.1.1
```

The AES-CBC functions exist too, and are deliberately not shown here: they add
no padding and no authentication, and presenting them beside a hash would
suggest they are a general-purpose way to encrypt something. See
`?crypt_aes_cbc_nopad` before using them.

[Getting started](https://pedrobtz.github.io/zucrypt/articles/zucrypt.html)
walks through every function, including what using AES-CBC correctly takes
and what each error means.

## Consuming it from C

Other packages can use these primitives without going through R, in either of
the two ways the `zu*` family links siblings:

- **The static archive** `libzucrypt.a`, for a package that cannot carry an
  `Imports:`. It is installed to `lib/` plus the R sub-architecture
  (`lib/x64/` on Windows), beside the licence of the backend compiled into it.
  This is the primary shape, and it is *frozen* as ABI 1: its first consumer,
  `zuxlsx`’s decryption of password-protected workbooks, was built and tested
  against it before the freeze.
- **A registered function table**, for a package that can carry an
  `Imports:`. *Experimental* until a package other than a test fixture uses
  it.

[Using zucrypt from C](https://pedrobtz.github.io/zucrypt/articles/c-api.html)
walks through choosing a shape and wiring it up; `?zucrypt_c_api` is the
reference, including what is and is not promised.

## Status

Version 0.1.0. The seven R functions are stable, the static archive is frozen
as ABI 1, and the registered table is experimental, as above. Every change
to either is recorded in `NEWS.md`. What is compiled in, where it came from,
and how a security fix reaches you are in
[The vendored backend](https://pedrobtz.github.io/zucrypt/articles/backend.html).
The design is in `.agents/design.md`, and
`.agents/roadmap.md` records how it was built, what was deliberately left out,
and what comes next.

## Installation

From CRAN:

``` r
install.packages("zucrypt")
```

The development version, from GitHub:

``` r
# install.packages("pak")
pak::pak("pedrobtz/zucrypt")
```
