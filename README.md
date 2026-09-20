# zucrypt

<!-- badges: start -->
[![Lifecycle: experimental](https://img.shields.io/badge/lifecycle-experimental-orange.svg)](https://lifecycle.r-lib.org/articles/stages.html#experimental)
[![R-CMD-check](https://github.com/pedrobtz/zucrypt/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/zucrypt/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

zucrypt is a narrow native cryptographic foundation for the `zu*` package
family: message digests, HMAC, unauthenticated AES-CBC/ECB, constant-time
comparison and secure erasure, over raw vectors. The backend is a vendored,
pinned subset of [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto),
the Mbed TLS project's cryptography library — 109 files of it, configured down
to the algorithms above and nothing else. Installing the package needs a C99
compiler and nothing else: no system cryptographic library, no Java, no
Python, and no network access during installation.

The same primitives are published to other packages twice, because the family
consumes siblings in two different ways: as a registered C function table for
consumers that can carry an `Imports:`, and as a static archive
(`inst/lib/libzucrypt.a`) for consumers that cannot.

It is **not** a replacement for
[openssl](https://cran.r-project.org/package=openssl) or
[sodium](https://cran.r-project.org/package=sodium). Those cover far more
ground, and a package that wants broad cryptographic functionality should use
them. zucrypt exists because the `zu*` packages need a small, fixed set of
primitives with a stable C ABI and an installation that depends on nothing.

Deliberately out of scope for now: authenticated encryption, password-based key
derivation, random number generation, signatures and key serialization. Each
needs a concrete consumer before it is added. Office/Excel decryption lives in
[zuxlsx](https://github.com/pedrobtz/zuxlsx), which is the first consumer of
this package, not here.

## Usage

Bytes in, bytes out. Raw vectors only — a character value is never guessed at,
never treated as a file name, and never given an encoding on your behalf.

``` r
library(zucrypt)

digest <- crypt_hash(charToRaw("the quick brown fox"))
digest
#>  [1] 05 c6 e0 8f 1d 9f 4f ... 

# Hex is an explicit conversion at the call site, not a default.
paste(format(digest), collapse = "")

# A keyed digest, and the right way to check one.
key <- as.raw(rep(0x0b, 32))
tag <- crypt_hmac(charToRaw("Hi There"), key)
crypt_equal(tag, crypt_hmac(charToRaw("Hi There"), key))
#> [1] TRUE
```

Use `crypt_equal()` rather than `identical()` whenever one side is a secret:
an ordinary comparison stops at the first differing byte, so how long it takes
measures how much of the expected value an attacker has guessed.

`crypt_info()` reports what the installed build actually contains — the
algorithms, the vendored backend version and the C ABI — read from the
compiled library rather than from anything written down in R.

The AES-CBC functions exist too, and are deliberately not shown here: they add
no padding and no authentication, and presenting them beside a hash would
suggest they are a general-purpose way to encrypt something. See
`?crypt_aes_cbc` before using them.

## Status

Early development. The design is in `.agents/design.md` and the path to the
first release in `.agents/roadmap.md`. The R interface above is complete and
tested against published vectors; the registered C function table for
`Imports:`-carrying consumers is not built yet.

## Installation

``` r
# install.packages("pak")
pak::pak("pedrobtz/zucrypt")
```
