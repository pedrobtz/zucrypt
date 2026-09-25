<!-- DRAFT for 0.2.0, the first CRAN submission (roadmap Stage 12).
     0.1.0 is a GitHub tag only and is not submitted. This file is rewritten
     in Stage 12 against the checks that have actually run by then. -->

## Test environments

* local macOS 26.2, R release
* GitHub Actions: Ubuntu, macOS (ARM64) and Windows, R release; Ubuntu R
  oldrel-1; Ubuntu R 4.1, which is the version `Depends` declares
* R-hub containers: `clang23` and `ubuntu-gcc16`, which are CRAN's r-devel
  flavours, and `nosuggests`
* Additional checks on every push: link-time optimisation, `rchk`,
  `gctorture`, AddressSanitizer, UndefinedBehaviorSanitizer, valgrind with
  `--leak-check=full`, and GCC's `-fanalyzer`. Weekly: i386, musl and
  aarch64 builds that run the test suite and fail on a WARNING, and a sweep
  that fails each allocation the `crypt_*()` calls make, one run per
  allocation, checking that every failure surfaces as an error.

## R CMD check results

0 errors | 0 warnings | 1 note

The note is:

```
checking pragmas in C/C++ headers and code ... NOTE
  Files which contain pragma(s) suppressing diagnostics:
    'src/vendor/tf-psa-crypto/lib/constant_time_impl.h'
    'src/vendor/tf-psa-crypto/lib/platform_util.c'
```

Both files are third-party, from the vendored TF-PSA-Crypto sources, and the
suppressions are upstream's. They are narrow: `-Wvla`, `-Wredundant-decls`,
and MSVC's C4146 for unary minus on an unsigned type. The last of those is
the point of a constant-time implementation rather than an oversight.

Removing them would mean carrying a local patch against upstream indefinitely
for diagnostics this package does not emit. The vendoring tooling supports
patches and one is applied for a genuine defect (see below), so this was a
deliberate decision rather than an omission.

## Bundled third-party code

This package vendors a subset of TF-PSA-Crypto (the Mbed TLS project's
cryptography library), release `tf-psa-crypto-1.1.1`, under the Apache-2.0
option of its dual Apache-2.0 OR GPL-2.0-or-later licence.

* `inst/COPYRIGHTS` lists every included file's provenance and licence.
* `DESCRIPTION` carries `Copyright:` and names The Mbed TLS Contributors as a
  copyright holder in `Authors@R`.
* `tools/vendor/manifest.tsv` records the release, the source archive URL and
  its SHA-256. `tools/vendor/verify` checks offline that the tree, the
  manifest, the build configuration and `inst/COPYRIGHTS` all agree, and runs
  in continuous integration.
* 109 of the archive's files are included — the dependency closure of the 18
  sources that carry a symbol under this package's configuration.
* One local patch is applied, `0001-avoid-zero-size-pubkey-array.patch`. It
  removes a zero-size array that upstream declares when no public-key
  algorithm is enabled; zero-size arrays are a GNU extension rather than ISO
  C, and GCC with `-Wpedantic` reports it as a significant warning. No
  upstream file is edited in place.

Installation requires only a C99 compiler. Nothing is downloaded and no
sources are generated during installation: the release archive ships the
generated files, so no CMake, Python or Perl is needed.

## Correctness of the cryptography

Every algorithm is checked against published known-answer vectors — FIPS
180-2, RFC 2202, RFC 4231 and NIST SP 800-38A — committed with their
provenance in `tests/testthat/fixtures/MANIFEST.tsv`. All 23 are additionally
recomputed by `tools/make-kat.R` against OpenSSL, an implementation sharing
no code with the vendored backend, so a transcription error in a fixture
cannot pass unnoticed.

## Method references

There are no published references describing methods original to this
package. It implements published standards only, and those are cited in the
documentation and in the fixture manifest at the point of use.

## This is a first submission

The package is new. `Version` is 0.1.0.
