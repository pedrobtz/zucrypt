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

0 errors | 0 warnings | 0 notes

Upstream's diagnostic-suppressing pragmas in two vendored files
(`-Wredundant-decls`, `-Wvla`) are removed by a local patch,
`tools/patches/tf-psa-crypto/0002-drop-diagnostic-pragmas.patch`: neither
warning is enabled by `-Wall`, `-Wextra` or `-pedantic`, so nothing warns
without them. See below.

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
* Two local patches are applied, and no upstream file is edited in place:
  * `0001-avoid-zero-size-pubkey-array.patch` removes a zero-size array that
    upstream declares when no public-key algorithm is enabled; zero-size
    arrays are a GNU extension rather than ISO C, and GCC with `-Wpedantic`
    reports it as a significant warning.
  * `0002-drop-diagnostic-pragmas.patch` removes upstream's
    `#pragma GCC/clang diagnostic` suppressions of `-Wredundant-decls` and
    `-Wvla`, which R CMD check notes. Neither warning is enabled by CRAN's
    flags; the code between the pragmas is unchanged.

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
