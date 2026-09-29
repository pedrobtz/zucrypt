## This is a first submission

zucrypt is new; `Version` is 0.1.0. It provides message digests, HMAC,
AES-CBC, constant-time comparison and hexadecimal encoding over raw vectors,
with no system cryptographic library, by building a pinned subset of the Mbed
TLS project's TF-PSA-Crypto from vendored sources. The same primitives are
published to other packages' C code; its first such consumer is `zuxlsx`
(reading password-protected Excel workbooks), which will be submitted after
this package.

## Test environments

* local macOS 26.2 (x86-64), R 4.5.2
* GitHub Actions, R CMD check `--as-cran` on every push:
  * macOS (arm64) and Windows (x86-64), R release
  * Ubuntu, R release, oldrel-1, and 4.1 (the version `Depends` declares)
  * the r-devel containers matching CRAN's Linux flavours (`clang23`,
    `ubuntu-gcc16`, `ubuntu-clang`), and a leg with no `Suggests` installed
  * CRAN's additional checks (`rcnst`, `rlibro`, `vnu`), on every push to
    the main branch
* Also on every push: link-time optimisation, `rchk`, `gctorture`,
  AddressSanitizer and UndefinedBehaviorSanitizer (gcc and clang), valgrind
  with `--leak-check=full`, and GCC's `-fanalyzer`. Weekly: i386, musl and
  aarch64 builds that run the test suite and fail on a WARNING, and a sweep
  that fails each native allocation the `crypt_*()` calls make, checking
  that every failure surfaces as an R error rather than a wrong answer.

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Bundled third-party code and licensing

The package's own code is MIT-licensed. It vendors a subset of
TF-PSA-Crypto 1.1.1, the Mbed TLS project's cryptography library, which is
dual-licensed Apache-2.0 OR GPL-2.0-or-later and used here under Apache-2.0.

* The Mbed TLS Contributors are listed as copyright holders in `Authors@R`,
  and `DESCRIPTION` has a `Copyright:` field pointing to `inst/COPYRIGHTS`,
  which gives the provenance and licence of every included file.
* Upstream's `LICENSE` is vendored with the sources and installed with the
  package as `licenses/tf-psa-crypto-LICENSE`.
* `tools/vendor/manifest.tsv` records the release, commit, archive URL and
  its SHA-256. `tools/vendor/fetch` reproduces `src/vendor/` byte for byte
  from that archive, and `tools/vendor/verify` checks offline, in continuous
  integration, that the tree, the manifest, the build configuration and
  `inst/COPYRIGHTS` agree.
* 113 files are included: the sources that carry code under this package's
  configuration and the headers they include. The tree is flattened to
  `inc/` and `lib/` because upstream's own paths exceed the 100-byte tarball
  limit; no file's content changes except through two patches:
  * `0001-avoid-zero-size-pubkey-array.patch`: with no public-key algorithm
    enabled, an upstream header declares a zero-size array, which is not ISO
    C and which GCC's `-Wpedantic` reports.
  * `0002-drop-diagnostic-pragmas.patch`: removes upstream's
    `#pragma GCC/clang diagnostic` suppressions of `-Wredundant-decls` and
    `-Wvla`, which R CMD check notes. Neither warning is enabled by CRAN's
    flags; the code between the pragmas is unchanged.

Installation needs only a C99 compiler. Nothing is downloaded and nothing
is generated: upstream's release archive ships its generated sources, so no
CMake, Python or Perl is used, and `src/Makevars` is portable make with an
explicit object list.

## The installed static library

Besides the shared object, the package installs a static archive,
`lib/libzucrypt.a` (`lib/x64/` on Windows), and the header
`include/zucrypt.h`. This is deliberate and documented (`?zucrypt_c_api`):
it lets another package use these primitives from C through `LinkingTo:`
alone, without a run-time dependency. `src/install.libs.R` installs it, and
the shared object still exports only `R_init_zucrypt`; every backend symbol
is compiled with hidden visibility, which a test asserts.

## Correctness of the cryptography

Every algorithm is checked against 34 published known-answer vectors (FIPS
180-2, RFC 6234, RFC 2202, RFC 4231 and NIST SP 800-38A), committed with
their provenance in `tests/testthat/fixtures/MANIFEST.tsv`. Each is also
recomputed with the 'openssl' package, an implementation sharing no code
with the vendored backend, so a transcription error in a fixture cannot pass
unnoticed. Tests that need 'openssl' are skipped when it is not installed.

## Method references

The package implements published standards only (the FIPS, RFC and NIST
documents above), cited in the documentation where each is used. There are
no references describing methods original to this package.
