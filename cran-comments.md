## Update

This is an update of zucrypt 0.1.0, published on CRAN on 2026-10-23. It adds
functions only: random bytes, AES-GCM authenticated encryption, PBKDF2, RSA
and elliptic-curve keys, signatures, encryption and key agreement, in an
interface shaped like the 'openssl' package's. Nothing in 0.1.0's R or C
interface is removed or changed in meaning. The bundled TF-PSA-Crypto is
updated from 1.1.1 to 1.1.2, a security release.

## R CMD check results

0 errors | 0 warnings | 0 notes

## Test environments

GitHub Actions, R CMD check `--as-cran`:

* macOS (arm64), R release
* Windows (x86-64), R release and R-devel
* Ubuntu, R release, oldrel-1, and 4.1 (the version `Depends` declares)
* the R-devel containers matching CRAN's Linux flavours (`clang23`,
  `ubuntu-gcc16`, `ubuntu-clang`), and a leg with no `Suggests` installed
* CRAN's additional checks (`rcnst`, `rlibro`, `vnu`)

Also: link-time optimisation, `rchk`, `gctorture`, AddressSanitizer and
UndefinedBehaviorSanitizer (gcc and clang), valgrind with
`--leak-check=full`, and GCC's `-fanalyzer`; musl and aarch64 builds that run
the test suite; and a sweep that fails each native allocation the
`crypt_*()` calls make in turn.

## Reverse dependencies

There are no reverse dependencies on CRAN. The one package that links
zucrypt's C archive, 'zuxlsx' (not yet on CRAN), is built and its tests run
against this version in continuous integration on Linux, macOS and Windows.

## Bundled third-party code and licensing

As in 0.1.0: the package's own code is MIT-licensed, and it vendors a subset
of TF-PSA-Crypto, the Mbed TLS project's cryptography library, used under
Apache-2.0. The Mbed TLS Contributors and the three individuals the bundled
files name as authors are in `Authors@R` as copyright holders, and
`inst/COPYRIGHTS` gives the provenance and licence of every included file.

The subset grows from 113 to 153 files, for the new algorithms. Four local
patches are applied, each recorded in `tools/vendor/manifest.tsv`: the two of
0.1.0 (a zero-size array, and diagnostic pragmas R CMD check notes), and two
that wipe secret data upstream leaves in freed memory. Installation needs only
a C99 compiler and downloads nothing.

## The installed static library

As in 0.1.0, the package installs a static archive, `lib/libzucrypt.a`
(`lib/x64/` on Windows), and the header `include/zucrypt.h`, so that another
package can use these primitives from C through `LinkingTo:` alone
(`?zucrypt_c_api`). The shared object exports only `R_init_zucrypt`.

## Method references

The package implements published standards only: the digests, HMAC (RFC
2104), AES and its modes (NIST SP 800-38A and 800-38D), PBKDF2 (RFC 8018), RSA
(RFC 8017), deterministic ECDSA (RFC 6979) and X25519 (RFC 7748), most of them
cited in the documentation where they are used. There are no references
describing methods original to this package.
