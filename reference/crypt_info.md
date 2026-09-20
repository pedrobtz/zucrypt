# Report what this build of zucrypt contains

Describes the installed package: its version, the C ABI it publishes,
the algorithms it provides, and the vendored cryptographic backend it
was compiled against.

## Usage

``` r
crypt_info()
```

## Value

A list with elements:

- `version`:

  the `zucrypt` package version, as a `package_version`.

- `abi_version`:

  the C ABI version published to `LinkingTo` consumers, as an integer.
  `0` while the interface is still moving; it becomes `1` at the first
  release.

- `algorithms`:

  the digest algorithms this build provides, which is exactly the set
  [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
  and
  [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md)
  accept.

- `vendored`:

  a data frame with one row per vendored source, giving its `source`
  name and the `version` the compiled library reports.

- `build_flags`:

  a named list of compile-time choices worth being able to see from R:
  the operating-system random source that was selected, and whether
  hardware acceleration is compiled in.

## Details

Everything here is read from the compiled library, never from
`tools/vendor/manifest.tsv`. The manifest is maintainer tooling and is
not installed, so it could only describe the tree a build was made
*from* – which is the one thing a user holding a binary package cannot
check.

## Examples

``` r
info <- crypt_info()
info$version
#> [1] ‘0.0.0.9000’
info$algorithms
#> [1] "sha1"   "sha256" "sha384" "sha512"
info$vendored
#>          source version
#> 1 TF-PSA-Crypto   1.1.1
```
