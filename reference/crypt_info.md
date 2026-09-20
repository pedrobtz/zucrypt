# Report what this build of zucrypt contains

Describes the installed package: its own version, and the vendored
cryptographic backend it was compiled against.

## Usage

``` r
crypt_info()
```

## Value

A list with elements:

- `version`:

  the `zucrypt` package version, as a `package_version`.

- `vendored`:

  a data frame with one row per vendored source, giving its `source`
  name and the `version` the compiled library reports.

- `random_backend`:

  the operating-system random source selected at compile time. No
  function in this version of the package consumes randomness; the
  backend requires the source to exist at link time.

## Details

Everything reported here is read from the compiled library, never from
`tools/vendor/manifest.tsv`. The manifest is maintainer tooling and is
not installed, so it can only describe the tree a build *was made from*
– which is the one thing a user with a binary package cannot check.

## Stage of development

This is a placeholder. The full `crypt_info()` described in the design
returns `abi_version`, the supported `algorithms` and `build_flags` as
well, and those arrive with the functions they describe. Nothing in this
list will change meaning when they do.

## Examples

``` r
info <- crypt_info()
info$version
#> [1] ‘0.0.0.9000’
info$vendored
#>          source version
#> 1 tf-psa-crypto   1.1.1
```
