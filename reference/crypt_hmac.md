# Compute an HMAC

Computes a keyed message authentication code (RFC 2104) over a raw
vector.

## Usage

``` r
crypt_hmac(data, key, algorithm = "sha256")
```

## Arguments

- data:

  A raw vector. Character input is never accepted: this package does not
  guess a text encoding and never treats a string as a file name.
  Convert deliberately with
  [`charToRaw()`](https://rdrr.io/r/base/rawConversion.html) or
  [`serialize()`](https://rdrr.io/r/base/serialize.html).

- key:

  A raw vector holding the key. Any length is accepted, including zero,
  as the standard specifies. This is a key, not a password: deriving a
  key from a password is the caller's responsibility and is not
  something this package does for you.

- algorithm:

  A single algorithm name: one of `"sha1"`, `"sha256"`, `"sha384"` or
  `"sha512"`, and whatever `crypt_info()$algorithms` reports is what
  this build actually accepts. Matched exactly – there is no partial
  matching and no fallback, so a typo is an error rather than a quietly
  different algorithm.

## Value

A raw vector the length of the underlying digest.

## Verifying a MAC

Compare with
[`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md),
never with [`identical()`](https://rdrr.io/r/base/identical.html) or
`==`. An ordinary comparison stops at the first differing byte, and the
time it takes is therefore a measurement of how much of the expected
value an attacker has guessed.

## Examples

``` r
key <- as.raw(rep(0x0b, 20))
tag <- crypt_hmac(charToRaw("Hi There"), key)
tag
#>  [1] b0 34 4c 61 d8 db 38 53 5c a8 af ce af 0b f1 2b 88 1d c2 00 c9 83 3d a7 26
#> [26] e9 37 6c 2e 32 cf f7

# Verification, done properly.
crypt_equal(tag, crypt_hmac(charToRaw("Hi There"), key))
#> [1] TRUE
```
