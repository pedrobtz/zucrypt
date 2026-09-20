# Compute a message digest

Hashes a raw vector with one of the digest algorithms this build
provides.

## Usage

``` r
crypt_hash(data, algorithm = "sha256")
```

## Arguments

- data:

  A raw vector. Character input is never accepted: this package does not
  guess a text encoding and never treats a string as a file name.
  Convert deliberately with
  [`charToRaw()`](https://rdrr.io/r/base/rawConversion.html) or
  [`serialize()`](https://rdrr.io/r/base/serialize.html).

- algorithm:

  A single algorithm name: one of `"sha1"`, `"sha256"`, `"sha384"` or
  `"sha512"`, and whatever `crypt_info()$algorithms` reports is what
  this build actually accepts. Matched exactly – there is no partial
  matching and no fallback, so a typo is an error rather than a quietly
  different algorithm.

## Value

A raw vector of the digest, 20 bytes for `"sha1"` and 32, 48 or 64 for
the SHA-2 family. Hex formatting is an explicit step at the call site;
see the examples.

## Choosing an algorithm

`"sha256"` is the default and the right answer unless something external
requires otherwise. `"sha1"` is available because document formats
specify it – notably the Office encryption profiles this package exists
to support – and it is not collision resistant. Do not select it for
anything new.

## See also

[`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md)
for a keyed digest,
[`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md)
for comparing digests without leaking timing information.

## Examples

``` r
digest <- crypt_hash(charToRaw("the quick brown fox"))
digest
#>  [1] 9e cb 36 56 13 41 d1 8e b6 54 84 e8 33 ef ea 61 ed c7 4b 84 cf 5e 6a e1 b8
#> [26] 1c 63 53 3e 25 fc 8f

# Hex, when you need it, is an explicit conversion.
paste(format(digest), collapse = "")
#> [1] "9ecb36561341d18eb65484e833efea61edc74b84cf5e6ae1b81c63533e25fc8f"

# The digest of empty input is well defined.
crypt_hash(raw(0))
#>  [1] e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4
#> [26] 95 99 1b 78 52 b8 55

crypt_hash(charToRaw("abc"), "sha512")
#>  [1] dd af 35 a1 93 61 7a ba cc 41 73 49 ae 20 41 31 12 e6 fa 4e 89 a9 7e a2 0a
#> [26] 9e ee e6 4b 55 d3 9a 21 92 99 2a 27 4f c1 a8 36 ba 3c 23 a3 fe eb bd 45 4d
#> [51] 44 23 64 3c e8 0e 2a 9a c9 4f a5 4c a4 9f
```
