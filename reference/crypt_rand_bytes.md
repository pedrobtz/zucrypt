# Cryptographically Secure Random Bytes

Draws `n` bytes from the operating system's cryptographic random source:
`rand_s` on Windows, `arc4random_buf` on macOS and the BSDs, `getrandom`
on Linux with glibc 2.25 or later, and `/dev/urandom` elsewhere. Where
the kernel or a seccomp filter refuses `getrandom` (a kernel before
3.17), it reads `/dev/urandom` instead.
[`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
names the source in use, in `build_flags$random_backend`. Use these
bytes for keys, initialisation vectors, nonces and salts.

## Usage

``` r
crypt_rand_bytes(n = 1)
```

## Arguments

- n:

  The number of bytes: a single non-negative whole number. `n = 0`
  returns `raw(0)`.

## Value

A raw vector of length `n`.

## Details

**R's random number generator is never involved.**
[`set.seed()`](https://rdrr.io/r/base/Random.html) has no effect on
these bytes and they do not change `.Random.seed`, so drawing them does
not disturb a reproducible simulation running beside them. That is
deliberate: R's generator is seeded from the session and reproducible on
purpose, which is exactly what a key must not be.

The name, argument and default mirror
[`openssl::rand_bytes()`](https://jeroen.r-universe.dev/openssl/reference/rand_bytes.html),
so code moving from openssl changes only the prefix.

## Errors

A failure of the operating-system source raises an error of class
`zucrypt_entropy_error`. It never returns fewer bytes than asked for,
and never returns bytes from a source that reported failure. An invalid
`n` is `zucrypt_invalid_argument`.

## See also

[`crypt_aes_cbc_encrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md),
whose `iv` for encryption must be unpredictable: `crypt_rand_bytes(16)`
is one.

## Examples

``` r
crypt_rand_bytes(16)
#>  [1] df 43 0f e6 41 b2 02 34 de 9e 3f 47 96 0b 09 58

# A 256-bit key, printed as hex.
crypt_hex(crypt_rand_bytes(32))
#> [1] "a915543c7e43b73246c9d6cb4dc4192e34572fa8fc41d61e81a5f0db924a3ed2"

# set.seed() does not repeat it.
set.seed(1)
a <- crypt_rand_bytes(8)
set.seed(1)
b <- crypt_rand_bytes(8)
identical(a, b)
#> [1] FALSE
```
