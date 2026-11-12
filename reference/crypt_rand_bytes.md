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
#>  [1] d9 38 56 92 fd cc 78 f1 28 47 25 71 74 50 d8 f9

# A 256-bit key, printed as hex.
crypt_hex(crypt_rand_bytes(32))
#> [1] "9c539ddb8a49faf8bba991cea2336f08c3ea5c62c69a932301be4fcc42422417"

# set.seed() does not repeat it.
set.seed(1)
a <- crypt_rand_bytes(8)
set.seed(1)
b <- crypt_rand_bytes(8)
identical(a, b)
#> [1] FALSE
```
