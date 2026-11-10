# Derive a Key from a Password with PBKDF2

`crypt_pbkdf2()` stretches a password into a key with PBKDF2 (RFC 8018,
section 5.2), using HMAC with the chosen digest as the pseudorandom
function.

## Usage

``` r
crypt_pbkdf2(password, salt, iterations, length = 32, algorithm = "sha256")
```

## Arguments

- password:

  The password, as a raw vector. A string is not accepted, because its
  bytes depend on an encoding: convert deliberately, for example with
  `charToRaw(enc2utf8(x))`. It may be empty.

- salt:

  The salt, as a raw vector. Use at least 16 random bytes from
  [`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md),
  a fresh salt for each password. It may be empty, which only
  interoperability with an existing format justifies.

- iterations:

  The iteration count, a whole number from 1 to 4294967295. It has no
  default, because the right value depends on the digest, the hardware
  and the time you can afford. OWASP recommended 600,000 for `"sha256"`
  in 2023.

- length:

  The number of bytes to derive, a whole number of at least 1. 32 gives
  an AES-256 key.

- algorithm:

  The digest for the HMAC: `"sha256"` (the default), `"sha384"`,
  `"sha512"` or `"sha1"`. `"sha1"` is for formats that specify it, never
  for anything new.

## Value

A raw vector of `length` bytes.

## Details

PBKDF2 derives a key. It is not an encryption format and not a password
storage format. The salt, the iteration count and the digest are yours
to choose, store beside what the key protects, and supply again to
derive the same key.

## Cost

The time is proportional to `iterations` times the number of
digest-sized blocks in `length`, and the call cannot be interrupted.
Bound `iterations` before passing a value that came from untrusted
input, such as a file header.

## Errors

An invalid argument is `zucrypt_invalid_argument`, and an unknown digest
is `zucrypt_unsupported_algorithm`.

## See also

[`crypt_aes_gcm_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md),
which takes the key this derives.

## Examples

``` r
salt <- crypt_rand_bytes(16)
key <- crypt_pbkdf2(charToRaw("correct horse"), salt, iterations = 10000)
key
#>  [1] 9a d9 19 75 c2 e6 a2 51 32 6b 93 9a 03 93 4b af a1 d6 8f d7 a8 6d f3 ce a4
#> [26] 0d 39 57 f1 74 de f1

# RFC 6070, test case 2.
crypt_hex(crypt_pbkdf2(charToRaw("password"), charToRaw("salt"),
                       iterations = 2, length = 20, algorithm = "sha1"))
#> [1] "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
```
