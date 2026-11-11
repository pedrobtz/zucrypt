# AES-GCM Authenticated Encryption

`crypt_aes_gcm_encrypt()` encrypts and authenticates `data`, and
`crypt_aes_gcm_decrypt()` checks the authentication tag before it
returns anything. This is AES in Galois/Counter Mode (NIST SP 800-38D)
with RFC 5116's contract: a 12-byte nonce, a 16-byte tag, and optional
associated data that is authenticated but not encrypted.

Decryption either returns the plaintext of an untouched message or
signals `zucrypt_auth_error` and returns nothing. A changed ciphertext,
tag, nonce or associated data, a truncated tag and a wrong key all fail
the same way.

## Usage

``` r
crypt_aes_gcm_encrypt(data, key, iv = crypt_rand_bytes(12), aad = NULL)

crypt_aes_gcm_decrypt(
  data,
  key,
  iv = attr(data, "iv"),
  tag = attr(data, "tag"),
  aad = NULL
)
```

## Arguments

- data:

  A raw vector: the plaintext to encrypt, or the ciphertext to decrypt.
  Character input is not accepted.

- key:

  A raw vector of exactly 16, 24 or 32 bytes, selecting AES-128, AES-192
  or AES-256. This is a key, not a password;
  [`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md)
  derives one from a password.

- iv:

  The nonce: a raw vector of exactly 12 bytes. Encryption draws a fresh
  one with
  [`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md)
  unless you pass one. **It must never repeat under the same key** (see
  "Nonces" below). Decryption reads it from the ciphertext's `iv`
  attribute unless you pass one.

- aad:

  Additional authenticated data, as a raw vector, or `NULL` for none. It
  is not encrypted and not returned. Decryption needs the same bytes,
  and fails if they differ.

- tag:

  The 16-byte authentication tag. Decryption reads it from the
  ciphertext's `tag` attribute unless you pass one.

## Value

`crypt_aes_gcm_encrypt()` returns the ciphertext, a raw vector the
length of `data`, with attributes `iv` (the nonce) and `tag` (the
authentication tag). Store or send all three. `crypt_aes_gcm_decrypt()`
returns the plaintext as a plain raw vector.

## Nonces

Two messages encrypted under one key with one nonce disclose the XOR of
their plaintexts. They also let anyone who sees both forge tags for that
key. The default nonce is 12 random bytes, which is safe for up to about
2^32 messages per key. Pass your own only when a protocol specifies it,
and then make sure it never repeats.

## Errors

An authentication failure signals `zucrypt_auth_error` and returns no
plaintext. A key or nonce of the wrong length is `zucrypt_bad_length`,
and a missing or non-raw argument is `zucrypt_invalid_argument`.

## Compared with openssl

The names and argument order follow
[`openssl::aes_gcm_encrypt()`](https://jeroen.r-universe.dev/openssl/reference/aes_cbc.html)
and
[`openssl::aes_gcm_decrypt()`](https://jeroen.r-universe.dev/openssl/reference/aes_cbc.html),
and the ciphertext bytes are the same. The behaviour differs on purpose.
openssl's encryption returns no tag, and its decryption returns altered
plaintext without an error. Here the tag is returned, and decryption
fails on any alteration, so these functions are not drop-in
replacements.

## Side channels

AES runs on the CPU's AES instructions where it has them, and on a
table-based software fallback otherwise;
[`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
reports which, in `build_flags$aes_implementation`. On the fallback both
AES and GHASH, the authentication half of GCM, read tables at addresses
that depend on the key. See
[crypt_aes_cbc_nopad](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md)
for what that exposes.

## See also

[`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md)
for keys and nonces,
[`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md)
to derive a key from a password.

## Examples

``` r
key <- crypt_rand_bytes(32)
sealed <- crypt_aes_gcm_encrypt(charToRaw("attack at dawn"), key)
sealed
#>  [1] 0b b2 48 fe 24 68 9a bd 30 8a 93 d1 04 e9
#> attr(,"iv")
#>  [1] 16 01 c5 97 76 6f 5a 41 9d 94 df 16
#> attr(,"tag")
#>  [1] 24 05 a5 2b b4 96 3a 5e 48 f7 0e dd ba 55 72 c7

rawToChar(crypt_aes_gcm_decrypt(sealed, key))
#> [1] "attack at dawn"

# Associated data is authenticated, not encrypted.
header <- charToRaw("message 7")
sealed <- crypt_aes_gcm_encrypt(charToRaw("hi"), key, aad = header)
rawToChar(crypt_aes_gcm_decrypt(sealed, key, aad = header))
#> [1] "hi"

# Any change is caught, and nothing is decrypted.
sealed[1] <- xor(sealed[1], as.raw(1))
try(crypt_aes_gcm_decrypt(sealed, key, aad = header))
#> Error in crypt_aes_gcm_decrypt() : 
#>   The cryptographic backend reported ZUC_ERR_AUTH.
```
