# Signatures and RSA Encryption

`crypt_signature_create()` signs data with a private RSA or EC key, and
`crypt_signature_verify()` checks the signature with the public key.
`crypt_rsa_encrypt()` encrypts a short message to a public key, and
`crypt_rsa_decrypt()` decrypts it with the private key. The names,
arguments and defaults follow `openssl`, with `pss` and `oaep_hash`
added.

A signature covers a digest: `hash` is applied to `data` and the digest
is signed, so `hash = crypt_sha256` gives an RSA-SHA256 signature. With
`hash = NULL`, `data` must already be a SHA-1 or SHA-2 digest. PKCS#1
v1.5 signatures are deterministic. PSS signatures (`pss = TRUE`, RFC
8017 section 8.1) are randomised, use MGF1 with the same digest, and a
salt as long as the digest; verification requires that salt length.

With a key on P-256, P-384 or P-521 the signature is ECDSA, encoded in
DER as openssl encodes it;
[`crypt_ecdsa_parse()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
gives its `r` and `s`. ECDSA signatures are randomised unless
`deterministic = TRUE`, which derives the nonce from the key and digest
as RFC 6979 specifies. Verification accepts only the canonical DER
encoding.

RSA encryption is for short secrets such as keys: a 2048-bit key with
OAEP over SHA-1 takes at most 214 bytes. OAEP (`oaep = TRUE`, RFC 8017
section 7.1) is the padding to use. `oaep_hash` picks the digest for
both its label hash and MGF1: `"sha1"`, as openssl uses, or `"sha256"`,
`"sha384"` or `"sha512"`. PKCS#1 v1.5 padding (`oaep = FALSE`, the
openssl default) is legacy: a decryptor that reveals whether padding was
valid can be attacked to decrypt messages (Bleichenbacher, 1998). It is
here for formats that specify it.

## Usage

``` r
crypt_signature_create(
  data,
  hash = crypt_sha1,
  key,
  password = NULL,
  pss = FALSE,
  deterministic = FALSE
)

crypt_signature_verify(data, sig, hash = crypt_sha1, pubkey, pss = FALSE)

crypt_rsa_encrypt(data, pubkey, oaep = FALSE, oaep_hash = "sha1")

crypt_rsa_decrypt(data, key, password = NULL, oaep = FALSE, oaep_hash = "sha1")
```

## Arguments

- data:

  A raw vector, or a path or connection to read one from. For
  `crypt_rsa_encrypt()` and `crypt_rsa_decrypt()`, a raw vector.

- hash:

  A digest function such as
  [`crypt_sha256()`](https://pedrobtz.github.io/zucrypt/reference/crypt_sha.md),
  or `NULL` when `data` is already a digest. The default, `crypt_sha1`,
  is openssl's; use `crypt_sha256` for anything new.

- key:

  A private key from
  [`crypt_read_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md),
  or anything
  [`crypt_read_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  reads.

- password:

  Not supported yet; must be `NULL`.

- pss:

  `TRUE` for RSASSA-PSS, `FALSE` (the default) for PKCS#1 v1.5. RSA keys
  only.

- deterministic:

  `TRUE` for RFC 6979 deterministic ECDSA. EC keys only.

- sig:

  The signature, a raw vector.

- pubkey:

  A public key from
  [`crypt_read_pubkey()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md),
  a private key (whose public half is used), or anything
  [`crypt_read_pubkey()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  reads.

- oaep:

  `TRUE` for OAEP, `FALSE` (the default) for PKCS#1 v1.5.

- oaep_hash:

  The OAEP digest: `"sha1"` (the default), `"sha256"`, `"sha384"` or
  `"sha512"`. Ignored unless `oaep = TRUE`.

## Value

`crypt_signature_create()` returns the signature, a raw vector as long
as the modulus. `crypt_signature_verify()` returns `TRUE`, or signals
`zucrypt_auth_error`. `crypt_rsa_encrypt()` returns the ciphertext and
`crypt_rsa_decrypt()` the plaintext, as raw vectors.

## Errors

A signature that does not verify, and a ciphertext that does not
decrypt, are `zucrypt_auth_error`, whatever the reason. A message too
long for the key is `zucrypt_bad_length`.

## Compared with openssl

`pss`, `deterministic` and `oaep_hash` are additions. There is no
default key: openssl reads `~/.ssh`. PKCS#1 v1.5 decryption of an
invalid ciphertext is an error here; OpenSSL 3 returns random bytes
instead (implicit rejection).

## Examples

``` r
key <- crypt_rsa_keygen(2048)
msg <- charToRaw("hello")

sig <- crypt_signature_create(msg, crypt_sha256, key)
crypt_signature_verify(msg, sig, crypt_sha256, key$pubkey)
#> [1] TRUE

sig <- crypt_signature_create(msg, crypt_sha256, key, pss = TRUE)
crypt_signature_verify(msg, sig, crypt_sha256, key$pubkey, pss = TRUE)
#> [1] TRUE

secret <- crypt_rand_bytes(32)
ct <- crypt_rsa_encrypt(secret, key$pubkey, oaep = TRUE,
                        oaep_hash = "sha256")
identical(crypt_rsa_decrypt(ct, key, oaep = TRUE, oaep_hash = "sha256"),
          secret)
#> [1] TRUE
```
