# Elliptic-Curve and X25519 Keys

Generate, build and use keys on the NIST curves P-256, P-384 and P-521
and on Curve25519, with `openssl`'s names and arguments under a `crypt_`
prefix.

- `crypt_ec_keygen()` generates a key on a NIST curve, for ECDSA
  signatures with
  [`crypt_signature_create()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
  and for key agreement with `crypt_ec_dh()`.

- `crypt_ec_key()` builds one from its coordinates, as a JSON Web Key
  carries them, and [`as.list()`](https://rdrr.io/r/base/list.html)
  takes one apart again.

- `crypt_x25519_keygen()`, `crypt_read_x25519_key()` and
  `crypt_read_x25519_pubkey()` make X25519 keys (RFC 7748), and
  `crypt_x25519_diffie_hellman()` computes their shared secret.

- `crypt_ecdsa_parse()` and `crypt_ecdsa_write()` convert an ECDSA
  signature between DER, as
  [`crypt_signature_create()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
  returns it, and its integers `r` and `s`.

Keys of these types are read and written by
[`crypt_read_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md),
[`crypt_write_pem()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
and the other key functions, as for RSA.

A Diffie-Hellman result is a shared secret, not a key: derive keys from
it with a key-derivation function. A peer key on another curve, a point
that is not on the curve, and an X25519 peer that yields an all-zero
secret are refused.

## Usage

``` r
crypt_ec_keygen(curve = c("P-256", "P-384", "P-521"))

crypt_ec_key(curve, x, y, d = NULL)

crypt_ec_dh(key, peerkey, password = NULL)

crypt_x25519_keygen()

crypt_read_x25519_key(x)

crypt_read_x25519_pubkey(x)

crypt_x25519_diffie_hellman(key, pubkey)

crypt_ecdsa_parse(sig)

crypt_ecdsa_write(r, s)
```

## Arguments

- curve:

  `"P-256"`, `"P-384"` or `"P-521"`.

- x, y:

  The public point's coordinates, as raw big-endian integers. For an
  X25519 key, `x` is the 32-byte key.

- d:

  The private scalar, as a raw big-endian integer, or `NULL` for a
  public key.

- key:

  A private key.

- peerkey, pubkey:

  The other party's public key, or a private key whose public half is
  used.

- password:

  Not supported; must be `NULL`.

- sig:

  An ECDSA signature in DER.

- r, s:

  The signature's integers, as raw big-endian vectors.

## Value

`crypt_ec_keygen()`, `crypt_x25519_keygen()`, `crypt_read_x25519_key()`
and `crypt_ec_key()` with `d` return a key of class
`c("crypt_key", "crypt_ecdsa")` or `c("crypt_key", "crypt_x25519")`; the
public forms are class `crypt_pubkey`. The Diffie-Hellman functions
return the shared secret as a raw vector: 32, 48 or 66 bytes for the
NIST curves, 32 for X25519. `crypt_ecdsa_parse()` returns `list(r, s)`
and `crypt_ecdsa_write()` the DER signature.
[`as.list()`](https://rdrr.io/r/base/list.html) on an EC key gives
`data` with `curve`, `x`, `y` and, for a private key, `secret`; on an
X25519 key, `x` and, private, `d`.

## Compared with openssl

`crypt_ecdsa_parse()` returns raw vectors rather than `bignum`s, and
[`as.list()`](https://rdrr.io/r/base/list.html) gives coordinates as raw
vectors. `crypt_ecdsa_parse()` reads strict DER: it refuses bytes after
the signature's SEQUENCE, which
[`openssl::ecdsa_parse()`](https://jeroen.r-universe.dev/openssl/reference/signatures.html)
ignores, as well as the negative, non-minimal and truncated encodings
both refuse. There is no Ed25519: the bundled library has no EdDSA.
There is no default key.

## Examples

``` r
alice <- crypt_ec_keygen("P-256")
bob <- crypt_ec_keygen("P-256")
identical(crypt_ec_dh(alice, bob$pubkey), crypt_ec_dh(bob, alice$pubkey))
#> [1] TRUE

sig <- crypt_signature_create(charToRaw("hi"), crypt_sha256, alice)
crypt_signature_verify(charToRaw("hi"), sig, crypt_sha256, alice$pubkey)
#> [1] TRUE
str(crypt_ecdsa_parse(sig))
#> List of 2
#>  $ r: raw [1:32] a3 ad ed a5 ...
#>  $ s: raw [1:32] eb 92 67 28 ...

a <- crypt_x25519_keygen()
b <- crypt_x25519_keygen()
identical(crypt_x25519_diffie_hellman(a, b$pubkey),
          crypt_x25519_diffie_hellman(b, a$pubkey))
#> [1] TRUE
```
