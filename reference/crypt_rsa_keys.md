# RSA Keys

Read, write, generate and take apart RSA keys. The names, arguments and
defaults follow the `openssl` package with a `crypt_` prefix, and the
encodings interoperate: a key one package writes, the other reads.

- `crypt_read_key()` reads a private key and `crypt_read_pubkey()` a
  public key, from PEM or DER: PKCS#1, PKCS#8 or SubjectPublicKeyInfo.
  `crypt_read_pubkey()` also accepts a private key and keeps its public
  half.

- `crypt_write_pem()` writes PKCS#8 (`PRIVATE KEY`) or
  SubjectPublicKeyInfo (`PUBLIC KEY`) PEM; `crypt_write_pkcs1()` writes
  PKCS#1 PEM (`RSA PRIVATE KEY`, `RSA PUBLIC KEY`); `crypt_write_der()`
  writes a private key as PKCS#1 DER and a public key as
  SubjectPublicKeyInfo DER, as
  [`openssl::write_der()`](https://jeroen.r-universe.dev/openssl/reference/write_pem.html)
  does.

- `crypt_rsa_keygen()` generates a key pair from the operating system's
  random source.

- `crypt_rsa_key()` builds a key from its integers, as a JSON Web Key
  carries them, and [`as.list()`](https://rdrr.io/r/base/list.html)
  takes one apart again.

A key object is an external pointer to key material held in C, and the
material of a private key is wiped when the object is garbage collected.
Key objects do not survive
[`saveRDS()`](https://rdrr.io/r/base/readRDS.html); save the PEM
instead.

## Usage

``` r
crypt_read_key(file, password = NULL, der = is.raw(file))

crypt_read_pubkey(file, der = is.raw(file))

crypt_rsa_keygen(bits = 2048)

crypt_write_pem(x, path = NULL, password = NULL)

crypt_write_der(x, path = NULL)

crypt_write_pkcs1(x, path = NULL, password = NULL)

crypt_rsa_key(
  n,
  e,
  d = NULL,
  p = NULL,
  q = NULL,
  dp = NULL,
  dq = NULL,
  qi = NULL
)
```

## Arguments

- file:

  The key: a raw vector of DER or PEM bytes, a single string of PEM
  text, a path to a file holding either, or a connection.

- password:

  Not supported yet: password-protected keys arrive in a later version.
  Must be `NULL`.

- der:

  Accepted for compatibility with `openssl`; the encoding is recognised
  from the content.

- bits:

  The modulus size, from 1024 to 4096. 2048 is the minimum for new keys;
  use 3072 or more for keys meant to last.

- x:

  A key from `crypt_read_key()`, `crypt_read_pubkey()`,
  `crypt_rsa_keygen()` or `crypt_rsa_key()`.

- path:

  `NULL` to return the encoding, or a file to write it to.

- n, e:

  The modulus and the public exponent, as raw big-endian unsigned
  integers.

- d, p, q, dp, dq, qi:

  The private exponent, the primes and the CRT parameters, as raw
  big-endian unsigned integers. Give all six for a private key, or none
  for a public key.

## Value

`crypt_read_key()`, `crypt_rsa_keygen()` and `crypt_rsa_key()` with the
private members return a key of class `c("crypt_key", "crypt_rsa")`;
`crypt_read_pubkey()` and `crypt_rsa_key()` without them return one of
class `c("crypt_pubkey", "crypt_rsa")`. `crypt_write_pem()` and
`crypt_write_pkcs1()` return a string, and `crypt_write_der()` a raw
vector, or with `path` write it and return `path` invisibly.
[`as.list()`](https://rdrr.io/r/base/list.html) returns `type`, `size`,
for a private key `pubkey`, and `data`: the integers as raw vectors,
`e`, `n` and for a private key `p`, `q`, `d`, `dp`, `dq` and `qi`.

## Errors

Input that is not a readable key is `zucrypt_invalid_argument`; a key of
another type, such as an EC key, is `zucrypt_unsupported_algorithm`.

## Compared with openssl

Only RSA keys are read in this version, of at most 4096 bits; encrypted
keys, SSH formats and fingerprints come later.
[`as.list()`](https://rdrr.io/r/base/list.html) gives the integers as
raw vectors rather than `bignum`s. There is no default key: `openssl`
reads `~/.ssh/id_rsa`, and this package never reads your files unless
you name them.

## Examples

``` r
key <- crypt_rsa_keygen(2048)
key
#> [2048-bit rsa private key]
pem <- crypt_write_pem(key$pubkey)
cat(pem)
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAza9ptW2dGwz26uFkKMMV
#> FQmPxJ781eyb5hpsW18OxvJl7RfXMBtK8qwPmooIi7nhGa8/6S27To+RVCyH6ebL
#> Q8epO8OWZ3rNEWInaCXPxAhwaHzu7ezwBKgOp6sR+WcF3aYu6BdKaXTnvGWm0wml
#> qN347wLamgkr+DaaLfod4my0qh7TqyaApV/fJdAdqGb72MpeXK5jyb4OAWuaLJDJ
#> WQS2RLYfszlWhSguBM31FaNWMuaiyHGimZlbugvdpI0S0H/6nODKLxF4rhGEPIZw
#> NF/Os9Jo7gq7Ehj4JKwq7SzOwqCxQ028HhbQrxysEP6yxdOV0l6Nzb1XewcKqLvC
#> rQIDAQAB
#> -----END PUBLIC KEY-----
pub <- crypt_read_pubkey(pem)

# The integers a JSON Web Key carries, and back.
parts <- as.list(pub)$data
identical(crypt_write_der(crypt_rsa_key(parts$n, parts$e)),
          crypt_write_der(pub))
#> [1] TRUE
```
