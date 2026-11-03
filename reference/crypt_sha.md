# Digests in the Style of openssl

`crypt_sha1()`, `crypt_sha256()`, `crypt_sha384()` and `crypt_sha512()`
mirror
[`openssl::sha1()`](https://jeroen.r-universe.dev/openssl/reference/hash.html)
and its siblings for raw input: the digest, or with `key` the HMAC, as a
raw vector of class `c("hash", "<algorithm>")`, and `"hmac"` after them
for an HMAC. They exist first so that
[`crypt_signature_create()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
can take `hash = crypt_sha256` as
[`openssl::signature_create()`](https://jeroen.r-universe.dev/openssl/reference/signatures.html)
takes `hash = sha256`.

This version accepts raw vectors only. openssl also hashes character
vectors element-wise and reads connections; that typing, and the other
digests, arrive with the rest of the openssl-shaped layer.

`crypt_sha1()` is for formats that specify SHA-1. It is not collision
resistant; use `crypt_sha256()` for anything new.

## Usage

``` r
crypt_sha1(x, key = NULL)

crypt_sha256(x, key = NULL)

crypt_sha384(x, key = NULL)

crypt_sha512(x, key = NULL)
```

## Arguments

- x:

  A raw vector.

- key:

  `NULL` for a digest, or a raw key for an HMAC.

## Value

A raw vector of class `c("hash", "<algorithm>")`: 20, 32, 48 or 64
bytes.

## See also

[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
and
[`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md),
the core functions these wrap.

## Examples

``` r
crypt_sha256(charToRaw("abc"))
#> sha256 ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad 
crypt_sha256(charToRaw("abc"), key = charToRaw("secret"))
#> sha256 hmac 99:46:da:d4:e0:0e:91:3f:c8:be:8e:5d:3f:7e:11:0a:4a:9e:83:2f:83:fb:09:c3:45:28:5d:78:63:8d:8a:0e 
```
