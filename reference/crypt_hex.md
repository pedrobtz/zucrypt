# Encode bytes as hexadecimal

Converts a raw vector to one lower-case hexadecimal string, two digits
per byte, with no separators and no prefix: the form `sha256sum` prints
and most formats store. The conversion runs in C, so for a short digest
it costs far less than the hash itself.

## Usage

``` r
crypt_hex(x)
```

## Arguments

- x:

  A raw vector, at most 2^30 - 1 bytes long (a longer result would
  exceed R's limit on the length of a single string).

## Value

A character vector of length one, `2 * length(x)` characters long.
`crypt_hex(raw(0))` is `""`.

## Details

Hex is an explicit step at the call site rather than an option on
[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
and
[`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md),
so the digest functions return one type and a caller who wants text says
so. It works on any bytes: a digest, a MAC, a key you need to print for
a test.

## See also

[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
and
[`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md),
whose results this is usually applied to.

## Examples

``` r
crypt_hex(crypt_hash(charToRaw("abc")))
#> [1] "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

crypt_hex(as.raw(c(0x00, 0x0f, 0xa0, 0xff)))
#> [1] "000fa0ff"

crypt_hex(raw(0))
#> [1] ""
```
