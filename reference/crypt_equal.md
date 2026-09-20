# Compare two raw vectors without leaking timing information

Compares in time that does not depend on the contents of the buffers.
Use it whenever one side is a secret: an authentication tag, a password
verifier, a derived key.

## Usage

``` r
crypt_equal(x, y)
```

## Arguments

- x, y:

  Raw vectors.

## Value

`TRUE` if the vectors have the same length and the same contents,
otherwise `FALSE`.

## Length is not hidden

Vectors of different lengths return `FALSE` immediately, without
comparing anything. Hiding a length difference is not something a
comparison function can do, and pretending otherwise would be worse than
saying so: if the length of your secret is itself secret, compare
digests of the values rather than the values.

## Examples

``` r
a <- crypt_hash(charToRaw("message"))
b <- crypt_hash(charToRaw("message"))
crypt_equal(a, b)
#> [1] TRUE

crypt_equal(a, crypt_hash(charToRaw("different")))
#> [1] FALSE

# Different lengths are simply not equal.
crypt_equal(a, raw(0))
#> [1] FALSE
```
