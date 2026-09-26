# Getting started with zucrypt

``` r

library(zucrypt)
```

zucrypt has six functions:

| Function | What it is for |
|----|----|
| [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md) | A digest of some bytes: SHA-1, SHA-256, SHA-384 or SHA-512 |
| [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md) | A keyed digest (HMAC) of some bytes |
| [`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md) | Comparing a secret value in constant time |
| [`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md) | What the installed build contains |
| [`crypt_aes_cbc_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md), [`crypt_aes_cbc_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md) | Unauthenticated AES-CBC, for formats that specify it |

This article walks through each of them. The short version is that there
is not much to learn, on purpose: every function takes raw vectors and
returns raw vectors, algorithm names are matched exactly, and anything
wrong is an error with a class you can catch.

## Bytes in, bytes out

Every argument that holds data or a key is a **raw vector**. zucrypt
never guesses how to turn something else into bytes, so a character
string is an error rather than a silent conversion:

``` r

e <- tryCatch(crypt_hash("the quick brown fox"), error = function(e) e)
class(e)
#> [1] "zucrypt_invalid_argument" "zucrypt_error"           
#> [3] "error"                    "condition"
conditionMessage(e)
#> [1] "`data` must be a raw vector, not character. Use charToRaw() to convert a string deliberately; this package never guesses an encoding, and never treats a string as a file name."
```

The conversion is always yours to make, and it is always one line:

``` r

crypt_hash(charToRaw("the quick brown fox"))
#>  [1] 9e cb 36 56 13 41 d1 8e b6 54 84 e8 33 ef ea 61 ed c7 4b 84 cf 5e 6a e1 b8
#> [26] 1c 63 53 3e 25 fc 8f
```

The same goes for anything else you want to hash. Each of these is a
deliberate choice about *which* bytes, which is exactly the choice a
package should not make for you:

``` r

# An R object: serialize() decides the bytes, and its `version` and `ascii`
# arguments change them, so pin what you rely on.
digest_of_object <- crypt_hash(serialize(mtcars, NULL, version = 3))

# A file's contents, read as bytes, never as text.
path <- tempfile()
writeLines("some file contents", path)
digest_of_file <- crypt_hash(readBin(path, "raw", n = file.size(path)))
```

A string is text in some encoding.
[`charToRaw()`](https://rdrr.io/r/base/rawConversion.html) gives you the
bytes R holds for it; if the string might not be UTF-8, convert it first
with [`enc2utf8()`](https://rdrr.io/r/base/Encoding.html) so that the
same text always hashes the same way.

## `crypt_hash()`: digests

The default is SHA-256, and unless an external format requires something
else, that is the right choice:

``` r

msg <- charToRaw("abc")
crypt_hash(msg)
#>  [1] ba 78 16 bf 8f 01 cf ea 41 41 40 de 5d ae 22 23 b0 03 61 a3 96 17 7a 9c b4
#> [26] 10 ff 61 f2 00 15 ad
```

Hex is an explicit step at the call site, not a default:

``` r

hex <- function(x) paste(format(x), collapse = "")
hex(crypt_hash(msg))
#> [1] "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

That is the FIPS 180-2 test vector for SHA-256(“abc”). The other
algorithms are named exactly as `crypt_info()$algorithms` lists them:

``` r

crypt_info()$algorithms
#> [1] "sha1"   "sha256" "sha384" "sha512"

for (a in crypt_info()$algorithms) {
  cat(sprintf("%-6s %s\n", a, hex(crypt_hash(msg, a))))
}
#> sha1   a9993e364706816aba3e25717850c26c9cd0d89d
#> sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
#> sha384 cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
#> sha512 ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
```

Exact means exact: there is no partial matching and no fallback, so a
typo cannot quietly select a different digest.

``` r

e <- tryCatch(crypt_hash(msg, "sha"), error = function(e) e)
class(e)
#> [1] "zucrypt_unsupported_algorithm" "zucrypt_error"                
#> [3] "error"                         "condition"
```

SHA-1 is there because some existing formats specify it. Do not choose
it for anything new.

The digest of empty input is well defined, and you get it:

``` r

hex(crypt_hash(raw(0)))
#> [1] "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

## `crypt_hmac()`: keyed digests

An HMAC is a digest that only someone holding the key can compute, which
makes it the standard way to check that data has not been changed by
someone who does not hold the key. The key is raw too, of any length:

``` r

key <- charToRaw("Jefe")
tag <- crypt_hmac(charToRaw("what do ya want for nothing?"), key)
hex(tag)
#> [1] "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
```

That is test case 2 of RFC 4231. The algorithm argument works as it does
for
[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md):

``` r

hex(crypt_hmac(charToRaw("what do ya want for nothing?"), key, "sha512"))
#> [1] "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
```

In real use the key should be random bytes from a cryptographic source,
at least as long as the digest, and kept secret. zucrypt does not
generate randomness;
[`openssl::rand_bytes()`](https://jeroen.r-universe.dev/openssl/reference/rand_bytes.html)
or `sodium::random()` do. R’s own
[`sample()`](https://rdrr.io/r/base/sample.html) and
[`runif()`](https://rdrr.io/r/stats/Uniform.html) do not, whatever the
seed.

## `crypt_equal()`: checking a secret

When you check a tag you received against the one you expect, compare
with
[`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md),
never [`identical()`](https://rdrr.io/r/base/identical.html) or `==`:

``` r

received <- tag
crypt_equal(received, crypt_hmac(charToRaw("what do ya want for nothing?"), key))
#> [1] TRUE

tampered <- crypt_hmac(charToRaw("what do ya want for nothing!"), key)
crypt_equal(tampered, tag)
#> [1] FALSE
```

An ordinary comparison stops at the first byte that differs, so how long
it takes tells an attacker how many leading bytes of their guess were
right — and a tag can then be guessed one byte at a time.
[`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md)
takes the same time whatever the contents.

The length is not treated as secret: inputs of different lengths are
simply not equal.

``` r

crypt_equal(tag, tag[1:16])
#> [1] FALSE
```

## `crypt_info()`: what is installed

[`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
reports what this build actually contains. Everything in it is read from
the compiled library, so it describes the code you are running, not a
file that says what was meant to be compiled:

``` r

str(crypt_info())
#> List of 5
#>  $ version    :Classes 'package_version', 'numeric_version'  hidden list of 1
#>   ..$ : int [1:3] 0 1 0
#>  $ abi_version: int 1
#>  $ algorithms : chr [1:4] "sha1" "sha256" "sha384" "sha512"
#>  $ vendored   :'data.frame': 1 obs. of  2 variables:
#>   ..$ source : chr "TF-PSA-Crypto"
#>   ..$ version: chr "1.1.1"
#>  $ build_flags:List of 2
#>   ..$ random_backend       : chr "getrandom"
#>   ..$ hardware_acceleration: logi FALSE
```

`vendored` names the bundled cryptography library and its version. That
matters because a vendored library is updated by updating the package,
not by updating your operating system. `abi_version` is the version of
the C interface that other packages link against (see
[`?zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)).

## AES-CBC: for formats that specify it

[`crypt_aes_cbc_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md)
and
[`crypt_aes_cbc_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md)
are **interoperability tools**, for reading and writing file formats
that are defined in terms of AES-CBC. They are deliberately low-level:

- **No padding is added or removed.** The data must already be a
  multiple of 16 bytes.
- **Nothing is authenticated.** Anyone who can reach a ciphertext can
  change it, and decryption will return changed plaintext without
  complaint.
- The key must be 16, 24 or 32 bytes (AES-128, -192 or -256), and the IV
  exactly 16.

If you want to encrypt something of your own, use a construction that
authenticates — `sodium::data_encrypt()`, for example — rather than
assembling one from these. The rest of this section shows what these
functions do and what “doing it correctly” requires, which is also the
argument for not doing it yourself.

### Reproducing a published vector

This is the first two blocks of the NIST SP 800-38A F.2.1 example, which
is the kind of thing these functions exist for: matching bytes that
another implementation specifies.

``` r

unhex <- function(x) {
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}
key <- unhex("2b7e151628aed2a6abf7158809cf4f3c")
iv  <- unhex("000102030405060708090a0b0c0d0e0f")
pt  <- unhex(paste0("6bc1bee22e409f96e93d7e117393172a",
                    "ae2d8a571e03ac9c9eb76fac45af8e51"))

ct <- crypt_aes_cbc_encrypt(pt, key, iv)
hex(ct)
#> [1] "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
identical(crypt_aes_cbc_decrypt(ct, key, iv), pt)
#> [1] TRUE
```

The IV is fixed here only so that the output can be compared with the
standard. An IV used to encrypt real data must be unpredictable and
never reused with the same key.

### Padding is yours

Data that is not a multiple of 16 bytes is refused, not padded:

``` r

e <- tryCatch(crypt_aes_cbc_encrypt(charToRaw("hello"), key, iv),
              error = function(e) e)
class(e)
#> [1] "zucrypt_bad_length" "zucrypt_error"      "error"             
#> [4] "condition"
```

If your format uses PKCS#7 padding, apply and check it yourself:

``` r

pad_pkcs7 <- function(x) {
  n <- 16L - length(x) %% 16L
  c(x, as.raw(rep(n, n)))
}
unpad_pkcs7 <- function(x) {
  n <- as.integer(x[length(x)])
  stopifnot(n >= 1L, n <= 16L, all(x[length(x) - seq_len(n) + 1L] == as.raw(n)))
  x[seq_len(length(x) - n)]
}

padded <- pad_pkcs7(charToRaw("hello"))
length(padded)
#> [1] 16
rawToChar(unpad_pkcs7(crypt_aes_cbc_decrypt(
  crypt_aes_cbc_encrypt(padded, key, iv), key, iv)))
#> [1] "hello"
```

### Formats that restart the chain

Some formats split data into segments and restart CBC at each boundary
with its own IV — Office’s agile encryption does this in 4096-byte
segments. Each call starts from the IV it is given, so a segmented
format is one call per segment:

``` r

# The NIST plaintext above as two 16-byte "segments", each from the same IV.
segments <- split(pt, rep(1:2, each = 16))
segmented <- unlist(lapply(segments, crypt_aes_cbc_encrypt, key = key, iv = iv),
                    use.names = FALSE)

# The first segment is the first block of the stream, so it matches:
identical(segmented[1:16], ct[1:16])
#> [1] TRUE
# The second does not continue the chain; it restarted from the IV:
identical(segmented[17:32], ct[17:32])
#> [1] FALSE
identical(segmented[17:32], crypt_aes_cbc_encrypt(pt[17:32], key, iv))
#> [1] TRUE
```

In a real format each segment gets its own IV, derived as the format
specifies; here both use one IV only to keep the example short.

### Authenticating what you encrypt

If you must build on CBC, the minimum is **encrypt-then-MAC**: compute
an HMAC over the IV and the ciphertext with a *second, independent* key,
send the tag alongside, and check it with
[`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md)
*before* decrypting anything.

``` r

enc_key <- unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
mac_key <- as.raw(1:32)   # in real use: 32 random bytes, kept secret

seal <- function(plaintext, iv) {
  ct <- crypt_aes_cbc_encrypt(pad_pkcs7(plaintext), enc_key, iv)
  list(iv = iv, ct = ct, tag = crypt_hmac(c(iv, ct), mac_key))
}
open_sealed <- function(box) {
  expected <- crypt_hmac(c(box$iv, box$ct), mac_key)
  if (!crypt_equal(box$tag, expected)) stop("authentication failed")
  unpad_pkcs7(crypt_aes_cbc_decrypt(box$ct, enc_key, box$iv))
}

box <- seal(charToRaw("meet at noon"), iv)
rawToChar(open_sealed(box))
#> [1] "meet at noon"

box$ct[1] <- xor(box$ct[1], as.raw(1))   # one bit flipped in transit
tryCatch(open_sealed(box), error = function(e) conditionMessage(e))
#> [1] "authentication failed"
```

Without the tag, that flipped bit would have decrypted into altered
plaintext and nothing would have noticed. Getting every detail of this
right — separate keys, the IV inside the MAC, checking before
decrypting, a fresh random IV each time — is exactly why a ready-made
authenticated construction is the better tool for your own data.

## When something goes wrong

Every error is a condition with a specific class, then `zucrypt_error`,
then `error`. Branch on the class, never on the message, which may be
reworded:

``` r

e <- tryCatch(crypt_aes_cbc_encrypt(raw(32), raw(15), raw(16)),
              error = function(e) e)
class(e)
#> [1] "zucrypt_bad_length" "zucrypt_error"      "error"             
#> [4] "condition"
e$algorithm
#> [1] "aes-cbc"
```

| Class | Raised when |
|----|----|
| `zucrypt_invalid_argument` | An argument has the wrong type, for example a string where raw bytes are needed |
| `zucrypt_unsupported_algorithm` | An algorithm name is not one of `crypt_info()$algorithms` |
| `zucrypt_bad_length` | A key, IV or data length is not allowed |
| `zucrypt_memory_error` | An allocation failed |
| `zucrypt_backend_error`, `zucrypt_internal_error` | The cryptographic library refused, or an invariant broke; please report these |

Every condition also carries `algorithm` and `native_status` fields.
None of them ever contains a key, an IV or any of your data, so an error
message is safe to paste into a bug report.

``` r

handled <- tryCatch(
  crypt_hash(msg, "md5"),
  zucrypt_unsupported_algorithm = function(e) "md5 is not provided; use sha256"
)
handled
#> [1] "md5 is not provided; use sha256"
```

## From C

The same primitives are available to other packages’ compiled code,
either through a registered function table or by linking a static
library, with no R involved at run time. See
[`?zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md).

## Is this the right package?

zucrypt is deliberately narrow. For most R work another package is the
better choice:

| You want | Reach for |
|----|----|
| Keys, certificates, signatures, broad algorithm coverage | [openssl](https://cran.r-project.org/package=openssl) |
| Modern authenticated encryption that is hard to misuse | [sodium](https://cran.r-project.org/package=sodium) |
| A cache key for an R object, or a fast non-cryptographic hash | [digest](https://cran.r-project.org/package=digest) |
| SHA-2 and HMAC with no system library, a constant-time compare, or cryptography callable from your package’s C code | zucrypt |
