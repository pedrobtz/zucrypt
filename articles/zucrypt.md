# Getting started with zucrypt

``` r

library(zucrypt)
```

zucrypt’s core is eleven functions:

| Function | What it is for |
|----|----|
| [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md) | A digest of some bytes: SHA-1, SHA-256, SHA-384 or SHA-512 |
| [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md) | A keyed digest (HMAC) of some bytes |
| [`crypt_hex()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hex.md) | Lower-case hex of some bytes, for printing or storing a digest |
| [`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md) | Comparing a secret value in constant time |
| [`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md) | Random bytes from the operating system, for keys, IVs and salts |
| [`crypt_aes_gcm_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md), [`crypt_aes_gcm_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md) | Authenticated encryption with AES-GCM |
| [`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md) | A key derived from a password |
| [`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md) | What the installed build contains |
| [`crypt_aes_cbc_encrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md), [`crypt_aes_cbc_decrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md) | Unauthenticated AES-CBC, for formats that specify it |

Beside the core, RSA keys and signatures follow the `openssl` package’s
names and arguments with a `crypt_` prefix:
[`crypt_read_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md),
[`crypt_write_pem()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md),
[`crypt_rsa_keygen()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md),
[`crypt_signature_create()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md),
[`crypt_rsa_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
and their partners, with the digests they take,
[`crypt_sha256()`](https://pedrobtz.github.io/zucrypt/reference/crypt_sha.md)
and its siblings. The section on RSA below introduces them.

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
#> [1] "`data` must be a raw vector or a connection, not character. Use charToRaw() to convert a string deliberately; this package never guesses an encoding, and never treats a string as a file name (pass file(path) for a file)."
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

Hex is an explicit step at the call site, not a default.
[`crypt_hex()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hex.md)
does it in C, so it costs little beside the hash:

``` r

crypt_hex(crypt_hash(msg))
#> [1] "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

That is the FIPS 180-2 test vector for SHA-256(“abc”). The other
algorithms are named exactly as `crypt_info()$algorithms` lists them:

``` r

crypt_info()$algorithms
#> [1] "sha1"   "sha256" "sha384" "sha512"

for (a in crypt_info()$algorithms) {
  cat(sprintf("%-6s %s\n", a, crypt_hex(crypt_hash(msg, a))))
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

crypt_hex(crypt_hash(raw(0)))
#> [1] "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

A file is hashed by passing a connection, never its path as a string. It
is read in 1 MiB chunks, so its size does not matter:

``` r

path <- tempfile()
writeBin(msg, path)
crypt_hex(crypt_hash(file(path)))
#> [1] "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
unlink(path)
```

An unopened connection is opened in binary mode and closed again; one
you have already opened must be in binary mode (`"rb"`), because a
text-mode connection may change the bytes before they are hashed.
[`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md)
takes connections in the same way.

## `crypt_hmac()`: keyed digests

An HMAC is a digest that only someone holding the key can compute, which
makes it the standard way to check that data has not been changed by
someone who does not hold the key. The key is raw too, of any length:

``` r

key <- charToRaw("Jefe")
tag <- crypt_hmac(charToRaw("what do ya want for nothing?"), key)
crypt_hex(tag)
#> [1] "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
```

That is test case 2 of RFC 4231. The algorithm argument works as it does
for
[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md):

``` r

crypt_hex(crypt_hmac(charToRaw("what do ya want for nothing?"), key, "sha512"))
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

## `crypt_rand_bytes()`: random bytes

A key, an IV or a salt needs bytes nobody can predict.
[`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md)
draws them from the operating system’s cryptographic source:

``` r

crypt_rand_bytes(16)
#>  [1] 65 ec 1d 5d 7a 7d 4b a7 e2 a6 64 32 e5 2a 06 d8
```

R’s own random number generator is not involved, so
[`set.seed()`](https://rdrr.io/r/base/Random.html) does not make it
repeat, and drawing bytes does not disturb a simulation that relies on
[`set.seed()`](https://rdrr.io/r/base/Random.html):

``` r

set.seed(1)
a <- crypt_rand_bytes(8)
set.seed(1)
identical(a, crypt_rand_bytes(8))
#> [1] FALSE
```

`crypt_info()$build_flags$random_backend` names the source compiled in.

## AES-GCM: authenticated encryption

[`crypt_aes_gcm_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md)
encrypts and authenticates in one step. The result is the ciphertext,
with the 12-byte nonce and the 16-byte tag attached as attributes. The
nonce is drawn fresh for each message unless you supply one:

``` r

key <- crypt_rand_bytes(32)
sealed <- crypt_aes_gcm_encrypt(charToRaw("meet at noon"), key)
sealed
#>  [1] fd 6c 55 af d6 32 e8 d1 4a 2f 9e dc
#> attr(,"iv")
#>  [1] 18 27 fb c1 18 71 d1 47 09 2b af 32
#> attr(,"tag")
#>  [1] f5 bb 38 27 f7 9e d9 4a 21 a8 a0 4e 95 f7 62 45
```

[`crypt_aes_gcm_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md)
reads the nonce and tag back from those attributes, checks the tag, and
only then returns the plaintext:

``` r

rawToChar(crypt_aes_gcm_decrypt(sealed, key))
#> [1] "meet at noon"
```

A changed ciphertext, tag, nonce or key is an error of class
`zucrypt_auth_error`, and nothing is decrypted:

``` r

tampered <- sealed
tampered[1] <- xor(tampered[1], as.raw(1))
e <- tryCatch(crypt_aes_gcm_decrypt(tampered, key), error = function(e) e)
class(e)
#> [1] "zucrypt_auth_error" "zucrypt_error"      "error"             
#> [4] "condition"
```

Data that must be authenticated but not encrypted, such as a header or a
record number, goes in `aad`, and decryption needs the same bytes.

Two rules carry the security. Never reuse a nonce with the same key: the
default random nonce is safe for about 2^32 messages per key. And keep
the key a key: 16, 24 or 32 random bytes, or the output of
[`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md).

The names and argument order follow
[`openssl::aes_gcm_encrypt()`](https://jeroen.r-universe.dev/openssl/reference/aes_cbc.html),
and the ciphertext bytes are the same. openssl returns no tag, though,
and its decryption accepts altered ciphertext, so the two are not
interchangeable.

## `crypt_pbkdf2()`: a key from a password

A password is not a key.
[`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md)
stretches one into a key with PBKDF2-HMAC, given a random salt and an
iteration count:

``` r

salt <- crypt_rand_bytes(16)
key <- crypt_pbkdf2(charToRaw("correct horse battery staple"), salt,
                    iterations = 10000)
length(key)
#> [1] 32
```

The password is raw, so its encoding is your decision. Keep the salt and
the iteration count with what the key protects: the same password, salt
and count give the same key, and nothing else does. Choose the count
from the time you can afford; OWASP recommended 600,000 for SHA-256 in
2023.

## `crypt_info()`: what is installed

[`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
reports what this build actually contains. Everything in it is read from
the compiled library, so it describes the code you are running, not a
file that says what was meant to be compiled:

``` r

str(crypt_info())
#> List of 5
#>  $ version    :Classes 'package_version', 'numeric_version'  hidden list of 1
#>   ..$ : int [1:4] 0 1 0 9000
#>  $ abi_version: int 1
#>  $ algorithms : chr [1:4] "sha1" "sha256" "sha384" "sha512"
#>  $ vendored   :'data.frame': 1 obs. of  2 variables:
#>   ..$ source : chr "TF-PSA-Crypto"
#>   ..$ version: chr "1.1.1"
#>  $ build_flags:List of 3
#>   ..$ random_backend       : chr "getrandom"
#>   ..$ aes_implementation   : chr "aesni"
#>   ..$ hardware_acceleration: logi TRUE
```

`vendored` names the bundled cryptography library and its version. That
matters because a vendored library is updated by updating the package,
not by updating your operating system. `abi_version` is the version of
the C interface that other packages link against (see
[`?zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)).

## RSA keys and signatures

RSA keys are read and written as PEM or DER (PKCS#1, PKCS#8 and
SubjectPublicKeyInfo), byte for byte as `openssl` writes them, and the
functions are named as `openssl` names them:

``` r

key <- crypt_rsa_keygen(2048)
key
#> [2048-bit rsa private key]
cat(crypt_write_pem(key$pubkey))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4r91ZHbHeJfJ9P5bTglz
#> CwMs0172lZVeYxoHZFsTdL4zKgAOfb4mGl/Tq5gmZd+PYgf/B8ETue1SayL6D7Lc
#> ADjIQM3G/XjBpqnTMAKsXhhEOaqNxsUCkSGd6L/MSNtLjch7hnERS9ATIneHgRTc
#> P1LLZlAvyj8fs+daWiZ3ytC5GUKKdHvPlsluvJUgowVd2NeXGuJiVwiN7lfdPAiO
#> oY83LaS63ymeKGQJrzHVDlLPm4NRWhaUEloZgf17rvnpOoLSMO6i9rTqcmrhFzIM
#> neXQDCY8jTfnwlRPKc4JGaX9S8pwoR59aR2DlKJl6pyAUQbU/G4xNHMip+W7Op0V
#> IwIDAQAB
#> -----END PUBLIC KEY-----
```

A signature covers a digest of the data. `hash` names the digest
function, as in `openssl`:

``` r

msg <- charToRaw("pay 10 to Alice")
sig <- crypt_signature_create(msg, crypt_sha256, key)
crypt_signature_verify(msg, sig, crypt_sha256, key$pubkey)
#> [1] TRUE
```

`pss = TRUE` makes an RSASSA-PSS signature instead of PKCS#1 v1.5. A
signature that does not verify is an error of class
`zucrypt_auth_error`.

RSA encryption is for short secrets, such as a key for AES-GCM. Use
OAEP; `oaep_hash` chooses its digest:

``` r

aes_key <- crypt_rand_bytes(32)
wrapped <- crypt_rsa_encrypt(aes_key, key$pubkey, oaep = TRUE,
                             oaep_hash = "sha256")
identical(crypt_rsa_decrypt(wrapped, key, oaep = TRUE, oaep_hash = "sha256"),
          aes_key)
#> [1] TRUE
```

A key also comes apart into its integers, and is built back from them,
which is how a JSON Web Key carries one:

``` r

names(as.list(key)$data)
#> [1] "e"  "n"  "p"  "q"  "d"  "dp" "dq" "qi"
```

Key objects live in C and do not survive
[`saveRDS()`](https://rdrr.io/r/base/readRDS.html); save the PEM
instead. Password-protected keys and SSH formats are not in this
version.

## Elliptic curves and X25519

Keys on P-256, P-384 and P-521 sign with ECDSA through the same
functions, and agree on a shared secret with
[`crypt_ec_dh()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md):

``` r

alice <- crypt_ec_keygen("P-256")
bob <- crypt_ec_keygen("P-256")
sig <- crypt_signature_create(msg, crypt_sha256, alice)
crypt_signature_verify(msg, sig, crypt_sha256, alice$pubkey)
#> [1] TRUE
identical(crypt_ec_dh(alice, bob$pubkey), crypt_ec_dh(bob, alice$pubkey))
#> [1] TRUE
```

ECDSA signatures come as DER, as `openssl` returns them;
[`crypt_ecdsa_parse()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
gives their `r` and `s`. `deterministic = TRUE` makes an RFC 6979
signature, the same for the same key and message.

X25519 keys only agree on secrets:

``` r

a <- crypt_x25519_keygen()
b <- crypt_x25519_keygen()
identical(crypt_x25519_diffie_hellman(a, b$pubkey),
          crypt_x25519_diffie_hellman(b, a$pubkey))
#> [1] TRUE
```

A shared secret is not a key. Derive keys from it, for example with HKDF
or the Concat KDF a protocol specifies. There is no Ed25519: the bundled
library has no EdDSA.

## AES-CBC: for formats that specify it

[`crypt_aes_cbc_encrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md)
and
[`crypt_aes_cbc_decrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md)
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

ct <- crypt_aes_cbc_encrypt_nopad(pt, key, iv)
crypt_hex(ct)
#> [1] "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
identical(crypt_aes_cbc_decrypt_nopad(ct, key, iv), pt)
#> [1] TRUE
```

The IV is fixed here only so that the output can be compared with the
standard. An IV used to encrypt real data must be unpredictable and
never reused with the same key.

### Padding is yours

Data that is not a multiple of 16 bytes is refused, not padded:

``` r

e <- tryCatch(crypt_aes_cbc_encrypt_nopad(charToRaw("hello"), key, iv),
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
rawToChar(unpad_pkcs7(crypt_aes_cbc_decrypt_nopad(
  crypt_aes_cbc_encrypt_nopad(padded, key, iv), key, iv)))
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
segmented <- unlist(lapply(segments, crypt_aes_cbc_encrypt_nopad, key = key, iv = iv),
                    use.names = FALSE)

# The first segment is the first block of the stream, so it matches:
identical(segmented[1:16], ct[1:16])
#> [1] TRUE
# The second does not continue the chain; it restarted from the IV:
identical(segmented[17:32], ct[17:32])
#> [1] FALSE
identical(segmented[17:32], crypt_aes_cbc_encrypt_nopad(pt[17:32], key, iv))
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
  ct <- crypt_aes_cbc_encrypt_nopad(pad_pkcs7(plaintext), enc_key, iv)
  list(iv = iv, ct = ct, tag = crypt_hmac(c(iv, ct), mac_key))
}
open_sealed <- function(box) {
  expected <- crypt_hmac(c(box$iv, box$ct), mac_key)
  if (!crypt_equal(box$tag, expected)) stop("authentication failed")
  unpad_pkcs7(crypt_aes_cbc_decrypt_nopad(box$ct, enc_key, box$iv))
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

e <- tryCatch(crypt_aes_cbc_encrypt_nopad(raw(32), raw(15), raw(16)),
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
| `zucrypt_connection_error` | A connection passed as `data` could not be opened, or ran dry before its end |
| `zucrypt_memory_error` | An allocation failed |
| `zucrypt_entropy_error` | The operating system’s random source failed |
| `zucrypt_auth_error` | Authenticated decryption failed: the ciphertext, tag, nonce, associated data or key is wrong, and no plaintext is returned. Also a signature that does not verify, and an RSA ciphertext that does not decrypt |
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

zucrypt is small today. For most R work another package is the better
choice:

| You want | Reach for |
|----|----|
| Ed25519, certificates, SSH keys, broad algorithm coverage | [openssl](https://cran.r-project.org/package=openssl) |
| Modern authenticated encryption that is hard to misuse | [sodium](https://cran.r-project.org/package=sodium), or [rmonocypher](https://cran.r-project.org/package=rmonocypher) with no system library |
| A cache key for an R object, or a fast non-cryptographic hash | [digest](https://cran.r-project.org/package=digest) |
| SHA-2, HMAC, AES-GCM, PBKDF2, RSA, ECDSA or X25519 with no system library, a constant-time compare, or cryptography callable from your package’s C code | zucrypt |
