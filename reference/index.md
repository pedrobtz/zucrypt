# Package index

## Hashing

Digests and keyed digests over raw vectors. This is what most callers
want, and
[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
with its default is the right answer unless something external requires
otherwise.

- [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
  : Compute a message digest
- [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md)
  : Compute an HMAC

## Comparison and information

Comparing a secret without leaking how much of it you guessed, and
finding out what this build contains.

- [`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md)
  : Compare two raw vectors without leaking timing information
- [`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
  : Report what this build of zucrypt contains

## Ciphers (advanced)

Unauthenticated AES-CBC, for reading and writing formats that specify
it. No padding is added or removed and nothing is authenticated:
ciphertext produced here can be altered undetectably, and detecting that
is the caller’s job. These are interoperability tools, not a way to
encrypt something of your own.

- [`crypt_aes_cbc_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md)
  [`crypt_aes_cbc_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc.md)
  : AES-CBC, without padding and without authentication

## C API

Consuming zucrypt from another package’s C code, through the registered
function table or the static archive.

- [`zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)
  [`zucrypt-c-api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)
  : Using zucrypt from C

## Package

- [`zucrypt`](https://pedrobtz.github.io/zucrypt/reference/zucrypt-package.md)
  [`zucrypt-package`](https://pedrobtz.github.io/zucrypt/reference/zucrypt-package.md)
  : zucrypt: Narrow Cryptographic Primitives with a Vendored Backend
