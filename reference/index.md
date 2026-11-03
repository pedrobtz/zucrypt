# Package index

## Hashing

Digests and keyed digests over raw vectors. This is what most callers
want, and
[`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
with its default is the right answer unless something external requires
otherwise.

- [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
  : Compute a Message Digest
- [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md)
  : Compute an HMAC
- [`crypt_hex()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hex.md)
  : Encode Bytes as Hexadecimal

## Comparison and information

Comparing a secret without leaking how much of it you guessed, and
finding out what this build contains.

- [`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md)
  : Compare Two Raw Vectors Without Leaking Timing Information
- [`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md)
  : Report What This Build of 'zucrypt' Contains

## Randomness

Random bytes from the operating system, for keys, initialisation
vectors, nonces and salts. R’s random number generator is never
involved.

- [`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md)
  : Cryptographically Secure Random Bytes

## Authenticated encryption and key derivation

AES-GCM, which encrypts and authenticates together, and PBKDF2, which
derives a key from a password.

- [`crypt_aes_gcm_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md)
  [`crypt_aes_gcm_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_gcm.md)
  : AES-GCM Authenticated Encryption
- [`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md)
  : Derive a Key from a Password with PBKDF2

## Public keys and signatures (openssl-style)

RSA and elliptic-curve keys, signatures, RSA encryption and key
agreement, with openssl’s names and arguments under a crypt\_ prefix,
and the openssl-style digests they take.

- [`crypt_read_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  [`crypt_read_pubkey()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  [`crypt_rsa_keygen()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  [`crypt_write_pem()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  [`crypt_write_der()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  [`crypt_write_pkcs1()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  [`crypt_rsa_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_keys.md)
  : RSA Keys
- [`crypt_ec_keygen()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_ec_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_ec_dh()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_x25519_keygen()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_read_x25519_key()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_read_x25519_pubkey()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_x25519_diffie_hellman()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_ecdsa_parse()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  [`crypt_ecdsa_write()`](https://pedrobtz.github.io/zucrypt/reference/crypt_ec_keys.md)
  : Elliptic-Curve and X25519 Keys
- [`crypt_signature_create()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
  [`crypt_signature_verify()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
  [`crypt_rsa_encrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
  [`crypt_rsa_decrypt()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rsa_crypto.md)
  : Signatures and RSA Encryption
- [`crypt_sha1()`](https://pedrobtz.github.io/zucrypt/reference/crypt_sha.md)
  [`crypt_sha256()`](https://pedrobtz.github.io/zucrypt/reference/crypt_sha.md)
  [`crypt_sha384()`](https://pedrobtz.github.io/zucrypt/reference/crypt_sha.md)
  [`crypt_sha512()`](https://pedrobtz.github.io/zucrypt/reference/crypt_sha.md)
  : Digests in the Style of openssl

## Ciphers (advanced)

Unauthenticated AES-CBC, for reading and writing formats that specify
it. No padding is added or removed and nothing is authenticated:
ciphertext produced here can be altered undetectably, and detecting that
is the caller’s job. These are interoperability tools, not a way to
encrypt something of your own.

- [`crypt_aes_cbc_encrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md)
  [`crypt_aes_cbc_decrypt_nopad()`](https://pedrobtz.github.io/zucrypt/reference/crypt_aes_cbc_nopad.md)
  : AES-CBC Without Padding or Authentication

## C API

Consuming zucrypt from another package’s C code, through the registered
function table or the static archive.

- [`zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)
  [`zucrypt-c-api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)
  : Using 'zucrypt' from C

## Package

- [`zucrypt`](https://pedrobtz.github.io/zucrypt/reference/zucrypt-package.md)
  [`zucrypt-package`](https://pedrobtz.github.io/zucrypt/reference/zucrypt-package.md)
  : zucrypt: Cryptography Without System Dependencies
