# zucrypt (development version)

## R interface

* `crypt_rand_bytes(n = 1)` returns `n` bytes from the operating system's
  cryptographic random source, mirroring `openssl::rand_bytes()` (#9). R's
  random number generator is never used or disturbed, so `set.seed()` has no
  effect on it. A failure of the source raises the new
  `zucrypt_entropy_error` class and never returns bytes.

* `crypt_aes_gcm_encrypt()` and `crypt_aes_gcm_decrypt()` provide AES-GCM
  authenticated encryption (#10), with a 12-byte nonce, a 16-byte tag and
  optional associated data. The nonce is random unless supplied, and the
  nonce and tag travel as attributes of the ciphertext. Decryption checks the
  tag first: any alteration, a truncated tag or a wrong key raises the new
  `zucrypt_auth_error` class and returns no plaintext. The names and argument
  order follow `openssl`, and the ciphertext bytes match, but `openssl`
  returns no tag and does not authenticate, so this is a documented
  difference rather than a mirror.

* `crypt_pbkdf2()` derives a key from a raw password with PBKDF2-HMAC over
  SHA-1, SHA-256, SHA-384 or SHA-512 (#12).

* RSA, in the openssl-style layer (#80): `crypt_read_key()`,
  `crypt_read_pubkey()`, `crypt_write_pem()`, `crypt_write_der()`,
  `crypt_write_pkcs1()`, `crypt_rsa_keygen()`, `crypt_signature_create()`,
  `crypt_signature_verify()`, `crypt_rsa_encrypt()` and `crypt_rsa_decrypt()`
  keep `openssl`'s names and arguments. Keys are read and written as PKCS#1,
  PKCS#8 and SubjectPublicKeyInfo, PEM or DER, byte for byte as `openssl`
  writes them. Additions: `pss = TRUE` for RSASSA-PSS, `oaep_hash` for OAEP
  over SHA-256 and longer digests, and `crypt_rsa_key()` and `as.list()` to
  build a key from its integers and take it apart. Moduli of 1024 to 4096
  bits. A signature that does not verify, or a ciphertext that does not
  decrypt, is `zucrypt_auth_error`.

* Elliptic curves (#81): `crypt_ec_keygen()`, `crypt_ec_dh()`,
  `crypt_x25519_keygen()`, `crypt_x25519_diffie_hellman()`,
  `crypt_read_x25519_key()`, `crypt_read_x25519_pubkey()`,
  `crypt_ecdsa_parse()` and `crypt_ecdsa_write()` keep `openssl`'s names and
  arguments, and `crypt_signature_create()` and `_verify()` sign with ECDSA
  on P-256, P-384 and P-521, in DER, with `deterministic = TRUE` for RFC
  6979. `crypt_ec_key()` and `as.list()` build an EC key from its
  coordinates and take it apart. EC and X25519 keys are read and written in
  every encoding `openssl` uses, byte for byte. Points off the curve, peers
  on another curve and all-zero X25519 secrets are refused. There is no
  Ed25519.

* `crypt_sha1()`, `crypt_sha256()`, `crypt_sha384()` and `crypt_sha512()`
  mirror `openssl`'s digest and HMAC functions on raw input, so that
  `hash = crypt_sha256` works as `openssl`'s `hash = sha256` does.

## C interface

* `zuc_random_bytes()` is added to the archive, and `random_bytes` is
  appended to the registered table; test for it with
  `ZUCRYPT_API_HAS(api, random_bytes)`. Both are additions, as ABI 1 allows.
* `ZUC_ERR_ENTROPY = 10` is appended to `zuc_status`.
* `zuc_aead_encrypt()`, `zuc_aead_decrypt()` and `zuc_pbkdf2_hmac()` are
  added to the archive, and `aead_encrypt`, `aead_decrypt` and `pbkdf2_hmac`
  are appended to the table. `ZUC_ALG_AES_GCM = 96` is the first identifier
  in the cipher range, and `ZUC_ERR_AUTH = 11` is appended to `zuc_status`.
  The digest and HMAC functions refuse `ZUC_ALG_AES_GCM`.
* RSA: an opaque `zuc_pkey` handle with `zuc_pkey_parse()`,
  `zuc_pkey_generate()`, `zuc_pkey_public()`, `zuc_pkey_free()`,
  `zuc_pkey_type()`, `zuc_pkey_bits()`, `zuc_pkey_is_private()`,
  `zuc_pkey_write()`, `zuc_pkey_sign_hash()`, `zuc_pkey_verify_hash()`,
  `zuc_pkey_encrypt()` and `zuc_pkey_decrypt()`, appended to the archive and
  the table. New `zuc_alg` values: `ZUC_ALG_RSA_OAEP = 97`,
  `ZUC_ALG_RSA_PKCS1V15_CRYPT = 98`, `ZUC_ALG_RSA = 192`,
  `ZUC_ALG_RSA_PKCS1V15_SIGN = 224` and `ZUC_ALG_RSA_PSS = 225`.
* Elliptic curves: `zuc_pkey_import()`, `zuc_pkey_export()` (the backend's
  raw key forms) and `zuc_pkey_agree()` (ECDH and X25519), appended to the
  archive and the table; the `zuc_pkey_*` functions take EC keys too. New
  `zuc_alg` values: `ZUC_ALG_EC_P256` to `_P521` (193-195),
  `ZUC_ALG_X25519 = 196`, `ZUC_ALG_ECDH = 197`, `ZUC_ALG_ECDSA = 226` and
  `ZUC_ALG_ECDSA_DETERMINISTIC = 227`.

## Bug fixes

* A condition about a key now carries that key's type in its `algorithm`
  field (`"rsa"`, `"p256"`, `"p384"`, `"p521"` or `"x25519"`), and `NA` when
  the input is not a key (#143); every key condition said `"rsa"`. A public
  key object given where a private key is needed, as in
  `crypt_signature_create(data, key = k$pubkey)`, is refused naming that
  argument and the function called, rather than as a bad `file` to
  `crypt_read_key()`.

* C interface: three places where the adapter broke a promise of
  `zucrypt.h` (#142). `zuc_pkey_write()` refused a PEM encoding written
  into a buffer of exactly its length, and wrote a NUL past it into a
  larger one; it now needs exactly the length it reports and writes
  nothing more. `zuc_aes_cbc_set_state()` and `zuc_aes_cbc_get_state()`
  on a handle kept across the last `zuc_shutdown()` returned `ZUC_OK`
  rather than `ZUC_ERR_NOT_READY`. `zuc_pkey_decrypt()` and
  `zuc_pkey_agree()` left the output buffer as it was when they refused an
  argument (a public key, an unsupported scheme, a peer on another curve),
  rather than zeroing it. The R functions were not affected.

* RSA keys follow one size rule everywhere: a modulus of 1024 to 4096 bits,
  a whole number of bytes (#141). `crypt_read_key()`, `crypt_read_pubkey()`
  and `crypt_rsa_key()` now refuse a key under 1024 bits, which they read and
  used before, as `zucrypt_unsupported_algorithm`; `openssl` still reads
  such keys. A key of 1028 or 2047 bits, which the bundled library cannot
  use, is refused with a message naming the rule rather than "up to 4096
  bits". `crypt_rsa_keygen()` refuses a size that is not a multiple of 8 as
  `zucrypt_invalid_argument` up front; 1025 used to pass the check and fail
  in the backend as an unsupported algorithm.

* A failing operating-system random source is reported as
  `zucrypt_entropy_error` (`ZUC_ERR_ENTROPY` in C) by every key operation
  (#140). `crypt_rsa_decrypt()` reported it as `zucrypt_auth_error`, as if
  the ciphertext had been forged, `crypt_ec_dh()` and
  `crypt_x25519_diffie_hellman()` as `zucrypt_invalid_argument`, as if the
  peer key were bad, and in C, writing the public half of a private EC or
  X25519 key as SubjectPublicKeyInfo returned `ZUC_ERR_BACKEND`. Decryption
  still reports every padding failure as the one status.

* In the C API, `zuc_aead_encrypt()` and `zuc_aead_decrypt()` now refuse,
  with `ZUC_ERR_OVERLAP`, a tag or output buffer that overlaps any other
  buffer of the call, as `zucrypt.h` promised (#138). Before, a tag inside
  the ciphertext silently overwrote it, an output over the tag failed a
  valid message, and a short tag with partially overlapping input and
  output zeroed part of the caller's ciphertext. The R functions were not
  affected: they never share buffers.

* `crypt_signature_create()` and `crypt_signature_verify()` given a
  non-blocking connection whose data had not all arrived signed or verified
  the part received so far, as if it were the whole (#145). Every function
  that reads a connection (`crypt_hash()`, `crypt_hmac()`,
  `crypt_read_key()`, `crypt_read_pubkey()`, and the signature functions'
  `data` and `sig`) now goes through one reader, which refuses such a
  connection with `zucrypt_connection_error`, refuses a text-mode one with
  `zucrypt_invalid_argument`, and reports a connection or file that cannot
  be opened, or a directory given as a key path, as a zucrypt condition
  rather than R's own error. A key file is read to its end rather than to
  the size it had when the read began.

* `crypt_equal()` and the AES-CBC functions read past the end of a buffer
  when given a classed raw vector whose `length()` method misreports its
  length: `crypt_equal()` could answer `TRUE` wrongly or crash R, and a
  1-byte IV was read as 16 (#106). The native code now checks every length,
  number, name and flag it relies on, rather than trusting R's checks; a
  logical `NA` reaching it is an error rather than `FALSE` (#107).
* `crypt_ecdsa_parse()` reads strict DER (#91). It accepted a SEQUENCE or
  INTEGER whose length ran past the input, padding a truncated INTEGER with
  invented zero bytes, and negative and non-minimal INTEGERs. It now refuses
  them, and bytes after the signature too, which `openssl::ecdsa_parse()`
  ignores. Signature verification was not affected.
* An RSA key over 4096 bits, the bundled library's limit, is
  `zucrypt_unsupported_algorithm` from both `crypt_read_key()` and
  `crypt_read_pubkey()`, in every encoding, and the message names the limit
  (#93). A public key was reported as "not a key", and a private key in DER
  depended on its encoding.
* C interface: a `zuc_hash`, `zuc_hmac` or `zuc_aes` handle kept across the
  last `zuc_shutdown()` returns `ZUC_ERR_NOT_READY` after a later
  `zuc_init()`, and its free leaves the key store alone (#92). Before, the
  new backend could give its key id to a new handle, and the old handle
  then encrypted under the new handle's key, returning `ZUC_OK`, and its
  free destroyed that key.
* C interface: a digest or HMAC update that fails in the backend ends the
  operation until reset, as a finish does (#108). The handle had stayed
  "active", and an empty update on it reported success.
* C interface: `zuc_aead_decrypt()` zeroes the output on every
  `ZUC_ERR_AUTH`, including a tag of the wrong length, which is refused
  before the backend runs and used to leave the buffer as it was. Found by
  the new GCM fuzz target's oracle.

## Backend

* `PSA_WANT_ALG_GCM` and `PSA_WANT_ALG_PBKDF2_HMAC` are enabled. Re-deriving
  the trim added two upstream sources, `gcm.c` and `psa_crypto_aead.c`, and
  no header: 115 vendored files. Measured on macOS x86-64, the source tarball
  grew from 548 KB to 580 KB, `zucrypt.so` from 162 KB to 188 KB, and
  `libzucrypt.a` from 518 KB to 632 KB.
* RSA and the PK, PEM, ASN.1 and Base64 modules are enabled. The trim adds
  15 upstream sources and 14 headers: 144 vendored files, 37 compiled.
  Measured on macOS x86-64, the source tarball grew to 730 KB, `zucrypt.so`
  to 536 KB and `libzucrypt.a` to 1.3 MB.
* The NIST curves, Curve25519, ECDSA (with RFC 6979) and ECDH are enabled:
  6 more upstream sources and 3 headers, 153 vendored files, 43 compiled.
  The source tarball is 854 KB, `zucrypt.so` 656 KB and `libzucrypt.a`
  1.6 MB on macOS x86-64. `tools/make-ec-kat.py` extracts the RFC 6979, RFC
  7748, RFC 5903 and RFC 7515 vectors and checks them against Python's
  `cryptography`. The allocation sweep's window holds deterministic ECDSA
  and X25519, about 10,000 of its 13,000 positions.
* The backend allocates through `zuc_int_calloc()`, which records a failed
  allocation. The RSA functions report any failure that followed one as
  `ZUC_ERR_MEMORY`: inside bignum and ASN.1 code an allocation failure
  otherwise surfaced as an invalid key, a bad argument or an RNG failure.
* `tools/make-rsa-kat.py` extracts the RFC 7515 A.2 and RFC 7516 A.1 and A.2
  vectors and generates PSS and OAEP ones, and checks them all against
  Python's `cryptography`; the tests cross-verify with `openssl` 2.4.2.
* The AEAD and KDF vectors are checked outside the package by
  `tools/check-kat.py`, against Python's `cryptography` and `hashlib`, and
  `tools/make-kat.R --check` compares the GCM ciphertexts with `openssl`.
* On glibc, a `getrandom()` call interrupted by a signal is retried instead
  of being reported as an entropy failure.

# zucrypt 0.1.0

First release, and the first on CRAN. A focused set of cryptographic primitives over
raw vectors, backed by a vendored, pinned crypto library, published to R and
to C. The seven R functions are stable, and the static archive is frozen as
ABI 1, after its first consumer -- `zuxlsx`'s decryption of password-protected
workbooks -- was built and tested against it. The registered table is
experimental (see "C interface" below).

## R interface

Seven functions, and deliberately no more:

* `crypt_hash()` and `crypt_hmac()` — SHA-1, SHA-256, SHA-384 and SHA-512
  digests and keyed digests, of a raw vector or of everything a connection
  yields: `crypt_hash(file(path))` hashes a file in 1 MiB chunks without
  reading it into memory (#11). Raw vectors in, raw vectors out; a character
  value is never given a guessed encoding and never treated as a file name.
  Algorithm names match exactly, with no partial matching and no fallback.
* `crypt_hex()` — lower-case hex of a raw vector, converted in C, for
  printing or storing a digest. Hex stays an explicit step at the call site
  (#59).
* `crypt_equal()` — constant-time comparison. Unequal lengths return `FALSE`
  rather than pretending the length is secret.
* `crypt_aes_cbc_encrypt_nopad()` and `crypt_aes_cbc_decrypt_nopad()` —
  AES-128/192/256 in CBC mode, with no padding and **no authentication**.
  Interoperability tools for formats that specify unauthenticated CBC, not a
  way to encrypt something of your own.
* `crypt_info()` — what this build contains, read from the compiled library.

Failures are R conditions classed
`c(<specific>, "zucrypt_error", "error", "condition")`, mapped from the C
status by enumerator name rather than by number. Every condition carries
`algorithm` and `native_status` fields; for AES, `algorithm` names the cipher
(`"aes-256-cbc"`), or `"aes-cbc"` when the key is what is wrong. No message
ever contains a key, an IV or plaintext.

Fixed before the tag, from the package review in #51:

* A condition no longer carries the call that raised it, only the function's
  name. Before, `print()` on an error and `conditionCall()` showed the
  caller's expression -- literal keys and plaintext included -- although the
  message itself was clean.
* `crypt_hmac()` (and `zuc_hmac_*()`) accept keys of any length, as
  documented. Keys of 8,192 bytes or more used to fail with
  `zucrypt_unsupported_algorithm`, because the backend caps an imported key
  there; a key longer than the hash's block is now hashed first, as RFC 2104
  specifies, which gives the same MAC.
* `?crypt_aes_cbc_nopad` now authenticates the IV as well as the ciphertext
  in its encrypt-then-MAC advice and example. A MAC over the ciphertext alone
  let the IV, and so the first plaintext block, be changed undetected.

Renamed before release (#56): the CBC pair was `crypt_aes_cbc_encrypt()` and
`crypt_aes_cbc_decrypt()` during development. The `_nopad` suffix names the
difference from `openssl::aes_cbc_encrypt()`, which pads, so that code moved
from `openssl` by changing a prefix can never silently get the padding back
as plaintext. The unsuffixed names are reserved for an `openssl`-compatible
padded pair. The C interface (`zuc_aes_*()`) is unchanged.

## C interface

Both shapes the `zu*` family consumes siblings by, at `ZUCRYPT_ABI_VERSION 1`,
with different stability (`?zucrypt_c_api`):

* A static archive, `libzucrypt.a`, installed to `lib/` plus the R
  sub-architecture (`lib/x64/` on Windows), for a package that cannot carry
  an `Imports:` — `LinkingTo:` only, no runtime dependency, and the consumer
  owns the backend's lifetime through `zuc_init()`/`zuc_shutdown()`. This is
  the primary shape, and it is **frozen as ABI 1**: within major version 1,
  functions may be added, nothing is removed or given a new meaning, and
  enumerator values are permanent.
* A registered function table, `inst/include/zucrypt-r.h`, for a package that
  can carry an `Imports:`. Resolved lazily through `zucrypt_api()`; test an
  appended field with `ZUCRYPT_API_HAS()`. **Experimental** until a package
  uses it.

Settled before the freeze, from the first consumer's report (#43):

* `zuc_alg` values are grouped into reserved ranges, published as
  `ZUC_ALG_*_FIRST`/`_LAST` (digests, other MACs, ciphers and AEAD, key
  derivation, key families, signatures), so later families never renumber.
* A buffer pointer may be `NULL` exactly when its length is 0, for the
  incremental digest and HMAC calls as for CBC -- now stated, and tested.
* The lifecycle note in `zucrypt.h` says what an R package needs for
  `zuc_shutdown()` to run at all: an `.onUnload()` that calls
  `library.dynam.unload()`. The archive fixture now does, and its checks
  prove the DLL is released.

`inst/include/zucrypt.h` compiles standalone as C99 against `<stddef.h>` and
`<stdint.h>`, and names no backend type: a consumer never has to reproduce
this package's build configuration.

Both shapes are exercised on Linux, macOS and Windows by consumer fixture
packages, as a real consumer would use them:
- the table through an `Imports:` + `LinkingTo:` package that calls every
  entry;
- the archive through a `LinkingTo`-only package whose `configure` resolves
  `libzucrypt.a`.

The archive fixture's checks cover:
- linking through a library path that contains a space;
- exporting no backend symbol from its own shared object;
- running beside `zucrypt` in the same R session, in either load order;
- running with `zucrypt` not installed at all.

Settled before any consumer linked the ABI (design revision 3):

* AES-ECB is not provided. Its one use was Office Standard encryption, which
  `zuxlsx` does not implement.
* The backend's key store grows on demand, so the number of live AES and
  HMAC handles is bounded only by memory. The static store it replaces
  allowed 16 live AES handles per process and reported the 17th as an
  allocation failure.
* `ZUC_ERR_NOT_READY` (9) is returned by a call made before `zuc_init()` or
  after the last `zuc_shutdown()`.
* `zuc_info` gains `hardware_acceleration`, appended after the required
  prefix, and `crypt_info()$build_flags$hardware_acceleration` now reads it
  from the compiled library.
* TF-PSA-Crypto's licence is installed as `licenses/tf-psa-crypto-LICENSE`,
  since the archive carries its object code into every consumer.

## Backend

Vendored TF-PSA-Crypto 1.1.1, an LTS release, trimmed to 113 files — the
dependency closure of the sources that carry a symbol under this package's
configuration. Installation needs a C99 compiler and nothing else: no system
cryptographic library, no CMake, no Python or Perl, and no network access.

AES runs on the CPU's AES instructions — AES-NI on x86, the Cryptography
Extension on 64-bit Arm — chosen at run time, and on a software fallback
where the CPU has neither. The backend's own security policy warns that the
software fallback leaks key material through cache timing;
`crypt_info()$build_flags$aes_implementation` reports which path a machine
uses, and `?crypt_aes_cbc_nopad` explains when that matters. Every path produces
the same bytes. (Until the review in #51 hardware AES was off everywhere.)

Upstream symbols are hidden. The installed shared object exports exactly one
symbol, `R_init_zucrypt`, so an independently vendored copy of the same
library in another package cannot bind to this one, and no OpenSSL-ABI name
is exported beside the `libcrypto` other packages link.

## Supported platforms

Checked on every push: Linux, macOS (ARM64) and Windows; R release, oldrel-1
and 4.1; CRAN's clang-23 and GCC-16 containers; the no-Suggests flavour; LTO;
rchk and gctorture; ASan, UBSan, valgrind and GCC's `-fanalyzer`. Weekly:
i386, musl and aarch64 builds that run the test suite and fail on a WARNING,
and a sweep that fails each allocation the `crypt_*()` calls make, one run per
allocation — about 250 of them, of which some 77 land in zucrypt's own code —
checking that each surfaces as an error rather than a crash or a wrong answer.

Correctness is checked against published vectors — FIPS 180-2, RFC 2202, RFC
4231, RFC 6234 and NIST SP 800-38A, including the one-million-byte messages
and HMAC keys longer than the block — every one of which is also recomputed
with OpenSSL, an implementation sharing no code with the vendored backend.
Inputs up to 4 MiB are compared with OpenSSL directly, and the iterated hash
Office agile encryption uses is checked against msoffcrypto-tool.

## Not in this release

Deliberate omissions, each waiting on a concrete consumer rather than on
effort: authenticated encryption, password-based key derivation (PBKDF2,
HKDF, Argon2), random byte generation, signatures, key serialization, file
hashing and connection wrappers. There is no `encrypt_file(password = )`, and
there will not be one without a specified authenticated format, a nonce policy
and a key derivation step.

Office/Excel decryption is not here either. It belongs to
[zuxlsx](https://github.com/pedrobtz/zuxlsx), which consumes this package.
