# zucrypt: Narrow Cryptographic Primitives with a Vendored Backend

Provides a small, predictable set of cryptographic primitives over raw
vectors: message digests, keyed-hash message authentication codes
(HMAC), unauthenticated Advanced Encryption Standard (AES) encryption in
cipher block chaining (CBC) and electronic codebook (ECB) modes,
constant-time comparison and secure erasure. The backend is vendored and
pinned, so no system cryptographic library, 'Java' or 'Python' is
required at install or run time. Binary arguments are raw vectors only,
algorithm names are matched exactly, and failures are reported as
structured conditions. The same primitives are published to other
packages as a registered C interface and as a static archive, so a
consumer can drive them from C without going through R. This is a
focused foundation for the 'zu\*' package family rather than a
general-purpose cryptography toolkit.

## See also

Useful links:

- <https://github.com/pedrobtz/zucrypt>

- <https://pedrobtz.github.io/zucrypt/>

- Report bugs at <https://github.com/pedrobtz/zucrypt/issues>

## Author

**Maintainer**: Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

Authors:

- Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

Other contributors:

- The Mbed TLS Contributors (TF-PSA-Crypto, bundled in
  src/vendor/tf-psa-crypto) \[copyright holder\]
