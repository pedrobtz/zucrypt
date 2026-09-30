# zucrypt: Cryptography Without System Dependencies

Cryptographic functions over raw vectors, including message digests of
in-memory data, files and connections, keyed-hash message authentication
codes (HMAC), Advanced Encryption Standard (AES) encryption,
constant-time comparison and hexadecimal encoding, backed by a bundled
and pinned copy of the 'Mbed TLS' project's cryptography library,
'TF-PSA-Crypto' (<https://github.com/Mbed-TLS/TF-PSA-Crypto>). No system
cryptographic library, 'Java' or 'Python' is required at install or run
time. Algorithm names are matched exactly, and failures are reported as
structured conditions. The same primitives, and secure erasure of native
buffers, are published to other packages as a static archive and as a
registered C interface, so that a package can call them from C without
going through R.

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
