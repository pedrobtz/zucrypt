# Assurance

How this package meets `.claude/shared/assurance.md`. CI checks this
file (r-actions `assurance.yml`), so keep the headings and table
columns as they are.

- **Statuses:** a cell is a fact, `gap #<issue>` or `n/a: <reason>`.
- **Kinds:** delete the ones that do not apply.
- **Tables:** delete a table only when no kind requires it. Delete the
  example rows.

Written 2026-11-10 by `pkg-assurance` from the code on `main` at
`e8e81d0`. Each cell says what a test compares against, read from the
test. Test files are under `tests/testthat/`; `zucrypt_test.c` is
`src/zucrypt_test.c`, the harness the suite drives the adapter through.

## Kinds

`compiled` `untrusted-input` `spec` `lifecycle` `emits`

## Required checks

`Where` names the workflow file under `.github/workflows/` that runs the
check. Add `(own)` when that workflow is the package's own rather than a
call to r-actions.

| Check         | Status     | Where               |
| ------------- | ---------- | ------------------- |
| sanitizers    | done       | native-checks.yaml  |
| valgrind      | done       | native-checks.yaml  |
| rchk          | done       | native-checks.yaml  |
| gctorture     | done       | native-checks.yaml  |
| analyzers     | done       | native-checks.yaml  |
| alloc-failure | done       | alloc-failure.yaml  |
| mutation      | done       | mutation.yaml       |
| fuzz          | done       | fuzz.yaml (own)     |
| fuzz-reach    | done       | fuzz.yaml (own)     |

## Boundaries

One row per boundary the package crosses. An oracle knows the answer:

- a conformance suite or test vectors;
- a reference implementation;
- a round trip;
- equivalent inputs compared;
- the bytes the other side received.

"No crash" is not an oracle.

<!-- markdownlint-disable MD013 -->
| Boundary | Oracle | Carried by |
| -------- | ------ | ---------- |
| SHA-1/256/384/512 digest | FIPS 180-2 and RFC 6234 vectors (16); openssl at 1,000 B, 64 KiB + 1 and 4 MiB; incremental equals one-shot at every split point | test-kat.R, test-size.R |
| SHA and HMAC breadth: every message length 0 to 1024 bits, long messages, Monte Carlo chains through one reused context | NIST CAVP SHAVS (ShortMsg, LongMsg, Monte: 1,172 vectors) and HMACVS (1,200), through the R functions and the harness; Monte Carlo as 100,000 digests through one reset handle in C and an R loop over `crypt_hash()`; the archives checked by SHA-256 (tools/make-cavp.py) | test-cavp.R with ZUCRYPT_CAVP: aes-paths.yaml, platforms.yaml; a subset ships |
| HMAC-SHA1/256/384/512 | RFC 2202 and RFC 4231 vectors (15); openssl at keys of 0 to 10,000 B straddling each block and the backend's 8,191-byte key cap, one-shot, incremental and after a reset | test-kat.R |
| HMAC edge cases: truncated tags, odd key lengths | NIST CAVP HMACVS: keys of 10 to 145 bytes across each block size, tags truncated to 10 to 64 bytes; Wycheproof (pinned C2SP commit a3d5d14, tools/make-wycheproof.py): every valid case accepted with its output, every invalid one refused, 1,036 cases over SHA-1/256/384/512 | test-cavp.R, test-wycheproof.R |
| Digest of a connection | equals the digest of the same bytes in memory at 0, 1, 63, chunk - 1, chunk, chunk + 1 and 3 chunks + 17; openssl reading the same file | test-connection.R |
| Secrets in freed backend memory: private-key write in every encoding and read of each, RSA, P-256, P-384, P-521, X25519 | a residue scan in the adapter's allocator (`zuc_int_residue_arm()`, zuc_live.h) searches every block the backend frees for 24 bytes of the private key, raw and as the base64 that encodes them; a positive control (a planted needle is found, a wiped one is not) (#137) | test-residue.R |
| Buffer aliasing in the C API: AEAD (strict: exact in-place only), hash, HMAC, PBKDF2, RSA and ECDSA signing, RSA decryption (differential) | AEAD: every written buffer moved onto every other, refused as ZUC_ERR_OVERLAP with nothing written, or (in-place) the separate-buffer result; the others: the output at five offsets into each input gives the separate-buffer result or is refused unwritten (#138) | test-alias.R (zucrypt_test_alias) |
| ABI 1 (the archive and the table) against what v0.1.0 published | the frozen v0.1.0 headers (tools/abi/v0.1.0/): a generated probe prints all 70 published enumerator and macro values and `zuc_info`/`zucrypt_api_v1` field offsets and sizes, compiled against the frozen and the current headers, and every old line must be in the new output; a consumer compiled against the frozen zucrypt.h runs 66 checks with published vectors through the current libzucrypt.a; the archive's defined symbols are checked against every function the installed header declares (#139) | tools/ci/check-abi.sh (abi.yaml, platforms.yaml macOS), test-linking.R |
| Every connection reader (`crypt_hash()`, `crypt_hmac()`, `crypt_read_key()`, `crypt_read_pubkey()`, signature `data` and `sig`) through one `read_connection()` | a non-blocking socket whose writer is still open (an in-process `serverSocket()` pair) is refused as `zucrypt_connection_error` by each, returning nothing; text mode, an unopenable file and a directory path refused by class without warnings; an open connection left open, one opened closed (#145) | test-connection.R |
| AES-CBC, no padding, encrypt and decrypt | NIST SP 800-38A F.2 vectors, both directions; openssl over 4 MiB at 128/192/256; one adapter call equals the chunked wrapper; each AES implementation path | test-kat.R, test-size.R, aes-paths.yaml |
| AES-CBC breadth: GFSbox, KeySbox, VarKey, VarTxt, MMT, MCT | NIST CAVP AESAVS at 128/192/256, both directions (2,738 vectors); MCT chained 1,000 blocks per handle with the key update in C, and per checkpoint through the R functions; on every AES implementation | test-cavp.R with ZUCRYPT_CAVP: aes-paths.yaml (AES-NI, software), platforms.yaml (Arm CE, Windows AES-NI) |
| Hash, HMAC and AES-CBC at arbitrary lengths, keys and split points | Randomized differential against openssl (#68): seeded random lengths biased to 0, 1, a block either side and the 1 MiB chunk either side; HMAC keys empty, shorter than, equal to and longer than the block; one-shot, incremental at random split points (zero-length updates included), and from a rawConnection and a file; AES-CBC (all key sizes, against openssl's padded output) and AES-GCM ciphertext; and RSA, ECDSA, ECDH and X25519 both ways. 40 cases a family in the suite, 2,000 with a fresh logged seed in aes-paths.yaml; a planted HMAC key bug failed it on the first default run | test-differential.R, aes-paths.yaml (own) |
| AES-GCM encrypt | McGrew-Viega test cases 1-4, 7, 8, 13-16; ciphertext equals openssl's at 1 B to 1 MiB + 3 (openssl returns no tag, so the tag is checked by the vectors only) | test-aead.R |
| AES-GCM decrypt (ciphertext, tag, nonce and AAD from elsewhere) | the vectors, decrypted; every single alteration (ciphertext, tag, AAD, nonce, key, truncated or empty tag, AAD added or dropped, shortened ciphertext) is `zucrypt_auth_error`; the C contract checks the output buffer is zeroed on failure | test-aead.R, zucrypt_test.c (`wiped_on_failure`) |
| AES-GCM decrypt against attack vectors | Wycheproof (pinned C2SP commit a3d5d14, tools/make-wycheproof.py): every valid case accepted with its output, every invalid one refused, the 197 cases with a 96-bit nonce and 128-bit tag. fuzz_gcm: the round trip holds; one bit changed in the ciphertext, tag, AAD or nonce, and every other tag length, is `ZUC_ERR_AUTH` with the output all zeros; an arbitrary ciphertext accepted under the input's tag must re-encrypt to itself | fuzz/fuzz_gcm.c, fuzz.yaml |
| PBKDF2-HMAC | RFC 6070 and RFC 7914 vectors; Python `hashlib` for SHA-384/512; a shorter output is a prefix of a longer one | test-kdf.R |
| Key read: RSA PKCS#1, PKCS#8 and SPKI; EC SEC1 and PKCS#8; X25519 RFC 8410; PEM and DER | openssl reads every encoding zucrypt writes and zucrypt reads every encoding openssl writes, compared as the re-written bytes; from a file, a connection and PEM text | test-rsa.R, test-ec.R |
| Key read: malformed and hostile PEM and DER | fuzz_pkey: a refusal is a documented status with no handle left; an accepted key is a fixed point of write-then-read in all four formats and both halves, and of raw export and import; an RSA key is 1024 to 4096 bits in whole bytes. Seeds: every fixture key in every encoding, and regress-93/regress-91 inputs. Differential against openssl (#68): every corpus input zucrypt accepts, openssl reads too, and both write the same DER for both halves (one-way: zucrypt reads more strictly) | fuzz/fuzz_pkey.c, fuzz.yaml, test-differential.R |
| Key write: the same encodings | byte-for-byte equal to openssl's | test-rsa.R, test-ec.R |
| Keys from integers and coordinates (`crypt_rsa_key()`, `crypt_ec_key()`) | the RFC vectors reproduce from the key's integers; round trip through `as.list()`; off-curve and mismatched points refused | test-rsa.R, test-ec.R |
| RSA signatures, PKCS#1 v1.5 and PSS | RFC 7515 A.2 vector signed and verified; PSS signatures made by Python `cryptography` verified; cross-verified with openssl both ways | test-rsa.R |
| RSA signature verification against attack vectors | Wycheproof (pinned C2SP commit a3d5d14, tools/make-wycheproof.py): every valid case accepted with its output, every invalid one refused: 259 PKCS#1 v1.5 and 108 PSS cases, RSA-2048 with SHA-256. fuzz_verify (PKCS#1 v1.5 and PSS, SHA-256/384/512): a fresh signature verifies; one bit changed in it or the digest, or its length changed, is refused; the fuzzer's bytes offered as a signature are refused | test-wycheproof.R, fuzz/fuzz_verify.c, fuzz.yaml |
| RSA encryption, OAEP and PKCS#1 v1.5 | RFC 7516 A.1 and A.2 ciphertexts decrypted; OAEP-SHA256/384/512 ciphertexts made by Python `cryptography` decrypted; openssl decrypts ours and we decrypt openssl's | test-rsa.R |
| RSA decryption against attack vectors | Wycheproof (pinned C2SP commit a3d5d14, tools/make-wycheproof.py): every valid case accepted with its output, every invalid one refused: 41 OAEP cases (SHA-1 and SHA-256, empty label) and 67 PKCS#1 v1.5 cases, RSA-2048 | test-wycheproof.R |
| ECDSA P-256/384/521 sign and verify | RFC 6979 vectors (24, deterministic), RFC 7515 A.3 and A.4; cross-verified with openssl both ways | test-ec.R |
| ECDSA verification against attack vectors | Wycheproof (pinned C2SP commit a3d5d14, tools/make-wycheproof.py): every valid case accepted with its output, every invalid one refused: 1,530 DER cases on P-256, P-384 and P-521. fuzz_verify (P-256): as for RSA, with the digest flips kept inside the bits ECDSA reads (FIPS 186-5 6.4.2) | test-wycheproof.R, fuzz/fuzz_verify.c, fuzz.yaml |
| ECDSA DER signature read by `crypt_ecdsa_parse()` (coverage-guided fuzzing: gap #123) | an independent strict-DER model in the test: the 14 malformed shapes of #91 refused, and 480 random mutations of real signatures accepted or refused exactly as the model says, with the same `r` and `s`; `openssl::ecdsa_parse()` agrees on valid signatures and on the malformed inputs it refuses (it accepts trailing bytes, a documented difference) | test-ec.R |
| ECDSA DER signature write | equals `openssl::ecdsa_write()`; verification re-encodes the input and refuses any non-canonical form | test-ec.R |
| ECDH P-256/384/521 | RFC 5903 vectors; openssl agrees both ways | test-ec.R |
| X25519 | RFC 7748 6.1 vector; openssl agrees; an all-zero shared secret refused | test-ec.R |
| ECDH and X25519 against invalid and low-order peer points | X25519: Wycheproof (pinned C2SP commit a3d5d14, tools/make-wycheproof.py): every valid case accepted with its output, every invalid one refused, 518 cases, the "acceptable" low-order points accepted with the right secret or refused for an all-zero one; ECDH on the NIST curves: Wycheproof's ecdh_* files not yet run, gap #70 | test-wycheproof.R |
| Constant-time comparison (`crypt_equal()`), values | equal, unequal at the first and the last byte, empty, length-aware | test-adapter.R, test-interface.R |
| Timing of `crypt_equal()`, the GCM tag check and private-key operations | gap #97 | gap #97 |
| Operating-system random source | two draws differ under one R seed; every byte value appears in 1 MiB + 64; the tail past a chunk is filled; a failing source is `zucrypt_entropy_error`, never bytes; every key operation under a failing source gives its working-source answer or `zucrypt_entropy_error` / `ZUC_ERR_ENTROPY`, never another status (#140); `getrandom()` refused (ENOSYS, simulated by the harness) falls back to `/dev/urandom`, draws differ and the backend is reported, checked on every glibc leg; scripted `getrandom()` calls (#119): short reads, `EINTR` once and twice, fill the buffer; `EIO`, at once or after a short read, is `ZUC_ERR_ENTROPY` with the buffer wiped; `EPERM` or `ENOSYS` after a short read finishes from `/dev/urandom`; a real kernel refusal via a seccomp profile was checked by hand (#144) | test-random.R, test-entropy.R, ctest `test_entropy` |
| Random bytes and ECDSA nonces in forked children | two `parallel::mcparallel()` children and the parent draw different bytes, sign one message with different ECDSA `r` (the nonce), and generate different RSA keys; a source seeded once and replayed (what a DRBG copied by `fork()` does) fails all six (#98). Not on Windows, which has no `fork()` | test-random.R |
| Hex encoding | every byte value; published digests' hex; openssl's hex | test-hex.R |
| The vendored TF-PSA-Crypto under zucrypt's configuration | gap #69 | gap #69 |
| The C archive and the registered table (ABI 1) | the msoffcrypto-tool derivation vector through both consumer fixtures and `zuxlsx`'s decryption tests; every table entry called | consumer.yaml, revdep.yaml, abi.yaml |
<!-- markdownlint-enable MD013 -->

## Objects

One row per object that outlives the call that made it. "Sequences" is
the test of its out-of-order use (abort then read, use after end, use
after free). The guard columns name the test, or say why the guard
cannot apply.

<!-- markdownlint-disable MD013 -->
| Object | Sequences | Fork | Unwind | Owner |
| ------ | --------- | ---- | ------ | ----- |
| Key object (`crypt_key`, `crypt_pubkey`: an external pointer tagged `zucrypt_pkey` to a `zuc_pkey`) | a key restored by `readRDS()` is refused, by class, by every function; a public key where a private one is needed, and each key type in another type's operation, refused | n/a: holds only heap bytes (its DER), no descriptor, connection or DRBG state; each operation imports it into the key store and destroys it, and randomness is read from the OS on every call (test-random.R forks, #98) | the pointer exists, finalized, before the handle (`pkey_ptr()`); `.onUnload()` finalizes every live object before the DLL goes, checked by test-unload.R in a subprocess (#144); alloc-failure.yaml sweeps RSA, ECDSA and X25519 key calls (tools/alloc-exercise.R) | test-lifetime.R counts handles back to baseline after `gc()`; `pkey_destroy()` wipes before freeing |
| Connection digest stream (an external pointer to a `zuc_hash` or `zuc_hmac`, kept across R calls inside `digest_connection()`) | a finished stream cannot be updated or finished again | n/a: lives inside one `crypt_hash()` or `crypt_hmac()` call and is never returned to the caller | test-lifetime.R interrupts the stream with `setTimeLimit()` and checks the count after `gc()` | test-lifetime.R: success and refused text-mode connections leave no live context |
| One-shot loop contexts (hash, HMAC, AES in `src/zucrypt_crypt.c`, live across `R_CheckUserInterrupt()`) | n/a: created and released inside one `.Call`; no R code holds the pointer | n/a: never outlives the call except as garbage awaiting its finalizer | test-lifetime.R interrupts each loop and checks the count after `gc()`; gctorture | test-lifetime.R: success and native failure leave no live context, released eagerly |
| Archive and table handles for C consumers (`zuc_hash`, `zuc_hmac`, `zuc_aes`, `zuc_pkey`) | gap #99 (model-based sequences); partial: test-adapter.R covers reset, chaining across calls, calls outside the init window, 1,000 live handles, a handle kept across the last `zuc_shutdown()` (every operation `ZUC_ERR_NOT_READY`, checked in ctest `test_lifetime` against the list of handle functions read from `zucrypt.h`, #142; the new handles' output equal to the exported functions' under their key, before and after the old ones are freed; #92), and a backend failure inside an update (refused until reset, then the known digest; #108) | n/a: the consumer's object in the consumer's process; it holds no descriptor | n/a: the adapter never calls R; the consumer owns its unwind (zucrypt.h) | the consumer, through `zuc_*_free()`, which wipes; `zucrypt_test.c` checks `free_null` |
<!-- markdownlint-enable MD013 -->

## Limits

One row per limit the package enforces. "Straddled by" is the test of
`limit - 1`, `limit` and `limit + 1` on every path that reaches it.

<!-- markdownlint-disable MD013 -->
| Limit | Unit | Straddled by |
| ----- | ---- | ------------ |
| Interrupt chunk, `ZUCRYPT_CHUNK` = 1 MiB, in-memory `crypt_hash()`, `crypt_hmac()`, AES-CBC and `crypt_rand_bytes()` | input bytes | test-size.R (#100): hash and HMAC at 1 byte and 1 MiB - 1, 1 MiB and 1 MiB + 1, AES-CBC at a block and 1 MiB - 16, 1 MiB and 1 MiB + 16, against one adapter call and openssl; the random fill loop over a sentinel buffer at the same sizes. An off-by-one loop bound in each of the four loops fails only its 1-unit and 1 MiB + 1 cases |
| Connection read chunk, 1 MiB (R/hash.R) | bytes read | test-connection.R: chunk - 1, chunk, chunk + 1 |
| AES key length 16, 24 or 32 | bytes | test-validation.R (CBC: 0, 1, 8, 15, 17, 23, 25, 31, 33, 64); test-aead.R (GCM: 0, 15, 17, 31, 33) |
| AES-CBC IV exactly 16 | bytes | test-validation.R: 0, 8, 15, 17, 32 |
| AES-CBC data a multiple of 16 | bytes | test-validation.R: 1, 15, 17, 31, 33 |
| GCM nonce exactly 12 | bytes | test-aead.R: 0, 8, 11, 13, 16 |
| GCM tag exactly 16 on decryption (any other length is an authentication failure) | bytes | test-aead.R (#101): 0, 15, 17 and 32 bytes (the right tag plus a byte, and twice) are `zucrypt_auth_error` and, in the C contract, `ZUC_ERR_AUTH` with the output wiped. A compare over the first 16 bytes fails it; the backend also refuses a long tag, so a bare `tag_len < 16` check does not |
| HMAC key: block size, and the backend's 8,191-byte key cap | bytes | test-kat.R: 63, 64, 65, 127, 128, 129, 8191, 8192, 10000 |
| PBKDF2 iterations in [1, 2^32 - 1] | count | test-kdf.R: 0 and 2^32 refused, 1 accepted; 2^32 - 1 is not run, as it would take hours |
| PBKDF2 output length at least 1 | bytes | test-kdf.R: 0 refused, 7 and 20 accepted |
| RSA modulus of 1024 to 4096 bits, a whole number of bytes (#93, #141), on read, import and generation; the backend's `PSA_VENDOR_RSA_MAX_KEY_BITS` is the top | bits | test-rsa.R: openssl's keys of 512, 1000, 1016, 1028, 2047, 4104 and 8192 bits refused as unsupported, with the rule in the message, and 1024, 2048, 4088 and 4096 read, by both readers, in all six encodings (fixtures/rsa-limit.tsv; at the top a byte either side, as openssl cannot make a 4095- or 4097-bit key); `crypt_rsa_key()` refuses 512 to 2047-bit integers outside the rule; generation: 1016, 1023, 1025, 1028 and 4097 refused, 1024 and 1032 accepted, 4088 and 4096 accepted (not on CRAN). ctest `test_rsa_limits`: every fixture row through `zuc_pkey_parse()` and `zuc_pkey_import()`, generation at 0, 512, 1016, 1023, 1024, 1025, 1026, 1028, 1032, 4097, 4104, 8192; fuzz_pkey's oracle requires the rule of any key it accepts |
| RSA encryption message length | bytes | test-rsa.R (#102): on a 2048-bit key, PKCS#1 v1.5 (245) and OAEP-SHA1, -SHA256, -SHA384 and -SHA512 (214, 190, 158, 126) encrypt and decrypt at the limit and one under, and refuse one over as `zucrypt_bad_length`; Python cryptography's ciphertexts at those lengths (rsa.tsv `rsa-limit-*`) decrypt, and openssl decrypts the SHA-1 and v1.5 ones; also OAEP-SHA1 at 1024 bits (86, 87) |
| `ZUC_PKEY_MAX_WRITE_SIZE` = 8192, the key write buffer | bytes | zucrypt_test.c `write_small` refuses a short buffer; the largest key (RSA-4096 private PEM, 3,272 B) fits by construction |
| Live handles in the dynamic key store | count | test-adapter.R: 64 and 1,000 of each kind (the static store failed at 17) |
| `crypt_rand_bytes()` `n` in [0, 2^52] (R checks a whole number) | bytes | test-random.R: 0 accepted; -1, 1.5 and 2^53 refused |
<!-- markdownlint-enable MD013 -->
