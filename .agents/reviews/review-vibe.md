# zucrypt correctness review — findings and verification notes

Review of the R package `zucrypt` (v0.1.0 source tree, branch `chore/post-release-0.1.0`),
focused on correctness bugs: code that compiles and "works" on simple input but can
return wrong results, crash R, or corrupt memory. Style, performance and
documentation are out of scope.

Scope reviewed, in priority order:

1. C boundary layer (`src/zucrypt_r.c`, `src/zucrypt_crypt.c`, `src/zucrypt_api.c`,
   `src/zucrypt_test.c`) — SEXP contract, PROTECT discipline, NA/NaN/Inf, integer
   overflow / long-vector safety, allocation-failure handling, input mutation.
2. Adapter layer (`src/zuc_hash.c`, `src/zuc_aes.c`, `src/zuc_util.c`,
   `src/zuc_status.c`, `src/zuc_backend.c`, `src/zuc_random.c`) and its use of the
   vendored PSA API.
3. Vendored C (`src/vendor/tf-psa-crypto`): local patches only
   (`tools/patches/tf-psa-crypto/0001-*.patch`, `0002-*.patch`) plus upstream-API
   misuse.
4. Build/registration: `src/Makevars`, `src/install.libs.R`, `NAMESPACE`,
   `R_init_zucrypt`.
5. R layer: `R/hash.R`, `R/aes.R`, `R/hex.R`, `R/conditions.R`, `R/info.R`,
   `R/c-api.R`.

Method: full read of every non-vendored source file; full compile sweep under
`clang -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wcast-qual -Wsign-compare`
(0 non-vendored warnings); and *executed* edge-case probe scripts against the
installed package cross-checked against OpenSSL, including 2 GiB / >2^31-byte
long vectors, interrupt tests under `setTimeLimit`, live-context counts,
connection paths (file, gzfile, non-blocking), and type-confusion probes through
the registered symbols.

**Headline result: no crash-class, wrong-result-class, or memory-safety bug was
found in any code reachable through the exported API.** The three reportable
findings (A1-A3) are all robustness issues, none of which triggers from a normal
user call. Everything verified clean is listed as A4 onward, with the evidence.

---

## Findings

### A1 — NA logical silently means "decrypt" in the AES entry point

- **Severity:** robustness (wrong-result only via internal-symbol misuse; NOT
  reachable through `crypt_aes_cbc_encrypt_nopad()` / `crypt_aes_cbc_decrypt_nopad()`,
  which pass literal `TRUE`/`FALSE`).
- **Location:** `src/zucrypt_crypt.c` line ~356, in `zucrypt_aes_cbc()`:
  ```c
  int do_encrypt = Rf_asLogical(encrypt) == TRUE;
  ```
- **Trigger (confirmed by execution):**
  ```r
  .Call(zucrypt:::zucrypt_aes_cbc, as.raw(1:16), as.raw(1:16), raw(16), NA)
  ```
  returns `status = 0` with a "successful" result that is identical to the
  `FALSE` (decrypt) call. Verified in a live session:
  ```r
  identical(.Call(z, as.raw(1:16), as.raw(1:16), raw(16), NA),
            .Call(z, as.raw(1:16), as.raw(1:16), raw(16), FALSE))
  # [1] TRUE
  ```
- **Why:** `Rf_asLogical(NA)` is `NA_LOGICAL`, and `NA_LOGICAL == TRUE` is false,
  so NA (and any non-canonical logical representation a future R might accept)
  falls into the decrypt arm without any signal. The file's design comment says
  "argument *types* ... R has already checked" — but NA is a *value* problem and
  nothing checks it.
- **Fix (minimal diff):**
  ```c
  int do_encrypt = Rf_asLogical(encrypt);
  if (do_encrypt == NA_LOGICAL) {
      Rf_error("zucrypt: encrypt must be TRUE or FALSE, not NA");
  }
  do_encrypt = do_encrypt == TRUE;
  ```
- **Confidence / test:** high — demonstrated live. Regression test: the `.Call`
  above must raise an R error, not return a value; add it next to the existing
  stream-lifecycle tests so it runs against any future signature drift.

### A2 — Test harness that tears down the backend is registered in production binaries

- **Severity:** robustness now; escalates to crash/wrong-results the moment a
  registered-table consumer (`zucrypt-r.h` shape) exists that holds native
  handles across calls. Possible — verify before it matters.
- **Location:** `src/zucrypt_test.c`, `zucrypt_test_not_ready()` (~line 569),
  registered in `zucrypt_test_call_methods` and therefore live in every shipped
  `zucrypt.so`.
- **Trigger:** `.Call(zucrypt:::zucrypt_test_not_ready())` in a user session.
  Today it is harmless: zucrypt's own R functions never hold a context across
  calls, and no R allocation happens in its shutdown→init window, so no
  finalizer can run mid-window. The latent break: the entry performs
  `zuc_shutdown()` → `mbedtls_psa_crypto_free()` → `zuc_init()`, destroying
  every key in the process's single PSA key store. A table consumer (per
  `R/c-api.R`, the table shape is "experimental"; no real package uses it yet)
  holding a `zuc_aes`/`zuc_hmac` handle in ANOTHER package would have its key
  material destroyed mid-session; after the re-init, the consumer's stale key
  IDs resolve against a *fresh* key store, so its later `psa_destroy_key` could
  hit a recycled ID owned by someone else.
- **Why:** the in-code comment states "safe only when no other zucrypt context
  is live in the process; the test calls gc() first" — a correct argument for
  the package's own test suite, but unenforced and unenforceable once the table
  shape has any consumer.
- **Fix:** gate the backend-lifetime harness entries
  (`zucrypt_test_not_ready`) behind an environment variable checked once in
  `R_init_zucrypt` (install that table entry only when the variable is set), or
  compile the entry out of release builds. No refactor needed.
- **Confidence / test:** medium — the hazard requires a consumer that does not
  exist yet; the registration path itself is confirmed live in the installed
  0.1.0 binary (`getDLLRegisteredRoutines("zucrypt")` lists it). A test:
  register a consumer package that holds a `zuc_aes` across the harness call
  and assert subsequent use fails noisily rather than returning garbage.

### A3 — `getrandom()` EINTR is reported as entropy exhaustion

- **Severity:** portability/robustness. Possible — verify. Currently a dead code
  path.
- **Location:** `src/zuc_random.c`, getrandom branch (~lines 88-96):
  ```c
  ssize_t n = getrandom(output, output_size, 0);
  if (n < 0) {
      return PSA_ERROR_INSUFFICIENT_ENTROPY;
  }
  ```
- **Trigger:** none exists today — nothing in the current profile draws
  randomness (CBC takes its IV from the caller; no key generation). When a
  future entry point does (`psa_generate_key`, an AEAD, a nonce), a signal
  arriving during the syscall yields a spurious
  `PSA_ERROR_INSUFFICIENT_ENTROPY` failure instead of a retry. The file's own
  comment says "getrandom() may return short, and returns EINTR on a signal" —
  but the code does not distinguish EINTR from real failures.
- **Fix (minimal diff):**
  ```c
  ssize_t n = getrandom(output, output_size, 0);
  if (n < 0) {
      if (errno == EINTR) continue;   /* and #include <errno.h> */
      return PSA_ERROR_INSUFFICIENT_ENTROPY;
  }
  ```
  The same file's `/dev/urandom` fallback (`fread` once) and the `arc4random_buf`
  and `rand_s` branches are fine, and the `-Wconversion`-clean compile confirms
  the arithmetic there.
- **Confidence / test:** low-to-medium for current releases (unreachable path),
  high as a future hazard. Test would need a callable RNG entry point plus a
  `SIGPROF`-storm loop asserting no spurious entropy failures.

---

## Verified clean (with evidence)

### A4 — SEXP contract at the boundary

Every registered entry's arity matches its `.Call` sites exactly (checked line by
line against both registration tables: `zucrypt_hash` 2, `zucrypt_hmac` 3,
`zucrypt_aes_cbc` 4, `zucrypt_equal` 2, `zucrypt_hex` 1,
`zucrypt_hash_stream_new` 1, `zucrypt_hmac_stream_new` 2,
`zucrypt_stream_update` 2, `zucrypt_stream_finish` 1, `zucrypt_algorithms` 0,
plus the harness and info/status entries). Algorithm strings reach C only after
`check_algorithm()` enforces scalar, non-NA, exact-name matching (no
`match.arg`, no partial matching); `crypt_hash(raw(1), c("sha1","sha256"))`,
`character(0)`, `NA_character_`, `factor("sha256")` all error with
`zucrypt_invalid_argument`, verified by execution. Key/IV/data lengths are
checked in R before every native call AND independently re-checked in the
adapter (`ZUC_ERR_BAD_LENGTH` for a key not 16/24/32 bytes, an IV not 16, a
data length not a multiple of 16).

Type confusion through the registered symbols is safe on modern R because the
checked accessors error before any dereference:
```r
.Call(zucrypt:::zucrypt_hash, 1:10, "sha256")
# ERROR: RAW() can only be applied to a 'raw', not a 'integer'
```
The package's documented stance ("a wrong type arriving here is a bug in this
package") therefore does not create a memory hazard in practice. The one value
case that slips through is A1.

### A5 — PROTECT discipline

PROTECT/UNPROTECT balanced on every path in all four R-facing files, including
both `Rf_error` sites and every early status-return path. The
"result()-inside-protection" ordering (allocate `out`, finish into it, call
`result()` only while `out` is still protected) is correct at every one of the
six call sites, and each site carries a comment explaining exactly this hazard.
`R_MakeExternalPtr` + `R_RegisterCFinalizerEx(ptr, ..., TRUE)` before context
creation is done in the correct order everywhere, so no allocation can
longjmp with a live unowned context. `release_ptr()` clears the pointer before
freeing, which is the order that prevents a double free from the finalizer.
Interrupt probes (below) confirmed no context leak and no double-free under
longjmp.

### A6 — NA/NaN/Inf

No boundary entry point accepts doubles, so NaN/Inf have no entry surface; raw
vectors cannot carry NA; `algorithm` NA is rejected in R (A4). No bitwise
`x == NA_REAL`-style comparisons exist anywhere. The only NA leak found in the
whole package is A1, plus the deliberate `Rf_asInteger`-NA tolerance in the test
harness (`zucrypt_test_status(NA_integer_)` maps to the designed
"ZUC_ERR_UNKNOWN" fallback — intentional and documented).

### A7 — Integer overflow / long-vector (>2^31) safety

All buffer lengths and offsets are carried as `size_t`; `XLENGTH` casts are
correct; the 1 MiB chunk constant (1048576) is a multiple of the AES block, so
CBC chunking stays whole-block (verified by reading, and by construction
comment in `zucrypt_crypt.c`). Verified by execution with a real long vector:

- `x <- raw(2^31 + 32)`: `crypt_hash(x)` matches
  `openssl dgst -sha256` on the same bytes byte-for-byte (`TRUE`).
- `crypt_aes_cbc_encrypt_nopad(x, key, iv)` round-trips through the paired
  decrypt at full length (`TRUE`), and a 3 MiB + 16-byte input (non-chunk
  aligned) matches `openssl enc -aes-128-cbc -nopad` byte-for-byte.
- Small HMAC/AES vectors match OpenSSL for all four algorithms and both
  directions (sha1/256/384/512 HMAC over 100-byte messages, including a key
  longer than the SHA-512 block, exercising the RFC 2104 key-reduction path in
  `import_hmac_key`).
- `crypt_hex`'s R-side guard (`length(x) > 1073741823`) is consistent with
  `Rf_mkCharLenCE`'s `int` length parameter (2*n <= 2^31-2 fits), and R 4.x
  `R_alloc(R_SIZE_T, int)` takes the doubled size without int overflow
  (signature checked against installed `R_ext/Memory.h`).

### A8 — Allocation failure handling and lifetime

All `calloc` results are checked (`ZUC_ERR_MEMORY`); `zuc_hash_new` /
`zuc_hmac_new` / `zuc_aes_new` set `*out = NULL` before anything can fail, so a
failed constructor leaves a NULL safe to free; partially built contexts are
destroyed rather than returned (verified on every error path in
`src/zuc_hash.c`/`src/zuc_aes.c`). `all_call_methods()`'s `calloc` for the
concatenated registration table is NULL-checked and freed after
`R_registerRoutines`, matching R's documented copy semantics. `Rf_error` after
`zuc_init()` failure in `R_init_zucrypt` occurs after the table free — no leak.

Interrupt/lifetime proof by execution (2 GiB inputs, `setTimeLimit`):

- interrupt during `crypt_hash(raw(2^31))`: live-context count 1 immediately
  after the error (context owned by the finalized extptr), 0 after `gc()` —
  finalizer releases it, no leak, no double free;
- interrupt during `crypt_aes_cbc_encrypt_nopad(raw(2^31), ...)`: identical
  result (after=1, after_gc=0);
- interrupt during the connection read loop: identical.

### A9 — No input mutation; fresh outputs

Outputs are always freshly allocated raw vectors; `.Call` arguments are never
written. Verified by execution at multiple sizes against OpenSSL references,
and by the package's own byte-identity tests (`test-interface.R`), which
deliberately rebuild expected values rather than copying inputs (avoiding the
shared-storage trap their comment describes). Attributes on inputs (names,
dims) are ignored by the C layer, verified with a named IV. `zuc_int_overlaps`
uses `uintptr_t` correctly in both directions (input inside output span and
vice versa) with adjacency accepted and exact alias accepted (tested by their
in-place harness entry).

### A10 — Vendored C: patches and PSA API usage

Only two patches exist, both in `tools/patches/tf-psa-crypto/`:

- `0001`: `MBEDTLS_PK_MAX_PUBKEY_RAW_LEN` 0 → 1 (one byte in a struct never
  instantiated in this build) to avoid a zero-size array under `-Wpedantic`.
  Cosmetic; no behavioral effect in any configuration that enables a
  public-key algorithm.
- `0002`: removes two diagnostic-suppressing `#pragma` blocks
  (`constant_time_impl.h`, `platform_util.c`). I checked the patched
  `platform_util.c` preprocessor balance explicitly (a hunk that removed
  `#endif`s) — the file is balanced and compiles clean with this build's
  include set (confirmed by `clang -fsyntax-only`). The zeroization barrier
  itself (`asm volatile ...`) survives intact.

No other in-tree deviations from upstream carry zucrypt markers. PSA usage
patterns were checked against the API contract:

- `psa_hash_setup` after `psa_hash_abort` (in `zuc_hash_reset`) and
  `psa_mac_sign_setup` after abort (in `zuc_hmac_reset`) are legal on
  terminated operations; covered by their reset-equivalence tests.
- `psa_cipher_update` with exact in-place buffers (input == output) is
  exercised by their in-place harness entry and by PSA's implementation.
- One `psa_cipher_update` call with output capacity == input length is exact
  for CBC-no-padding and the produced/finished check in `cipher_run` converts
  a backend surprise into `ZUC_ERR_INTERNAL` instead of stale output.
- `MBEDTLS_PSA_KEY_STORE_DYNAMIC` is a real macro in the pinned upstream and
  is what the 100k-live-handles test exercises (#30's fix confirmed active).
- The private-identifier reach-down in `zuc_backend.c`
  (`MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` + `mbedtls_aes_get_implementation`)
  is contained to the pinned release: a rename is a compile error, not a
  silent behavior change.

### A11 — Build / registration

- No `src/init.c`, but registration is complete and correct in
  `R_init_zucrypt`: `R_registerRoutines(dll, NULL, methods, NULL, NULL)` +
  `R_useDynamicSymbols(dll, FALSE)` + `R_forceSymbols(dll, TRUE)`, matching
  `useDynLib(zucrypt, .registration = TRUE)` in NAMESPACE. All 27 registered
  names and arities match the `.Call` sites.
- `Makevars`: `all` is the first target; `PKG_CFLAGS = $(C_VISIBILITY)` (does
  not override `$(CFLAGS)`); `PKG_CPPFLAGS` carries only `-I`/`-D`; no
  `-w` or any warning suppression; no optimization overrides; `libzucrypt.a`
  (adapter + vendor objects only, no R glue) built from the same objects as
  the shared object, and `tools/check-layering.sh`/`test-linking.R` audits the
  split. `.Rbuildignore` covers the committed build artifacts
  (`src/libzucrypt.a`, `src/vendor/**/*.o`).
- `install.libs.R` checks every `file.copy()` return (no silent missing
  files), installs `symbols.rds` when present, and the vendor LICENSE beside
  the archive.

### A12 — R layer validation

All validation happens before native calls with named-argument, single-class
error messages: `check_raw`, `check_algorithm` (exact match, no partial
matching — a typo cannot silently pick a weaker digest), `check_aes_key`,
`check_aes_iv`, `check_block_multiple` (type and length in one pass). The
connection path (`digest_connection`) refuses non-connections, unopenable
connections (with the warning surfaced), text-mode and non-readable
connections, validates key/algorithm before opening, closes only what it
opened, leaves open connections open, reads to end in 1 MiB chunks, and
refuses a non-blocking connection that runs dry mid-file rather than hashing
a prefix (`isIncomplete` guard) — the silent-prefix hazard specifically
probed: a non-blocking file connection hashes the whole file and matches the
plain digest. `gzfile` input matches the plaintext digest. Condition `call`s
are centrally redacted to the bare function name so arguments (keys!) never
reach the console.

---

## Ranked severity summary

| # | Finding | Severity | Reachable from exported API today? |
|---|---------|----------|-------------------------------------|
| 1 | A2 — backend-teardown harness registered in production | robustness, escalates once a table consumer exists | no (deliberate `:::` misuse) |
| 2 | A1 — NA logical → silent decrypt | wrong-result via internal `.Call` only (confirmed) | no |
| 3 | A3 — `getrandom` EINTR as entropy error | robustness/portability; dead path today | no |

No crash-class, memory-safety-class, or user-reachable wrong-result-class
findings. This verdict is based on executed trigger inputs, not reading alone.

## Edge-case battery to re-run on every release

1. **Empty:** `crypt_hash(raw(0))`, `crypt_hmac(raw(0), raw(0))`,
   AES with `raw(0)` data — currently return the correct empty digest/ciphertext.
2. **All-NA:** `crypt_hash(raw(1), NA_character_)`, `c("sha1","sha256")`,
   `character(0)`, `factor("sha256")` — all rejected with
   `zucrypt_invalid_argument`; plus A1's NA-logical `.Call` once fixed.
3. **NaN/Inf:** no double-accepting entry point exists; any future numeric
   interface needs its own NA/Inf/NaN handling — current machinery would not
   catch it.
4. **Zero-length dims / dimnames:** N/A (raw-only); attributes are ignored —
   keep the named-IV probe.
5. **Near 2^31:** repeat the 2^31+32-byte hash/AES-vs-OpenSSL byte-exact
   checks; `crypt_hex` exactly at `2^30-1` and `2^30` bytes (guard boundary).
6. **Non-contiguous arrays:** impossible via raw vectors; keep chunked
   connection hashes at `chunk-1`, `chunk`, `chunk+1`.
7. **Unusual SEXP types:** integer-where-raw through the registered symbols
   (currently a clean checked-accessor error — one regression test would fail
   loudly if a future R relaxed the checks).
8. **Silent coercion:** A1's `Rf_asLogical(NA)`; the deliberate
   `Rf_asInteger(NA)` tolerance in the harness.
9. **Connection edge cases:** non-blocking socket/pipe delivering a prefix
   (`isIncomplete` refusal) — the one connection test their suite does not
   have; `gzfile`, `rawConnection`, already-open text-mode connection, missing
   file (covered by their suite; keep them).

---

*Review performed by static read of every non-vendored source plus executed
probes against installed zucrypt 0.1.0 on arm64 macOS (R 4.6.2, aesce path),
cross-checked against system OpenSSL. Probe scripts were run under `/tmp` and
have been deleted; the commands above are reproducible verbatim.*
