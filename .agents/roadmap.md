# zucrypt: roadmap to v0.1.0

Status: proposed plan.
Date: 2026-09-20.
Implements: [design.md](design.md) sections 3, 5, 6, 7, 10, 11, and steps 1–2 of section 12.

## Scope of v0.1.0

v0.1.0 is the **core package**: a vendored Mbed TLS / TF-PSA-Crypto backend, the six-function R
interface, and the versioned C API, released independently of any consumer. It ships when a
compiled consumer can resolve the API and run the Office-style key derivation loop against it, on
all CI platforms, from a source install with no network access and no Python/Perl.

Out of scope for v0.1.0 (owned by later versions or other packages):

- Office/CFB parsing, password derivation constants, `office_*()` functions — `zuxlsx`.
- Authenticated encryption, PBKDF2/HKDF, random bytes, signatures, key serialization — design §5.
- File hashing and connection wrappers — later convenience.
- Worker-thread use of the C API — design §7.
- A shared compiled backend with `zuhttp` — design §9.
- CRAN submission. v0.1.0 is a GitHub tag; CRAN is a separate decision after the ABI has a consumer.

Stages are sequential. Each stage ends with its exit criteria met and CI green; no stage starts
work belonging to a later one.

## Stage 0 — Package identity

Goal: replace the usethis placeholders so every later check runs against a real package.

- Fill `DESCRIPTION`: `Title`, `Description`, `Authors@R`, `BugReports`, `SystemRequirements`
  (C compiler; refine after Stage 1). Add `Config/Needs/website` if pkgdown needs extras.
- `README.md`: state the purpose in the design's own terms (narrow native foundation for the
  `zu*` family; not a replacement for `openssl`/`sodium`). Keep the example block empty until
  Stage 3.
- `NEWS.md`: replace "Initial CRAN submission" with a development-version heading.
- Add `tests/testthat/` with one trivial test so `devtools::test()` runs.
- Add `.Rbuildignore` entries for `^\.agents$` and `^CLAUDE\.md$`.

Exit: `devtools::check()` passes with 0 errors, 0 warnings, 0 notes on all five CI configurations.

## Stage 1 — Backend spike

Goal: resolve the four backend decisions in design §13 with evidence, and prove a source install
of the vendored crypto subset on macOS, Windows (Rtools) and Linux.

Decisions to record in a manifest (`src/vendor/MANIFEST.md` or similar):

- Exact Mbed TLS release and matching TF-PSA-Crypto release (initial candidate: the 4.1 LTS
  family). Source archive URLs and SHA-256 checksums.
- The minimal upstream configuration: PSA crypto only; SHA-1, SHA-256/384/512, HMAC, AES with
  CBC-no-padding and ECB-no-padding; everything else disabled through upstream config, not by
  editing internals. No X.509, no TLS, no entropy/RNG (deferred).
- The build integration: upstream CMake versus a maintained `Makevars`/`Makevars.win`. The
  spike must try both and record why one wins. The chosen one must not download anything or
  invoke Python/Perl during `R CMD INSTALL`.
- Local patches, if any, as separate files applied by the update script — never edits inside the
  vendored tree without a corresponding patch file.

Work items:

- Write `tools/update-vendor.R` (or shell) that downloads the pinned archives, verifies checksums,
  extracts only the required files into `src/vendor/`, applies patches, and rewrites the manifest.
  The script is developer tooling, not part of installation.
- Preserve upstream `LICENSE`/notice files; select the Apache-2.0 option; add
  `inst/COPYRIGHTS` listing all included third-party files and their licenses; update
  `DESCRIPTION` `License` and `Authors@R` (`cph` role for upstream) accordingly.
- Symbol isolation: compile with hidden visibility and a symbol prefix so no `mbedtls_*` or
  `psa_*` symbol is exported from `zucrypt.so`/`.dll`. Verify with `nm`/`dumpbin` in a test.
- Hardware acceleration: either disable it uniformly or verify identical observable results
  across platforms; record the choice.
- Measure and record: source archive size after vendoring, installed shared-object size, and
  install time on each platform.
- Minimal proof: a single internal C routine returning the backend version string, called by a
  placeholder `crypto_info()`.

Exit:

- `R CMD INSTALL` from a source tarball succeeds offline on all CI platforms, including
  macOS ARM64.
- Symbol test passes; `library(openssl); library(zucrypt)` and the reverse order both load and
  `openssl::sha256()` still works.
- Manifest, update script, licenses and size measurements are committed.
- `SystemRequirements` in `DESCRIPTION` reflects what the spike proved (compiler and, if CMake
  won, CMake with a minimum version).

## Stage 2 — Private native adapter

Goal: one internal C layer (`src/adapter.c`, `src/adapter.h`) that wraps PSA and is the only
code that includes upstream headers. Both the R wrappers (Stage 3) and the public table
(Stage 4) call this layer; neither touches PSA directly.

Work items:

- Status code enum covering: OK, invalid argument, unsupported algorithm, allocation failure,
  backend failure, API-version mismatch, overlap not supported. Backend failures carry the
  upstream code internally for diagnostics but map to one public status.
- Fixed-width algorithm identifiers for SHA-1, SHA-256, SHA-384, SHA-512, and AES-128/192/256.
- Hash: one-shot and incremental (`init`, `update`, `finish`, `reset`, `free`). Incremental
  contexts are heap-allocated opaque handles owned by the adapter.
- HMAC: same shape as hash, keyed at `init`.
- AES: key context creation (validates 16/24/32-byte keys), CBC encrypt/decrypt over
  block-aligned buffers with an explicit mutable chaining state that the caller can reset, ECB
  encrypt/decrypt for compatibility. No padding, ever.
- Constant-time equality for equal-length buffers; secure zeroing of caller buffers.
- Overlap policy: exact in-place permitted where the backend supports it; partial overlap
  rejected with a status code. Document per operation.
- Backend initialization and shutdown owned here with a reference count so no consumer context
  outlives the backend; main-thread only.
- Length and arithmetic checks before every allocation; partial contexts destroyed on any
  failed init; key material wiped on free.

Testing at this stage goes through temporary internal `.Call` entry points (removed or hidden
in Stage 3) so known-answer vectors run under `devtools::test()`:

- Published KATs for every enabled hash, HMAC, key size and cipher mode (NIST CAVP / RFC test
  vectors, stored as fixtures with their source recorded).
- One-shot versus incremental equivalence at boundary lengths (0, 1, block-1, block, block+1,
  several blocks, and across an internal buffer boundary).
- Reset behaviour: a reset context matches a fresh one.
- CBC chaining: two half-length calls with retained state equal one full call; reset restores
  the original IV.

Exit: all KATs pass on all CI platforms; adapter has no R API dependencies beyond memory
allocation helpers; upstream headers are included from exactly one translation unit.

## Stage 3 — R interface

Goal: the design §6 surface with its full contract.

Functions: `crypto_info()`, `hash_raw()`, `hmac_raw()`, `constant_time_equal()`,
`aes_cbc_encrypt_raw()`, `aes_cbc_decrypt_raw()`.

Work items:

- Argument validation in R before any native call: raw type, exact-length rules for keys/IVs,
  block-multiple data length, scalar algorithm name matched exactly against a documented
  vector (no `match.arg`).
- Condition system: an `abort_zucrypt()` helper producing conditions with classes
  `c("zucrypt_<code>_error", "zucrypt_error", "error", "condition")`, a `code` field, and a
  message that never includes argument values. Map adapter status codes to these.
- Native entry points registered with `R_registerRoutines`, `useDynLib(zucrypt, .registration = TRUE)`.
- Cleanup on error and interrupt: contexts allocated during a `.Call` are protected by
  `R_UnwindProtect` or an external-pointer finalizer path so an interrupt during a large hash
  cannot leak a context or a key buffer.
- Input immutability: native code never writes into an input raw vector; outputs are freshly
  allocated.
- `crypto_info()` returns a named list: package version, API version, backend name and
  version(s), enabled algorithms, and build flags relevant to behaviour. Nothing else.
- roxygen2 documentation for every export, with the CBC pages stating in the first paragraph
  that no authentication is provided and that this is the caller's responsibility, and that
  SHA-1/ECB exist for compatibility only.

Tests (per design §11 "R interface" row):

- Every validation rule has a test asserting the class and `code` of the condition.
- Empty inputs: hash/HMAC of `raw(0)`; CBC of `raw(0)` returns `raw(0)` only after key/IV
  validation succeeds.
- Immutability: inputs are byte-identical after each call.
- KAT tests re-run through the public R functions, not only the internal entry points.

Exit: `devtools::check()` clean; `NAMESPACE` exports exactly the six functions; internal
Stage 2 entry points are no longer exported.

## Stage 4 — Public C API

Goal: the design §7 interface, with a compiled consumer proving it.

Work items:

- `inst/include/zucrypt.h`: C89/C99-compatible, includes only standard headers. Defines the
  ABI version constant, status codes, algorithm identifiers, capability flags, opaque context
  typedefs, and the function-pointer table struct. No upstream types, no R types.
- One accessor `const zucrypt_api_v1 *zucrypt_get_api(unsigned int requested_version)`
  registered with `R_RegisterCCallable("zucrypt", "zucrypt_get_api", ...)`. Returns `NULL`
  with a version-mismatch status when the requested major version is unsupported.
- Table contents: one-shot and incremental hash/HMAC; AES key context create/destroy; CBC with
  explicit chaining-state get/set/reset; ECB; constant-time compare; secure zero; backend info;
  context destruction. Every function returns a status code; none raise R errors, allocate R
  objects or call back into R.
- Ownership documented in the header: provider-allocated objects are destroyed only by provider
  functions; caller buffers are never retained after return.
- Backend lifetime: the API holds the Stage 2 reference count so a consumer context stays valid
  as long as `zucrypt`'s namespace is loaded; document that unloading `zucrypt` while consumer
  contexts exist is unsupported.
- Consumer fixture: a minimal package under `tests/testthat/consumer/` (or `inst/consumer/`)
  with `LinkingTo: zucrypt`, `Imports: zucrypt`, that resolves the API via `R_GetCCallable` and
  exercises every table entry. Tests install it into a temporary library with
  `pkgload`/`callr` and run its checks. Skip on CRAN if compilation in tests is unavailable.
- Office derivation rehearsal (the ABI validation gate): inside the consumer fixture, implement
  the generic iterative loop `H_n = hash(int32le(n) || H_{n-1})` for a configurable spin count
  using one reused incremental hash context, plus one CBC segment decryption with a reset between
  segments. This is not Office support; it is proof that the incremental and chaining APIs suit
  the real consumer before the ABI is frozen. Compare its output with an independent R
  implementation over small spin counts.
- A vignette or `man` page (`?zucrypt_c_api`) describing how to consume the API, with the
  `LinkingTo` + `Imports` requirement stated explicitly.

Exit:

- Consumer fixture passes on all CI platforms.
- ABI rejection test: requesting an unsupported major version returns `NULL` and the status
  code; the fixture handles it without crashing.
- Loading order tests from Stage 1 extended to load the consumer, `openssl`, and `zucrypt` in
  all orders.

## Stage 5 — Hardening and release gates

Goal: satisfy the design §11 evidence table for the layers that exist in v0.1.0.

Work items:

- Sanitizer CI job: R-devel with ASan/UBSan (R-hub `clang-asan` or `rocker/r-devel-san`)
  running the full test suite including the consumer fixture. Fix every finding.
- Valgrind run on Linux at least once per release; record the command in this file.
- Fuzz the argument-validation and adapter layers (not an Office parser — none exists here) with
  random lengths and algorithm identifiers; check for leaks and crashes only.
- Boundary and size tests: multi-megabyte inputs through both one-shot and incremental paths;
  confirm no R allocation per block.
- Symbol isolation test made permanent in the test suite, not only in the Stage 1 spike.
- Security update rehearsal: run `tools/update-vendor.R` against the same pinned release and
  confirm a no-op diff; document in `MANIFEST.md` the procedure for moving to a new upstream
  patch release and the expected review checklist.
- Platform coverage: confirm CI covers macOS ARM64 (macos-latest), Windows x64 (Rtools),
  Linux x64 on devel/release/oldrel-1. Add Linux ARM64 if a runner is available; otherwise
  record it as unverified.
- Record the supported minimum R version and compiler versions that the vendored build actually
  needs, and set `Depends: R (>= x.y)` accordingly.

Exit: all CI jobs green including sanitizers; no open findings; manifest documents the update
procedure.

## Stage 6 — v0.1.0 release

- Documentation pass: pkgdown reference grouped as "Hashing", "Ciphers (advanced)",
  "Comparison and information", "C API"; README example filled with a hash and an HMAC only
  (no cipher example in the README, to avoid presenting CBC as a general-purpose tool).
- `NEWS.md` entry for 0.1.0 listing the API, the pinned backend release, supported platforms and
  the explicit non-goals.
- Freeze the C ABI: bump `ZUCRYPT_API_VERSION` to 1 and state the compatibility promise
  (additions allowed within major version; nothing removed or reordered).
- `DESCRIPTION` version 0.1.0; tag `v0.1.0`; GitHub release notes point at the pkgdown site.
- Open the `zuxlsx` Agile integration as the next tracked piece of work, in that repository.

## Stage map against the design's open decisions (§13)

| Open decision | Resolved in |
| --- | --- |
| Exact Mbed/TF-PSA release pair and minimal build configuration | Stage 1 |
| Source-install build tooling and supported R/compiler versions | Stage 1, confirmed Stage 5 |
| Default Office resource limits | not in this package; `zuxlsx` |
| CFB parser reuse versus narrow implementation | not in this package; `zuxlsx` |
| Whether the `zuxlsx` ZIP interface accepts raw memory | not in this package; `zuxlsx`/`zukomp` |
| Shared compiled backend with `zuhttp` | deferred; revisit after Stage 6 with Stage 1 size data |

## Risks to watch

- **Windows build.** Rtools toolchain and path-length limits are the most likely place the
  vendored build fails. Stage 1 must not be declared done on macOS/Linux evidence alone.
- **ABI frozen too early.** The Stage 4 derivation rehearsal exists to catch a missing
  incremental or chaining primitive before v0.1.0; do not skip it to save time.
- **Configuration drift.** Any upstream feature enabled "temporarily" during the spike must be
  removed before Stage 2, or it becomes part of the supported profile by accident.
- **License bookkeeping.** `inst/COPYRIGHTS` and `DESCRIPTION` must be updated in Stage 1, not
  at release, because `R CMD check` and CRAN reviewers read them, and because it is easy to
  forget which files carry which license after the tree has been trimmed.
