# zucrypt: roadmap to v0.1.0

Status: proposed plan.
Date: 2026-09-20.
Implements: [design.md](design.md) sections 3–8, 11, 12, and steps 1–2 of section 13.
Revised 2026-09-20 to match the design's review against the sibling packages: both consumer
shapes (table and static archive), `zuc_`/`crypt_` naming, family condition classes and the
`tools/vendor/` layout.

## Scope of v0.1.0

v0.1.0 is the **core package**: a vendored Mbed TLS / TF-PSA-Crypto backend, the six-function R
interface, and the C API in both shapes the family uses — the registered function table
(`zucrypt-r.h`, for `zuhttp`-style consumers) and the static archive (`inst/lib/libzucrypt.a`,
for `zuxlsx`, which has no `Imports:` by design). It ships when a consumer of each shape can run
the Office-style key derivation loop against it, on all CI platforms, from a source install with
no network access and no Python/Perl.

Out of scope for v0.1.0 (owned by later versions or other packages):

- Office/CFB parsing, password derivation constants, `office_*()` functions — `zuxlsx`.
- Authenticated encryption, PBKDF2/HKDF, random bytes, signatures, key serialization — design §6.
- File hashing and connection wrappers — later convenience.
- Worker-thread use of the C API — design §8.
- A shared compiled backend with `zuhttp` — design §10.
- CRAN submission. v0.1.0 is a GitHub tag; CRAN is a separate decision after the ABI has a consumer.

Stages are sequential. Each stage ends with its exit criteria met and CI green; no stage starts
work belonging to a later one.

## Continuous integration

CI comes from [`pedrobtz/r-actions`](https://github.com/pedrobtz/r-actions), the
family's shared reusable workflows, rather than from hand-rolled jobs. Two rules:

- **Pin to a commit, with the tag in a trailing comment.** A tag is mutable, so
  `@v1` means "whatever it points at when the job starts". Current pin:
  `@1878271fd55900994a1b04dae87dd2d23af547a1 # v1.9.0`.
- **Add a workflow at the stage where it has something to check.** A job that is
  green because it inspected nothing is worse than no job: it trains people to
  read the tick rather than the log, and it is indistinguishable from the same
  job after it breaks.

| Workflow | Added in | Why here |
|---|---|---|
| `r-cmd-check.yml` | Stage 0 *(done)* | CRAN's clang-23/GCC-16 containers, ahead of the vendored C that needs them |
| `coverage.yml` | Stage 3 | covr instruments `R/`, which is empty until then; `native: true` in the same commit |
| `vendor.yml` | Stage 1 | guards `src/vendor/` against undeclared drift |
| `vendor-upstream.yml` | Stage 1 | watches upstream for the releases design §4 requires shipping |
| `lto.yml` | Stage 2 | adapter and wrappers are separate translation units |
| `rchk.yml`, `gctorture.yml` | Stage 3 | first R-facing C, so first PROTECT discipline |
| `abi.yaml`, `consumer.yaml` (bespoke) | Stage 4 | r-actions has no ABI workflow; copy `zukomp`'s |
| `sanitizers.yml`, `valgrind.yml`, `analyzers.yml` | Stage 5 | memory safety, once there is a suite that reaches it |
| `arch.yml`, `alloc-failure.yml` | Stage 5 | 32-bit/musl arithmetic; the OOM paths design §11 specifies |
| `fuzz.yml` | deferred | see Stage 5 |

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
- `Depends: R (>= 4.1)` to match `zuxml`/`zuxlsx`; `Config/testthat/parallel: true` as in `zukomp`.
- CI: `R-CMD-check.yaml` already calls `r-cmd-check.yml` with `nosuggests: true`. That leg
  checks the package with none of its `Suggests` installed, so `tests/testthat.R` guards its
  `library(testthat)` with `requireNamespace()`; unguarded, it is an ERROR there and nowhere
  else.
- CI: `coverage.yaml` is **removed here and returns in Stage 3**. Its own comment said to land
  it with the first test file, and that was the wrong trigger: covr instruments the package's
  `R/`, not its tests. With no function to measure, `covr::percent_coverage()` is `NaN` and the
  badge step fails on a comparison against `NaN` — a red job that says nothing about the
  package. Restore it with `git show 244fb729:.github/workflows/coverage.yaml`; the reasoning in
  its comments about reading the "taken at least once" column, and about leaving
  `native-exclude` empty over `src/vendor/`, is still the reasoning that applies.

Exit: `devtools::check()` passes with 0 errors, 0 warnings, 0 notes; every leg of
`r-cmd-check.yml` is green, containers included. (The two NOTEs the CRAN-like containers report
— no `pandoc` for `README.md`/`NEWS.md`, and "New submission / version contains large components"
for `0.0.0.9000` — are properties of those containers and of a development version, not of the
package.)

## Stage 1 — Backend spike

**Resolved. The evidence and every decision it settled are in
[stage-1-spike.md](stage-1-spike.md); this section is the plan it was executed against, kept
as written.** Three things came out differently from the plan below, each recorded there with
its reason: Mbed TLS is not vendored at all (TF-PSA-Crypto is the whole crypto library in 4.x,
so there is one manifest row, not two), the vendored tree is flattened to `inc/` and `lib/`
because upstream's own paths exceed the 100-byte tarball limit, and `vendor-upstream.yaml` has
one job rather than two, for the first reason.

Goal: resolve the four backend decisions in design §14 with evidence, and prove a source install
of the vendored crypto subset on macOS, Windows (Rtools) and Linux.

Decisions to record in `tools/vendor/manifest.tsv` (family layout, design §3 — one row per
upstream source, columns `source repo tag commit version_string archive archive_sha256 license
defines patches`):

- Exact Mbed TLS release and matching TF-PSA-Crypto release (initial candidate: the 4.1 LTS
  family). Source archive URLs and SHA-256 checksums.
- The minimal upstream configuration: PSA crypto only; SHA-1, SHA-256/384/512, HMAC, AES with
  CBC-no-padding and ECB-no-padding; everything else disabled through upstream config, not by
  editing internals. No X.509, no TLS, no entropy/RNG (deferred).
- Build integration is decided (design §4): a portable `src/Makevars` with an explicit
  `OBJECTS` list, no CMake. What the spike settles is the length of that list for the trim, how
  the configuration header is supplied without generation, and that the release archive's
  pre-generated sources suffice — nothing downloaded, no Python/Perl, during `R CMD INSTALL`.
- Entropy/initialisation policy (design §4): does `psa_crypto_init()` in the pinned release need
  an entropy source for a hash/MAC/cipher-only profile? Record which of the two configurations
  applies; if an OS backend is needed, select it the `zux_expat_random.c` way.
- Local patches as `tools/patches/<source>/NNNN-*.patch`, applied by `tools/vendor/fetch` —
  never edits inside the vendored tree without a corresponding patch file.

Work items:

- Copy `zukomp`'s `tools/vendor/{common.sh,fetch,record,verify}` and adapt `keep_files()` for
  the two sources. `fetch` downloads the pinned archives, verifies checksums, keeps only the
  required files under `src/vendor/<source>/`, applies patches; `record` writes
  `checksums.sha256`; `verify` checks offline that the tree, both manifests, the `Makevars`
  define set and `inst/COPYRIGHTS` agree. Maintainer tooling, never run during installation.
- Preserve upstream `LICENSE`/notice files; select the Apache-2.0 option; add
  `inst/COPYRIGHTS` listing all included third-party files and their licenses; update
  `DESCRIPTION` `License` and `Authors@R` (`cph` role for upstream) accordingly.
- Symbol isolation: compile with hidden visibility so no `mbedtls_*` or `psa_*` symbol is
  exported from `zucrypt.so`/`.dll`, and no OpenSSL-ABI name either (`SHA256_Init`, `AES_encrypt`,
  `HMAC`, `EVP_*` — `zuhttp` links system `libcrypto`). Verify with `nm`/`dumpbin` in
  `test-abi.R`, the way `zukomp` bans zlib names.
- Hardware acceleration: either disable it uniformly or verify identical observable results
  across platforms; record the choice.
- Measure and record: source archive size after vendoring, installed shared-object size, and
  install time on each platform.
- Minimal proof: a single internal C routine returning the backend version string, called by a
  placeholder `crypt_info()`.
- CI: add `vendor.yaml` calling `vendor.yml`. Its defaults (`src/vendor`,
  `tools/vendor/verify`, `tools/vendor/manifest.tsv` + `checksums.sha256`) are
  the layout above, so adopt that layout rather than configuring around it. The
  pull-request half is the part the verifier cannot do alone: a hand-edited
  vendored file whose checksum was re-recorded to match passes verification and
  is still unreproducible from the manifest.
- CI: add `vendor-upstream.yaml` calling `vendor-upstream.yml` on a weekly
  schedule, with a `current-version` command reading the pinned release out of
  the manifest. The plan called for two jobs, `Mbed-TLS/mbedtls` and
  `Mbed-TLS/TF-PSA-Crypto`, since 4.x splits the crypto dependency out and a
  stale pin on either half would be the same defect; the spike found that no
  Mbed TLS file is vendored, so there is one. It never fails the check, and it
  reports upstream security advisories — which is the automation behind design
  3's "Ship security updates promptly. Vendored code does not receive fixes
  merely because the operating system is updated."

Exit:

- `R CMD INSTALL` from a source tarball succeeds offline on all CI platforms, including
  macOS ARM64.
- Symbol test passes; `library(openssl); library(zucrypt)` and the reverse order both load and
  `openssl::sha256()` still works.
- `tools/vendor/` manifest, checksums, scripts, patches, `inst/COPYRIGHTS` and size
  measurements are committed; `tools/vendor/verify` is clean; `DESCRIPTION` carries
  `Copyright: See inst/COPYRIGHTS and tools/vendor/manifest.tsv.` and the upstream `cph` entry.
- `SystemRequirements` in `DESCRIPTION` reflects what the spike proved (compiler and, if CMake
  won, CMake with a minimum version).

## Stage 2 — Private native adapter

Goal: one **R-free** C layer (`src/zuc_*.c`, `src/zuc_internal.h`) that wraps PSA and is the
only code that includes upstream headers. It is what goes into `inst/lib/libzucrypt.a`, so it
must never include `R.h` — `zuxlsx` links the archive into its own shared object, where R glue
would be a duplicate symbol. The R wrappers (Stage 3) and the public table (Stage 4) call this
layer; neither touches PSA directly. Its exported functions are the `zuc_*` declarations of
`inst/include/zucrypt.h` (design §8.1), which this stage writes.

Work items:

- `zuc_status`: `ZUC_OK = 0`, then `ZUC_ERR_INVALID_ARGUMENT`, `ZUC_ERR_UNSUPPORTED`,
  `ZUC_ERR_BAD_LENGTH`, `ZUC_ERR_OVERLAP`, `ZUC_ERR_MEMORY`, `ZUC_ERR_BACKEND`, `ZUC_ERR_ABI`,
  `ZUC_ERR_INTERNAL`. No negative value. `zuc_status_string()` covers every enumerator, with a
  test. Backend failures carry the upstream code internally but map to one public status.
- `zuc_alg`: fixed-width identifiers for SHA-1, SHA-256/384/512 and AES-128/192/256; values are
  permanent, an algorithm compiled out keeps its number and reports unavailable.
- Hash: one-shot and incremental (`init`, `update`, `finish`, `reset`, `free`). Incremental
  contexts are heap-allocated opaque handles owned by the adapter.
- HMAC: same shape as hash, keyed at `init`.
- AES: key context creation (validates 16/24/32-byte keys), CBC encrypt/decrypt over
  block-aligned buffers with an explicit mutable chaining state that the caller can reset, ECB
  encrypt/decrypt for compatibility. No padding, ever.
- Constant-time equality for equal-length buffers; secure zeroing of caller buffers.
- Overlap policy: exact in-place permitted where the backend supports it; partial overlap
  rejected with a status code. Document per operation.
- `zuc_init()`/`zuc_shutdown()` owned here with a reference count so no consumer context
  outlives the backend; main-thread only. An archive consumer calls them itself.
- Every options/info struct has a leading `uint32_t struct_size` and a `ZUC_*_REQUIRED_SIZE`
  macro giving the prefix the core dereferences — never the full current `sizeof`.
- The archive: `src/Makevars` builds `libzucrypt.a` from the adapter and vendored objects with
  `$(ALL_CFLAGS)` (position-independent), `all: $(SHLIB) libzucrypt.a` as the first target;
  `src/install.libs.R` installs the shared object *and* the archive to `inst/lib/` (defining that
  file stops R installing the `.so` by itself). No upstream header is installed — design §8.3.
- Length and arithmetic checks before every allocation; partial contexts destroyed on any
  failed init; key material wiped on free.

Testing at this stage goes through an always-compiled `zucrypt_test_*` `.Call` harness — the
analogue of `zukomp`'s `zu_test_stream()`, kept permanently so split-point sweeps stay tested —
plus `test-linking.R` against the installed package:

- Published KATs for every enabled hash, HMAC, key size and cipher mode (NIST CAVP / RFC test
  vectors, stored as fixtures with their source recorded).
- One-shot versus incremental equivalence at boundary lengths (0, 1, block-1, block, block+1,
  several blocks, and across an internal buffer boundary).
- Reset behaviour: a reset context matches a fresh one.
- CBC chaining: two half-length calls with retained state equal one full call; reset restores
  the original IV.
- `test-linking.R` (skips under `load_all()`): `inst/lib/libzucrypt.a` and `zucrypt.h` exist after
  the install-step merge; the archive defines every `zuc_*` entry point and no `R_init_`,
  `zucrypt_` or R symbol.
- KAT fixtures committed with a `MANIFEST.tsv` recording their source (NIST CAVP / RFC), and a
  `tools/make-kat.R --check` that reproduces them.

CI: add `lto.yml` to a new `native-checks.yaml`. The adapter, the wrappers and the
vendored tree are separate translation units, and `-flto` is what cross-checks a
declaration in `adapter.h` against its definition — a signature mismatch that
ordinary checks compile happily and that surfaces as corruption at runtime. `coverage.yml` and its
`native: true` arrive together in Stage 3, once there is an R surface to instrument alongside
the C.

Exit: all KATs pass on all CI platforms; the adapter includes no R header at all; upstream
headers reach no file outside the adapter; `test-linking.R` passes under `R CMD check`.

The second and third criteria were written as "upstream headers are included from exactly one
translation unit", which the implementation does not meet and should not: the adapter is five
files (`zuc_status`, `zuc_backend`, `zuc_hash`, `zuc_aes`, `zuc_util`), and collapsing them into
one to satisfy a count would be worse code for no gain. What the criterion is actually about is
isolation, and that is now enforced in both directions and mechanically, by
`tools/check-layering.sh` in `native-checks.yaml`: `src/zuc_*.c` and `inst/include/zucrypt.h` may
not name an R header, `SEXP` or `Rf_*`; `src/zucrypt_*.c` may not name a backend header, `psa_*`,
`mbedtls_*` or `PSA_*`; the public header includes `<stddef.h>` and `<stdint.h>` and nothing
else; and every `zuc_*` it declares is defined in the adapter. `src/zuc_internal.h` is the single
place where backend vocabulary enters the package.

## Stage 3 — R interface

Goal: the design §7 surface with its full contract.

Functions: `crypt_info()`, `crypt_hash()`, `crypt_hmac()`, `crypt_equal()`,
`crypt_aes_cbc_encrypt()` / `crypt_aes_cbc_decrypt()` (design §7 — family prefix, no `_raw`).

Work items:

- Argument validation in R before any native call: raw type, exact-length rules for keys/IVs,
  block-multiple data length, scalar algorithm name matched exactly against a documented
  vector (no `match.arg`).
- Condition system as in `zukomp/R/conditions.R`: a `zucrypt_abort(class, message, algorithm,
  native_status)` helper producing `c(<specific>, "zucrypt_error", "error", "condition")`;
  the status→class map keyed by C enumerator *name* (`zucrypt_invalid_argument`,
  `zucrypt_unsupported_algorithm`, `zucrypt_bad_length`, `zucrypt_memory_error`,
  `zucrypt_backend_error`, `zucrypt_abi_mismatch`, `zucrypt_internal_error`), names fetched via
  `.Call(zucrypt_status_codes)` so renumbering cannot remap. Messages never include argument
  values.
- Native entry points registered with `R_registerRoutines`, `useDynLib(zucrypt, .registration = TRUE)`.
- Cleanup on error and interrupt: contexts allocated during a `.Call` are protected by
  `R_UnwindProtect` or an external-pointer finalizer path so an interrupt during a large hash
  cannot leak a context or a key buffer.
- Input immutability: native code never writes into an input raw vector; outputs are freshly
  allocated.
- `crypt_info()` follows `komp_info()`: `version` (character), `abi_version`, `algorithms`,
  `vendored` (data frame of `source`/`version` reported from the compiled library via
  `zucrypt_vendored()`, never from the manifest), `build_flags`. Nothing else.
- roxygen2 documentation for every export, with the CBC pages stating in the first paragraph
  that no authentication is provided and that this is the caller's responsibility, and that
  SHA-1/ECB exist for compatibility only.

Tests (per design §12 "R interface" row):

- Every validation rule has a test asserting the class and `code` of the condition.
- Empty inputs: hash/HMAC of `raw(0)`; CBC of `raw(0)` returns `raw(0)` only after key/IV
  validation succeeds.
- Immutability: inputs are byte-identical after each call.
- KAT tests re-run through the public R functions, not only the internal entry points.

CI: restore `coverage.yaml` (see Stage 0) with `native: true` on from the start — this is the
first stage with R functions for covr to instrument, and the C from Stage 2 is measured in the
same commit. Add `rchk.yml` and `gctorture.yml` to `native-checks.yaml`. This is the stage
that introduces R-facing C, so it is the stage that introduces PROTECT bugs. The
two are complements, not alternatives: rchk reasons statically about the PROTECT
stack, gctorture provokes real collections. Start `rchk` informational; turn on
`fail-on-findings: true` the moment it reads zero, with a `baseline:` file ready
for the first false positive — a boolean gate has one bad day in it, and what
happens on that day is that someone sets it to false and the gate is gone.

The `R_UnwindProtect` path above is exactly what gctorture is good at: an
interrupt during a large hash is a `longjmp` past whatever C had allocated.

Exit: `devtools::check()` clean; `NAMESPACE` exports exactly the six `crypt_*` functions;
`zucrypt_test_*` symbols stay compiled but unexported.

## Stage 4 — Public C API

**Done.** One deviation: `consumer.yaml` runs the fixture on Linux, macOS and Windows, but
`tools/check-linking.sh` only on the first two. It compiles a plain C program with `cc`, and
doing that portably under Rtools is a different script rather than a different flag; the
archive itself is built and installed on Windows by every `R-CMD-check` run, and
`test-linking.R` audits it there.

Goal: the design §8.2 table, with a compiled consumer proving each shape. (The archive shape
exists since Stage 2; this stage adds its consumer proof.)

Work items:

- `inst/include/zucrypt-r.h`: includes `zucrypt.h`, then `R.h`/`Rinternals.h`/`Rdynload.h`;
  defines `zucrypt_api_v1` (leading `abi_version`, `struct_size`, then pointers mirroring
  §8.1) and a `static inline zucrypt_api()` that resolves `R_GetCCallable("zucrypt",
  "zucrypt_get_api")` once through a union (not a function-pointer cast — that is a
  `-Werror` failure for the consumer), passes `ZUCRYPT_ABI_VERSION`, caches, and returns `NULL`
  on mismatch. Lazy, because `Imports:` alone does not load the namespace.
- `zucrypt_get_api(uint32_t requested)` registered from `R_init_zucrypt` after backend init.
  Callable-name versioning rule from `zuxml.h`: a layout change to any non-table type renames the
  callable, so an old consumer fails at `R_GetCCallable()` rather than corrupting its stack.
- Table contents: one-shot and incremental hash/HMAC; AES key context create/destroy; CBC with
  explicit chaining-state get/set/reset; ECB; constant-time compare; secure zero; backend info;
  context destruction. Every function returns a status code; none raise R errors, allocate R
  objects or call back into R.
- Ownership documented in the header: provider-allocated objects are destroyed only by provider
  functions; caller buffers are never retained after return.
- Backend lifetime: the API holds the Stage 2 reference count so a consumer context stays valid
  as long as `zucrypt`'s namespace is loaded; document that unloading `zucrypt` while consumer
  contexts exist is unsupported.
- Consumer fixture, shape one: `tests/consumer/zucrypttest`, a package with `Imports:` +
  `LinkingTo:` + a real `importFrom()` in `NAMESPACE`, exercising every table entry.
  `.Rbuildignore`d; built only by `consumer.yaml` (`R CMD INSTALL .`, then the fixture, then
  `testthat::test_local()`, failing if zero tests ran).
- Consumer fixture, shape two: `tools/check-linking.sh` compiles a C program against
  `zucrypt.h` and links `inst/lib/libzucrypt.a` from the installed package, calls `zuc_init()`,
  hashes a KAT, and exits non-zero on mismatch — `zukomp`'s pattern for its ZIP reader.
- Office derivation rehearsal (the ABI validation gate): inside the consumer fixture, implement
  the generic iterative loop `H_n = hash(int32le(n) || H_{n-1})` for a configurable spin count
  using one reused incremental hash context, plus one CBC segment decryption with a reset between
  segments. This is not Office support; it is proof that the incremental and chaining APIs suit
  the real consumer before the ABI is frozen. Compare its output with an independent R
  implementation over small spin counts.
- A vignette or `man` page (`?zucrypt_c_api`) describing how to consume the API, with the
  `LinkingTo` + `Imports` requirement stated explicitly.

CI: two workflows here are **bespoke** — r-actions has no ABI or consumer job,
because both are specific to what a package publishes. Copy `zukomp`'s, which
were written for this exact shape:

- `abi.yaml` — compiles `inst/include/zucrypt.h` standalone as C99 with
  `-Wall -Wextra -Wpedantic -Werror` and no R headers, again as C++ through the
  `extern "C"` wrapper, compiles a consumer probe against `zucrypt-r.h` with `-Werror`, and
  greps the comment-stripped header for leaked vocabulary (`mbedtls`, `psa_`, `PSA_`, `SEXP`,
  `Rf_`, and the OpenSSL names from design §3). design §3 makes that a requirement rather than a
  preference, and it is invisible to `R CMD check`, which only ever compiles the header inside a
  translation unit that already included R's. Add a probe that includes the header *without
  using it* and still compiles `-Werror`: a header-defined plain `static` is an unused-function
  error in the consumer's tree and warning-free in ours.
- `consumer.yaml` — installs `zucrypt`, then the fixture, then runs its tests on
  Linux/macOS/Windows. Fail when zero tests are discovered; `any()` over an empty
  vector is `FALSE`, so a fixture that silently stopped being found is a green
  job that proved nothing.

Exit:

- Consumer fixture passes on all CI platforms.
- ABI rejection test: requesting an unsupported major version returns `NULL` and the status
  code; the fixture handles it without crashing.
- Loading order tests from Stage 1 extended to load the consumer, `openssl`, and `zucrypt` in
  all orders.
- `tools/check-linking.sh` passes on Linux and macOS in `consumer.yaml`.

## Stage 5 — Hardening and release gates

**Done, with one documented deviation.** `extra-ubsan-checks` is not passed, and the argument
for it below still stands — it just cannot be applied only to our code. Two instrumented runs
found two deliberate cases in the vendored tree: `aes.c`'s GF(2^8) doubling truncating to
`uint8_t`, and `sha256.c`'s compression function adding modulo 2^32, which is the one this
section predicted. Writing them down in `tools/ubsan.supp` is the right answer and is currently
unavailable: passing `ubsan-suppressions` breaks the `asan` job, which runs inside a container
where the checkout is mounted at `/__w/...` while the path is built from `github.workspace`,
the host path. So the choice is ASan or the extra integer checks, and ASan wins — it finds
use-after-free and double-free on exactly the cleanup paths §11 legislates about, while the
length arithmetic is simple, validated in R before any native call, and separately exercised by
`arch.yml`'s 32-bit leg. Both suppression entries are written down and ready; restoring is two
lines once r-actions resolves that path. The fix belongs in `r-actions`, not here.

Two further notes. `rchk` and `analyzers` land informational, as planned, and are gated the
moment they read zero rather than in the same commit — a gate turned on before it has ever
been green is a gate somebody turns off. And the R floor is now a measurement rather than a
claim: `R-CMD-check.yaml` carries an explicit `4.1` leg, because `release` and `oldrel-1` prove
the package works on two recent versions and say nothing about the minimum `DESCRIPTION`
declares.

Goal: satisfy the design §12 evidence table for the layers that exist in v0.1.0.
Almost all of it is adopting the remaining r-actions workflows into
`native-checks.yaml`, plus two scheduled ones of their own.

**`sanitizers.yml`**, with both halves on:

```yaml
  sanitizers:
    uses: pedrobtz/r-actions/.github/workflows/sanitizers.yml@1878271... # v1.9.0
    with:
      asan: true
      extra-ubsan-checks: -fsanitize=integer
      ubsan-suppressions: tools/ubsan.supp
```

`extra-ubsan-checks: -fsanitize=integer` is the one addition worth arguing for.
Unsigned overflow is *defined* behaviour, so CRAN does not check it, and it is
still a bug when it happens to a length, an offset or a block count — and design
§10 rests the package's safety on exactly that arithmetic ("Validate lengths and
arithmetic before allocation"). It is fatal and adoption means working through
findings a run at a time, so turn it on early, not at the end.

`tools/ubsan.supp` is where the deliberate cases get written down, one
`<check>:<file or function>` per line. Expect the vendored tree to need entries:
hash mixing wants wrapping. Write them down rather than dropping the flag.

`asan: true` runs in the R-hub containers, where R itself is instrumented — the
one place ASan works for an R package without `-shared-libasan` gymnastics. Not
redundant with the UBSan job: the design's error and cleanup paths are where a
double-free or a use-after-free would live, and UBSan does not look at the heap.

**`valgrind.yml`**, with `--leak-check=full`:

```yaml
      valgrind-opts: >-
        --leak-check=full
        --show-leak-kinds=definite,indirect --errors-for-leak-kinds=definite,indirect
```

R's own `--use-valgrind` does not set `--leak-check=full`, so a "definitely lost"
total arrives with no stack and cannot be attributed. For this package the
expected leak is precise — a context or a key buffer stranded when
`R_CheckUserInterrupt()` `longjmp`s past the free below it — and a total with no
stack is exactly what would not find it.

**`analyzers.yml`** — GCC's `-fanalyzer`, for allocator lifecycle: leak on an
error path, free of a partially built context, use after destruction. That is the
bug class design §11 legislates against, and unlike ASan and valgrind it reaches
code no test executes. Set `exclude: src/vendor` — upstream's findings are not
ours to fix and a report full of them is one people learn to skip. Informational
first, `fail-on-findings: true` once at zero.

**`arch.yml`** on a weekly schedule. `r-cmd-check.yml` covers CRAN's compilers
well and its architectures not at all — everything there is x86_64 glibc. The
32-bit leg is the one that matters here: `size_t` narrows to 32 bits, and every
length check, block count and "is this a multiple of 16" becomes different
arithmetic. A bound computed as a product can overflow there while being nowhere
near the limit on 64-bit. The musl leg costs little alongside it. Neither needs
QEMU. Add the aarch64 target from the README before tagging.

**`alloc-failure.yml`** on a weekly schedule, with a small driver:

```yaml
      run: Rscript tools/alloc-exercise.R
      expect-pattern: "zucrypt_alloc_error|cannot allocate"
```

This is the direct test of a design §11 sentence that nothing else reaches:
"Destroy partial contexts after any failed initialization." Nothing in an
ordinary suite makes `malloc` fail, so that code is executed zero times — ASan
and valgrind check what happens to memory that *was* allocated, gctorture forces
collections rather than failures, rchk reasons about PROTECT rather than a NULL
return. `expect-pattern` is what makes it "behaved" instead of "did not crash":
the allocation-failure code from Stage 3's condition system is the string to
match.

**`fuzz.yml` is deferred, deliberately.** Design §12 says to fuzz the Office
parser, and the Office parser is in `zuxlsx`. Fuzzing a hash or a CBC block
against a vendored library that upstream already fuzzes buys close to nothing:
the inputs are unstructured bytes with no format to discover, which is the case
coverage-guided fuzzing is *least* suited to. The honest target here is the
incremental/chaining state machine — arbitrary split points across an update
sequence — and that is better expressed as a property test in Stage 2's suite.
Revisit if the C API grows anything that parses.

Remaining work items, which are not workflow adoption:

- Symbol isolation test from Stage 1 made permanent in the test suite, not left
  as a one-off spike result.
- Boundary and size tests: multi-megabyte inputs through both one-shot and
  incremental paths; confirm no R allocation per block.
- Security update rehearsal: re-run `tools/vendor/fetch` against the same pinned release,
  then `record` and `verify`, and confirm a no-op diff. `vendor-upstream.yml` from Stage 1
  tells you *when* upstream moves; this proves the procedure for acting on it works before it
  is needed under time pressure.
- Record the minimum R version and compiler versions the vendored build actually
  needs, and set `Depends: R (>= x.y)` accordingly.

Exit: every job green, including the sanitizer and container legs; `rchk` and
`analyzers` both gating rather than informational; no open findings; the manifest
documents the upstream-update procedure.

## Stage 6 — v0.1.0 release

- Documentation pass: pkgdown reference grouped as "Hashing", "Ciphers (advanced)",
  "Comparison and information", "C API"; README example filled with a hash and an HMAC only
  (no cipher example in the README, to avoid presenting CBC as a general-purpose tool).
- `NEWS.md` entry for 0.1.0 listing the API, the pinned backend release, supported platforms and
  the explicit non-goals.
- Freeze the C ABI: bump `ZUCRYPT_API_VERSION` to 1 and state the compatibility promise
  (additions allowed within major version; nothing removed or reordered).
- `DESCRIPTION` version 0.1.0; tag `v0.1.0`; GitHub release notes point at the pkgdown site.
- Badges in `README.md`: the R-CMD-check badge already points at
  `R-CMD-check.yaml` (keep that filename — the badge URL uses the caller's file
  name, not the workflow's `name:`), plus the self-hosted coverage badge from
  `.github/badges/coverage.svg`.
- README example uses `crypt_hash()` and `crypt_hmac()` only.
- Bump every r-actions pin to the current release in one commit, read the diff,
  and let a full CI run finish before tagging. Pins are commits precisely so
  this is a decision rather than something that happened between two runs.
- Open the `zuxlsx` Agile integration as the next tracked piece of work, in that repository.

## Stage map against the design's open decisions (§14)

| Open decision | Resolved in |
| --- | --- |
| Exact Mbed/TF-PSA release pair and minimal build configuration | Stage 1 |
| Build tooling | resolved: portable `Makevars` (design §4); Stage 1 settles the object list |
| Entropy / `psa_crypto_init()` policy | Stage 1 |
| Supported R/compiler versions | Stage 1, confirmed Stage 5 |
| Default Office resource limits | not in this package; `zuxlsx` |
| CFB parser reuse versus narrow implementation | not in this package; `zuxlsx` |
| Handing decrypted bytes to xlsxio | resolved: `xlsxioread_open_memory()` (design §9) |
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
- **Vacuous green CI.** Every workflow above is scheduled into the stage where it
  has something to inspect. Adding one earlier does not buy early warning; it
  buys a tick that means nothing and is indistinguishable from the same tick
  after the job silently stops testing anything. The r-actions jobs that verify
  their own instrumentation (`nm` on the sanitizer builds, the
  `LLVMFuzzerTestOneInput` check) exist because that failure mode is real.
