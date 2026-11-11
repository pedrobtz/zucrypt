# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Shared conventions

The portfolio’s shared rules are synced into `.claude/shared/` from
`pedrobtz/packages:claude/shared/`. Never edit them here. Where this
file and a shared file disagree, this file wins for zucrypt.

@.claude/shared/workflow.md @.claude/shared/r-package.md
@.claude/shared/ci.md @.claude/shared/native-code.md
@.claude/shared/correctness.md @.claude/shared/assurance.md

## What this is

zucrypt is cryptography over raw vectors with no system library: a
vendored, pinned TF-PSA-Crypto subset (the Mbed TLS project’s
cryptography library) built from source, exposed to R as `crypt_*`
functions and to other packages as a static archive and a registered C
table. It is one package in the `zu*` family (siblings are checked out
alongside it: `zuxlsx`, `zuxml`, `zukomp`, `zuhttp`, `zujwt`, …). Design
revision 4 widened it from `zuxlsx`’s archive provider into an
alternative to the `openssl` package, through an openssl-shaped layer
(design §7.1) added in tranches after v0.1.0. A primitive enters on the
admission rule of design §6 (a numbered standard, published vectors, an
outside oracle, a composition contract, a demonstrated workflow
benefit), not on a named consumer.

The boundary is strict and is the main thing to preserve:

- **zucrypt owns cryptography**: hashes, HMAC, AES, randomness, AEAD,
  KDFs, keys, signatures and, from Stage 17, certificate data; and, if
  Stage 18 is taken, a TLS client *engine* for `zuhttp` (design §10). It
  never acquires XML, ZIP, Office, socket, name-resolution, proxy or
  trust-store dependencies, and never reaches the user’s environment (no
  key files, passphrase prompts or certificate downloads: design §5).
- **Office/Excel decryption orchestration lives in `zuxlsx`**: iteration
  counts, salts, block keys, password verifiers and segment IVs. It may
  depend on zucrypt and `zuxml`, never the reverse.
- **`zuhttp` owns connections, trust and TLS policy** and keeps its
  native OS TLS backends. A bundled TLS engine, if ever taken (Stage
  18), is compiled into `zucrypt.so`, published through a separate table
  (`zucrypt-tls.h`) that `zuhttp` resolves at run time from `Suggests:`,
  driven over I/O callbacks `zuhttp` supplies, verifying only against
  the CA bundle, host name and pins `zuhttp` passes. It is **never in
  `libzucrypt.a`**, so ABI 1 never sees it.
- No `encrypt_file(password = )`, ever: the package specifies no format.

[.agents/design.md](https://pedrobtz.github.io/zucrypt/.agents/design.md)
(revision 4, 2026-09-29) is the specification and outranks this file;
design changes belong there. §3–§8 and §11–§12 describe `main`; §6, §7.1
and §10 describe where revision 4 takes it (Stages 13–17); §9 and §13
steps 3–5 are plans owned by `zuxlsx` and `zuhttp`.
[.agents/roadmap.md](https://pedrobtz.github.io/zucrypt/.agents/roadmap.md)
Part A is the plan (its stage map says which stage is current); Part B
is the executed v0.1.0 roadmap, kept as the record. Read
[.agents/stage-1-spike.md](https://pedrobtz.github.io/zucrypt/.agents/stage-1-spike.md)
before touching `src/vendor/`, `src/Makevars` or
`src/zuc_crypto_config.h`.

## Current state

Verified 2026-11-09: 0.1.0 is on CRAN, published 2026-10-23 (crandb); it
was submitted 2026-09-30 and resubmitted 2026-10-13 from `5a43275`,
tagged `v0.1.0` with its GitHub release. `main` is `0.1.0.9000`. The
open version issue is [v0.1.1
(#77)](https://github.com/pedrobtz/zucrypt/issues/77), with no stage
sub-issues yet; the roadmap’s release table plans each tranche as its
own minor release (v0.2.0 onwards).

On `main`, beyond the v0.1.0 surface: Stages 13a (randomness, \#9), 14a
(AES-GCM and PBKDF2, \#10, \#12), 15a (RSA and key I/O, \#80) and 16a
(EC keys, ECDSA, ECDH, X25519, \#81) are done. They were split off their
tranches because `zujwt` needed them first. Not built yet: 13b (the rest
of tranche 1), 14b (ChaCha20-Poly1305, CTR, padded CBC, HKDF), 15b
(envelopes, SSH, fingerprints, bignum, encrypted PEM), 17 (certificates)
and 18 (the TLS engine). Stages 15–18 are candidates, each decided when
the one before has shipped. Ed25519 is absent from the pinned release:
the first documented gap against `openssl`.

**Stability comes in tiers (design §8.6).** The seven core R functions
of design §7 are stable. The archive (`zucrypt.h`, `libzucrypt.a`,
`ZUCRYPT_ABI_VERSION 1`) is **frozen as ABI 1** since Stage 11, on
`zuxlsx`’s real decryption core in C
([zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22) step 3,
zuxlsx#64) passing on three operating systems. The table is
*experimental*: no package uses it (#14, \#28).

## Versions and dependents

The current version’s parent issue is [v0.1.1
(#77)](https://github.com/pedrobtz/zucrypt/issues/77). Dependents:

- **`zuxlsx`** links the static archive
  (`LinkingTo: zucrypt (>= 0.1.0)`, no `Imports:`). `revdep.yaml` builds
  it on Linux against every push and pull request, and `platforms.yaml`
  on macOS and Windows at the full profile. Every zucrypt release after
  0.1.0 is additions only, so none puts `zuxlsx` back in the release
  sequence.
- **`zujwt`** is the workflow that admitted Stages 13a–16a.
- **`zuhttp`** is the table consumer that was *hoped* for, not a real
  one: its `DESCRIPTION` has no `Imports:` and its one pin
  implementation hashes with the TLS backend’s own SHA-256 (#14).

Deviations from `.claude/shared/workflow.md`: there is no
`cran-release.yaml`, `CRAN-SUBMISSION` is git-ignored, and the 0.1.0 tag
is `v0.1.0`, not the bare version. A release is tagged by hand with
`pkg-post-cran`.

A stage that adds or changes a scheduled job closes only after that
job’s first real run, dispatched by hand, whose log shows it exercised
what it is named for (design §12). Before pushing a stage, `document()`,
`test()` and `check()` are clean locally at 0/0/0: CI is for the
platforms this machine is not. A failing leg is part of the stage until
it is understood, never “unrelated”.

## Commands

Beyond the shared `devtools` commands:

``` sh
Rscript -e 'devtools::build_readme()'     # README.Rmd -> README.md
Rscript -e 'pkgdown::build_site()'        # site in docs/ (gitignored)
Rscript -e 'pkgbuild::clean_dll()'        # when native state gets stale
Rscript tools/make-kat.R --check          # recompute kat.tsv against openssl
python3 tools/check-kat.py                # aead.tsv, kdf.tsv vs cryptography
python3 tools/make-rsa-kat.py --check     # rsa.tsv, rsa-keys.tsv vs the RFCs
python3 tools/make-ec-kat.py --check      # ec.tsv, ec-keys.tsv vs the RFCs
python3 tools/make-derivation-kat.py ZUXLSX_CHECKOUT --check
sh tools/check-layering.sh                # adapter R-free, glue backend-free
bash tools/check-linking.sh               # the archive, as a consumer links it
make -C ctest run                         # the adapter's C driver (ZUC_CTEST_FULL=1: every alloc)
make -C fuzz replay-run                   # the fuzz corpus through every oracle
make -C fuzz replay-asan                  # the same under ASan + UBSan
tools/ci/platform.sh macos                # platforms.yaml's per-OS checks
tools/vendor/fetch && tools/vendor/record # re-vendor after a keep/patch change
tools/vendor/verify                       # vendored tree vs manifest
R_ENABLE_JIT=0 Rscript tools/alloc-exercise.R [--baseline]
Rscript tools/openssl-usage.R [dir]       # openssl usage by CRAN revdeps
```

The Python tools need the `cryptography` package (the derivation one
needs msoffcrypto-tool 6.0.0 and a `zuxlsx` checkout); run them from a
venv. Without `--check` the generators write their fixtures and manifest
rows; `make-kat.R` keeps the rows other generators own.
`openssl-usage.R` is network-bound and backs the tranche order and the
migration article’s “N of openssl’s exports”; its results are dated in
the roadmap, so re-run it before restating the claim.

## Architecture

Three surfaces:

1.  **The R surface.** The core `crypt_*` functions
    ([`crypt_info()`](https://pedrobtz.github.io/zucrypt/reference/crypt_info.md),
    [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md),
    [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md),
    [`crypt_hex()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hex.md),
    [`crypt_equal()`](https://pedrobtz.github.io/zucrypt/reference/crypt_equal.md),
    [`crypt_rand_bytes()`](https://pedrobtz.github.io/zucrypt/reference/crypt_rand_bytes.md),
    the `crypt_aes_cbc_*_nopad()` pair, the `crypt_aes_gcm_*()` pair,
    [`crypt_pbkdf2()`](https://pedrobtz.github.io/zucrypt/reference/crypt_pbkdf2.md))
    and the openssl-shaped layer (key read and write, RSA, EC, X25519,
    signatures, `crypt_sha*()`). The CBC pair carries `_nopad` (#56) so
    that Stage 14’s openssl-compatible padded pair can take the ordinary
    names.
2.  **A registered function table** (`inst/include/zucrypt-r.h`,
    `zucrypt_api_v1`, resolved lazily via `zucrypt_get_api`) for
    consumers with `Imports:` + `LinkingTo:` + a real `importFrom()`.
3.  **A static archive**, `libzucrypt.a`, for `zuxlsx`-style consumers
    (`LinkingTo:` + `configure` resolving `system.file("lib")`, no
    `Imports:`). `src/install.libs.R` installs it to the package’s
    `lib${R_ARCH}/`, beside `licenses/tf-psa-crypto-LICENSE`; there is
    no `inst/lib/` in the sources. It holds the R-free adapter plus
    vendored crypto, **not** raw upstream (unlike `zukomp`/`zuxml`), so
    consumers see only `inst/include/zucrypt.h`.

The native layer is in two halves, and the split is load-bearing.
`src/zuc_*.c` is the adapter: R-free, and what goes into the archive.
`src/zucrypt_r.c`, `src/zucrypt_crypt.c`, `src/zucrypt_api.c` and
`src/zucrypt_test.c` are the R glue: backend-free, and not in the
archive. `src/zucrypt_crypt.c` holds the `.Call` entry points behind the
exports. `src/zucrypt_test.c` is a permanently compiled harness
(`zucrypt_test_*`, the analogue of `zukomp`’s `zu_test_stream()`)
through which the suite drives the adapter at caller-chosen split
points.

An opaque `zuc_pkey` holds RSA (PKCS#1 DER), EC and X25519 key material,
its `ptype` the backend type, and imports it into PSA per operation, so
one key serves every scheme and digest. Randomness reads
`src/zuc_random.c`’s operating-system source directly, not through
`psa_generate_random()`.

Naming (design §3, `zukomp`’s CLAUDE.md is the reference): C ABI prefix
`zuc_`/`ZUC_`, never `zu_` (that is `zukomp`’s public namespace and
`zuhttp`’s internal one, so a `zucrypt.h` using it could not be included
beside `zukomp.h`); R exports `crypt_*`; entry points `zucrypt_*`;
internal `zuc_int_*`; test-only `zucrypt_test_*`; condition classes
`zucrypt_*`.

Long-form documentation is pkgdown-only, in `vignettes/articles/`
(zukomp’s layout), kept out of the tarball. `zucrypt.Rmd` is “Get
started”; `c-api.Rmd` (“Using zucrypt from C”, \#13) quotes the `tools/`
fixtures, so it moves when they do; `backend.Rmd` (“The vendored
backend”, \#17) is what a CRAN or security reviewer reads.

## Invariants that are easy to break

- **The ABI 1 promise.** Within major version 1, archive functions and
  table fields may be *added*, always appended; nothing is removed,
  reordered or given a new meaning; enumerator values are permanent; and
  a `ZUC_*_REQUIRED_SIZE` macro never grows. A layout change to a type
  `struct_size` cannot see renames the registered callable instead, so
  an old consumer fails at `R_GetCCallable()` rather than reading a
  moved structure.
  [`?zucrypt_c_api`](https://pedrobtz.github.io/zucrypt/reference/zucrypt_c_api.md)
  is the published statement.
- **Layering.** Including `R.h` in the adapter compiles fine here and
  fails much later in a consumer’s build; a backend header in the R glue
  is the start of PSA types in an installed header.
  `tools/check-layering.sh` enforces both directions in CI.
- **`inst/include/zucrypt.h` compiles standalone as C99** with no R or
  PSA vocabulary.
- **Upstream symbols are hidden** (`PKG_CFLAGS = $(C_VISIBILITY)`) so
  independent vendored copies cannot bind to each other; `test-abi.R`
  asserts the shared object exports `R_init_zucrypt` and nothing else.
- **Heap state across a longjmp is owned by R.** Every context in
  `src/zucrypt_crypt.c` is owned by a finalized external pointer from
  the moment it exists, created *before* the context, because the loops
  call `R_CheckUserInterrupt()` between 1 MiB chunks. C returns status
  codes, never `Rf_error()` below the outermost `.Call`.
  `src/zuc_live.h` counts live handles; `test-lifetime.R` interrupts
  each `crypt_*` loop with
  [`setTimeLimit()`](https://rdrr.io/r/base/setTimeLimit.html) and
  checks the count returns to baseline after
  [`gc()`](https://rdrr.io/r/base/gc.html).
- **Key objects are tagged external pointers.** Never strip their
  attributes: an external pointer is not duplicated.
- **Allocation failures are reported as such.** The backend allocates
  through `zuc_int_calloc()` (`MBEDTLS_PLATFORM_CALLOC_MACRO`), which
  records a NULL return; the `zuc_pkey_*` entry points report any
  failure after one as `ZUC_ERR_MEMORY`, because bignum and ASN.1 code
  turns allocation failures into “invalid key” and the like.
- **The PSA key store is dynamic** (`MBEDTLS_PSA_KEY_STORE_DYNAMIC`,
  \#30): each `zuc_aes` and `zuc_hmac` holds one volatile key. The
  static 32-slot store it replaced failed at the 17th live AES handle as
  `ZUC_ERR_MEMORY`. `zuc_shutdown()` to zero destroys every key, so a
  test that does it runs with nothing else live.
- **Binary arguments are raw vectors only**, except `data` to
  [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
  and
  [`crypt_hmac()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hmac.md),
  which may be a connection (#11), streamed in 1 MiB chunks through
  `zucrypt_*_stream_*` and refused in text mode. A character value is
  never a filename, password or byte sequence: a file is hashed as
  `crypt_hash(file(path))`. The openssl-shaped layer is the one place
  character input is accepted, typed as `openssl` types it.
- **Algorithm names are exact scalars**: no partial matching, no
  fallback.
- **AES wrappers add no padding and no authentication** (the CBC pair):
  keys of 16/24/32 bytes, IVs of exactly 16, data a multiple of 16. The
  GCM pair is one-shot, with a 12-byte nonce and a 16-byte tag; a
  received tag of another length is `ZUC_ERR_AUTH`.
- **Hardware AES stays on.** AES-NI or the Arm Cryptography Extension is
  selected at run time, with table-based software AES as fallback (#51);
  that fallback leaks key material through cache timing and is
  documented, not refused; `crypt_info()$build_flags$aes_implementation`
  reports the path. Never turn hardware AES off to make platforms “run
  the same C”: `aes-paths.yaml` checks each path, including a
  `ZUC_AES_SOFTWARE_ONLY` build.
- **SHA-1 is for Office compatibility**, never a default for new
  formats. AES-ECB was removed (#29); it is admissible and in no
  tranche.
- **openssl compatibility is checked, and subordinate to security.**
  Every mirrored function is byte-identical to `openssl`,
  cross-verified, or a documented difference in the migration article; a
  function in none of the three lists fails the suite. Never mirror a
  failure to authenticate or verify: `openssl` 2.3.4’s GCM returns no
  tag and accepts tampered ciphertext, so `crypt_aes_gcm_*` keeps RFC
  5116’s contract.
- **EC encodings match OpenSSL byte for byte**, built in
  `src/zuc_pkey.c`: SEC1 with the curve, PKCS#8 around SEC1 without it,
  RFC 8410 for X25519. ECDSA signatures are raw `r || s` in C and DER in
  R, read strictly (the encoding must re-encode identically).
  `zuc_pkey_agree()` refuses an all-zero X25519 result.
- **Randomness never uses R’s RNG.** `test-random.R` sets a seed, draws
  twice and expects a difference.
- **No secrets in conditions.** Errors are
  `c(<specific>, "zucrypt_error", "error", "condition")`, built in R
  from a `zuc_status` mapped by enumerator *name*. Never attach keys,
  passwords or plaintext, in the message *or the call*:
  `zucrypt_abort()` reduces every call to the bare function name,
  because R prints the call with its arguments (#51).
- **API resolution and calls are main-thread only** in 0.1.
- **The Office derivation rehearsal is not Office support.** It lives in
  the consumer fixtures and is the ABI validation gate: the generic
  `H_n = hash(int32le(n-1) || H_{n-1})` loop through one reused
  incremental context, compared with an R loop over
  [`crypt_hash()`](https://pedrobtz.github.io/zucrypt/reference/crypt_hash.md)
  and with one msoffcrypto-tool vector (`fixtures/derivation.tsv`). No
  constants, no block keys.
- **Articles run when the site builds**, with no `Suggests` beyond the
  website needs: mention openssl or sodium in prose, never in a chunk.
  `backend.Rmd`’s facts (file counts, defines, sizes, patches) are
  updated whenever the vendored tree or its configuration changes.
- **Never edit `README.md`**: `readme.yaml` re-renders it and fails on
  any difference.

## Testing

- **Gate** (design §12): published known-answer vectors per algorithm,
  one-shot vs incremental equivalence, and independent-implementation
  compatibility. A self round trip is not sufficient. Tests run offline
  from synthetic fixtures.
- **Fixtures** are in `tests/testthat/fixtures/` (`kat.tsv`, `aead.tsv`,
  `kdf.tsv`, `rsa*.tsv`, `ec*.tsv`), with provenance in `MANIFEST.tsv`,
  read as committed and never regenerated at test time. Generators and
  oracles are under Commands.
- **Helpers**: `helper-kat.R` (fixture access and `zucrypt_test_*`
  harness wrappers), `helper-abi.R` (symbol audit of the loaded shared
  object), `helper-linking.R` (audits of the installed `LinkingTo`
  surface, which skip under `load_all()`), and `helper-<name>.R` for
  what one `test-<name>.R` uses. They are helpers rather than file-scope
  code because testthat’s parallel workers
  (`Config/testthat/parallel: true`) source `helper-*.R` but not a test
  file’s file scope, and `shuffle = TRUE` runs it in a random place;
  `test-package.R` fails on any top-level expression in a test file
  other than `test_that()`.
- `zuc_int_random_fail()` (`src/zuc_live.h`) makes the entropy source
  fail for the harness.
- **The `nosuggests` leg** checks with no `Suggests` installed, so
  `tests/testthat.R` wraps
  [`library(testthat)`](https://testthat.r-lib.org) in
  [`requireNamespace()`](https://rdrr.io/r/base/ns-load.html). Anything
  else that reaches for a suggested package from a top-level test or
  example file is guarded the same way.

## Continuous integration

Shared workflows from `pedrobtz/r-actions`, tracking `@v1`, except
`coverage.yaml`, pinned to a commit with the tag in a comment. Bump that
pin deliberately, reading the diff. Add a workflow at the stage where it
has something to check: a job that is green because it inspected nothing
is worse than no job.

- `R-CMD-check.yaml`: runners plus the `clang23`, `ubuntu-clang` and
  `ubuntu-gcc16` containers, `nosuggests` on.
- `native-checks.yaml`: LTO, rchk, gctorture, sanitizers, valgrind,
  analyzers, `cran-special`, and the bespoke layering check. `rchk` and
  `analyzers` stay informational until they read zero, then gate with
  `fail-on-findings: true`; answer the first false positive with a
  `baseline:` file, never by turning the gate off.
- `coverage.yaml` (`native: true`).
- `arch.yaml` (weekly): until Stage 8 its legs installed no testthat and
  ran **no tests** while green. The Debian legs now install
  `r-cran-testthat` and the `en_US.UTF-8` locale, Alpine builds testthat
  (with `libuv-dev` and `linux-headers`), and the job sets
  `error-on: warning` and `require-tests: true`.
- `alloc-failure.yaml` (weekly): sweeps the allocations of the `crypt_*`
  calls only, and compares every result that survives byte for byte with
  `tools/alloc-expected.tsv` (written from openssl and hashlib by
  `tools/alloc-expected.R`); a namespace loaded inside the window fails
  the run. `expect-pattern` lists R’s own out-of-memory wordings, and
  `ignore-crash-pattern` R’s regex and `gzfile` crashes.
  `tools/alloc-exercise.R --baseline` runs the prefix so it sits under
  the floor, and both commands set `R_ENABLE_JIT=0`, because a failed
  allocation in R’s own compiler or regex engine crashes R.
  `target-pattern: ZUC_ERR_MEMORY` with `min-target-hits: 20` proves
  each run reached the adapter. Needs r-actions \>= v1.15.0. The window
  holds deterministic ECDSA and X25519 only: ECDSA verification and
  P-256 ECDH allocate 36,000 and 21,000 times and are left out on
  purpose.
- `vendor.yaml`: the vendored tree matches its manifest, and a pull
  request touching it updates the manifest. `vendor-upstream.yaml`
  (weekly) opens an issue when TF-PSA-Crypto releases.
- Bespoke, adapted from `zukomp`, because what a package publishes is
  its own: `abi.yaml`; `consumer.yaml`, which builds both fixture
  packages and fails when zero tests are discovered
  ([`any()`](https://rdrr.io/r/base/any.html) over an empty vector is
  `FALSE`); `revdep.yaml`, which builds `zuxlsx` against this checkout
  and runs its decryption tests; `aes-paths.yaml`; `readme.yaml`. These
  four run on Linux only.
- `platforms.yaml` (r-actions’ `platforms.yml`, weekly) is their macOS
  and Windows legs, one job per OS, running `tools/ci/platform.sh <os>`:
  the headers standalone (macOS), the hardware AES path and the suite
  against the installed package, both consumer fixtures. At the full
  profile it adds the fuzz replay (under ASan on macOS) and the `zuxlsx`
  revdep. Add a new macOS or Windows check there as a step, never as a
  new job.
- `fuzz.yaml` (own, gated by `changes.yml`): the corpus in
  `fuzz/corpus/` through every target’s oracle, plain and under ASan +
  UBSan, on Linux; a 30-second libFuzzer run (600 s at full); and the
  reach job, whose floor is `tools/coverage/floor.dcf`. A crash found
  becomes a `regress-<issue>-*` seed.
- `mutation.yaml` (r-actions’ `mutation.yml`): Mull over `src/zuc_*.c`,
  killed by the C driver in `ctest/`. Reported and read, never gated;
  survivors are filed as issues (#126–#130).
- `pkgdown.yaml` is this repository’s own, deploying to `gh-pages` on
  push to `main`.
- `assurance.yaml` runs r-actions’ `assurance.yml`, which holds
  [.agents/assurance.md](https://pedrobtz.github.io/zucrypt/.agents/assurance.md)
  to the portfolio standard: a `done` check must be backed by a
  workflow, and a gap must name an issue. Update the file’s rows in the
  same pull request as a new boundary, object or limit.

**The consumer fixtures** under `tools/` (zukomp’s layout) are
unreachable from `R CMD check`. `tools/zucrypttest` is the table
consumer and calls every table entry, because a pointer never assigned
is indistinguishable from a working one until something calls it.
`tools/zucryptlink` is the archive consumer: `LinkingTo` only,
`configure`/`configure.win` resolving `lib/<arch>` then `lib/` into a
single-quoted `PKG_LIBS`, exactly as `zuxlsx` does.
`tools/check-linking.sh` installs it into a library path containing a
space, audits that the backend is linked in and that no
`zuc_`/`psa_`/`mbedtls_` symbol is exported from the consumer, checks
both copies report the same backend, runs it beside `zucrypt.so` in both
load orders, and with zucrypt removed from the library path. Both
fixtures carry the msoffcrypto derivation vector.

## Vendored native code

TF-PSA-Crypto 1.1.1 (an LTS branch), Apache-2.0, crypto subset only: no
TLS, no X.509 (Stage 17 would need a second vendored library). No Mbed
TLS file is vendored: in the 4.x architecture TF-PSA-Crypto is the whole
cryptography library. Installation downloads nothing and needs no Python
or Perl; the release archive ships the generated sources. The tag,
commit, archive checksum, defines and patches are in
`tools/vendor/manifest.tsv`; `tools/vendor/verify` fails if a vendored
file names an author missing from `Authors@R` or `inst/COPYRIGHTS`
(CRAN’s 2026-10-13 return).

Local patches, in `tools/patches/tf-psa-crypto/`:

- `0001-avoid-zero-size-pubkey-array.patch`
- `0002-drop-diagnostic-pragmas.patch`
- `0003-guard-aead-finish-tag-wipe.patch` (upstream report: \#85)

The configuration is `src/zuc_crypto_config.h` (forty-eight defines);
the trim is 43 objects and 153 files, with `aesce.c` kept by hand
because it has symbols only on Arm. `src/Makevars` is portable make with
an explicit `OBJECTS` list (no CMake, no GNU make).

Departures from the family layout, both recorded in
`.agents/stage-1-spike.md`: the trim is a two-column keep list
(`tools/vendor/keep/<source>.txt`) rather than a `keep_files()` case
arm, and the tree is flattened to `inc/` and `lib/` because upstream’s
paths exceed the 100-byte tarball limit. The patch record is the
manifest’s `patches` column, not a `src/vendor/PROVENANCE`. Never edit
`src/vendor/` in place: change the keep list or add a patch, re-run
`tools/vendor/fetch` and `tools/vendor/record`, then
`tools/vendor/verify` before committing.
