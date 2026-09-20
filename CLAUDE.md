# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

Roadmap Stages 0 (package identity), 1 (backend spike) and 2 (native adapter) are complete.
The package builds a vendored TF-PSA-Crypto 1.1.1 crypto subset from source and exposes it
through `inst/include/zucrypt.h` and `inst/lib/libzucrypt.a`. R still exports only the
placeholder `crypt_info()`; the six `crypt_*` functions and the condition system are Stage 3,
which is the current stage.

The native layer is in two halves and the split is load-bearing. `src/zuc_*.c` is the adapter:
R-free, and what goes into the archive. `src/zucrypt_r.c` and `src/zucrypt_test.c` are the R
glue: backend-free, and not in the archive. `tools/check-layering.sh` enforces both directions
in CI, because neither breaks loudly — including `R.h` in the adapter compiles fine here and
fails much later in a consumer's build.

`src/zucrypt_test.c` is a permanently-compiled `.Call` harness (`zucrypt_test_*`), the analogue
of `zukomp`'s `zu_test_stream()`. It is how the suite drives the adapter at caller-chosen split
points, and it stays compiled in every build. Fixtures are in `tests/testthat/fixtures/`, with
provenance in `MANIFEST.tsv`; `Rscript tools/make-kat.R --check` recomputes every vector against
`openssl` and fails on a mismatch.

[.agents/stage-1-spike.md](.agents/stage-1-spike.md) records what the spike measured and every
decision it settled — the pinned release, the eleven-define configuration, the 18-object trim
and how to re-derive it, the external-RNG choice, and the measurements. Read it before touching
`src/vendor/`, `src/Makevars` or `src/zuc_crypto_config.h`.

The real content of this repository is [.agents/design.md](.agents/design.md) — a detailed, *proposed*
(not implemented) design. Read it before writing code; it is the authoritative spec for the API,
boundaries and constraints summarised below, and it is where design changes belong.
[.agents/roadmap.md](.agents/roadmap.md) breaks the path to v0.1.0 into stages with exit criteria;
check which stage is current before starting work.

## Working rhythm: one pull request per roadmap stage

[.agents/roadmap.md](.agents/roadmap.md) is the unit of work. Each stage ships as its own pull
request against `main`, and the loop is the same every time:

1. Branch from an up-to-date `main` (`stage-N-<slug>`), do the stage's work, and check it
   locally first — `devtools::document()`, `devtools::test()`, `devtools::check()` clean at
   0/0/0 before anything is pushed. CI is for the platforms and toolchains this machine is not,
   not for finding what a local check would have caught.
2. Open the PR with `gh pr create`. The body states the stage, what it implements, and the
   stage's exit criteria from the roadmap as a checklist.
3. Watch the checks to completion (`gh pr checks --watch`, `gh run view --log-failed`). Every
   leg green, not "green except the container ones" and not "the failure is unrelated" — a
   failure is part of the stage until it is understood. Fix on the same branch and push again.
4. Merge only once every required check has passed, then delete the branch and pull `main`.
5. Update this file's **Current state** section and start the next stage.

A stage does not end because its code is written. It ends when its exit criteria are met and CI
is green, which is also what makes the next stage safe to start: the roadmap's stages are
sequential precisely so that a later one never inherits an unproven earlier one.

## Commands

```r
devtools::load_all()          # load package for interactive work
devtools::document()          # regenerate NAMESPACE + man/ from roxygen2 (markdown enabled)
devtools::test()              # run all tests
testthat::test_file("tests/testthat/test-<name>.R")   # run one test file
devtools::test(filter = "<name>")                      # run tests matching a pattern
devtools::check()             # full R CMD check, as CI runs it
pkgdown::build_site()         # build the docs site (output in docs/, gitignored)
```

Once C sources exist, `devtools::load_all()` recompiles; use `pkgbuild::clean_dll()` when native
state gets stale.

## CI

CI is adopted from [`pedrobtz/r-actions`](https://github.com/pedrobtz/r-actions), the family's
shared reusable workflows — never hand-rolled jobs. Two conventions:

- **Pin calls to a commit**, with the tag in a trailing comment (`@1878271... # v1.9.0`). A tag
  is mutable; `@v1` means "whatever it points at when the job starts". Bump deliberately.
- **Add a workflow at the stage where it has something to check.** The roadmap's CI table says
  which workflow lands in which stage and why. A job that is green because it inspected nothing
  is worse than no job.

Today: `R-CMD-check.yaml` (runners plus CRAN's clang-23/GCC-16 containers, `nosuggests` on),
`native-checks.yaml` (LTO, and the bespoke layering check), `vendor.yaml` (the vendored tree matches its manifest, and a PR touching it updates that
manifest), `vendor-upstream.yaml` (weekly; opens an issue when TF-PSA-Crypto releases) and
`pkgdown.yaml` deploying to `gh-pages` on push to `main`. `pkgdown.yaml` is this repo's own, not
an r-actions call. `coverage.yaml` returns in Stage 3: covr instruments `R/`, so until there is a
function to measure `percent_coverage()` is `NaN` and the job fails for a reason that has nothing
to do with the package.

The `nosuggests` leg checks with no `Suggests` installed, which is why `tests/testthat.R` wraps
its `library(testthat)` in `requireNamespace()`. Anything else that reaches for a suggested
package from a top-level test or example file must be guarded the same way.

`abi.yaml` and `consumer.yaml` at Stage 4 are bespoke by necessity — r-actions has no ABI or
consumer workflow. Copy the ones in the sibling `zukomp` repo rather than inventing a shape.

## Architecture (planned)

`zucrypt` is one package in the `zu*` family (siblings are checked out alongside it:
`zuxlsx`, `zuxml`, `zukomp`, `zuhttp`, …). The boundary is strict and is the main thing to preserve:

- **`zucrypt` owns cryptographic primitives only** — hashes, HMAC, AES-CBC/ECB, constant-time
  compare, secure cleanup. It must never acquire XML, ZIP, Office, socket or TLS dependencies.
- **Family conventions are binding** (design §3): C ABI prefix `zuc_`/`ZUC_` (never `zu_`,
  which is `zukomp`'s public namespace and would not compile beside `zukomp.h` in `zuxlsx`);
  R exports `crypt_*`; entry points `zucrypt_*`; internal `zuc_int_*`; test-only
  `zucrypt_test_*`; condition classes `zucrypt_*`. `zukomp`'s CLAUDE.md is the reference.
- **Office/Excel decryption orchestration lives in `zuxlsx`**, not here. The Office adapter owns
  iteration counts, salts, block keys, password verifiers and segment IVs; it may depend on
  `zucrypt` and `zuxml`, never the reverse.
- **`zuhttp` owns TLS and trust**, and keeps its native OS TLS backend. Mbed TLS there is a
  separate, optional backend, not something `zucrypt` provides.

Three surfaces are exposed:

1. A small R surface: `crypt_info()`, `crypt_hash()`, `crypt_hmac()`, `crypt_equal()`,
   `crypt_aes_cbc_encrypt()` / `crypt_aes_cbc_decrypt()`.
2. A registered function table (`inst/include/zucrypt-r.h`, `zucrypt_api_v1`, resolved lazily
   via `zucrypt_get_api`) for `zuhttp`-style consumers: `Imports:` + `LinkingTo:` + a real
   `importFrom()`.
3. A static archive `inst/lib/libzucrypt.a` for `zuxlsx`-style consumers (`LinkingTo:` +
   `configure` resolving `system.file("lib")`, no `Imports:`). It contains the R-free adapter
   plus vendored crypto — **not** raw upstream, unlike `zukomp`/`zuxml`'s archives — so consumers
   see only `inst/include/zucrypt.h`, which must compile standalone as C99 with no R or PSA
   vocabulary.

The backend is a vendored, pinned TF-PSA-Crypto crypto subset (no TLS, no X.509) — currently
1.1.1, an LTS branch. No Mbed TLS file is vendored: in the 4.x architecture TF-PSA-Crypto is the
whole cryptography library and Mbed TLS supplies only X.509 and TLS. Installation downloads
nothing and needs no Python or Perl; the release archive ships the generated sources. Upstream
symbols are hidden (`PKG_CFLAGS = $(C_VISIBILITY)`) so independent vendored copies cannot bind
to each other, and `tests/testthat/test-abi.R` asserts that the shared object exports
`R_init_zucrypt` and nothing else.

## Non-obvious constraints from the design

- Binary arguments are **raw vectors only**. A character value is never interpreted as a filename,
  password or byte sequence.
- Algorithm names are exact scalars — no partial matching, no fallback.
- AES wrappers add/strip **no padding and no authentication**; keys must be 16/24/32 bytes, IVs
  exactly 16, data a multiple of 16. Authentication is the caller's responsibility.
- SHA-1 and AES-ECB exist purely for Office compatibility and are never defaults for new formats.
- No `encrypt_file(password = )`, no PBKDF2/HKDF/AEAD/RNG in the initial scope — each needs a
  concrete consumer first.
- Any future randomness uses platform entropy or a seeded backend RNG, **never R's RNG**.
- Errors are R conditions `c(<specific>, "zucrypt_error", "error", "condition")` built in R from a
  `zuc_status`, mapped by enumerator *name*; never attach keys, passwords or plaintext. C returns
  status codes, never `Rf_error()` below the outermost `.Call`; heap state that must survive a
  `longjmp` (`Rf_error`, `R_CheckUserInterrupt`) is owned by a finalized external pointer.
- Vendoring uses the family layout — `src/vendor/<source>/`, `tools/patches/`,
  `tools/vendor/{manifest.tsv,checksums.sha256,fetch,record,verify}`, `inst/COPYRIGHTS` — and
  `src/Makevars` is portable make with an explicit `OBJECTS` list (no CMake, no GNU make).
  Two local departures, both in `.agents/stage-1-spike.md`: the trim is a two-column keep list
  (`tools/vendor/keep/<source>.txt`) rather than a `keep_files()` case arm, and the tree is
  flattened to `inc/` and `lib/` because upstream's own paths exceed the 100-byte tarball limit.
  Never edit `src/vendor/` in place: change the keep list or add a patch, then re-run
  `tools/vendor/fetch` and `tools/vendor/record`, and `tools/vendor/verify` before committing.
- API resolution and calls are main-thread only in 0.1.
- Testing gate: published known-answer vectors per algorithm, one-shot vs incremental equivalence,
  and independent-implementation compatibility — a self round trip is explicitly not sufficient.
  Tests must run offline from synthetic fixtures.

## Skills

Several R-specific skills are available and worth using here: `r-package-development`,
`testing-r-packages`, `review-testing`, `cran-extrachecks`, `review-cran-submission`.
