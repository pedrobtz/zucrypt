# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

`zucrypt` is an empty R package skeleton (two commits: skeleton + pkgdown setup). `R/` contains only
`zucrypt-package.R`, `NAMESPACE` is empty, `tests/` has only `testthat.R`, and `DESCRIPTION` still
carries usethis placeholder `Title`, `Description` and `Authors@R` values that must be filled before
any release.

The real content of this repository is [.agents/design.md](.agents/design.md) — a detailed, *proposed*
(not implemented) design. Read it before writing code; it is the authoritative spec for the API,
boundaries and constraints summarised below, and it is where design changes belong.
[.agents/roadmap.md](.agents/roadmap.md) breaks the path to v0.1.0 into stages with exit criteria;
check which stage is current before starting work.

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
`coverage.yaml`, and `pkgdown.yaml` deploying to `gh-pages` on push to `main`. `pkgdown.yaml` is
this repo's own, not an r-actions call.

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

The backend is a vendored, pinned Mbed TLS 4.x / TF-PSA-Crypto crypto subset (no TLS, no X.509).
Installation must not download sources or require Python/Perl to generate them, and upstream symbols
must be hidden or namespaced so independent vendored copies cannot bind to each other.

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
- API resolution and calls are main-thread only in 0.1.
- Testing gate: published known-answer vectors per algorithm, one-shot vs incremental equivalence,
  and independent-implementation compatibility — a self round trip is explicitly not sufficient.
  Tests must run offline from synthetic fixtures.

## Skills

Several R-specific skills are available and worth using here: `r-package-development`,
`testing-r-packages`, `review-testing`, `cran-extrachecks`, `review-cran-submission`.
