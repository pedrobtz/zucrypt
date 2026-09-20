# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Current state

`zucrypt` is an empty R package skeleton (two commits: skeleton +
pkgdown setup). `R/` contains only `zucrypt-package.R`, `NAMESPACE` is
empty, `tests/` has only `testthat.R`, and `DESCRIPTION` still carries
usethis placeholder `Title`, `Description` and `Authors@R` values that
must be filled before any release.

The real content of this repository is
[.agents/design.md](https://pedrobtz.github.io/zucrypt/.agents/design.md)
— a detailed, *proposed* (not implemented) design. Read it before
writing code; it is the authoritative spec for the API, boundaries and
constraints summarised below, and it is where design changes belong.
[.agents/roadmap.md](https://pedrobtz.github.io/zucrypt/.agents/roadmap.md)
breaks the path to v0.1.0 into stages with exit criteria; check which
stage is current before starting work.

## Commands

``` r

devtools::load_all()          # load package for interactive work
devtools::document()          # regenerate NAMESPACE + man/ from roxygen2 (markdown enabled)
devtools::test()              # run all tests
testthat::test_file("tests/testthat/test-<name>.R")   # run one test file
devtools::test(filter = "<name>")                      # run tests matching a pattern
devtools::check()             # full R CMD check, as CI runs it
pkgdown::build_site()         # build the docs site (output in docs/, gitignored)
```

Once C sources exist, `devtools::load_all()` recompiles; use
[`pkgbuild::clean_dll()`](https://pkgbuild.r-lib.org/reference/clean_dll.html)
when native state gets stale.

CI (`.github/workflows/R-CMD-check.yaml`) runs `R CMD check` on macOS,
Windows and Ubuntu (devel/release/oldrel-1). pkgdown deploys to
`gh-pages` on push to `main`.

## Architecture (planned)

`zucrypt` is one package in the `zu*` family (siblings are checked out
alongside it: `zuxlsx`, `zuxml`, `zukomp`, `zuhttp`, …). The boundary is
strict and is the main thing to preserve:

- **`zucrypt` owns cryptographic primitives only** — hashes, HMAC,
  AES-CBC/ECB, constant-time compare, secure cleanup. It must never
  acquire XML, ZIP, Office, socket or TLS dependencies.
- **Office/Excel decryption orchestration lives in `zuxlsx`**, not here.
  The Office adapter owns iteration counts, salts, block keys, password
  verifiers and segment IVs; it may depend on `zucrypt` and `zuxml`,
  never the reverse.
- **`zuhttp` owns TLS and trust**, and keeps its native OS TLS backend.
  Mbed TLS there is a separate, optional backend, not something
  `zucrypt` provides.

Two interfaces are exposed:

1.  A small R surface: `crypto_info()`, `hash_raw()`, `hmac_raw()`,
    `constant_time_equal()`, `aes_cbc_encrypt_raw()` /
    `aes_cbc_decrypt_raw()`.
2.  A versioned C ABI: a public header at `inst/include/zucrypt.h` plus
    one accessor registered with `R_RegisterCCallable`, returning a
    table of function pointers with opaque context handles. Consumers
    use `LinkingTo: zucrypt` + `Imports: zucrypt` and resolve via
    `R_GetCCallable`. Upstream Mbed/PSA types must never appear in the
    header.

The backend is a vendored, pinned Mbed TLS 4.x / TF-PSA-Crypto crypto
subset (no TLS, no X.509). Installation must not download sources or
require Python/Perl to generate them, and upstream symbols must be
hidden or namespaced so independent vendored copies cannot bind to each
other.

## Non-obvious constraints from the design

- Binary arguments are **raw vectors only**. A character value is never
  interpreted as a filename, password or byte sequence.
- Algorithm names are exact scalars — no partial matching, no fallback.
- AES wrappers add/strip **no padding and no authentication**; keys must
  be 16/24/32 bytes, IVs exactly 16, data a multiple of 16.
  Authentication is the caller’s responsibility.
- SHA-1 and AES-ECB exist purely for Office compatibility and are never
  defaults for new formats.
- No `encrypt_file(password = )`, no PBKDF2/HKDF/AEAD/RNG in the initial
  scope — each needs a concrete consumer first.
- Any future randomness uses platform entropy or a seeded backend RNG,
  **never R’s RNG**.
- Errors are R conditions inheriting from `zucrypt_error` with a stable
  code; never attach keys, passwords or plaintext to a condition. C
  functions return status codes and never raise R errors, allocate R
  objects or call back into R.
- API resolution and calls are main-thread only in 0.1.
- Testing gate: published known-answer vectors per algorithm, one-shot
  vs incremental equivalence, and independent-implementation
  compatibility — a self round trip is explicitly not sufficient. Tests
  must run offline from synthetic fixtures.

## Skills

Several R-specific skills are available and worth using here:
`r-package-development`, `testing-r-packages`, `review-testing`,
`cran-extrachecks`, `review-cran-submission`.
