# zucrypt: roadmap

Status: adopted 2026-09-25 (#38); re-planned 2026-09-29 for design revision 4. This plan
implements [design.md](design.md) revision 4.
- Stages 0–4 are done.
- Stage 5 was reopened (#26) and closed with Stage 8, once its weekly gates ran real tests.
- Stage 6 was prepared and never tagged. Its remaining items became Stages 7–9.
- **Stages 7–10 are done** (#45, #46, #47, #49), with #48 clearing the last check NOTE.
- **v0.1.0 is the first CRAN release** (decided 2026-09-29, replacing the GitHub-only tag of
  #27 and the separate v0.2.0). It carries the freeze. `zuxlsx` 0.1.0, with password-protected
  workbooks, follows it onto CRAN.
- **Two R-only additions join v0.1.0** (decided 2026-09-29): `crypt_hex()` (#59) and connection
  input to `crypt_hash()`/`crypt_hmac()` (#11, moved here from Stage 13). Neither touches the
  archive, so neither affects the freeze. `dastash` asked for both, but on reflection is **not
  a committed consumer**: it uses `tools::sha256sum()` (R >= 4.5), and zucrypt's only material
  gain for it is the R floor (4.1), which is its maintainer's call. The additions stand on their
  general value instead -- hashing a file is the commonest reason to reach for a hashing
  package. Measured 2026-09-29 on a 512 MiB file: `crypt_hash(file())` 225 MB/s against base
  R's 205 MB/s, but it allocates 513 MB in 1 MiB `readBin()` chunks where base R allocates
  nothing; reading through `R_ReadConnection()` into one reused buffer would remove that, at
  the price of R's connection API, which R documents as subject to change.
- **The CBC rename is done, and so is Stage 11**: zuxlsx#22 step 3 (zuxlsx#64) decrypted the
  real fixture against `main` on three operating systems, its two pre-freeze findings are
  fixed, and ABI 1 is frozen (2026-09-29). **Next:** Stage 12 takes v0.1.0 to CRAN. The
  vendored-backend article (#17) is done; the C-API vignette (#13) is left.
- **Re-planned 2026-09-29 for design revision 4.** Stages 11 and 12 are unchanged except one
  Stage 11 item, the `zuc_alg` ranges. Stages 13–17 are new: the openssl-shaped layer and its
  tranches, one CRAN minor release each. Stage 18, the TLS engine for `zuhttp` inside this
  package (design §10), is a candidate on `zuhttp`'s trigger. The goal they serve: an alternative to the `openssl`
  package, vendored Mbed TLS ecosystem underneath, for what `openssl` is used for.
- **Amended the same day by the review in #56.** Before v0.1.0, the CBC pair is
  renamed `_nopad` (design §7). Stage 14's GCM keeps RFC 5116's contract rather than
  `openssl`'s. Stages 15–17 are candidates, each decided when the one before it has shipped.
  Stage 13's survey counts detected usage, and real migrations are added before any claim.

Date: 2026-09-20; reviewed 2026-09-22 (#37); re-planned 2026-09-25; updated 2026-09-26;
re-planned 2026-09-29.

The file has two parts:
- **Part A** is the plan from here.
- **Part B** is the v0.1.0 roadmap as it was written and executed, with its 2026-09-22 review.
  It is kept because its stage sections are the exit criteria that issues #26 and #27 link to,
  and because the review's lessons are why Part A is shaped the way it is.

# Part A — Plan from 2026-09-25

## Where things stand

The code on `main` is sound, and the R surface is not in question. What the review found is a
plan that ran ahead of its evidence:
- an ABI frozen with no consumer;
- a primitive (ECB) with no consumer;
- a 16-handle key-store limit reported as out of memory;
- two gates that had not run. One of them has since run and failed: see #31, 2026-09-25.

Nothing is tagged and nothing links the archive, so every one of these is still free to fix.
That stops being true the day a consumer links `libzucrypt.a`, which is why the order below puts
every surface change first.

## Releases

| Release | Where | What it promises | Gated by |
| --- | --- | --- | --- |
| **v0.1.0** | CRAN, first release | The seven R functions are stable (six, plus `crypt_hex()`, #59), and `crypt_hash()`/`crypt_hmac()` take connections (#11). The archive is frozen as ABI 1. The table is *experimental* (design §8.6) | Stages 7–12, the CBC rename (#56), and `zuxlsx`'s decryption core in C ([zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22) step 3) |
| **v0.2.0** | CRAN | Tranche 1: randomness, the remaining digests, Base64, and the openssl-shaped layer with its gate and migration article (design §7.1) | Stage 13 |
| **v0.3.0** | CRAN | Tranche 2: AES-GCM, ChaCha20-Poly1305, CTR, PKCS#7 padding, PBKDF2, HKDF | Stage 14 |
| **v0.4.0** | CRAN | *Candidate.* Tranche 3: key objects, PEM and DER, RSA, signatures, envelopes | Stage 15, if admitted |
| **v0.5.0** | CRAN | *Candidate.* Tranche 4: EC keys, ECDSA, ECDH, X25519 | Stage 16, if admitted |
| **v0.6.0** | CRAN | *Candidate.* Tranche 5: X.509 certificate data, on a second manifest row | Stage 17, if admitted |
| **next minor** | CRAN | *Candidate.* A TLS client engine for `zuhttp`, as a run-time table; never in the archive (design §10) | Stage 18, on `zuhttp`'s trigger |

**The CBC rename is done** (#56, 2026-09-29): `crypt_aes_cbc_encrypt()` and `_decrypt()` are
now `crypt_aes_cbc_encrypt_nopad()` and `_decrypt_nopad()` (design §7, §7.1), with the help
topic at `?crypt_aes_cbc_nopad`, through the R code, the tests, the article,
`tools/alloc-exercise.R`, `tools/check-linking.sh`, the `zucrypttest` fixture and NEWS. The C
archive (`zuc_aes_*`) and the internal `.Call` entry point did not change.

**Stages 15–17 are candidates, not commitments** (design §6, criterion 5). Each opens with a
recorded decision, taken once the stage before it has shipped: is there demonstrated demand
(verified migrations, requests, the survey re-run against the adoption the earlier releases
got)? If not, the stage waits, and the plan says so rather than slipping silently.

**The family order** (decided 2026-09-29): zucrypt 0.1.0 on CRAN, then `zuxlsx` 0.1.0 on CRAN
with password-protected workbooks.
1. zucrypt reaches CRAN first, since `zuxlsx` cannot pass CRAN's checks with a `LinkingTo:` on
   a package that is not there.
2. `zuxlsx` 0.1.0 links zucrypt 0.1.0's archive, so 0.1.0 is where the archive freezes, and
   it freezes on the consumer's own code, not on fixtures alone: freezing first is the mistake
   this plan corrects. What must exist is the part of zuxlsx#22 that touches the archive, its
   step 3 — key derivation, key decryption, the segment loop and the HMAC check, in C — tested
   against the real encrypted fixture with the `EncryptionInfo` parameters supplied from R.
   The CFB stream reader, `EncryptionInfo` parsing, fuzzing and limits (zuxlsx#25, #26, #45)
   never call zucrypt, so they finish after zucrypt is submitted, before `zuxlsx` is.

The sequence is: zuxlsx's decryption core on a branch against zucrypt `main`, then zucrypt
frozen and submitted as 0.1.0, then the rest of zuxlsx#22, then `zuxlsx` 0.1.0 submitted with
`LinkingTo: zucrypt (>= 0.1.0)`. Every zucrypt release after 0.1.0 is additions only, so none
of them puts `zuxlsx` in the sequence again. If the rest of zuxlsx#22 finds that the archive
needs something, it is an addition in a zucrypt 0.1.x, submitted before `zuxlsx`.

## Stage map

| Stage | Release | Issues | Needs | Status |
| --- | --- | --- | --- | --- |
| 7 — Settle the surface before anything links it | v0.1.0 | #29, #30, #28, #33 (layout and licence), #19 (decision), #36 (header and resolver text) | — | **done**, #45 |
| 8 — Evidence that has run | v0.1.0 | #31, #34, #35; closes #26 | Stage 7. A fix in `r-actions` for the allocation interposer | **done**, #46 (r-actions v1.12.2–v1.15.0) |
| 9 — Documentation that matches the code | v0.1.0 | #36 (the rest) | Stage 8 | **done**, #47 and #48. Its tag (#27) is superseded: v0.1.0 goes to CRAN in Stage 12 |
| 10 — The archive proved the way a consumer uses it | v0.1.0 | #32, #33 (fixture location) | Stage 9 | **done**, #49 |
| — The CBC rename | v0.1.0 | #56 | Stage 10 | **done** |
| — Hex output and connection hashing | v0.1.0 | #59, #11 | — | in progress |
| 11 — The first consumer, and the freeze | v0.1.0 | #28 (the freeze itself); the `zuc_alg` ranges (revision 4) | The rename. `zuxlsx`'s decryption core in C (zuxlsx#22 step 3) | **done**, 2026-09-29 |
| 12 — v0.1.0 and CRAN | v0.1.0 | #17, #13, #15 | Stage 11 | |
| 13 — Tranche 1: the openssl-shaped layer over what exists | v0.2.0 | #9, #16 | Stage 12 | |
| 14 — Tranche 2: authenticated encryption and key derivation | v0.3.0 | #10, #12 | Stage 13 | |
| 15 — Tranche 3: key objects, PEM and DER, RSA | v0.4.0 | new | Stage 14 | |
| 16 — Tranche 4: EC keys, ECDSA, ECDH, X25519 | v0.5.0 | new | Stage 15 | |
| 17 — Tranche 5: certificates | v0.6.0 | new | Stage 16 | |
| 18 — The TLS engine for zuhttp | next minor | new | Stage 17, and `zuhttp`'s trigger | |

Issue #14 is closed as *not planned* when this plan merges (design revision 3, item 9).

The working rhythm is unchanged (CLAUDE.md):
- one pull request per stage;
- a local `document()`, `test()` and `check()` at 0/0/0 before pushing;
- every CI leg green before merging.

This plan adds one rule, taken from the review: **a stage that adds or changes a scheduled job
closes only after that job's first real run**, dispatched by hand. "Real" means the log shows
the job exercised what it is named for (design §12).

## Stage 7 — Settle the surface before anything links it

**Done in #45 (2026-09-26).** Re-deriving the trim under the new configuration reproduced the
same 18 objects and 108-file closure, so the vendored tree did not change; only the manifest's
`defines` moved. `tag-pattern` for the watcher landed upstream as r-actions v1.13.0.

Goal: make every change to the archive's surface now, while it costs nothing, so that
`zuxlsx`'s C path is written once against the surface that will be frozen.

Work items:

- **Remove AES-ECB** (#29).
  - Delete `zuc_aes_ecb_encrypt()`/`zuc_aes_ecb_decrypt()` from `zucrypt.h`, `src/zuc_aes.c`
    and `src/zucrypt_api.c`.
  - Delete both table fields from `zucrypt_api_v1`, and the ECB checks from the consumer fixture's
    `probe.c`.
  - Remove `PSA_WANT_ALG_ECB_NO_PADDING` from `src/zuc_crypto_config.h` and from the manifest's
    `defines`.
  - Re-derive the trim (stage-1-spike §3), then run `tools/vendor/fetch`, `record` and `verify`.
  - Update DESCRIPTION's `Description` field.
  - Remove the three ECB rows from `kat.tsv` and `MANIFEST.tsv`, and ECB from
    `tools/make-kat.R`, `test-kat.R`, `test-adapter.R` and `test-linking.R`. The last of these
    checks that the archive defines every entry point, so it has to lose the two ECB names.
- **Make the key store dynamic** (#30).
  - Define `MBEDTLS_PSA_KEY_STORE_DYNAMIC`, and add it to the manifest's `defines`.
  - Re-derive the trim again, in the same commit as the ECB removal, so it is derived once.
  - `zuc_aes_new()` now imports one key.
  - Document in `zucrypt.h` that the number of live handles is bounded by memory.
  - Test: 64 live `zuc_aes` and 64 live `zuc_hmac` handles through the harness, a one-shot HMAC
    and CBC call with all of them live, and then all freed.
- **Append `ZUC_ERR_NOT_READY = 9`** (#28).
  - Return it from every `zuc_int_ready()` check that returns `ZUC_ERR_INVALID_ARGUMENT` today.
  - Add it to `zuc_status_string()`, and to the R status map as `zucrypt_internal_error`.
  - A harness test calls a function between shutdown and init.
- **Add `ZUCRYPT_API_HAS(api, field)`** to `zucrypt-r.h`, modelled on `zuxml.h`'s macro, and
  use it once in the fixture.
- **Correct the resolver's contract** in `zucrypt-r.h` and `?zucrypt_c_api` (#28, #36): a
  missing `zucrypt` is an R error from `R_GetCCallable()`, and `NULL` means only a version
  mismatch.
- **Install as `zukomp` does** (#33, first half).
  - `src/install.libs.R` installs the archive to `lib${R_ARCH}/` and checks every copy.
  - It installs `licenses/tf-psa-crypto-LICENSE` from `src/vendor/tf-psa-crypto/LICENSE`.
  - `inst/COPYRIGHTS` points at the installed path.
  - `test-linking.R` and `tools/check-linking.sh` resolve `lib/<arch>` first, then `lib/`.
- **Report hardware acceleration from C** (#36). It becomes a `zuc_info` field or a
  `zucrypt_backend_info` entry, whichever does not change `zuc_info`'s required size.
- **State the tiers** (design §8.6) in `?zucrypt_c_api`: the archive provisional, the table
  experimental. The README and NEWS follow in Stage 9.
- **Record the upstream decision** (#19): stay on 1.1 LTS (design §4).
  - Close #19 with that reason.
  - Open an issue in `pedrobtz/r-actions` asking `vendor-upstream` for a tag pattern, so the
    watcher follows `tf-psa-crypto-1.1.*`.
- Keep `ZUCRYPT_ABI_VERSION` at 1 (design revision 3, item 1), and say why in NEWS.

Exit:

- `abi.yaml` is green. The header still compiles standalone as C99 and C++ with ECB gone and the
  new status and macro present.
- The consumer fixture calls every remaining table entry, and none that was removed.
- `tools/vendor/verify` is clean, and the manifest's `defines` match the configuration header.
- The handle-count test passes under ASan and valgrind.
- `test-abi.R` still shows only `R_init_zucrypt` exported.
- The installed package has `lib${R_ARCH}/libzucrypt.a` and `licenses/tf-psa-crypto-LICENSE`,
  and `test-linking.R` asserts both.

## Stage 8 — Evidence that has run

**Done in #46 (2026-09-26); closed #26 and with it Stage 5.**
- It needed three r-actions releases: the interposer's `free()` (v1.12.2), arch's
  `error-on`/`require-tests` (v1.14.0), and alloc-failure's `target-pattern` (v1.15.0).
- Measured:
  - arch ran 754, 751 and 754 passing expectations on i386, musl and aarch64, where it had run 0;
  - alloc-failure injected 258 failures, none crashed, and 77 reached the adapter.
- Two findings the gates turned up on their first real runs: the musl leg needed `libuv-dev` and
  `linux-headers` to build testthat, and musl's linker exports the toolchain's `_init`/`_fini`,
  which `test-abi.R` now allows by exact name.

Goal: every gate Stage 5 claimed is shown, by its own log, to exercise what it is named for.
The published vectors reach past one compression block. The longjmp paths the design legislates
about are executed at least once.

Work items:

- **`arch.yaml`** (#31).
  - Install testthat in the legs.
  - Find and fix the `checking R files for syntax errors ... WARNING` on i386 and aarch64.
  - Fail on WARNING.
  - Assert that each leg ran a nonzero number of tests.
  - Dispatch it by hand, and record the counts in the PR.
- **`alloc-failure.yaml`** (#31).
  - Report to `pedrobtz/r-actions` that its interposer aborts every run: `free()` is not
    interposed for arena pointers, so glibc aborts with `free(): invalid pointer`. Bump the pin
    once r-actions has released the fix.
  - Move the sweep window onto the adapter. Measure the startup floor *after*
    `library(zucrypt)` and `crypt_info()`, by making the baseline command do both. If the r-actions
    inputs do not allow that, raise `CAP` to cover the ~4,700-allocation workload.
  - Match `expect-pattern` on text that is actually printed (`ZUC_ERR_MEMORY`), or print
    `class(e)` in `tools/alloc-exercise.R`.
  - Confirm from the log that failures land inside `zuc_*_new()`.
- **Independent vectors** (#34).
  - Add to `kat.tsv`, each with provenance in `MANIFEST.tsv` and recomputed by
    `tools/make-kat.R --check`:
    - RFC 4231 cases 6 and 7;
    - FIPS 180-2 SHA-256 B.2 and SHA-512 C.2;
    - "one million a" for every digest.
  - Compare inputs of 1,000 B, 64 KiB + 1 and 4 MiB with `openssl`, under
    `skip_if_not_installed("openssl")`.
  - Add the derivation known-answer vector: the spin-loop output for `zuxlsx`'s committed agile
    fixture parameters, computed by msoffcrypto-tool and stored as input and output bytes, with
    its generation recorded. It is test data only (design §12).
- **The longjmp paths** (#35).
  - Add a test-only live-context counter in the adapter.
  - Add a harness entry point that raises an R error after N chunks, and a `setTimeLimit()` test
    that interrupts `crypt_hash()` on a 64 MiB input.
  - Assert the counter is 0 after `gc()`.
  - Break the finalizer once, locally, to show the test fails, and record that in the PR.
  - Add a lint in `tools/check-layering.sh` that rejects a `return` of an allocating call right
    after `UNPROTECT()` in `src/zucrypt_*.c`, with a canary that proves it fires.
- **Correct the claims.** Remove from `NEWS.md` and `cran-comments.md` every statement that a
  check is performed, unless this stage has shown it run.

Exit:

- The i386, musl and aarch64 legs each report a nonzero test count and no WARNING.
- `alloc-failure.yaml` is green, and its log shows failures injected inside the adapter's
  allocation window.
- All new vectors pass, and `make-kat.R --check` recomputes them.
- The interrupt test passes, and was shown to fail with the finalizer broken.
- The lint's canary fires.
- #26 closes, and Stage 5 with it.

## Stage 9 — Documentation that matches the code, and the tag

**Done in #47 (2026-09-26), except the tag, which is the maintainer's (#27).** #48 then removed
the last `R CMD check` NOTE with a second vendored patch,
`0002-drop-diagnostic-pragmas.patch`, so every leg reports `Status: OK`.

Goal: nothing a user or consumer reads contradicts the code, and v0.1.0 is tagged at a commit
where that is true.

Work items (#36, the parts Stage 7 did not take):

- **Render the README from `README.Rmd`**, so that its example output is computed and cannot
  drift. Today the printed digest is not SHA-256 of its input.
  - The lifecycle badge becomes "experimental" (design §8.6).
  - The "Consuming it from C" and "Status" paragraphs state the tiers.
  - The archive path becomes `lib${R_ARCH}/`.
- **Fix the stale roxygen and comments:**
  - `R/info.R` (the `abi_version` text);
  - `R/aes.R` (`?zucrypt` → `?zucrypt_c_api`);
  - `R/c-api.R` (the `NULL` promise);
  - `src/zuc_backend.c:5-6`;
  - `src/zucrypt_r.c:3,8`;
  - `src/Makevars:85`;
  - the Suggests comment in `R-CMD-check.yaml`.
- **Make AES conditions carry `algorithm`** (design §11).
- **Rewrite `NEWS.md`'s 0.1.0 entry.** It gives the API, the pinned backend release, the three
  tiers, what changed since #8 (ECB removed, dynamic key store, `ZUC_ERR_NOT_READY`,
  `ZUCRYPT_API_HAS`, install layout, licence), and the explicit non-goals.
- **Mark `cran-comments.md` as a draft for v0.2.0**, or delete it until Stage 12.
- **Update CLAUDE.md's Current state.**
- **Tag.** This is for the maintainer, because a tag and a release are public and hard to walk
  back. Tag `v0.1.0` on the merge commit of this stage. Publish the GitHub release with notes that
  point at the pkgdown site. Then move `main` to `0.1.0.9000`.

Exit:

- `devtools::check()` is 0/0/0.
- The README's rendered output matches a fresh `knitr` run in CI.
- The tag exists at a commit where every CI leg, including this stage's weekly dispatches, is
  green.
- #27 closes.

## Stage 10 — The archive proved the way a consumer uses it

**Done in #49 (2026-09-26).**
- `tools/zucryptlink` and `tools/zucrypttest` build on all three operating systems.
- `tools/check-linking.sh` checks eight things: the install layout, no run-time dependency, the
  link through a path containing a space, the symbol audit, the tests, matching backend
  versions, coexistence in both load orders, and running with zucrypt uninstalled.
- Building zucrypt without hidden visibility makes the audit fail on the leaked `mbedtls_*`
  symbols, as it should.
- The family table's `zucrypt` cells are now stale. They wait for the next five-repository
  change, and a zucrypt-only note under the table says so, as zuhttp's does.

Goal: the archive's claims are tested by a package that consumes it exactly as `zuxlsx` will:
position-independent code, hidden symbols, two backend copies in one process, Windows paths, and
running without `zucrypt` installed. Until this stage, a plain `main()` has been standing in for
that consumer.

Work items (#32, and the second half of #33):

- **Add `tools/zucryptlink`**, a `LinkingTo`-only package. Its `configure`, `configure.win` and
  `src/Makevars.in` are copied from `zuxlsx`'s.
  - It resolves `system.file("lib", .Platform$r_arch, ...)`, then `lib/`, into a single-quoted
    `PKG_LIBS`.
  - It runs the derivation rehearsal and the known-answer vector from Stage 8 through the archive.
- **Assert what the archive promises:**
  - `nm -D` (and `dumpbin /exports` on Windows) on the fixture's shared object shows no `psa_`,
    `mbedtls_` or `zuc_` export;
  - the fixture and `zucrypt.so`, loaded in both orders, each compute correct results;
  - with `R_LIBS_USER='-'` and `zucrypt` removed from the library path, the fixture still works
    (`zukomp`'s `check-linking.sh` step).
- **Run it from `consumer.yaml`** on Linux, macOS and Windows, failing when zero tests are
  discovered.
- **Move the table fixture** from `tests/consumer/zucrypttest` to `tools/zucrypttest`, and update
  `.Rbuildignore` and `consumer.yaml`.
- **Retire `tools/check-linking.sh`**, or reduce it to a smoke test called by the fixture's CI
  step.
- **Update the family table's `zucrypt` cells** (licence installed, `lib${R_ARCH}`, fixture
  packages) in all five repositories together, as that section requires.

Exit:

- `consumer.yaml` is green on three operating systems with both fixtures, and neither discovers
  zero tests.
- The Windows leg links through a library path that contains a space.
- The export check fails on a deliberately unhidden build. Record it in the PR.

## Stage 11 — The first consumer, and the freeze

**Done 2026-09-29.** zuxlsx#64 (`feat/agile-decrypt-core`) decrypted `two-sheets-encrypted.xlsx`
byte-exact against `main`, with a UTF-16 password fixture too, green on Linux, macOS and
Windows; its report is on #43. Nothing was missing from `zucrypt.h`. Its two pre-freeze
findings were taken: `tools/zucryptlink` gained the `.onUnload()` without which
`R_unload_` (and `zuc_shutdown()`) never runs, with `check-linking.sh` step 9 proving the DLL
is released; and the NULL-buffer rule is stated in `zucrypt.h` and tested. The `zuc_alg` ranges
are reserved, `revdep.yaml` builds zuxlsx against every push, the freeze is stated in
`zucrypt.h`, `?zucrypt_c_api`, the README (badge now "stable") and NEWS, and the table stays
experimental. A one-shot `zuc_aes_cbc_decrypt_oneshot()` was suggested and is a possible
addition, not a change.

Goal: freeze ABI 1 because a real consumer has shown the archive suits it, not because a stage
number came up.

Entry: `zuxlsx`'s decryption core in C
([zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22) step 3) exists on a `zuxlsx`
branch, linking `libzucrypt.a` from this repository's `main` through `LinkingTo:` and
`configure`, and decrypts the real encrypted fixture to its known plaintext with the
`EncryptionInfo` parameters supplied from R. It covers every archive call `zuxlsx` will make:
the spin loop, the key and verifier decryption, the per-segment IV, the segment loop and the
HMAC over the package. It need not be merged; the CFB reader and the rest of zuxlsx#22 need
not exist.

Work items:

- **Answer the consumer.** Anything `zuxlsx` finds missing or awkward is fixed here before the
  freeze, and recorded in NEWS. A change that is not an addition is allowed only in this window.
- **Add a reverse-dependency job.** It builds `zuxlsx` at that branch (at `main` once it
  merges) against this checkout, and runs its decryption tests on three operating systems. This is the family convergence target that
  [zukomp#35](https://github.com/pedrobtz/zukomp/issues/35) tracks for `zukomp`. Write it so that
  `zukomp` and `zuxml` can adopt it unchanged, or propose it to `r-actions` as a reusable
  workflow.
- **Reserve the `zuc_alg` ranges** (design §8.1, revision 4 item 5) in `zucrypt.h`, as
  comments and as `ZUC_ALG_*_FIRST`/`_LAST` bounds: digests, MACs, ciphers and AEAD modes,
  key derivation, key families, signatures. No value is assigned in advance. This is the one
  revision 4 item inside the frozen window: a tranche that arrives after the freeze and finds
  no range would have to renumber, which ABI 1 forbids.
- **Declare the freeze.**
  - `?zucrypt_c_api`, the README and NEWS say the archive is ABI 1 and frozen.
  - The lifecycle badge becomes "stable" for the archive.
  - The table's tier is restated as experimental.
- **Decide the table's future** (design §14), if a non-fixture consumer has appeared by now.
  Otherwise it stays experimental.

Exit:

- The reverse-dependency job is green on three operating systems.
- The freeze is stated in every place design §8.6 lists.
- #28 closes.

## Stage 12 — v0.1.0 and CRAN

Goal: zucrypt on CRAN as 0.1.0, its first release, before `zuxlsx` 0.1.0 is submitted.

Work items:

- **Write the vendored-backend vignette** (#17), the document a CRAN reviewer or a security
  reviewer will read. *Done early, 2026-09-29, as a pkgdown article
  (`vignettes/articles/backend.Rmd`, "The vendored backend"), following CLAUDE.md's
  articles-only layout rather than #17's shipped vignette; the version it describes is in
  `crypt_info()`, and the site is versioned with the package.* It covers:
  - the trim;
  - the fourteen defines, and what is not enabled;
  - hardware AES where the CPU has it, the software fallback and its timing caveat (#51);
  - provenance and reproduction;
  - the patch;
  - how a security fix reaches an archive consumer, which is only when that consumer is
    reinstalled;
  - what the testing does and does not establish.
- **Write the C-API vignette** (#13), now that the promise is settled. It quotes both fixture
  packages rather than inventing examples. *Done 2026-09-29, as a pkgdown article
  (`vignettes/articles/c-api.Rmd`, "Using zucrypt from C"): choosing a shape, the
  `configure`/`Makevars.in` wiring with the single-quoted `PKG_LIBS`, the backend's lifetime
  including `.onUnload()`, the table's `Imports:` + `importFrom()` + lazy resolution, the ABI 1
  promise, and how a security fix reaches each shape.*
- **Write the getting-started article** (#15). *Done early, 2026-09-26:
  `vignettes/articles/zucrypt.Rmd`, pkgdown's "Get started" page, excluded from the
  tarball by `.Rbuildignore`. It covers all six functions, including an encrypt-then-MAC
  example that argues for not building your own.*
- **Run the CRAN preparation** (*done 2026-09-29, except CI on the final commit*):
  - the `cran-extrachecks` pass (*done: the README gains `install.packages("zucrypt")`, the
    Description names file hashing and hex and moves secure erasure to the C sentence it
    belongs to; everything else on its list already held*). There is no
    `review-cran-submission` skill in this environment, so that pass is not run;
  - `R CMD check --as-cran` on macOS and Windows: *by the `R-CMD-check.yaml` legs, not
    win-builder or macbuilder* (maintainer decision, 2026-09-29), with the r-devel
    containers for CRAN's Linux flavours;
  - `urlchecker` (*clean; the new C-API article's URL answered 404 only until GitHub Pages
    caught up with its deploy*);
  - the spelling check (*no misspellings; `inst/WORDLIST` records the 78 technical terms,
    package names and British spellings it flagged*).
- **Rewrite `cran-comments.md`** as a first submission. It lists only checks that have run, and
  explains the vendored backend and the installed static archive in one paragraph each.
  *Done 2026-09-29.*
- **Reposition the package before it is first published** (design revision 4, item 1), so
  that the title CRAN shows from the first release is the one that still holds at 0.6.0.
  *Done early, 2026-09-29:* `DESCRIPTION`'s Title is "Cryptography Without System
  Dependencies", the family's phrasing (`zuxlsx`: "Read 'xlsx' Workbooks Without System
  Dependencies"), true with six functions and true with sixty; the Description names the
  backend and lists categories with "including", so additions do not falsify it. It
  describes what ships and promises no migration: that claim waits for Stage 13's layer
  (#56). The README's opening and the getting-started article were aligned in the same PR.
  Still to do here: the README's lifecycle statement, once the freeze is declared.
- The version stays 0.1.0. There is no GitHub-only release before it; #27 closes as
  superseded.
- **Submission** is for the maintainer: submit, and on acceptance tag `v0.1.0` and publish the
  GitHub release.

Exit: accepted on CRAN, `main` at `0.1.0.9000`, and `zuxlsx` notified that it can submit 0.1.0
once the rest of zuxlsx#22 has merged.

## Stage 13 — Tranche 1: the openssl-shaped layer over what exists

Goal: put the design §7.1 layer, its gate and its migration article in place on functions whose
primitives already exist, so that every later tranche adds to a working pattern rather than
inventing one. Plus the one primitive every later tranche needs: randomness.

Entry: development can start on a branch once Stage 11 has frozen the archive, since every
addition is compatible; the 0.2.0 release follows 0.1.0 on CRAN. Nothing here changes the
frozen archive; every C addition is appended.

**Why this subset first, measured 2026-09-29** with `tools/openssl-usage.R` over the R sources
of the 104 CRAN packages that import or depend on `openssl` 2.3.4 (102 call at least one of its
functions). The most-called functions are `base64_encode()` (39 packages), `sha256()` (34),
`md5()` (23), `read_key()` (20), `rand_bytes()` (18), `base64_decode()` (17), then
`aes_cbc_decrypt()` and `write_pem()` (12 each). Twenty-seven exports are called by no
package, among them `sha224()`, `sha3()`, `ec_dh()`, the X25519 functions and `cert_verify()`.
Cumulatively, the tranches cover the detected usage of:

| After | Packages whose detected usage falls within the subset |
| --- | --- |
| Stage 13 | 63 of 102 (62%) |
| Stage 14 | 72 (71%) |
| Stage 15 | 89 (87%) |
| Stage 16 | 91 (89%) |
| Stage 17 | 95 (93%) |

The seven left need Ed25519, DSA, `read_p12()`, `bcrypt_pbkdf()` or `askpass()`: the design
§6 gaps. This is also why Stage 15 is RSA and key I/O and Stage 16 is the curves, not the
other way round: `read_key()` and RSA are what a fifth of the importers use, and nobody calls
ECDH or X25519. Re-run the script before restating the count in the migration article.

This is prioritization evidence, not a migration rate (#56). The script matches function names
in `R/` and `NAMESPACE`; it does not establish compatible arguments, key formats, object
methods or that anything runs, and it reuses a cached download when one exists. Removing
`openssl` from a package also does not always remove a system requirement: `httr2` imports
`curl` too, and libcurl stays.

Work items:

- **State the claim** (design revision 4, item 1). The title and Description were settled in
  Stage 12; this stage adds the README's coverage count and the gaps of design §6 beside it,
  now that there is a layer to count.
- **Randomness** (#9): `zuc_random_bytes()` in the archive over the existing
  `src/zuc_random.c` source, `crypt_rand_bytes(n)` mirroring `openssl::rand_bytes()`, and a
  `zucrypt_entropy_error` condition class. Never R's RNG: a test sets a seed, draws twice, and
  expects a difference. The harness injects an entropy failure and expects the class.
- **The remaining digests**: MD5, SHA-224, RIPEMD-160, SHA-3 (224/256/384/512). One define
  each, the trim re-derived once, `zuc_alg` values from the digest range, vectors with
  provenance (RFC 1321, FIPS 180-4, the RIPEMD-160 reference vectors, FIPS 202). MD5 and
  RIPEMD-160 are documented as legacy, not for security, in the same words as SHA-1.
- **Base64**: `crypt_base64_encode()` and `crypt_base64_decode()` over the backend's
  `base64.c`, with `openssl`'s `linebreaks` argument; RFC 4648 vectors.
- **The mirrored digest and HMAC functions**: `crypt_md5()`, `crypt_sha1()`, `crypt_sha224()`,
  `crypt_sha256()`, `crypt_sha384()`, `crypt_sha512()`, `crypt_sha2(x, size)`,
  `crypt_sha3(x, size)`, `crypt_ripemd160()`, `crypt_multihash()`, each with `key = NULL` for
  HMAC, and raw, character and connection input by the §7.1 typing rules. Connection input
  reuses the core's stream path, in v0.1.0 since #11; `crypt_hash_file()` is withdrawn.
  `crypt_rand_num()` beside `crypt_rand_bytes()`.
- **Measure the claim.** The migration article's table is generated from
  `getNamespaceExports("openssl")` at the pinned version (78 at 2.3.4), so every export is in
  exactly one of: covered, planned (with its stage), or a gap with its reason. A README line
  states the count covered, never "all".
- **The gate**: `tests/testthat/test-openssl-compat.R`, the three result kinds of design §7.1,
  and the export audit that fails on a mirrored function in no list. One CI leg sets
  `ZUCRYPT_REQUIRE_OPENSSL=1` so the gate cannot pass by being skipped.
- **The migration article**: `vignettes/articles/from-openssl.Rmd`, one table, and the gaps
  of design §6 listed under "missing" from this release on. It absorbs #16, the comparison
  article.
- **Migration trials, before any public claim** (#56). Migrate two or three representative
  importers locally, run their own test suites, and record for each whether dropping the
  `openssl` import actually removes a system requirement. The survey run behind the README
  count is saved with package versions, source hashes, scan failures and per-package results.
- **Reference index** grouped into core, openssl-shaped, and C interface.
- Close #9 and #16. Record the `openssl` version the gate ran against in NEWS.

Exit:

- Every mirrored function is byte-identical to `openssl` on Linux, macOS and Windows, and the
  required leg shows a nonzero count for the gate.
- `tools/vendor/verify` is clean, the manifest's `defines` match, and the trim was derived
  once for the stage.
- The source tarball, installed size, installed shared object, clean build time and a
  representative throughput are measured and recorded in NEWS, so "small" is a number; the
  tarball is under 5 MB.
- The migration trials are recorded, and the article's claims are no stronger than they are.
- The alloc-failure sweep's `min-target-hits` is raised to cover the new adapter code, and its
  first real run shows it.
- Accepted on CRAN as 0.2.0.

## Stage 14 — Tranche 2: authenticated encryption and key derivation

Goal: the constructions a caller composes into password-based encryption, without this
package specifying a format.

Work items:

- **AEAD** (#10): AES-GCM and ChaCha20-Poly1305 under design §6's AEAD contract: nonce,
  associated data and tag explicit, and decryption that fails with `zucrypt_auth_error` and
  releases no plaintext. `zuc_aead_*` in the archive, one-shot first; incremental decryption
  only if its buffering and verify-before-release semantics are justified and specified.
  `crypt_aes_gcm_encrypt()`/`_decrypt()` keep `openssl`'s names and argument order but not its
  behaviour: `openssl` 2.3.4 returns no tag and does not verify one (#56), which the migration
  article lists as a documented difference with the reason. Nonce policy per design §6. NIST
  SP 800-38D and RFC 8439 vectors; the second oracle is an implementation that exposes the tag,
  never `openssl`'s GCM.
- **AES-CTR**: `crypt_aes_ctr_encrypt()`/`_decrypt()`; NIST SP 800-38A vectors.
- **The mirrored CBC pair**: `crypt_aes_cbc_encrypt(data, key, iv = crypt_rand_bytes(16))`
  and `crypt_aes_cbc_decrypt()`, PKCS#7 padded and byte-identical to `openssl`'s, over the same
  `zuc_aes` core as the stable `_nopad` pair, which does not change (design §7.1).
- **KDFs** (#12): PBKDF2-HMAC (`crypt_pbkdf2()`, raw password, RFC 6070 and 8018 vectors) and
  HKDF (`crypt_hkdf()`, RFC 5869 vectors). Neither has an `openssl` R counterpart, so both
  follow the core typing rule; `bcrypt_pbkdf()` is listed as a gap.
- **Hardware paths**: `aes-paths.yaml` asserts GCM and CTR on each path, including the
  software-only build, and the side-channel note in `?crypt_aes_gcm_encrypt` and `zucrypt.h`
  covers them.
- `zuc_alg` values from the cipher and KDF ranges; table entries appended; `ZUCRYPT_API_HAS`
  used in the fixture for one new field.

Exit: vectors and the gate green on three operating systems; design §12's authenticated
encryption gate green (tampered ciphertext, tag and associated data, truncated tag, wrong key:
each an error, no plaintext); the sweep reaches the AEAD adapter; `tools/zucrypttest` calls
every new table entry; the archive fixture links the new `zuc_*` functions; CRAN 0.3.0.

## Stage 15 — Tranche 3 (candidate): key objects, PEM and DER, RSA

Entry: the admission decision (design §6, criterion 5), recorded once 0.3.0 has shipped. The
same holds for Stages 16 and 17, each after the stage before it.

Goal: the first public-key tranche, ordered by the measurement above: key reading and writing
and RSA are what the importers use, and the key-object model introduced here is what every
later tranche builds on.

Work items:

- **Key objects**: `crypt_key` and `crypt_pubkey` S3 classes over finalized external
  pointers to backend keys; `print()`, `as.list()` and the accessors `openssl` has; wiped on
  finalization.
- **PEM and DER**: `crypt_read_key()`, `crypt_read_pubkey()`, `crypt_read_pem()`,
  `crypt_write_pem()`, `crypt_write_der()`, `crypt_write_pkcs1()`, with `password` for
  encrypted PEM where the backend supports the cipher. PK, PEM and ASN.1 are in the pinned
  TF-PSA-Crypto tree (`extras/`, `utilities/`), so no new manifest row. The gate here is
  cross-reading: `openssl` reads what we write, and we read what it writes, for every key
  type this tranche and the next can produce.
- **RSA**: `crypt_rsa_keygen()`, PKCS#1 v1.5 and PSS signatures through
  `crypt_signature_create()`/`_verify()`, OAEP encryption (`crypt_rsa_encrypt()`/`_decrypt()`),
  PKCS#1 v1.5 encryption present and documented as legacy. RFC 8017 and FIPS 186-5 vectors;
  cross-verification with `openssl` for everything randomised.
- **Fingerprints**: `crypt_fingerprint()` over public keys.
- **Envelopes**: `crypt_encrypt_envelope()` and `crypt_decrypt_envelope()`, `openssl`'s
  RSA-plus-AES-CBC hybrid, reproduced field for field and cross-verified. A construction,
  admitted because it is `openssl`'s documented format, not one of ours.
- **SSH key formats**: `crypt_write_ssh()` and `crypt_write_openssh_pem()` for the key types
  this package can produce, cross-read by `openssl` and by `ssh-keygen` where CI has it.
- **Bignum, conversion only**: `crypt_bignum()` from raw, integer or a decimal or hex string,
  with `as.raw()`, `as.character()` and `print()`. Four importers, `jose` among them, need it
  to move RSA parameters between JWK and PEM. Arithmetic (`bignum_mod_exp()`,
  `bignum_mod_inv()`) is called by no importer and stays out.
- **Size**: bignum and RSA are a large addition. The trim is derived and measured before
  anything else in the stage, and the numbers go in the PR.

Exit: cross-reading, cross-verification and the vectors green on three operating systems;
constant-time claims are upstream's and are quoted, not restated; CRAN 0.4.0.

## Stage 16 — Tranche 4 (candidate): EC keys, ECDSA, ECDH and X25519

Work items:

- **Curves**: P-256, P-384 and P-521 through `crypt_ec_keygen(curve)`, and `crypt_ec_dh()`;
  X25519 through `crypt_x25519_keygen()`, `crypt_x25519_diffie_hellman()`,
  `crypt_read_x25519_key()` and `crypt_read_x25519_pubkey()`. RFC 7748 vectors, NIST CAVP
  ECDH vectors, `sodium` as the second oracle for X25519.
- **ECDSA**: `crypt_signature_create()`/`_verify()` extended to EC keys, RFC 6979 deterministic
  signatures as an option, DER-encoded signatures as `openssl` emits them. The backend
  produces raw `r || s`; `crypt_ecdsa_parse()` and `crypt_ecdsa_write()` are that conversion,
  exported as `openssl` exports them and tested in both directions.
- **Ed25519 is a documented gap**, stated in the article and in `?crypt_x25519_keygen`, with
  the reason: the pinned release has no EdDSA. Two importers need it (`jose`, `shinyOAuth`).
- The gate is cross-verification throughout, since signing and key generation are randomised.

Exit: CRAN 0.5.0.

## Stage 17 — Tranche 5 (candidate): certificates

Goal: X.509 *data*: parse, write, verify a chain against a caller-supplied bundle, and
fingerprint. Not trust discovery and not fetching, which are `zuhttp`'s.

Work items:

- **A second manifest row**, `mbedtls`, on the Mbed TLS 4.1 LTS line paired with the pinned
  TF-PSA-Crypto, trimmed by the same method to the X.509 files. Never the whole library:
  Mbed TLS 4.1.0's `library/` has 36 sources, of which 9 are X.509, 19 are TLS and 8 are
  support (measured 2026-09-29). The row keeps the 9 and their header closure; the 19 TLS
  sources wait for Stage 18. `inst/COPYRIGHTS`, the installed licence and
  `tools/vendor/verify` extend to two rows. This is the row the TLS engine builds on.
- `crypt_read_cert()`, `crypt_read_cert_bundle()`, `crypt_write_pem()` for certificates,
  `crypt_cert_verify(cert, root)`, `crypt_fingerprint()` for certificates, and `crypt_read_p7b()`
  over upstream's parse-only `pkcs7.c`. PKCS#12 and PKCS#7 writing are gaps.
- Test fixtures: a synthetic CA, intermediate and leaf generated by a `tools/` script with
  `openssl`, committed with provenance.

Exit: CRAN 0.6.0, and the manifest row documented well enough that Stage 18 can extend it.

## Stage 18 — The TLS engine for zuhttp (candidate)

Goal: a TLS 1.2/1.3 client engine inside `zucrypt`, over caller-supplied I/O, that `zuhttp`
can select at run time as its bundled backend (design §10). It is not a tranche of the
`openssl` alternative and has no R surface.

Entry: Stage 17 shipped, and `zuhttp`'s trigger has fired (its D-63: proxied HTTPS on macOS
11–13, or a later `zuhttp` decision), recorded in both repositories. Admission criterion 5 is
met by that trigger. Without it, this stage does not start.

Work items:

- **The trim.** The Stage 17 `mbedtls` row gains the TLS sources the client configuration
  compiles (TLS 1.2 and 1.3 client, the fixed suite and group set, no server, no DTLS, no
  renegotiation), derived once by the spike's method; the define set extends and is recorded
  in the manifest. The archive's object list does not change: `tools/check-layering.sh` gains
  a check that no `ssl_*` object is in `libzucrypt.a`.
- **The adapter.** `src/zuc_tls*.c`, R-free like the rest of the adapter: a client context
  owned by a handle, I/O through send and receive callbacks, CA bundle, host name, minimum
  version and pins passed in, verification that fails closed with a named status, and
  handshake, read, write, close-notify and free. DRBG seeded from tranche 1's entropy.
- **The table.** `inst/include/zucrypt-tls.h`, `zucrypt_tls_api_v1` registered with
  `R_RegisterCCallable()`, with `struct_size` and a `ZUCRYPT_TLS_API_HAS()` macro, experimental
  until `zuhttp` ships with it. A fixture package, `tools/zucrypttls`, resolves it from
  `Suggests:` only, and fails cleanly when `zucrypt` is absent.
- **Tests, offline.** Handshakes over loopback against a local `openssl s_server` with a
  synthetic CA, for TLS 1.2 and 1.3: success; an untrusted root; a wrong host name; an expired
  leaf; a version below the minimum; a pin mismatch; a truncated record; an unexpected close.
  Each failure is a named status and never plaintext. The same matrix on three operating
  systems, plus the sanitizer and alloc-failure legs over the adapter.
- **Security process.** The vendored-backend vignette states that TLS advisories on the
  enabled configuration are patch releases, and `vendor-upstream.yaml` watches the `mbedtls`
  row's advisories as well as its releases.
- **Size.** Measured before anything else in the stage, as for Stage 15; the tarball stays
  under 5 MB or the stage records why the gate moves.

Exit: the handshake matrix green on three operating systems; `zuhttp`'s own handshake matrix
green against it on a branch; the archive's object list unchanged; a CRAN minor release.

## After Stage 18

- **Ed25519** when upstream ships it; **ML-DSA** on the admission rule (design §14).
- **Threads** when a consumer asks (design §8.4).
- **1.0.0** when the package has demonstrated external use (a CRAN package other than
  `zuxlsx` depending on it), a security update has been rehearsed end to end (an upstream
  advisory taken through vendoring, release and the note that archive consumers must
  reinstall), and the openssl-shaped layer has had two releases without a
  documented-difference change (#56).

## CI from Stage 7

Pins stay commits, with the tag in a trailing comment, and a bump is its own reviewed commit.

| Workflow | Changes in | Why |
| --- | --- | --- |
| `alloc-failure.yaml` | Stage 8 | Interposer fix (r-actions), a window over the adapter, and a printed pattern |
| `arch.yaml` | Stage 8 | testthat installed, WARNING fails, test count asserted |
| `native-checks.yaml` (layering) | Stage 8 | The `UNPROTECT`/`return` lint and its canary |
| `vendor-upstream.yaml` | Stage 7, if r-actions supports it | Follow the 1.1 LTS tags only |
| `consumer.yaml` | Stage 10 | Two fixture packages under `tools/`, three operating systems |
| `revdep.yaml` (new, bespoke) | Stage 11 | Build `zuxlsx` against this checkout on three operating systems and run its decryption tests; its ref is zuxlsx `main` since zuxlsx#64 merged (it was `feat/agile-decrypt-core` before) |
| `R-CMD-check.yaml` | Stage 13 | One leg sets `ZUCRYPT_REQUIRE_OPENSSL=1`, so the compatibility gate must run there |
| `vendor.yaml` | Stage 13 | Tarball-size gate (5 MB) and the object and file counts printed per run |
| `aes-paths.yaml` | Stage 14 | GCM and CTR on each path |
| `alloc-failure.yaml` | Stages 13–16 | `min-target-hits` raised as the adapter grows; each first real run dispatched by hand |
| `vendor.yaml`, `vendor-upstream.yaml` | Stage 17 | Two manifest rows |
| TLS handshake matrix (new) | Stage 18 | Loopback handshakes and failures against `openssl s_server`, three operating systems |

## Risks

- **An r-actions release is on the critical path.** Stage 8 cannot close until the interposer is
  fixed upstream. CLAUDE.md forbids hand-rolled jobs, so the mitigation is to file the fix early,
  in Stage 7, not to work around it.
- **v0.1.0 waits on another repository by design**, but only on the part of it that touches
  the archive: `zuxlsx`'s decryption core in C (zuxlsx#22 step 3), not its CFB reader, fuzzing
  or limits. Freezing without that core is the mistake being corrected: do not trade it away
  for a date.
- **The rest of zuxlsx#22 may still find a gap.** It then becomes an addition in a zucrypt
  0.1.x, submitted before `zuxlsx` 0.1.0. A needed change that is not an addition would mean
  ABI 2, which is exactly what freezing on the consumer's decryption core is meant to prevent.
- **Re-deriving the trim twice.** ECB's removal and the dynamic store both change the define set.
  Do them in one commit, so the trim is derived and reviewed once.
- **The dynamic key store allocates.** Its slices are heap memory, so it adds allocation sites in
  vendored code. That is one more reason Stage 8's sweep must reach the adapter rather than stop
  in R's startup.
- **An upstream security release mid-plan.** Take it at once, as its own pull request, by the
  procedure in stage-1-spike §11. No stage waits for it and it waits for no stage.
- **Every tranche is compiled by every `zuxlsx` install.** Static linking pulls only the
  objects a consumer references, so `zuxlsx.so` does not grow with primitives it never calls,
  but zucrypt's own install time and tarball do. Each stage measures before it merges, and the
  5 MB tarball gate is the stop.
- **Mirroring drifts.** The `openssl` package can change a default or a return type. The gate
  pins the version it ran against in NEWS; a divergence becomes a documented difference, never
  a silent change to a `crypt_` function.
- **The gaps are where migration fails.** Ed25519, `bcrypt_pbkdf()`, PKCS#12 and `bignum` are
  listed from Stage 13 so that no one moves a package that needs them and finds out at run
  time.
- **Public-key side channels are upstream's promise, not ours.** Bignum and curve code claim
  constant time in upstream's terms; this package quotes that and adds no claim. The software
  AES caveat extends to GCM and CTR.
- **The enum ranges must land in Stage 11.** It is the one revision 4 item inside the frozen
  window; missing it means a renumbering that ABI 1 forbids.
- **One maintainer, a wider surface.** A broad crypto package attracts requests for
  constructions. The admission rule and the no-format rule are the standing answers; a request
  that fails them is closed with the rule as the reason.

# Part B — The v0.1.0 roadmap as executed (2026-09-20)

Everything below is the plan as written on 2026-09-20 and amended by the 2026-09-22 review. Its
stage sections stay because the stage issues link to their anchors, and because they are the
exit criteria that were claimed. Two status notes are added: Stage 5 is reopened, and Stage 6
is superseded by Part A.

## Scope of v0.1.0

v0.1.0 is the **core package**: a vendored TF-PSA-Crypto backend (no Mbed TLS file is vendored;
[stage-1-spike.md](stage-1-spike.md) §1), the six-function R
interface, and the C API in both shapes the family uses — the registered function table
(`zucrypt-r.h`, for consumers that can carry an `Imports:` — `zuhttp` was the hoped-for one
and is not, #14) and the static archive (`libzucrypt.a`, installed to `lib/`;
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
  The family order makes the deadline concrete: zucrypt must reach CRAN before zuxlsx 0.2.0
  (agile decryption, [zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22)), not before
  zuxlsx 0.1.0, which does not link it. `cran-comments.md` (drafted in #18) reads "This is a first
  submission" and cites weekly checks that had not run (#31); it is a draft, not a decision.

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
only code that includes upstream headers. It is what goes into `libzucrypt.a`, so it
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
  `src/install.libs.R` installs the shared object *and* the archive, the latter to the installed package's `lib/` — there is no `inst/lib/` (defining that
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
- `test-linking.R` (skips under `load_all()`): the installed `lib/libzucrypt.a` and `zucrypt.h` exist after
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

- Every validation rule has a test asserting the class and `native_status` of the condition
  (conditions carry `algorithm` and `native_status`; there is no `code` field).
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
  `zucrypt.h` and links `lib/libzucrypt.a` from the installed package, calls `zuc_init()`,
  hashes a KAT, and exits non-zero on mismatch — `zukomp`'s pattern for its ZIP reader.
- Office derivation rehearsal (the ABI validation gate): inside the consumer fixture, implement
  the generic iterative loop `H_n = hash(int32le(n-1) || H_{n-1})` for a configurable spin count
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
- ABI rejection test: requesting an unsupported major version returns `NULL`; the fixture
  handles it without crashing. (`zucrypt_get_api()` returns only a pointer, so there is no
  status code to assert.)
- Loading order tests from Stage 1 extended to load the consumer, `openssl`, and `zucrypt` in
  all orders.
- `tools/check-linking.sh` passes on Linux and macOS in `consumer.yaml`.

## Stage 5 — Hardening and release gates

**Reopened 2026-09-22 (#26); closes with Part A's Stage 8**, which makes its two weekly gates
execute against their targets. The record below is unchanged.

**Closed, with two documented deviations** — the second found after closing, below. The first:
`extra-ubsan-checks` is not passed, and the argument
for it below still stands — it just cannot be applied only to our code. Two instrumented runs
found two deliberate cases in the vendored tree: `aes.c`'s GF(2^8) doubling truncating to
`uint8_t`, and `sha256.c`'s compression function adding modulo 2^32, which is the one this
section predicted. Writing them down in `tools/ubsan.supp` is the right answer and is currently
unavailable: passing `ubsan-suppressions` breaks the `asan` job, which runs inside a container
where the checkout is mounted at `/__w/...` while the path is built from `github.workspace`,
the host path. So the choice is ASan or the extra integer checks, and ASan wins — it finds
use-after-free and double-free on exactly the cleanup paths §11 legislates about, while the
length arithmetic is simple, validated in R before any native call, and was meant to be
exercised by `arch.yml`'s 32-bit leg — which, as configured, runs no tests (see the second
deviation below), so that half of the argument does not hold until #31 closes. Both suppression
entries are written down and ready; restoring is two lines once r-actions resolves that path.
The fix belongs in `r-actions`, not here.

**Second deviation, found 2026-09-22.** The exit criterion "every job green" was not met when
this stage closed, because two of its jobs had not run. `alloc-failure.yaml` first ran on
2026-09-23 (run 35850281104) and failed, for two independent reasons: r-actions' interposer
does not interpose `free`, so every injected run aborts on `free(): invalid pointer`; and the
300-allocation sweep window starts at the startup floor, inside R's namespace loading, so no
`zuc_*_new()` call is ever failed. `arch.yaml` first ran two days later (run 35716615253), with `install-dependencies: ""`:
no `Suggests` were installed, `tests/testthat.R`'s `requireNamespace()` guard skipped the suite,
and the i386, musl and aarch64 legs finished the test step in 0.2 s. The i386 and aarch64 legs were
green with a WARNING. A job that has not run is not green, and one that runs no tests is the vacuous tick
this roadmap's CI rule exists to prevent. #31 tracks making both real.

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
`analyzers` both gating rather than informational; no open findings; the upstream-update
procedure is documented ([stage-1-spike.md](stage-1-spike.md) §11 — a TSV manifest cannot
carry it).

## Stage 6 — v0.1.0 release

**Superseded 2026-09-25 by Part A.** Its remaining items were split into Stages 7–9, and the
`v0.1.0` tag is Stage 9's last item. The record below is unchanged.

**Prepared.** One item was a no-op and is recorded as one: every r-actions pin was already at
`v1.9.0`, the current release, at the exact commit `1878271`, so "bump every pin in one commit"
changed nothing. Checked rather than assumed — the point of the item is that the pins are a
decision, and confirming they are current is that decision.

Tagging and the GitHub release are deliberately not done by the same hand that wrote the code
without asking: they are public and hard to walk back.

**What remains, as of 2026-09-22** (tracked in #27). Code changed after "Prepared": #18 fixed an
unprotected result vector in `src/zucrypt_crypt.c` that rchk, gctorture and the sanitizers had
all passed, so the tag belongs on `954284e` or later, not on #8's merge.

- Tag `v0.1.0` and publish the GitHub release.
- Decide whether ABI 1 is frozen now or when the first consumer's C path merges (#28), and
  whether AES-ECB leaves the ABI first (#29). Both are free to change today and not after a
  consumer links them.
- Record whether the pin stays on the TF-PSA-Crypto 1.1 LTS line or moves to 1.2.0 (#19); the
  tag names the release it ships.
- Fix or document the 16-handle limit of the static PSA key store (#30).
- Make the two Stage 5 gates real: `arch.yaml` running the suite, `alloc-failure.yaml`
  green with failures actually injected into the adapter (#31).
- Correct the README example, whose printed digest is not SHA-256 of its input (#36).
- CRAN timing is not settled by this stage: see "Scope of v0.1.0" above, which conflicts with
  `cran-comments.md` as drafted.

- Documentation pass: pkgdown reference grouped as "Hashing", "Ciphers (advanced)",
  "Comparison and information", "C API"; README example filled with a hash and an HMAC only
  (no cipher example in the README, to avoid presenting CBC as a general-purpose tool).
- `NEWS.md` entry for 0.1.0 listing the API, the pinned backend release, supported platforms and
  the explicit non-goals.
- Freeze the C ABI: bump `ZUCRYPT_ABI_VERSION` to 1 and state the compatibility promise
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
  Done: [zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22), agile only — Standard (ECB)
  encryption is out of scope there (design-zuxlsx §21c), which leaves ECB here without a consumer.

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

## Review 2026-09-22

A critical read of the stages against the code, the CI history and the sibling repositories,
two days after Stage 6 was prepared. The stage sections above are kept as the plan they were;
what follows is what the evidence says about them.

### What should have gone differently

- **The pace defeated the sequencing rule.** The skeleton landed at 07:11 on 2026-09-20 and
  #8 merged at 12:58 the same day. Stage 5 took 64 minutes, and the ABI was frozen 16 minutes
  after it merged. Stages are sequential "so that a later one never inherits an unproven
  earlier one", but Stage 5 added weekly jobs whose first run could only come after Stage 6. A
  stage that adds a scheduled job should close only after that job's first run, dispatched by
  hand if need be.
- **The ABI was frozen before any consumer existed.** "ABI frozen too early" is listed under
  the risks, and the Stage 4 rehearsal was its only mitigation. No consumer of either shape
  exists: `zuhttp` has no `Imports:` and never mentions this package (#14), and
  [zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22) has not started its C path. Found
  since: a 16-handle limit in the key store (#30), an ECB surface with no consumer (#29), and
  `R_GetCCallable()` raising an R error where the header promises `NULL` (#36). The first two
  are free to change while nothing is tagged or linked, and need a new major ABI after a
  freeze (#28); the third is a documentation fix either way.
- **The rehearsal shares a backend with what it checks.** Its "independent" R loop calls
  `crypt_hash()`, so it proves that reset equals a fresh context and that the segment reset
  works — not that any primitive is right. "No constants, no salts" also ruled out the one
  strong check on offer: a known-answer vector taken from zuxlsx's committed agile fixture,
  with msoffcrypto-tool as the independent oracle. The rehearsal never uses per-segment IVs or
  an HMAC over the whole stream, which are the calls the real consumer makes.
- **Gates were declared green before they ran.** `alloc-failure.yaml` ran for the first
  time after the freeze and failed without ever reaching the adapter, and `arch.yaml` runs no
  tests (#31). #18's unprotected vector was found by reading the code after
  the freeze; rchk had analysed 496 functions and passed, and nothing now guards the pattern
  (#35). The published vectors are all shorter than one compression block, so every multi-block
  result is checked only against zucrypt itself (#34).
- **The archive proof is the one zukomp retired.** `tools/check-linking.sh` links a plain
  `main()`. zukomp replaced exactly that with a `LinkingTo`-only fixture package, because a
  plain `main()` never exercises `configure`, `system.file()`, path quoting or linking into a
  package shared object. Here it also never checks hidden visibility inside a consumer, never
  runs beside `zucrypt.so`, and skips Windows (#32).

### Recommended v0.1.0 scope

- **The six R functions stay as they are.** Their contract — raw only, exact names, classed
  conditions — is consistent with the family and has not been contradicted by anything found.
- **The archive shape is the one with a consumer.** Freeze `zucrypt.h` and `libzucrypt.a`
  when zuxlsx#22's C path merges and its archive fixture (#32) is green, not before.
- **The registered table ships marked experimental**, outside the freeze, until something
  consumes it (#14, #28).
- **ECB leaves the ABI** (#29). If it stays, its key should be imported lazily so it stops
  halving the handle limit (#30).
- **Tag after #28–#31, #19 and #36.** CRAN comes before zuxlsx 0.2.0, not before zuxlsx 0.1.0,
  and after #33's licence half, #34 and #35.

### Open issues against the tag

| Issue | Gates v0.1.0? | Why |
|---|---|---|
| #28 ABI freeze decision | Yes | Freezing is what the tag announces; with no consumer it is still free to change |
| #29 Remove AES-ECB | Yes | No consumer since zuxlsx §21c, and it doubles the key slots each AES handle takes |
| #30 16 live AES handles | Yes | A hard limit under a promised ABI, reported as an allocation failure |
| #31 Stage 5 gates never executed | Yes | Stage 5's own exit criterion; `arch` is also the stated reason for dropping `-fsanitize=integer` |
| #32 Archive fixture package | Before the archive freezes | The archive's claims (PIC, hidden symbols, two backend copies) are untested until then |
| #33 Family conventions | No; the licence half before CRAN | `lib${R_ARCH}` and the fixture location are convergence; installing upstream's licence is an obligation once binaries ship |
| #34 Multi-block and long-key vectors | No; before CRAN | Design §12 requires independent checks and today they stop at one block. Cheap to add, since `openssl` is already in `Suggests` |
| #35 longjmp paths | No; before CRAN | Hardening of paths that currently have zero executions |
| #36 Stale docs and comments | Yes | The README prints a digest that is not SHA-256 of its input |
| #19 Upstream 1.2.0 | Yes, as a decision | The tag names the pinned release; staying on the 1.1 LTS line needs its reason recorded |
| #14 zuhttp SPKI pinning | No | A zuhttp decision; its answer feeds #28 |
| #9 `crypt_random()`, #10 AES-GCM, #11 file hashing, #12 PBKDF2/HKDF | No | Each waits on a concrete consumer (design §6, §7) |
| #13 C-API vignette | No | Worth writing once #28 settles what is promised |
| #15 getting-started, #16 choosing, #17 vendored backend | No | Documentation; #17 is the one a CRAN reviewer would read |
