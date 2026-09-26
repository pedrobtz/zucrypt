# zucrypt: design

Status: revision 3, adopted 2026-09-25 (#38). §3–§8 and §11–§12 describe the package on `main`.
[roadmap.md](roadmap.md) Stages 7–10 have implemented revision 3's decisions, all except the
two tied to the first consumer: the ABI 1 freeze (§8.6, Stage 11) and CRAN (Stage 12). §9,
and §13 steps 3–5, are plans owned by `zuxlsx` and `zuhttp`.
Date: 2026-09-19. Revised 2026-09-20 against the `zu*` packages as shipped; reviewed
2026-09-22 against the implementation (#37); revision 3 on 2026-09-25; implementation
status updated 2026-09-26.
Initial application: cryptographic support for password-encrypted Excel input.
Related packages: `zuxlsx`, `zukomp`, `zuxml`, and `zuhttp`.

## Revision 3 (2026-09-25)

The 2026-09-22 review found three problems:

- v0.1.0 was prepared, and its C ABI frozen, before either consumer shape had a consumer;
- two release gates had never executed;
- one primitive no longer had a reason to exist.

It left each choice open as an issue. This revision makes those choices. Every item below names
its issue and the sections it changes. Nothing here moves the package's boundary: `zucrypt`
still owns primitives only.

1. **A surface is frozen when a consumer links it, not before.** (#28; §8.6)
   - The six R functions are stable from v0.1.0.
   - The static archive (`zucrypt.h`, `libzucrypt.a` and its install path) is *provisional* in
     v0.1.0. It becomes frozen ABI 1 in v0.2.0, once `zuxlsx`'s agile C path
     ([zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22)) has merged against it and the
     archive fixture package is green on three operating systems.
   - The registered function table is *experimental* until a package that is not a fixture
     uses it.
   - `ZUCRYPT_ABI_VERSION` stays 1. Nothing was tagged or linked against it, so the removals
     below break no published ABI.
2. **AES-ECB is removed.** (#29; §6, §8.1, §9)
   - Its one justification was Office Standard encryption, which `zuxlsx` §21c put out of scope
     on 2026-09-20.
   - It leaves the header, the table, the adapter, the configuration and the vendored trim.
   - Bringing it back later is an *addition*, allowed in any minor version, once a consumer
     exists.
3. **The PSA key store is dynamic.** (#30; §4, §8.1)
   - `MBEDTLS_PSA_KEY_STORE_DYNAMIC` replaces the 32-slot static store, which allowed only 16
     live AES handles per process and reported the limit as `ZUC_ERR_MEMORY`.
   - After item 2, each handle holds exactly one key. Volatile keys live in slices that double
     in size, up to about 6.7 × 10⁷, so the only practical limit is memory, and
     `ZUC_ERR_MEMORY` becomes the truthful status.
4. **Calls before initialisation get their own status.** (#28; §8.1, §11)
   `ZUC_ERR_NOT_READY = 9` is appended. It is returned when a function runs before `zuc_init()`
   or after the last `zuc_shutdown()`. Today that case returns `ZUC_ERR_INVALID_ARGUMENT`.
5. **The resolver is documented as it behaves.** (#28, #36; §8.2)
   - `R_GetCCallable()` raises an R error, rather than returning `NULL`, when `zucrypt` is
     missing. So `zucrypt_api()` returns `NULL` only for a version mismatch.
   - `ZUCRYPT_API_HAS(api, field)` is added so that a consumer can test `struct_size` before
     calling an appended field, as with `zuxml`'s `ZUXML_API_HAS`.
6. **The archive installs as `zukomp`'s does.** (#33; §3, §4, §8.3)
   - The archive goes to `lib${R_ARCH}/libzucrypt.a`, and Apache-2.0's text to
     `licenses/tf-psa-crypto-LICENSE`, with every install copy checked.
   - Fixture packages live under `tools/`.
   - This lands before `zuxlsx` writes its C path, so that path is written once. `zuxlsx`'s
     `configure` already tries `lib/<arch>` and then `lib/`.
   - The family table below still shows today's layout. Its `zucrypt` cells are updated in all
     five repositories together once Stages 7 and 10 land.
7. **Upstream stays on the TF-PSA-Crypto 1.1 LTS line.** (#19; §4)
   - 1.1.1 and 1.2.0 were released the same day (2026-07-07).
   - 1.2 is a feature line, and nothing in this profile needs a feature from it.
   - 1.1 is supported with Mbed TLS 4.1 LTS until March 2029.
   - Patch releases within 1.1.x are taken promptly. The package changes lines only when the LTS
     line moves, or when a consumer needs a feature that only a newer line has.
8. **A gate counts only when its log shows it exercised its target.** (#31, #34, #35; §12)
   - The architecture legs must report a nonzero test count.
   - The allocation-failure sweep must report failures injected inside `zuc_*` allocations.
   - Multi-block and long-key results are checked against published vectors and against OpenSSL.
   - Interrupt cleanup is observed through a live-context counter.
   - The derivation rehearsal gains one known-answer vector with an oracle outside this package
     (§12).
9. **No table consumer is being sought.** (#14; §1, §5)
   - `zuhttp` hashes with each TLS backend's own SHA-256, and consumes no sibling in 0.x.
   - #14 closes as not planned.
   - The table stays, in the experimental tier. It costs one fixture that runs on every push,
     and it can still be removed while it is experimental.
10. **CRAN is v0.2.0.** (#27; §13)
    - v0.1.0 is a GitHub tag.
    - v0.2.0 is the first CRAN submission. It follows the archive freeze and precedes
      `zuxlsx` 0.2.0, which cannot reach CRAN with a `LinkingTo:` on a package that is not
      there.
    - `main` carries a `.9000` version between releases.

### Revision 2 (2026-09-20), kept for its reasons

The first draft was written from the sibling packages' design documents. Revision 2 checked it
against the packages themselves, and moved in one direction: making `zucrypt` consumable the way
the siblings already consume each other.

- **It gave `zucrypt` two consumer shapes**, adding the static archive to the table. Revision 3
  ranks them (§8.6).
- **It chose the `zuc_`/`ZUC_` prefix**, because `zu_` is `zukomp`'s public namespace and
  `zuhttp`'s internal one. A `zucrypt.h` declaring `zu_status` could not be included beside
  `zukomp.h`.
- **It made the archive contain the adapter**, never raw upstream (§8.3).
- **It adopted the family's R names, condition classes, vendoring layout, build rules and test
  conventions** (§3).

## 1. Purpose

`zucrypt` provides a small, predictable cryptographic foundation for R packages. It is backed by
vendored code from the Mbed TLS ecosystem. It exposes a narrow R interface and a versioned C
interface, and needs no installed OpenSSL, Java or Python at runtime.

**The one planned consumer is `zuxlsx`**, reading password-encrypted `.xlsx` files (agile
encryption only, `zuxlsx` §21c). It links the static archive.

**`zuhttp` is not a consumer, and none is being sought (#14).**
- `zuhttp` imports nothing by policy.
- Its SPKI pin digests come from each TLS backend.
- What blocks pins on Secure Transport and Schannel is extracting the SubjectPublicKeyInfo, not
  hashing it (pedrobtz/zuhttp#4, #12).
- The one point of contact left is §10: a future Mbed TLS engine in `zuhttp` would pin the same
  upstream release.

The package's value is straightforward installation, controlled algorithm support, and a C
surface that other packages can link. It does not claim that R lacks cryptography:
- `openssl` provides broad cryptographic functionality;
- `sodium` provides modern encryption interfaces;
- encrypted Excel can already be read through Java or Python integrations.

What does not exist elsewhere is a focused native foundation that fits the `zu*` family.
Neither `openssl` nor `sodium` publishes a C ABI for other packages. See the
[openssl manual](https://jeroen.r-universe.dev/openssl/doc/manual.html),
[sodium documentation](https://docs.ropensci.org/sodium/),
[xlsx manual](https://cran.r-project.org/web/packages/xlsx/refman/xlsx.html) and
[rpxl](https://github.com/epicentre-msf/rpxl).

## 2. Main decisions

| Decision | Rationale |
| --- | --- |
| Use the Mbed TLS ecosystem rather than BearSSL | Align document cryptography with the potential TLS backend for `zuhttp` |
| Build only the crypto components (TF-PSA-Crypto; no Mbed TLS file) | Excel cryptography needs no TLS or certificate processing |
| Keep Office parsing and decryption orchestration in `zuxlsx` | HTTP and other crypto consumers must not depend on Office, XML or ZIP code |
| Expose a small wrapper API, not upstream types | Isolate consumers from upstream configuration and ABI changes |
| **The static archive is the primary C shape. The registered table is experimental** | `zuxlsx` links archives and has no `Imports:`. No package uses a table, in this repository or in any sibling (#14, §8.6) |
| **Freeze a surface when a consumer links it** | A freeze with no consumer protects nothing and blocks the fixes a first consumer finds (#28) |
| **Each primitive needs a named consumer** | ECB lost its consumer and is removed (#29). Later primitives enter on the same rule (§6) |
| **The archive contains the adapter, never raw upstream** | PSA headers depend on the configuration and expose key identifiers. With only `zucrypt.h` visible, there is no define for a consumer to match |
| **C ABI prefix `zuc_`/`ZUC_`, never `zu_`** | `zu_` is `zukomp`'s public namespace and `zuhttp`'s internal one |
| **Dynamic PSA key store** | A static store turns "too many live handles" into a false out-of-memory error (#30) |
| **TF-PSA-Crypto 1.1 LTS** | Supported until 2029. 1.2 adds nothing this profile uses (#19) |
| Support raw bytes explicitly | Avoid implicit text encoding, serialization or path interpretation |
| Treat cipher operations as low-level interfaces | They do not by themselves define a secure encrypted-file format |
| Share upstream provenance with `zuhttp` first | A single shared compiled backend is a separate, deferred decision (§10) |

If Office support later serves several readers, extract it from `zuxlsx` into a dedicated
document package. Do not introduce that package before there is a second consumer.

## 3. Conventions inherited from the `zu*` family

These are established in `zukomp` and `zuxml`, and restated in `zuxlsx`'s CLAUDE.md. Several are
enforced by tests that a new package is expected to carry too. They are listed here so nothing
below has to re-derive them.

**Naming by layer.**

| Layer | Prefix | Examples |
| --- | --- | --- |
| R exports | `crypt_` | `crypt_hash()`, `crypt_info()` |
| C ABI (installed headers) | `zuc_` / `ZUC_` | `zuc_status`, `ZUC_OK`, `zuc_hash_new()` |
| Entry points and registration | `zucrypt_` | `R_init_zucrypt`, `zucrypt_get_api`, `zucrypt_api_v1` |
| Internal only, never installed | `zuc_int_` | `zuc_int_backend_init()` |
| Test-only `.Call` symbols | `zucrypt_test_` | `zucrypt_test_hash_split()` |
| R condition classes | `zucrypt_` | `zucrypt_invalid_argument`, `zucrypt_error` |

**The prefixes are unique in the family** (checked 2026-09-20 across `zukomp`, `zuxml`, `zuhttp`,
`zucsv`, `zujson`, `zuyaml` and `zuxlsx`):
- `zuc_` and `ZUC_` are used by no other package.
- `zu_` is `zukomp`'s public namespace and `zuhttp`'s internal one.
- `zux_` is `zuxml`'s.

**Nothing that reads as another library's ABI may be exported.**
- No `mbedtls_*` or `psa_*` name.
- No OpenSSL-ABI name either (`SHA256_Init`, `SHA256_Update`, `AES_encrypt`, `HMAC`, `EVP_*`),
  because `zuhttp` links system `libcrypto` on Linux.
- `test-abi.R` audits the shared object for all of these, the way `zukomp`'s bans zlib names.

**Headers.**
- `inst/include/zucrypt.h` compiles standalone as C99 against only `<stddef.h>` and
  `<stdint.h>`.
- It contains no `R.h`, no `SEXP`, and no upstream type or vocabulary in a declaration. A comment
  may say "PSA"; a declaration may not.
- R-specific resolution lives in `inst/include/zucrypt-r.h`.
- Both rules are enforced twice, with the same comment-stripped check: an `abi.yaml` job compiles
  the header standalone under `-Werror` in C99 and C++, and `test-abi.R` greps the *installed*
  copy.

**Build.**
- `src/Makevars` is portable make only.
- `OBJECTS` is listed explicitly: R compiles only `src/*.c` by itself, and vendored code lives in
  a subdirectory.
- No `$(wildcard)` and no GNU-make conditionals; either one forces
  `SystemRequirements: GNU make`.
- No `-W*` or optimisation overrides (CRAN policy).
- Project code is C99: no C11 atomics, intrinsics, assembly or thread APIs. Vendored sources may
  use whatever upstream requires.

**Errors.**
- C layers return a status enum and never call `Rf_error()` below the outermost `.Call`. R
  constructs the conditions.
- Anything that holds heap state across a possible `longjmp` is owned by an external pointer with
  `R_RegisterCFinalizerEx(..., TRUE)`. Both `Rf_error()` *and* `R_CheckUserInterrupt()` jump past
  every `free()` beneath them.
- On the success path the object is freed eagerly, with the pointer cleared first.
- Condition classes are `c(<specific>, "zucrypt_error", "error", "condition")`.
- The status-to-class map is keyed by C enumerator *name*, fetched from C at runtime, so
  renumbering the enum cannot silently remap a condition.

**Tests.**
- Self-sufficient (inputs built inside each `test_that()`) and self-contained
  (`withr::local_*()`).
- Assertions are on condition classes, never on message text.
- The suite passes under `devtools::test(shuffle = TRUE)` and finishes in under 60 seconds.
- Fixtures are committed with provenance in a `MANIFEST.tsv`, plus a `tools/` generator that
  supports `--check`. Nothing is generated at test time.
- An always-compiled `.Call` harness, the analogue of `zukomp`'s `zu_test_stream()`, drives the
  native layer at caller-chosen chunk sizes. For this package that means the incremental
  hash/HMAC/CBC paths at every split point.
- Consumer fixture packages live under `tools/` (`zukomp`'s `tools/zukomptest` and
  `tools/zukomplink`) and are built only by `consumer.yaml`.

**Vendoring.**
- Third-party code lives under `src/vendor/<source>/` and is never edited in place.
- Patches go in `tools/patches/<source>/NNNN-*.patch`.
- `tools/vendor/manifest.tsv` has the columns
  `source repo tag commit version_string archive archive_sha256 license defines patches`.
  Beside it are `tools/vendor/checksums.sha256` and three scripts:
  - `fetch` (network, maintainer only);
  - `record` (offline);
  - `verify` (offline). It checks that the tree, both manifests, the `Makevars` define set and
    `inst/COPYRIGHTS` all agree.

  These are also the defaults `r-actions`' `vendor.yml` expects.
- Provenance is *reported from the compiled library* (`crypt_info()$vendored`). It is never read
  from the manifest, which is not installed.
- The upstream licence text is installed with the package (§4).

**DESCRIPTION.**
- `Copyright: See inst/COPYRIGHTS and tools/vendor/manifest.tsv.`
- Upstream authors appear as `cph` in `Authors@R`, with a `comment` naming what they hold.
- `Imports:` is limited to base-priority packages (`utils`, for `packageVersion()`).
- Everything test-only goes in `Suggests`, and nothing in `Suggests` is referenced from `R/`.
- Between releases, `main` carries a `.9000` version.

**Definition of done for a stage** (from `zukomp`):
- `document()` and `check()` are clean at 0/0/0, and the shuffled tests are green;
- CI is green on every leg, including the CRAN-like containers;
- new public surface has roxygen docs with runnable examples;
- `tools/vendor/verify` is clean if `src/vendor/` moved.

Revision 3 adds one more condition: **every gate the stage relies on has a log showing that it
exercised its target** (§12).

## 4. Backend and vendoring

**The backend is TF-PSA-Crypto on its 1.1 LTS line, currently 1.1.1.** It is the crypto library
of Mbed TLS 4.1 LTS, which upstream supports until March 2029
([support policy](https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md)).
- In the 4.x architecture, TF-PSA-Crypto *is* the cryptography library. Mbed TLS supplies only
  X.509 and TLS, so no Mbed TLS file is vendored.
  See [stage-1-spike.md](stage-1-spike.md) §1 for the pin and §11 for the rehearsed update
  procedure.
- **Line policy.** Take 1.1.x patch releases promptly. Move to a newer line only when the LTS line
  moves, or when a named consumer needs a feature that exists only there.
- `vendor-upstream.yaml` watches the latest release, whatever its line. Each non-LTS release
  therefore produces an issue that is closed with this policy as its reason, until the watcher
  can be restricted to a tag pattern. That restriction is a follow-up in `r-actions` (#19).

**The configuration** is `src/zuc_crypto_config.h`, which replaces upstream's configuration. It
holds eleven defines, each recorded in the manifest's `defines` column and cross-checked by
`tools/vendor/verify`:
- SHA-1, SHA-256, SHA-384 and SHA-512;
- HMAC and the HMAC key type;
- CBC without padding, and the AES key type;
- the PSA core;
- external RNG;
- `MBEDTLS_PSA_KEY_STORE_DYNAMIC`.

Revision 3 swaps ECB-without-padding for the dynamic key store, so the count stays at eleven.
Nothing else is enabled:
- no public-key cryptography, AEAD or key derivation;
- no X.509 or TLS;
- no persistent key storage.

**Vendoring requirements:**

- **One manifest row**, `tf-psa-crypto`, with release, source URL, checksum, licence, define set
  and patch list, in the §3 layout. `zuhttp`'s eventual TLS spike should pin the *same* row, so
  the two packages track one upstream release and one patch set.
- **Official release archives only.** Use archives that contain the generated files. Installation
  never downloads anything and never generates sources with Python or Perl.
- **`tools/vendor/fetch` re-derives the tree from the archive.**
  - It keeps only what `tools/vendor/keep/tf-psa-crypto.txt` lists. That is a two-column keep
    list rather than the family's `keep_files()` case arm, and it is re-derived by the method in
    [stage-1-spike.md](stage-1-spike.md) §3 whenever the define set changes.
  - The tree is flattened to `inc/` and `lib/`, because upstream's own paths exceed the tarball's
    100-byte limit.
- **Disable features through upstream's configuration.** Never rewrite cryptographic internals.
  Local changes are patches, never edits in place.
- **Preserve and install the licence.**
  - Select the Apache-2.0 option where upstream offers one.
  - Document every included file's licence in `inst/COPYRIGHTS`.
  - Install Apache-2.0's full text as `licenses/tf-psa-crypto-LICENSE`, and point
    `inst/COPYRIGHTS` at that installed path. A binary `zucrypt`, and every consumer that links
    `libzucrypt.a`, redistributes Apache-2.0 object code, and §4(a) of the licence requires the
    text to travel with it (#33).
- **Hide upstream symbols.**
  - The archive objects and the shared object are compiled with hidden visibility
    (`$(C_VISIBILITY)`). `mbedtls_*` and `psa_*` therefore never appear in a dynamic symbol
    table.
  - R loads packages with `RTLD_LOCAL`, and Windows DLLs have per-module namespaces. So two
    independently vendored copies, `zucrypt` inside `zuxlsx.so` and a TLS build inside
    `zuhttp.so`, cannot bind to one another.
- **Keep the feature set and the output identical on every platform.** Hardware acceleration is
  off everywhere (stage-1-spike §6). `crypt_info()` reports that from the compiled library, not
  from R (#36).
- **Ship security updates promptly.** The operating system does not patch code compiled into an
  R package.
  - **An archive consumer gets the fix only when that consumer is reinstalled.**
  - `zuxlsx` should therefore report the `zucrypt` and backend versions it actually linked, as
    `zuxlsx_native()` does for Expat. Detecting a stale link is tracked in
    [pedrobtz/zuxlsx#15](https://github.com/pedrobtz/zuxlsx/issues/15).

**Build tooling is `src/Makevars`, not CMake.** A CMake step at install time would add a
`SystemRequirements` the siblings do not carry. The archive shape also needs objects built with
R's own flags: `$(ALL_CFLAGS)` carries `$(CPICFLAGS)`, which is what lets the archive link into
a consumer's shared object.

**Entropy uses external-RNG mode.** `src/zuc_random.c` selects the operating-system source at
compile time: `rand_s`, `arc4random_buf`, `getrandom` or `/dev/urandom`. It works the way
`zuxml`'s `src/zux_expat_random.c` selects Expat's (stage-1-spike §5). No randomness is exposed
yet (§6).

## 5. Dependency boundaries

| Package | Owns | Does not acquire through `zucrypt` | How it consumes `zucrypt` |
| --- | --- | --- | --- |
| `zucrypt` | Crypto primitives, state and native API | XML, ZIP, Office, sockets, TLS or trust stores | — |
| `zuxlsx` | Workbook interpretation, the Office encryption adapter and the CFB reader | TLS | `LinkingTo` + `configure` + the installed `lib${R_ARCH}/libzucrypt.a`. No `Imports:` (its design §3) |
| `zuxml` | XML parsing, reused for Agile encryption metadata | Cryptographic policy | does not |
| `zukomp` | ZIP entry access and decompression after decryption | Office password handling | does not |
| `zuhttp` | HTTP, sockets, TLS backend selection and certificate trust | Office processing | does not, and plans not to in 0.x. A future Mbed TLS engine would vendor its own build, aligned on the same manifest row (§10) |

The Office adapter may use `zuxml` and `zucrypt`. It must not create a reverse dependency from
either package to `zuxlsx`.

## 6. Algorithm scope

The enabled profile is exactly this:

| Capability | Consumer | Exposure |
| --- | --- | --- |
| SHA-1 | Office agile profiles that declare it | R and C, as an explicit compatibility option |
| SHA-256, SHA-384, SHA-512 | Office agile key derivation; general hashing | R and C |
| HMAC with the supported hashes | Office agile data integrity; general MACs | R and C |
| AES-128/192/256-CBC without padding | Office agile key and payload decryption | Advanced R interface, and C |
| Constant-time comparison of equal-length byte strings | Verifiers and authentication tags | R and C |
| Secure cleanup of native buffers | Keys and intermediate state | Internal |

**Removed before release: AES-ECB** (#29). Its only use was Office Standard encryption, which
`zuxlsx` does not implement (§9). SHA-1 is a compatibility facility, never a default. Its
availability for document handling must not weaken `zuhttp`'s TLS policy.

**Deferred primitives, and what would admit each one.** Every item needs one define and a trim
re-derivation ([stage-1-spike.md](stage-1-spike.md) §3, §11). The table records what makes it
worth that cost, so the question is not re-argued from scratch each time:

| Primitive | Issue | Enters when |
| --- | --- | --- |
| `crypt_random()` over the existing OS entropy source | #9 | A named consumer needs IVs or nonces, or AES-GCM is admitted. It needs its own condition class for entropy failure, and it never touches R's RNG |
| AES-GCM | #10 | A named consumer needs authenticated encryption, and the nonce policy is decided: generated internally with `crypt_random()`, never supplied by the caller |
| PBKDF2, HKDF | #12 | A named consumer needs them. PBKDF2 is not Office's derivation. Shipping it together with GCM and randomness is the password-encryption construction this section rules out, so decide the format question first |
| File and connection hashing | #11 | Not a primitive, so it needs no consumer rule. It is a convenience over the existing incremental path (§7) |

There is no general `encrypt_file(password = ...)`. Such an interface needs a separately
specified authenticated format, a password KDF, a nonce policy and a reliable entropy source.
Argon2 is not in the backend, and supporting it would mean vendoring something else.

## 7. R interface

```r
crypt_info()

crypt_hash(data, algorithm = "sha256")
crypt_hmac(data, key, algorithm = "sha256")
crypt_equal(x, y)

# Advanced interoperability functions; no padding or authentication is added.
crypt_aes_cbc_encrypt(data, key, iv)
crypt_aes_cbc_decrypt(data, key, iv)
```

**These six are stable from v0.1.0 (§8.6).** The names follow the family's short package prefix:
`komp_`, `xml_`, `json_`, `yaml_`, and `zu_` in `zuhttp`.

Contract:

- Binary arguments are raw vectors. A character value is never interpreted as a filename,
  password or byte sequence.
- A scalar algorithm name selects one documented algorithm. There is no partial matching
  (`match.arg()` is not used), and no fallback to another algorithm.
- Hashes and HMACs are returned as raw vectors. Hex formatting is an explicit conversion at the
  call site.
- AES keys are exactly 16, 24 or 32 bytes, CBC IVs exactly 16 bytes, and data a multiple of 16
  bytes.
- CBC returns raw data of the same length and never mutates R inputs. It neither adds nor strips
  PKCS#7 padding.
- Empty hash and HMAC inputs are valid. Empty CBC input produces an empty result, after the
  parameters are validated.
- Equal-length comparison uses a timing-resistant native operation. Unequal lengths return
  `FALSE`; length is not hidden.
- `crypt_info()` follows `komp_info()`. It returns a list with:
  - `version`;
  - `abi_version`;
  - `algorithms` (those enabled in this build);
  - `vendored` (a data frame of `source` and `version`);
  - `build_flags` (`random_backend`, `hardware_acceleration`).

  Every element is read from the compiled library. It never contains keys or internal addresses.

These functions operate on keys the caller supplies. They do not turn a password into a key. CBC
provides confidentiality only, and its documentation must make authentication the caller's
explicit responsibility.

**Later conveniences** follow the same contract. `crypt_hash_file(path, algorithm)` (#11) would:
- chunk through the existing incremental path, checking for interrupts between chunks;
- raise its own condition class for a missing or unreadable file;
- refuse text-mode connections, whose encoding conversion would change the bytes.

## 8. Native interface and R package integration

Two consumer shapes exist in the family. They are not equally supported; §8.6 ranks them.

### 8.1 The public header

`inst/include/zucrypt.h` declares plain C functions, standalone per §3. Its vocabulary:

- **`zuc_status`.**
  - `ZUC_OK = 0`, then the errors: `ZUC_ERR_INVALID_ARGUMENT`, `ZUC_ERR_UNSUPPORTED`,
    `ZUC_ERR_BAD_LENGTH`, `ZUC_ERR_OVERLAP`, `ZUC_ERR_MEMORY`, `ZUC_ERR_BACKEND`,
    `ZUC_ERR_ABI`, `ZUC_ERR_INTERNAL`, and now `ZUC_ERR_NOT_READY = 9`.
  - No negative value is ever returned, so `if (st)` reliably means "not success".
  - `zuc_status_string()` covers every enumerator and never returns `NULL`; a test asserts this.
- **`zuc_alg`**: fixed-width identifiers for SHA-1 and SHA-256/384/512.
  - Values are permanent. An algorithm compiled out keeps its number and reports unavailable.
  - AES has no identifier: the key length selects AES-128/192/256, and CBC is the only mode.
    Removing ECB therefore renumbered nothing.
- **Opaque handles**: `zuc_hash`, `zuc_hmac` and `zuc_aes`. The provider allocates them, and only
  provider functions destroy them.
  - Each `zuc_aes` and `zuc_hmac` holds one volatile key in the dynamic key store. The number of
    live handles is bounded only by memory. Exhaustion is `ZUC_ERR_MEMORY`, and `zucrypt.h`
    says so.
- **Operations**:
  - one-shot and incremental hash and HMAC (`new`, `update`, `finish`, `reset`, `free`);
  - AES key context creation, which validates 16/24/32-byte keys;
  - block-aligned CBC with an explicit, resettable chaining state;
  - constant-time compare, secure zero, and backend information.
- **Versioned structs.** Every options or information struct starts with a `uint32_t
  struct_size`. A `ZUC_*_REQUIRED_SIZE` macro gives the prefix the core actually reads, never
  the full current `sizeof`. Otherwise every appended field would break a consumer built against
  an older header.
- **No R.** Functions return status codes. They never raise R errors, allocate R objects or call
  back into R.
- **Overlap.** Exact in-place operation is allowed where the backend supports it, and rejected
  with `ZUC_ERR_OVERLAP` otherwise. Partial overlap is always rejected.
- **CBC state.** For streaming, the mutable chaining state is documented separately from the R
  wrapper's immutable input IV. Office callers reset it at the segment boundaries the file format
  requires.
- **Initialisation.** It is explicit and reference-counted (`zuc_init()`/`zuc_shutdown()`). Any
  call outside an initialised window returns `ZUC_ERR_NOT_READY`.

### 8.2 Shape one: the registered function table (experimental)

**What the header provides.**
- `inst/include/zucrypt-r.h` includes `zucrypt.h`, then adds the one thing that must know about
  R: how to reach the table.
- It defines `zucrypt_api_v1`: a leading `uint32_t abi_version` and `uint32_t struct_size`, then
  function pointers that mirror §8.1.
- It defines `static inline const zucrypt_api_v1 *zucrypt_api(void)`, which:
  - resolves `R_GetCCallable("zucrypt", "zucrypt_get_api")` once;
  - goes through a union rather than a function-pointer cast, because
    `-Wcast-function-type-mismatch` under `-Werror` is a build failure *for the consumer*;
  - passes `ZUCRYPT_ABI_VERSION`, and caches the result.

  It is `static inline`, not plain `static`: a plain `static` function defined in a header is an
  unused-function error in every consumer file that includes the header without calling it.

**What a missing `zucrypt` does.**
- `R_GetCCallable()` raises an R error when the callable is not registered. It does not return
  `NULL`. That error longjmps out of the consumer's C code.
- `zucrypt_api()` therefore returns `NULL` only for a version mismatch.
- A consumer should resolve the table before it acquires anything that a longjmp would strand.
  The header, `?zucrypt_c_api` and the README say exactly this.

**Versioning.**
- `zucrypt_get_api(requested)` returns `NULL` for an unsupported major version.
- There are two discriminators, as in `zuxml.h`:
  - `struct_size` versions the table, whose fields are only ever appended.
  - The registered callable's *name* versions every other type in the header. `struct_size`
    cannot see a layout change in an options struct, and R does not rebuild `LinkingTo`
    dependents on upgrade. Any such change renames the callable.
- `ZUCRYPT_API_HAS(api, field)` tests whether `api->struct_size` covers a field before the field
  is called.

**Consumer requirements.**
- The consumer needs `Imports: zucrypt` and `LinkingTo: zucrypt`, and a real `importFrom()` in
  its `NAMESPACE`. `Imports:` alone does not load the namespace.
- Resolution is lazy, on first use.
- The accessor is registered from `R_init_zucrypt` after the backend is initialised.

**The table is experimental** (§8.6). No package uses it (#14), and the fixture
`tools/zucrypttest` calls every entry on every push. That is why it survives: it proves itself
at little cost, and a future consumer finds it working.

### 8.3 Shape two: the static archive (primary)

**How it is built and installed.**
- `src/Makevars` builds `libzucrypt.a` beside the shared object, with `all: $(SHLIB) libzucrypt.a`
  as the first target.
- `src/install.libs.R` installs the archive to `lib${R_ARCH}/`, as `zukomp` does (#33). Every
  copy is checked, and a failed copy stops the install. On every current platform `R_ARCH` is
  empty or a single architecture.
- `install.libs.R` also installs the shared object itself, because defining that file stops R
  doing it.

**What the archive contains.**
- The R-free core only: the adapter objects and the vendored crypto objects, compiled with
  `$(ALL_CFLAGS)` so they are position-independent.
- **No R glue.** `test-linking.R` greps the archive for `R_init_`, `zucrypt_` and any R symbol,
  and expects none.
- **No upstream header is installed.** This is the departure from `zukomp` and `zuxml`, whose
  archives are raw miniz and raw Expat with `miniz.h`/`expat.h` installed beside them. A consumer
  of those must reproduce the provider's define set, or its declarations describe a different
  library. PSA headers are worse, because sizes and key-identifier types are generated from the
  configuration. A consumer of `libzucrypt.a` therefore sees `zucrypt.h` only, and there is no
  define for it to match.

**The consumer recipe is `zuxlsx`'s.**
- `LinkingTo: zucrypt` supplies the header.
- A `configure`/`configure.win` resolves `system.file("lib", .Platform$r_arch, package =
  "zucrypt")`, then `lib/`, and substitutes the result into `src/Makevars.in`. The entry is a
  **single-quoted** `PKG_LIBS` entry: otherwise a library path containing a space, which is the
  norm on Windows, reaches the linker as two arguments.
- When the archive is absent, the failure message names `pak::pak("pedrobtz/zucrypt")`.
- No `Imports:`, and no GNU make. `zucrypt` itself needs no `configure`.

**What this shape has that the table does not:**

- **The consumer carries its own backend.** Its shared object contains a private copy of the
  backend, with its own key store. Symbol hiding (§4) keeps that copy private, and `tools/zucryptlink` proves it
  (§8.5).
- **Upgrades need a rebuild.** A `zucrypt` upgrade does nothing to an installed consumer until
  the consumer is rebuilt. The consumer should report the versions it actually linked by calling
  `zuc_get_info()`, not by reading a macro.
- **The consumer owns initialisation.** `zuc_init()`/`zuc_shutdown()` are in the archive, so the
  consumer decides when to call them: in its `R_init_`, or lazily on first use.

### 8.4 Threads

API resolution and backend initialisation happen on the R main thread, and every call is
main-thread only.

This is stricter than `zukomp` §19, which allows distinct streams on distinct threads with one
object used by one thread at a time. It is stated so that a consumer designed against `zukomp`'s
promise does not assume it here. PSA's global key store needs upstream's threading option, which
needs pthreads.

- Relax the rule only after initialisation, locking and shutdown are verified, and only for a
  consumer that asks.
- R wrappers clean up on both errors and interrupts.
- Never tear down global crypto state while consumer contexts remain alive.

### 8.5 Enforced by tests

**`test-abi.R`, against the shared object:**
- no `mbedtls_`, `psa_` or OpenSSL-ABI name is exported;
- the installed header leaks no upstream or R vocabulary, and carries its guard and C++ wrapper;
- the backend is compiled in at the pinned version.

**`test-linking.R`, against the installed package** (skipped under `load_all()`):
- the archive and both headers exist in the installed package;
- the archive defines every `zuc_*` entry point a consumer needs, and no R symbol.

**Two fixture packages** under `tools/`, built only by `consumer.yaml` on Linux, macOS and
Windows:

- `tools/zucrypttest` covers shape one. It uses `Imports:` + `LinkingTo:` + a real
  `importFrom()`, and calls every table entry. A pointer that was never assigned looks the same
  as a working one until something calls it.
- `tools/zucryptlink` covers shape two, and replaces `tools/check-linking.sh`'s plain `main()`
  (#32). It is `LinkingTo`-only, with `configure`, `configure.win` and `Makevars.in` taken from
  `zuxlsx`. It:
  - links `libzucrypt.a` into its own shared object;
  - asserts that `nm -D` on that object shows no `psa_`, `mbedtls_` or `zuc_` export;
  - runs the derivation rehearsal (§12) in the same R process as `zucrypt.so`, so two backend
    copies and two key stores coexist;
  - runs again with `zucrypt` removed from the library path, using `zukomp`'s
    `R_LIBS_USER='-'` step, so that it proves linking rather than loading.

  zukomp's CLAUDE.md records why a plain `main()` was retired: it "exercised none of what
  actually breaks".

### 8.6 Stability

| Surface | v0.1.0 (GitHub tag) | v0.2.0 (CRAN) | Changes allowed |
| --- | --- | --- | --- |
| The six `crypt_*` functions and their condition classes | stable | stable | Additions only; nothing removed or given a new meaning |
| `zucrypt.h`, `libzucrypt.a`, install path | **provisional** | **frozen as ABI 1** | Before the freeze: any change, recorded in `NEWS.md` and applied to `zuxlsx` together. After: additions only |
| `zucrypt-r.h`, the registered table | **experimental** | experimental | Any change, recorded in `NEWS.md`. Leaves the tier when a non-fixture package uses it |

**The freeze** is the event that moves the archive to "frozen". It happens when all of the
following hold:
- `zuxlsx`'s agile decryption C path has merged, linking `libzucrypt.a`;
- `tools/zucryptlink` is green on three operating systems;
- `zuxlsx` builds against `zucrypt@main` in this repository's CI.

**What "frozen" means.** Within major version 1:
- functions and table fields may be added;
- nothing is removed, reordered or given a new meaning;
- enumerator values are permanent;
- a `ZUC_*_REQUIRED_SIZE` never grows.

A layout change to a type that `struct_size` cannot see renames the registered callable, so an
old consumer fails at `R_GetCCallable()` instead of reading a structure that has moved.

**Where the tier is published.** `?zucrypt_c_api`, the README and `NEWS.md` state each surface's
tier. The README's lifecycle badge says "experimental" until the freeze and "stable" after it.

## 9. Excel integration contract

The user-facing goal is a call such as:

```r
zuxlsx::read_xlsx("risk.xlsx", password = password)
```

This is a target integration in `zuxlsx`
([zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22)), not a guarantee made here. `zucrypt`
does not export `office_decrypt()` or `office_info()`.

**How `zuxlsx` uses the archive.** `zuxlsx` links `zucrypt` as the §8.3 archive and calls `zuc_*`
directly. It opens the decrypted package with `xlsxioread_open_memory()`, so no plaintext
temporary file is needed in the bounded case. `zuxlsx_native()` should gain a `zucrypt` row
reporting the linked adapter and backend versions.

**What agile decryption needs from this package**, all of which exists:
- the incremental hash with `reset`, for the spin loop over one reused context;
- HMAC, for data integrity;
- AES-CBC with an explicit chaining state, for the key blobs and for the 4096-byte segments,
  each with its own IV.

The spin loop must run in C. At 100,000 iterations it took 0.74 s through R's `.Call` and takes
a few milliseconds natively.

**The Office adapter's sequence:**

1. Inspect file signatures rather than trusting the extension.
2. Read the outer OLE Compound File Binary container.
3. Locate and validate `EncryptionInfo` and `EncryptedPackage`. Accept only the agile version
   prefix, and refuse anything else by name.
4. Parse the declared profile, and reject unsupported combinations.
5. Convert the password to UTF-16LE without normalisation or truncation, and reject invalid input
   explicitly.
6. Derive keys and verify the password for that profile.
7. Validate payload integrity before exposing plaintext to the workbook reader.
8. Pass the recovered package bytes to ZIP and workbook processing.

**Who owns what.** This package provides the primitives. The Office adapter owns:
- iteration counts, salts and block-key constants;
- key expansion and password verifiers;
- segment IV derivation and payload-length rules.

**Out of scope.** Office Standard encryption (AES-128-ECB with SHA-1) is out of scope in
`zuxlsx` (§21c), and so ECB is out of scope here. The same holds for:
- worksheet protection, and passwords to modify a workbook;
- legacy `.xls` RC4/XOR encryption;
- rights-managed documents and certificate-based decryption;
- writing Office encryption.

Decrypting `.xlsb`, `.docx` or `.pptx` containers would not mean that `zuxlsx` can interpret
their contents.

**The authorities.** Microsoft's MS-OFFCRYPTO specification governs the implementation.
msoffcrypto-tool's
[agile implementation](https://msoffcrypto-tool.readthedocs.io/en/latest/_modules/msoffcrypto/method/ecma376_agile.html)
is the independent oracle.

**Bounds.**
- Start with a bounded in-memory decrypted package and an explicit maximum output size.
- The CFB reader validates sector bounds, allocation-chain cycles, mini-stream handling, stream
  sizes and integer arithmetic.
- Iteration counts, metadata size and output size are limited before any expensive work.
- ZIP decompression limits still apply after decryption.

## 10. Relationship with zuhttp

`zuhttp` keeps its native OS TLS backends. It adds Mbed TLS only as a separately tested backend,
and only where Mbed TLS solves a concrete portability problem. Its R-15 is the risk that Apple
removes Secure Transport, and pedrobtz/zuhttp#16 is the corresponding spike. Backend selection
must never happen as an automatic retry after certificate verification fails.

- **What `zuhttp` shares with this package is provenance, not code.** It shares the
  `tf-psa-crypto` manifest row, the patch set and the update tooling, so one upstream advisory is
  one change in each repository. Each package compiles its own private copy. This duplicates
  some crypto code, but it avoids exposing a broad upstream ABI too early.
- **The small `zucrypt` C interface cannot host a TLS engine.** TLS needs more operations, more
  initialisation and a compatible configuration. Do not describe the architecture as a single
  shared compiled crypto provider.
- **A shared backend package waits for measurement.** If duplication becomes material, evaluate a
  dedicated backend package with a deliberately designed interface and one initialisation owner.
  Measure source size, binary size, update burden and loading behaviour first; the Stage 1 numbers
  in [stage-1-spike.md](stage-1-spike.md) are the baseline. Keep upstream symbols private in
  either design.

`zuhttp` owns CA discovery, trust configuration, hostname verification, client certificates,
protocol policy, sockets and network errors.

## 11. Errors and resource handling

R conditions have the class `c(<specific>, "zucrypt_error", "error", "condition")`. A
`zucrypt_abort()` helper constructs them in R from a status the C layer returned. The specific
classes, keyed by C enumerator name, are:

| `zuc_status` | Condition class |
| --- | --- |
| `ZUC_ERR_INVALID_ARGUMENT` | `zucrypt_invalid_argument` |
| `ZUC_ERR_UNSUPPORTED` | `zucrypt_unsupported_algorithm` |
| `ZUC_ERR_BAD_LENGTH` | `zucrypt_bad_length` |
| `ZUC_ERR_MEMORY` | `zucrypt_memory_error` |
| `ZUC_ERR_BACKEND` | `zucrypt_backend_error` |
| `ZUC_ERR_ABI` | `zucrypt_abi_mismatch` |
| `ZUC_ERR_INTERNAL` | `zucrypt_internal_error` |
| `ZUC_ERR_NOT_READY` | `zucrypt_internal_error`. R initialises the backend in `R_init_zucrypt`, so from R this can only be a bug |

**How the map and the conditions behave.**
- The names are fetched from C with `.Call(zucrypt_status_codes)`, so renumbering cannot remap a
  condition.
- Every condition carries `algorithm` and `native_status` fields. AES conditions set
  `algorithm` to the cipher, for example `"aes-256-cbc"`; today they leave it `NA` (#36).
- Messages are one line and may be reworded; tests assert on class.
- Keys, passwords, IV-derived secret state and plaintext are never attached to a condition.

**Office errors belong to the Office adapter** (`zuxlsx_*`): incorrect passwords, malformed
containers and integrity failures. Where the format cannot tell causes apart reliably, report an
authentication failure without inventing a precise diagnosis.

**Rules in C.**
- Validate lengths and arithmetic before allocating, through checked helpers.
- Destroy partial contexts after any failed initialisation.
- Wipe key buffers and backend state with the cleanup primitives.
- Own a context that must survive `R_CheckUserInterrupt()` with an external pointer that has a
  finalizer, for the whole duration. Never use a bare local: `zukomp` leaked one stream per
  interrupted decompression before it learned this.
- Keep one rule in view: a `return` that allocates must never follow `UNPROTECT()`. #18 fixed
  exactly that, after rchk, gctorture and the sanitizers had all passed it. A lint in
  `tools/check-layering.sh` now guards against it (#35).
- R may retain copies of raw vectors and strings, so do not promise complete erasure from
  process memory, swap or crash dumps.

## 12. Testing and release gates

| Layer | Required evidence |
| --- | --- |
| Primitives | Published known-answer vectors for every enabled hash, HMAC and key size, committed with provenance in `MANIFEST.tsv` and recomputed against `openssl` by `tools/make-kat.R --check`. Vectors cover **multi-block** inputs (FIPS 180-2 SHA-256 B.2 and SHA-512 C.2, "one million a") and **keys longer than the block** (RFC 4231 cases 6 and 7) (#34) |
| Independent comparison | Inputs of 1,000 B, 64 KiB + 1 and 4 MiB compared with `openssl::sha*()` and `openssl::sha*(key =)`, under `skip_if_not_installed("openssl")`. A self round trip never counts |
| Stateful operations | One-shot versus incremental equivalence at every split point, through the always-compiled `zucrypt_test_*` harness. Reset behaviour and boundary lengths |
| Resource handling | A test-only live-context counter in the adapter (the pattern of `zukomp`'s `zu_int_outbuf_live_count()`). An interrupt or R error raised mid-loop, through `setTimeLimit()` or a harness entry point, leaves the counter at 0 after `gc()`. Breaking the finalizer once must make the test fail (#35) |
| R interface | Raw-type validation, key/IV lengths, empty input, input immutability, and conditions asserted by class |
| C interface | `tools/zucrypttest` and `tools/zucryptlink` on three OSes (§8.5). ABI rejection. 64 live handles of each kind (#30) |
| Derivation rehearsal | `H_n = hash(int32le(n-1) ‖ H_{n-1})` through one reused context, compared with an R loop *and* with one known-answer vector. The vector is the output for the parameters of `zuxlsx`'s committed agile fixture, with msoffcrypto-tool as oracle, stored as input and output bytes (#34). It is test data, not Office support: the fixture holds no block keys and no Office constants |
| Installed layout | `test-abi.R` and `test-linking.R`, as in §8.5 |
| Backend isolation | Loaded beside `openssl` and beside an archive consumer, in both orders, without symbol interference |
| Platforms | Windows, macOS and Linux runners, the CRAN-like containers, and the weekly i386, musl and aarch64 legs. **These legs run the test suite, and fail on a WARNING** (#31) |
| Allocation failure | The weekly sweep injects failures inside the `zuc_*` allocation window, and its log shows how many it injected there. Every one must yield `ZUC_ERR_MEMORY` or R's own allocation error, and never a wrong answer (#31) |
| Office integration (`zuxlsx`) | Fixtures from Excel and msoffcrypto-tool with recorded provenance. Wrong password, altered ciphertext or HMAC, unsupported profiles, Unicode passwords, truncation, malformed CFB chains |

**A gate counts only when it has run against its target.** A green job whose log shows zero
tests, or zero injected failures in the code it is named for, is recorded as not run. A stage
that adds a scheduled job closes only after that job's first real run, dispatched by hand if
necessary.

**Round trips prove nothing on their own.** An encrypt/decrypt round trip is insufficient,
because one implementation can contain matching mistakes. Tests run offline from synthetic
fixtures with known passwords and redistribution permission.

## 13. Implementation sequence

1. **Backend spike.** Done: stage-1-spike.md.
2. **Core package.** Done: roadmap Stages 2–4.
3. **Settle and prove the core** (roadmap Stages 7–9, v0.1.0): revision 3's surface changes,
   gates that execute, independent vectors, and documentation that matches the code.
4. **First consumer and freeze** (roadmap Stages 10–12, v0.2.0 on CRAN):
   - the archive fixture package;
   - `zuxlsx`'s agile C path against the archive;
   - the ABI 1 freeze.

   The family's first end-to-end success criterion is reading a password-encrypted workbook
   without Java, Python or a system OpenSSL. It is met in `zuxlsx` 0.2.0, which follows
   `zucrypt` 0.2.0 onto CRAN.
5. **HTTP evaluation**, owned by `zuhttp`: its Mbed TLS spike, on the shared manifest row, with
   native OS TLS retained.
6. **Measured expansion**: the §6 deferred primitives and a shared compiled backend. Each is
   admitted only on its own entry criterion.

Office Standard encryption, step 4 in revision 2, is dropped (§9).

## Position in the `zu*` family (reviewed 2026-09-22)

This table is identical in all five repositories' design documents. Change it in all five
together, or not at all.

| | zukomp | zuxml | zucrypt | zuxlsx | zuhttp |
|---|---|---|---|---|---|
| Role | provider | provider | provider | consumer | standalone |
| R prefix | `komp_` | `xml_` | `crypt_` | `read_xlsx()`, `xlsx_` | `zu_` |
| Info function | `komp_info()` | `zuxml_info()` | `crypt_info()` | `zuxlsx_native()` ([zuxlsx#46](https://github.com/pedrobtz/zuxlsx/issues/46)) | `zu_info()` |
| Root condition class | `zukomp_error` | `zuxml_error` | `zucrypt_error` | `zuxlsx_error` | `zu_error` ([zuhttp#19](https://github.com/pedrobtz/zuhttp/issues/19)) |
| Public C prefix | `zu_` / `ZU_` | `zux_` / `ZUX_` | `zuc_` / `ZUC_` | none | none — but the internal C code uses `zu_` and collides with `zukomp.h` ([zuhttp#15](https://github.com/pedrobtz/zuhttp/issues/15)) |
| Registered table | `zukomp_get_api(version)` via `zukomp-r.h` | `zuxml_api_v2` via `ZUXML_DEFINE_API_GET` in `zuxml.h` ([zuxml#36](https://github.com/pedrobtz/zuxml/issues/36)) | `zucrypt_get_api(version)` via `zucrypt-r.h` | — | — |
| Table consumers today | none (fixture `tools/zukomptest`) | none (no fixture) | none (fixture `tests/consumer/zucrypttest`) | — | — |
| Static archive | `lib${R_ARCH}/libzukomp.a` + `miniz.h` | `lib/libzuxml.a` + `expat.h`, `expat_external.h` | `lib/libzucrypt.a` + `zucrypt.h` | — | — |
| Archive consumers today | zuxlsx (miniz ZIP reader only); fixture `tools/zukomplink` | zuxlsx (xlsxio); fixture `tools/zuxmltest` | none; zuxlsx 0.2.0 agile decryption ([zuxlsx#22](https://github.com/pedrobtz/zuxlsx/issues/22)); no fixture package ([zucrypt#32](https://github.com/pedrobtz/zucrypt/issues/32)) | — | — |
| Upstream licence installed | `licenses/miniz-LICENSE` | no ([zuxml#42](https://github.com/pedrobtz/zuxml/issues/42)) | no ([zucrypt#33](https://github.com/pedrobtz/zucrypt/issues/33)) | Expat's and miniz's in `inst/licenses/`; xlsxio's not ([zuxlsx#62](https://github.com/pedrobtz/zuxlsx/issues/62)) | no: vendored picohttpparser and uriparser ([zuhttp#52](https://github.com/pedrobtz/zuhttp/issues/52)); zlib and TLS are system libraries |
| Symbols hidden (`$(C_VISIBILITY)`) | no ([zukomp#34](https://github.com/pedrobtz/zukomp/issues/34)) | no ([zuxml#39](https://github.com/pedrobtz/zuxml/issues/39)) | yes, audited | no | no ([zuhttp#15](https://github.com/pedrobtz/zuhttp/issues/15)) |
| r-actions pin | commit, v1.7.0 | mostly floating `@v1` ([zuxml#39](https://github.com/pedrobtz/zuxml/issues/39)) | commit, v1.9.0 | not used ([zuxlsx#44](https://github.com/pedrobtz/zuxlsx/issues/44)) | coverage only, `@v1` ([zuhttp#18](https://github.com/pedrobtz/zuhttp/issues/18)) |
| `Depends: R` | 4.0 | 4.1 | 4.1 | 4.1 | 3.5 |

*zucrypt-only note, 2026-09-26: four of the table's `zucrypt` cells are stale since Stages 7 and
10 (#45, #49). The table is left as it stands in the other four repositories, per the rule
above, until the next five-repository change. The corrected cells:*
- *Table consumers today: the fixture is `tools/zucrypttest`.*
- *Static archive: `lib${R_ARCH}/libzucrypt.a` + `zucrypt.h`.*
- *Archive consumers today: the fixture is `tools/zucryptlink`, which closed zucrypt#32.*
- *Upstream licence installed: `licenses/tf-psa-crypto-LICENSE`, which closed zucrypt#33.*

**Relationships, as decided rather than as hoped:**

- **zuhttp consumes no sibling in 0.x.** Compression is system zlib (zuhttp D-7, accepted
  2026-09-07). Pin digests come from the TLS backend: OpenSSL computes them today, and
  macOS and Windows refuse pins until SubjectPublicKeyInfo extraction lands
  ([zuhttp#4](https://github.com/pedrobtz/zuhttp/issues/4), [zuhttp#12](https://github.com/pedrobtz/zuhttp/issues/12)). zuxml could at most
  be a `Suggests:` for a future `zu_resp_xml()`. So zukomp's criterion 11 is deferred beyond 0.1.0
  ([zukomp#32](https://github.com/pedrobtz/zukomp/issues/32)), and zucrypt's hope of a
  table-mode consumer in zuhttp ([zucrypt#14](https://github.com/pedrobtz/zucrypt/issues/14))
  has no taker today.
- **zuxlsx is the only real consumer in the family**, and it consumes archives only: zuxml's
  Expat and zukomp's miniz ZIP reader now, and zucrypt's primitives for agile decryption in
  0.2.0. None of zukomp's codec registry, stream driver or `max_output`/`max_ratio` limits
  reaches zuxlsx. Standard (ECB) encryption is out of scope there, so zucrypt's ECB has no
  consumer ([zucrypt#29](https://github.com/pedrobtz/zucrypt/issues/29)).
- **No sibling uses any registered table.** All three tables are proven only by fixtures (or,
  for zuxml, not at all). That is an argument for keeping each table small and marked as the
  part most likely to change before a first consumer exists.
- **An archive fix reaches a consumer only when the consumer is rebuilt.** A security bump
  in Expat, miniz or TF-PSA-Crypto therefore means re-releasing zuxlsx too
  ([zuxlsx#15](https://github.com/pedrobtz/zuxlsx/issues/15)).

**Convergence targets** (each tracked where the change has to happen):

- Archives install under `lib${R_ARCH}`, with the upstream licence under `licenses/` and every
  `file.copy()` checked, as zukomp does ([zuxml#42](https://github.com/pedrobtz/zuxml/issues/42),
  [zucrypt#33](https://github.com/pedrobtz/zucrypt/issues/33)).
- Table resolvers follow `zukomp-r.h`: a pure-C99 `<pkg>.h` with an R-only `<pkg>-r.h`, a
  union cast of `DL_FUNC`, lazy resolution, and NULL on a version mismatch.
- Only `R_init_<pkg>` is exported from each shared object.
- Each consumer shape has one fixture package under `tools/` that runs on all three OSes.
  A plain `main()` does not count ([zucrypt#32](https://github.com/pedrobtz/zucrypt/issues/32)).
- Providers that zuxlsx tracks at `@main` build zuxlsx in CI
  ([zukomp#35](https://github.com/pedrobtz/zukomp/issues/35), [zuxml#39](https://github.com/pedrobtz/zuxml/issues/39)).
- `main` carries a `.9000` development version between releases, so a consumer can test a
  version instead of probing for files.
- **CRAN order:** zuxml and zukomp first, then zuxlsx 0.1.0. zucrypt must reach CRAN before
  zuxlsx 0.2.0 (decryption). zuhttp is independent.

## 14. Decisions left open

- **Whether the table leaves the experimental tier or leaves the package.** This is decided by
  the first non-fixture consumer, or by the lack of one at 1.0.
- **Whether ECB returns.** Only a named consumer can bring it back, and it would return as an
  addition.
- **Whether a shared compiled backend with `zuhttp` is worth its coupling.** This is measured
  after `zuhttp`'s Mbed TLS spike (§10).
- **When calls may leave the main thread.** Only when a consumer asks, and only after locking and
  shutdown are verified (§8.4).
- **The deferred primitives**, each on its own entry criterion (§6).
- **In `zuxlsx`:** default Office resource limits, and CFB parser reuse versus a narrow
  implementation.

**Resolved, and where:**
- the release pair and configuration (§4, stage-1-spike);
- build tooling (§4) and entropy (§4);
- the byte hand-off to xlsxio (§9);
- the consumer linkage model and its stability tiers (§8);
- ECB (§6);
- the key store (§8.1);
- the upstream line (§4);
- CRAN timing (§13).

These choices do not move the boundary. `zucrypt` owns reusable cryptography, document readers
own document formats, and `zuhttp` owns TLS and trust.
