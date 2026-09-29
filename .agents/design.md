# zucrypt: design

Status: revision 4, adopted 2026-09-29. §3–§8 and §11–§12 describe the package on `main`;
§6, §7.1 and §10 describe where revision 4 takes it. [roadmap.md](roadmap.md) Stages 7–10
have implemented revision 3's decisions, all except the two tied to the first consumer: the
ABI 1 freeze (§8.6, Stage 11) and CRAN (Stage 12), both in v0.1.0, the first CRAN release.
Stages 13–17 implement revision 4. §9,
and §13 steps 3–5, are plans owned by `zuxlsx` and `zuhttp`.
Date: 2026-09-19. Revised 2026-09-20 against the `zu*` packages as shipped; reviewed
2026-09-22 against the implementation (#37); revision 3 on 2026-09-25; implementation
status updated 2026-09-26; revision 4 on 2026-09-29.
Initial application: cryptographic support for password-encrypted Excel input.
Goal from revision 4: a no-system-library alternative to the `openssl` package.
Related packages: `zuxlsx`, `zukomp`, `zuxml`, and `zuhttp`.

## Revision 4 (2026-09-29)

Revision 3 planned a package with one consumer, `zuxlsx`, and a rule that no primitive enters
without a named consumer. The 2026-09-28 review of that plan, against the sibling packages as
they stand, found that the rule described `zukomp` and `zuxml` as well: every provider in the
family has one real consumer and `zuhttp` as a hoped-for second, so the rule did not
distinguish a package worth keeping from one worth merging into `zuxlsx`. What does
distinguish `zuxml` and `zukomp` is that each is useful on its own. This revision gives
`zucrypt` the same property, with a target that already exists.

1. **The goal is a no-system-library alternative to the `openssl` R package.** (§1, §2)
   - `openssl` needs system libssl and `sodium` needs libsodium on Linux. Self-contained
     cryptography already exists on CRAN (`rmonocypher`; `digest`'s `hmac()` and `AES()`), so
     the pitch is not uniqueness. It is the combination: standard algorithms that
     interoperate, familiar R calls, a bundled and maintained backend, and a C interface.
   - The audience is package authors who need a few cryptographic operations and want fewer
     installation requirements: Linux source installs, restricted build environments, compiled
     packages. Windows and macOS users installing `openssl` as a binary gain little.
   - `zuxlsx` stays the archive consumer, unchanged. Nothing here moves the archive or its
     freeze.
2. **The admission rule replaces the named-consumer rule.** (§2, §6)
   A primitive enters when it has: a standard with a number; a published vector set with
   provenance; an oracle outside this package; a composition contract stating what it does
   not do; and a demonstrated workflow benefit that justifies its maintenance (#56). The
   consumer rule is withdrawn; #9, #10 and #12 already satisfy the new one.
3. **An openssl-shaped layer, under the `crypt_` prefix.** (§7.1)
   - Each mirrored function is `crypt_` plus `openssl`'s name, with `openssl`'s arguments,
     order, dispatch and return types: `crypt_sha256(x, key = NULL)`, `crypt_rand_bytes(n)`,
     `crypt_base64_encode(x)`. For the functions the layer covers, and apart from its
     documented differences, migration is a prefix change; the promise is documented
     compatibility for selected operations, not universal substitution (#56).
   - Unprefixed names, and `zu_`, are rejected: `zu_` is `zukomp`'s C namespace and `zuhttp`'s
     R prefix, and the family has one R prefix per package.
   - The gate: every mirrored function is byte-identical to `openssl` on the same inputs, or
     is listed as a documented difference in the migration article. A function that is in
     neither list fails the suite.
4. **Raw-only stays for the core; the mirrored layer types as `openssl` does.** (§7)
   `crypt_hash()`, `crypt_hmac()` and the CBC pair keep the raw-only rule. The mirrored layer
   accepts character (hashed as UTF-8, returned as a hex string of class `hash`) and
   connections, because that is what a caller moving from `openssl` has written. New functions
   with no `openssl` counterpart follow the core rule.
5. **`zuc_alg` gets ranges before the freeze.** (§8.1, roadmap Stage 11)
   Enumerator values are permanent from ABI 1, so digests, MACs, ciphers, KDFs, key families
   and signatures each get a reserved range now, not when the first of each arrives.
6. **The table keeps its tier, and the option to remove it is withdrawn.** (§8.2, §14)
   A package that imports `zucrypt` for its R functions is exactly the kind that can carry
   `Imports:` + `LinkingTo:`, so the table's audience now exists. It stays experimental until
   one uses it.
7. **`zuhttp`'s route is a TLS engine in this package, never in `libzucrypt.a`.** (§10)
   `zuhttp`'s D-63 (2026-09-26) rejects a private Mbed TLS copy and names `zucrypt` as the
   route, while §10 said the opposite. The two are reconciled: a TLS client engine, if taken,
   is compiled into `zucrypt`'s shared object from the Stage 17 manifest row and published
   through a separate registered table that `zuhttp` resolves at run time from `Suggests:`.
   The archive never contains it. (First written as a fourth provider package; changed the
   same day, see the amendments below.)
8. **The boundary is restated.** (§5)
   Never sockets, trust stores or the user's environment: no `download_ssl_cert()`,
   `ca_bundle()`, `my_key()` or `askpass()` equivalents. Certificate *data* work is in scope
   (§6, tranche 5); fetching one is `zuhttp`'s.
9. **Two facts about the backend, checked against the 1.1.1 archive.** (§4, §6)
   - PK, PEM, ASN.1, OID and Base64 live in TF-PSA-Crypto (`extras/`, `utilities/`), so key
     I/O needs no second manifest row. X.509 does: certificates need Mbed TLS proper.
   - There is no EdDSA. X25519 exists (ECDH over Curve25519); Ed25519 does not. That is the
     first documented gap against `openssl`, and it is recorded rather than worked around.
10. **Release order: v0.1.0 is the first CRAN release, and carries the freeze.** (§8.6, §13)
    This supersedes revision 3's item 10 (a GitHub-only v0.1.0, CRAN at v0.2.0), decided
    2026-09-29. `zuxlsx` 0.1.0 ships password-protected workbooks and links zucrypt 0.1.0's
    archive, so the archive freezes there. It freezes on `zuxlsx`'s decryption core in C
    (zuxlsx#22 step 3), which exercises every archive call `zuxlsx` makes, rather than on all
    of zuxlsx#22, whose CFB reader and parsing never call zucrypt. Every later release is
    additions only, one per tranche, numbered from 0.2.0. Tranches 1 and 2 are the plan;
    tranches 3–5 are candidates, each decided afresh against the fifth admission criterion
    when the one before it has shipped (#56).

**Amended 2026-09-29 by the review in #56**, before anything was merged:
- The fifth admission criterion (item 2), and tranches 3–5 made conditional (item 10).
- **Compatibility is subordinate to the security contract** (§7.1). `openssl` 2.3.4's
  `aes_gcm_encrypt()` returns no tag and its `aes_gcm_decrypt()` returns tampered plaintext
  without error; mirroring that would ship unauthenticated "AEAD". Where `openssl` falls short
  of a primitive's standard contract, the standard wins and the difference is documented.
- **The CBC pair is renamed before v0.1.0** to `crypt_aes_cbc_encrypt_nopad()` and
  `crypt_aes_cbc_decrypt_nopad()` (§7, §7.1). Under the old names a caller migrating
  `openssl::aes_cbc_decrypt()` by prefix would silently get the PKCS#7 padding back in the
  plaintext. Nothing calls the R pair outside this repository, and nothing is tagged, so the
  rename is free now and never again. The ordinary names go to the openssl-shaped pair.
- The comparison with other packages (item 1, §1) no longer claims uniqueness, and the survey
  behind the tranche order is reported as detected usage, not migrations (roadmap Stage 13).

**Amended again on 2026-09-29, by maintainer decision:**
- v0.1.0 is the first CRAN release and carries the freeze (item 10).
- The `zuhttp` TLS engine lives in this package, not in a fourth one (item 7, §5, §10;
  roadmap Stage 18, a candidate). The boundary moves by exactly that much: TLS *sessions* over
  caller-supplied I/O enter; sockets, proxies, trust stores and trust policy stay out.

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

`zucrypt` is cryptography for R with no system library: a vendored, pinned backend from the
Mbed TLS ecosystem, a versioned C interface, and an R surface shaped after the `openssl`
package so that a caller can move from one to the other by changing a prefix. It needs no
installed OpenSSL, Java or Python at install or run time.

**Three audiences, in the order they arrived:**

- **`zuxlsx`**, reading password-encrypted `.xlsx` files (agile encryption only, `zuxlsx`
  §21c). It links the static archive (§8.3). This is the first consumer and the one the ABI
  freeze waits for.
- **Packages and users of `openssl`** who need a build that does not depend on system libssl:
  a package importing `openssl` for `sha256()`, `rand_bytes()` and Base64; a user on a machine
  where system OpenSSL is absent, old or unversioned. For them the product is the `crypt_`
  layer of §7.1 and the migration article.
- **`zuhttp`**, if it ever takes a bundled TLS engine, through a TLS table in this package,
  resolved at run time (§10). It consumes nothing in 0.x.

**What exists elsewhere, and what does not.**
- `openssl` is broad and needs system libssl; `sodium` is modern and needs libsodium on Linux.
  `rmonocypher` bundles Monocypher and offers authenticated encryption, Argon2 and random
  bytes with no system library. `digest` vendors its own hashes and also has `hmac()` and an
  `AES()` interface, though its DESCRIPTION discourages cryptographic deployment. Encrypted
  Excel can be read through Java or Python integrations.
- So self-contained cryptography already has a place in R, and this package does not claim
  otherwise. What it offers is the combination: standard algorithms that interoperate with
  `openssl` and everything else, `openssl`'s calls where it mirrors them, a bundled backend
  tracked against upstream's LTS line, and a C interface for other packages, which neither
  `openssl` nor `sodium` publishes.

See the [openssl manual](https://jeroen.r-universe.dev/openssl/doc/manual.html),
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
| **A primitive enters on the admission rule, not on a consumer** | A standard, published vectors, an outside oracle and a composition contract (§6). Revision 3's named-consumer rule described every provider in the family and distinguished none. ECB is admissible under the new rule and in no tranche: `openssl` exposes none |
| **An openssl-shaped R layer under `crypt_`** | Migration by prefix change for the operations it covers, no collision when `openssl` is attached, and one R prefix per package (§7.1) |
| **The archive contains the adapter, never raw upstream** | PSA headers depend on the configuration and expose key identifiers. With only `zucrypt.h` visible, there is no define for a consumer to match |
| **C ABI prefix `zuc_`/`ZUC_`, never `zu_`** | `zu_` is `zukomp`'s public namespace and `zuhttp`'s internal one |
| **Dynamic PSA key store** | A static store turns "too many live handles" into a false out-of-memory error (#30) |
| **TF-PSA-Crypto 1.1 LTS** | Supported until 2029. 1.2 adds nothing this profile uses (#19) |
| Support raw bytes explicitly | Avoid implicit text encoding, serialization or path interpretation |
| Treat cipher operations as low-level interfaces | They do not by themselves define a secure encrypted-file format |
| A TLS engine for `zuhttp` lives here, in the shared object and a separate table, never in the archive | One vendored Mbed TLS copy; `Suggests:` plus a run-time lookup makes it optional; `zuxlsx` never compiles it (§10) |

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
  moves, or when a tranche (§6) or a consumer needs a feature that exists only there.
- `vendor-upstream.yaml` watches the latest release, whatever its line. Each non-LTS release
  therefore produces an issue that is closed with this policy as its reason, until the watcher
  can be restricted to a tag pattern. That restriction is a follow-up in `r-actions` (#19).

**The configuration** is `src/zuc_crypto_config.h`, which replaces upstream's configuration. It
holds fourteen defines, each recorded in the manifest's `defines` column and cross-checked by
`tools/vendor/verify`:
- SHA-1, SHA-256, SHA-384 and SHA-512;
- HMAC and the HMAC key type;
- CBC without padding, and the AES key type;
- the PSA core;
- external RNG;
- `MBEDTLS_PSA_KEY_STORE_DYNAMIC`;
- hardware AES: `MBEDTLS_AESNI_C`, `MBEDTLS_AESCE_C`, and `MBEDTLS_HAVE_ASM`, which AES-NI
  needs on x86-64 (#51).

Revision 3 swapped ECB-without-padding for the dynamic key store, and #51 added the three
hardware-AES defines.
Nothing else is enabled:
- no public-key cryptography, AEAD or key derivation;
- no X.509 or TLS;
- no persistent key storage.

**Vendoring requirements:**

- **One manifest row**, `tf-psa-crypto`, with release, source URL, checksum, licence, define set
  and patch list, in the §3 layout. Stage 17 adds a second, `mbedtls`, and the TLS engine
  (§10) builds from the same two rows, so one upstream release and one patch set serve both.
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
    independently vendored copies, `zucrypt`'s archive inside `zuxlsx.so` and the backend
    inside `zucrypt.so`, cannot bind to one another.
- **Keep the feature set and the output identical on every platform; use hardware AES where the
  CPU has it.** AES is deterministic, so AES-NI, the Arm Cryptography Extension and the software
  path produce the same bytes, and the published vectors check that on every platform CI reaches.
  - **Why hardware matters.** The software AES indexes lookup tables with secret-dependent
    values. The pinned release's own `SECURITY.md` says that leaks through cache timing, locally
    and possibly remotely, and can recover the key, and it recommends hardware acceleration.
    Revision 3 first left hardware off "so every platform runs the same C"; the package review in
    #51 showed that was the wrong trade.
  - **The fallback.** Both paths are chosen at run time, so a CPU without AES instructions falls
    back to the software tables rather than failing (`MBEDTLS_AES_USE_HARDWARE_ONLY` is not set).
    On that fallback the timing exposure remains. It is documented in `?crypt_aes_cbc_nopad` and
    `zucrypt.h`, not refused: refusing would make `zuxlsx` unable to open a workbook on such a
    machine. The backend has no constant-time software AES to fall back to instead.
  - **Reporting.** `crypt_info()$build_flags$aes_implementation` and `zuc_info.aes_implementation`
    report the path this machine runs, `"aesni"`, `"aesce"` or `"software"`, read at run time
    from the backend (#36, #51). `aes-paths.yaml` asserts the expected path on each CI OS, and
    runs the whole suite on a software-only build (`ZUC_AES_SOFTWARE_ONLY`), so the fallback is
    tested even though no CI runner would choose it.
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
| `zucrypt` | Cryptographic primitives and constructions, key and certificate data, state and the native API; from Stage 18, a TLS client engine over caller-supplied I/O (§10) | XML, ZIP, Office, sockets, name resolution, proxies, trust stores, trust policy, or the user's environment (key files, passphrase prompts, certificate downloads) | — |
| `zuxlsx` | Workbook interpretation, the Office encryption adapter and the CFB reader | TLS | `LinkingTo` + `configure` + the installed `lib${R_ARCH}/libzucrypt.a`. No `Imports:` (its design §3) |
| `zuxml` | XML parsing, reused for Agile encryption metadata | Cryptographic policy | does not |
| `zukomp` | ZIP entry access and decompression after decryption | Office password handling | does not |
| `zuhttp` | HTTP, sockets, proxies, TLS backend selection, trust policy and CA discovery | Office processing | does not in 0.x. A bundled TLS engine, if ever taken: `Suggests:` + `R_GetCCallable()` on `zucrypt`'s TLS table (§10) |

The Office adapter may use `zuxml` and `zucrypt`. It must not create a reverse dependency from
either package to `zuxlsx`.

## 6. Algorithm scope

**The profile on `main`** is what v0.1.0 ships:

| Capability | First consumer | Exposure |
| --- | --- | --- |
| SHA-1 | Office agile profiles that declare it | R and C, as an explicit compatibility option |
| SHA-256, SHA-384, SHA-512 | Office agile key derivation; general hashing | R and C |
| HMAC with the supported hashes | Office agile data integrity; general MACs | R and C |
| AES-128/192/256-CBC without padding | Office agile key and payload decryption | Advanced R interface, and C |
| Constant-time comparison of equal-length byte strings | Verifiers and authentication tags | R and C |
| Secure cleanup of native buffers | Keys and intermediate state | Internal |

SHA-1 is a compatibility facility, never a default. Its availability for document handling
must not weaken `zuhttp`'s TLS policy. AES-ECB was removed before release (#29) and is in no
tranche: `openssl` exposes no ECB function and no construction here needs it.

**The admission rule** (revision 4, item 2). A primitive or construction enters when all five
hold:

1. **A standard with a number.** NIST, RFC or FIPS. Nothing is specified by this package.
2. **Published vectors with provenance**, committed under `tests/testthat/fixtures/` with a
   `MANIFEST.tsv` row, and recomputed by `tools/make-kat.R --check` against `openssl`.
3. **An oracle outside this package.** The `openssl` R package where it has the function, the
   `openssl` command line otherwise, `sodium` for the curve operations it shares. A self round
   trip never counts (§12).
4. **A composition contract.** The documentation says what the primitive does not do: CBC does
   not authenticate, GCM does not tolerate a repeated nonce, PBKDF2 is not a file format.
5. **A demonstrated workflow benefit** that justifies the implementation and its maintenance
   (#56). Not a named consumer: a verified migration, a missing workflow shown to be useful,
   or repeated user demand will do. The first four say a primitive *can* enter; this one says
   whether it *should*, so that an available standard never becomes a commitment by itself.

Each addition is one define in `src/zuc_crypto_config.h`, a re-derived trim
([stage-1-spike.md](stage-1-spike.md) §3, §11), a `zuc_*` addition to the archive and a
`crypt_*` wrapper, plus its `zuc_alg` value from the range §8.1 reserves.

**The tranches.** Each is one roadmap stage and one minor release. Tranches 1 and 2 are the
plan. Tranches 3–5 are candidates: each opens with a decision against criterion 5, taken once
the tranche before it has shipped and its adoption can be seen, and none is a release
commitment until then (#56). What the pinned release
can and cannot do was checked against the 1.1.1 archive on 2026-09-29. No tranche vendors a
whole upstream: TF-PSA-Crypto 1.1.1 has 77 buildable sources, of which 20 are vendored today,
and each tranche's keep list is re-derived from its define set by the spike's method, so the
tree holds what the enabled algorithms compile and nothing else. Mbed TLS proper enters only
at tranche 5, and only its X.509 files (9 of its 36 library sources in 4.1.0). Its 19 TLS
sources enter only with the TLS engine (§10, Stage 18), trimmed to the client configuration,
and never enter the archive.

| Tranche | Enters | Standard and oracle | Backend cost |
| --- | --- | --- | --- |
| 1 (Stage 13) | OS randomness (#9); MD5, SHA-224, RIPEMD-160, SHA-3; Base64; the openssl-shaped digest and HMAC functions, with character and connection input (#11) | RFC 1321, FIPS 180-4, FIPS 202, RFC 4648; `openssl` | small: `md5.c`, `ripemd160.c`, `sha3.c`, `base64.c` |
| 2 (Stage 14) | AES-GCM (#10), ChaCha20-Poly1305, AES-CTR, PKCS#7 padding for CBC; PBKDF2-HMAC and HKDF (#12) | NIST SP 800-38A and 38D, RFC 8439, RFC 8018 and 6070, RFC 5869; `openssl` | moderate: `gcm.c`, `chacha20.c`, `poly1305.c`, `chachapoly.c`, the KDF core |
| 3 (Stage 15) | Key objects; PEM and DER read and write; RSA key generation, PKCS#1 v1.5 and PSS signatures, OAEP and v1.5 encryption; `openssl`'s envelope format; SSH key formats; bignum conversion | RFC 8017, FIPS 186-5, RFC 5208 and 7468; `openssl` cross-reading and cross-verification | large: `bignum*.c`, `rsa.c`, `pk*.c`, `pem.c`, `asn1*.c`, `oid.c` |
| 4 (Stage 16) | EC key generation, ECDSA (RFC 6979 as an option), NIST-curve ECDH, X25519 | FIPS 186-5, RFC 6979, RFC 7748, NIST CAVP; `openssl`, `sodium` for X25519 | moderate on top of 3: `ecp*.c`, `ecdsa.c` |
| 5 (Stage 17) | X.509 certificates: read, write, verify against a caller-supplied bundle, fingerprints | RFC 5280; `openssl` | a second manifest row, Mbed TLS proper (X.509 is not in TF-PSA-Crypto) |

**Documented gaps against `openssl`**, measured against `openssl` 2.3.4's 78 exports on
2026-09-29 and listed in the migration article from Stage 13 so that nobody migrates into
one. About fifty of the 78 are covered by the end of tranche 5; these are not:

- **Not in the backend, by algorithm.** Ed25519 (`ed25519_keygen()`, `_sign()`, `_verify()`,
  `read_ed25519_key()`, `read_ed25519_pubkey()`): the pinned release has no EdDSA, though
  X25519 exists. It enters when upstream ships `PSA_WANT_ALG_PURE_EDDSA` on the LTS line, or
  not at all. DSA (`dsa_keygen()`), MD4, BLAKE2 (`blake2b()`, `blake2s()`) and raw Keccak
  (`keccak()`): removed or never present upstream.
- **Not in the backend, by construction.** `bcrypt_pbkdf()`, OpenSSH's KDF, which is not a
  standard with a number; PKCS#12 containers (`read_p12()`, `write_p12()`), for which Mbed TLS
  has only the KDF; CMS enveloped data (`pkcs7_encrypt()`, `pkcs7_decrypt()`) and PKCS#7
  writing (`write_p7b()`). `read_p7b()` is parse-only upstream and is a Stage 17 candidate.
- **Outside the boundary (§5).** `download_ssl_cert()`, `ca_bundle()`, `my_key()`,
  `my_pubkey()`, `askpass()`, the three `ssl_ctx_*()` curl hooks, and `fips_mode()`.
  `openssl_config()` maps to `crypt_info()`.
- **Bignum arithmetic** (`bignum_mod_exp()`, `bignum_mod_inv()`), called by no importer.
  `bignum()` itself enters at tranche 3 as conversion only, because four importers use it to
  move RSA parameters between JWK and PEM.
- Anything the `openssl` package adds after the version the gate was last run against.

**The AEAD contract** (#56). AEAD here is RFC 5116's: encryption takes a key, a nonce,
associated data and plaintext, and returns the ciphertext *and* a tag; decryption verifies the
tag over ciphertext and associated data before releasing anything, and on failure returns no
plaintext and signals `zucrypt_auth_error`. This holds in C and R, one-shot and incremental;
an incremental decrypt buffers or withholds output until the tag has verified. `openssl`
2.3.4's GCM pair does not meet it (checked 2026-09-29: `aes_gcm_encrypt()` returns no tag,
and `aes_gcm_decrypt()` returns tampered plaintext without error), so `crypt_aes_gcm_*` is a
documented difference, not a mirror, and its independent oracle is NIST SP 800-38D and
RFC 8439 vectors plus an implementation that exposes the tag, not the `openssl` R package.

**Nonce policy for AEAD** (revising revision 3's note on #10): the nonce is generated by
default with the tranche 1 randomness, a caller-supplied one is accepted, and the
documentation says that reusing a nonce under a key discloses the plaintext and forges tags.
That is a contract, not a guard; the guard would be refusing the argument.

**What stays out.** There is no `encrypt_file(password = ...)`, and there will not be one
here. The tranches give a caller PBKDF2, randomness and GCM to compose, and a format is a
separate specification owned by whoever needs it. Argon2 and bcrypt are not in the backend.
Post-quantum signatures (ML-DSA is in the 1.1.1 tree under `drivers/pqcp/`) are recorded in
§14, not planned.

## 7. R interface

```r
crypt_info()

crypt_hash(data, algorithm = "sha256")
crypt_hmac(data, key, algorithm = "sha256")
crypt_hex(x)
crypt_equal(x, y)

# Advanced interoperability functions; no padding or authentication is added.
crypt_aes_cbc_encrypt_nopad(data, key, iv)
crypt_aes_cbc_decrypt_nopad(data, key, iv)
```

**These seven are stable from v0.1.0 (§8.6).** `crypt_hex()` joined the original six before release (#59). The names follow the family's short package prefix:
`komp_`, `xml_`, `json_`, `yaml_`, and `zu_` in `zuhttp`. The CBC pair was
`crypt_aes_cbc_encrypt()`/`_decrypt()` until the rename before v0.1.0 (#56); the `_nopad`
suffix names the difference that matters, and frees the ordinary names for §7.1.

Contract:

- Binary arguments are raw vectors. A character value is never interpreted as a filename,
  password or byte sequence.
- A scalar algorithm name selects one documented algorithm. There is no partial matching
  (`match.arg()` is not used), and no fallback to another algorithm.
- Hashes and HMACs are returned as raw vectors. Hex formatting is an explicit conversion at the
  call site, `crypt_hex()`: lower-case, two digits a byte, in C, because `format()` and
  `paste()` cost several times what hashing a short input does (#59).
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

**File and connection hashing** (#11) is not a separate function. It is the connection input
of the openssl-shaped layer (§7.1), which chunks through the incremental path, checks for
interrupts between chunks, and refuses text-mode connections, whose encoding conversion would
change the bytes.

### 7.1 The openssl-shaped layer

Revision 4's product for the second audience. It is a layer *over* the core functions, in R,
with its own rules; the core functions and the `zuc_*` archive underneath do not change
to accommodate it.

**Naming.** `crypt_` plus `openssl`'s name: `crypt_sha256()`, `crypt_rand_bytes()`,
`crypt_base64_encode()`, `crypt_read_key()`. Arguments keep `openssl`'s names, order and
defaults. For a covered function without a documented difference, a migration is a prefix
change and an `importFrom()` edit; the promise is documented compatibility for selected
operations, never universal substitution. Unprefixed names would collide the moment both
packages are attached; `zu_` is taken twice in the family (revision 4, item 3).

**Compatibility is subordinate to the security contract** (#56). Where `openssl`'s behaviour
falls short of the contract the primitive's standard gives it, this layer keeps the name and
the standard's contract, and the difference is documented. The case that set the rule is GCM
(§6, the AEAD contract). A mirror never reproduces a failure to authenticate, to verify, or to
reject malformed input.

**Typing follows `openssl`, not §7.** In this layer:
- raw in gives raw out;
- a character vector is hashed element-wise as UTF-8 bytes and returns a hex string of class
  `hash`, as `openssl` does;
- a connection is streamed through the incremental path;
- `key = ` on a digest function selects HMAC.

Everything under this layer is still the raw-only core, so the rule that a character value is
never a byte sequence still holds for `crypt_hash()`, `crypt_hmac()` and the CBC pair, and for
any new function that has no `openssl` counterpart. Which layer a function belongs to is
stated in its documentation, and the reference index groups them separately.

**No core name may collide with a mirrored one.** The one case was the CBC pair: `openssl`'s
`aes_cbc_encrypt()` pads with PKCS#7 and generates an IV; ours adds no padding and requires
the IV. Keeping our contract under `openssl`'s name would make a prefix migration of
`aes_cbc_decrypt()` return the padding bytes as plaintext, silently. The core pair is
therefore renamed `_nopad` before v0.1.0 (§7), and `crypt_aes_cbc_encrypt()`/`_decrypt()`
arrive in Stage 14 as the mirrored pair, padding and generating an IV as `openssl` does, over
the same `zuc_aes` core. Nothing stable changes meaning.

**The gate.** `test-openssl-compat.R` runs every function in this layer against `openssl` on
the same inputs, under `skip_if_not_installed("openssl")`, and on at least one CI leg the
`openssl` package is required to be present so that the gate cannot pass by being skipped.
Three kinds of result are allowed:

- **byte-identical**: the default, asserted with `expect_identical()` on the bytes and on the
  classes, attributes, defaults and error behaviour a caller can observe; for character input,
  on the hex string and its class; for connections, on the bytes streamed;
- **cross-verified**: for randomised operations (ECDSA, key generation): what we produce,
  `openssl` accepts, and what `openssl` produces, we accept;
- **a documented difference**: listed in the migration article with the reason and the
  workaround. GCM is one (the AEAD contract, §6). Key objects are another in kind: serialized
  keys interoperate, but a `crypt_key` external pointer is never an `openssl` key object.

A function exported from this layer that is in none of the three lists fails the suite, so a
new mirrored function cannot ship without a decision. The `openssl` version the gate last ran
against is recorded in NEWS, because a semantic change upstream is a change to what "identical"
means.

**The migration article** (`vignettes/articles/from-openssl.Rmd`) is the layer's contract for
a reader: one table, `openssl` name against `crypt_` name, with identical, cross-verified,
different or missing in the last column, and the §6 gaps listed under "missing".

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
  - **Ranges are reserved before ABI 1 is declared** (revision 4, item 5), because the
    tranches of §6 add identifiers after the freeze and the values are permanent: 1–15
    digests, 16–31 MACs, 32–63 ciphers and AEAD modes, 64–95 key derivation, 96–127 key
    families and agreements, 128–159 signatures. The header states the ranges; a value is
    assigned when its primitive enters, never in advance.
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
`tools/zucrypttest` calls every entry on every push. Revision 4 gives it an audience it did
not have: a package that imports `zucrypt` for the §7.1 layer already carries `Imports:`, and
`LinkingTo:` is then one line away. The option of removing the table before 1.0 is withdrawn;
it leaves the experimental tier when such a package uses it, and its entries grow with the
archive's, appended only.

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

| Surface | `main` before the freeze | v0.1.0 (CRAN) onward | Changes allowed |
| --- | --- | --- | --- |
| The core `crypt_*` functions (§7) and their condition classes | stable | stable | Additions only; nothing removed or given a new meaning |
| `zucrypt.h`, `libzucrypt.a`, install path | **provisional** | **frozen as ABI 1** | Before the freeze: any change, recorded in `NEWS.md` and applied to `zuxlsx` together. After: additions only |
| `zucrypt-r.h`, the registered table | **experimental** | experimental | Any change, recorded in `NEWS.md`. Leaves the tier when a non-fixture package uses it |
| The openssl-shaped layer (§7.1), from v0.2.0 | — | — | Each function is stable from the release that ships it. Its contract is `openssl`'s at the version NEWS records; a divergence upstream becomes a documented difference, never a changed `crypt_` function |

**The freeze** is the event that moves the archive to "frozen", in v0.1.0 (revision 4,
item 10). It happens when all of the following hold:
- `zuxlsx`'s decryption core in C (zuxlsx#22 step 3) links `libzucrypt.a` from `main` on a
  `zuxlsx` branch and decrypts the real encrypted fixture to its known plaintext;
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

## 10. Relationship with zuhttp: the TLS engine

`zuhttp` keeps its native OS TLS backends: Schannel, Network.framework and OpenSSL. Its D-63
(2026-09-26) removed Secure Transport, rejected vendoring a private Mbed TLS copy on every
platform, and named `zucrypt` as the route for a bundled engine if one is ever needed. Its
trigger is narrow, proxied HTTPS on macOS 11–13, and it is not planned before `zuhttp` 1.0.
Backend selection must never happen as an automatic retry after certificate verification fails.

**The engine lives in this package** (decided 2026-09-29, replacing revision 4's first answer,
a fourth provider package). It is a candidate stage (roadmap Stage 18), taken on `zuhttp`'s
trigger and after tranche 5, whose X.509 row it builds on. The reasons a separate package was
proposed do not require one:

- **It is not in `libzucrypt.a`.** A TLS client needs the SSL state machine, X.509, the key
  exchange and AEAD suites, a DRBG and `mbedtls/ssl.h` with a matching configuration. None of
  it enters the archive, so no `zuxlsx` install compiles or links it, and the archive's ABI 1
  is untouched. The engine is compiled into `zucrypt`'s shared object only.
- **"Optional" is met by the table.** `LinkingTo:` is an install-time requirement and cannot be
  optional, but `R_GetCCallable()` is a run-time lookup. `zuhttp` lists `zucrypt` in
  `Suggests:` and resolves a separate registered table, `zucrypt_tls_api_v1` in
  `inst/include/zucrypt-tls.h`, only when the bundled backend is selected. That is §8.2's shape
  pointed from engine to client, in this package.
- **One vendored copy.** Stage 17's `mbedtls` manifest row, with its trim method and patch set,
  gains the TLS sources the enabled configuration compiles. The engine and the X.509 functions
  share one pinned release, one watcher and one advisory stream, instead of a second package
  re-vendoring the same upstream.

**What the engine is, and is not.**
- A TLS 1.2 and 1.3 **client** protocol engine. No server role, no DTLS, no renegotiation, no
  session tickets stored on disk. Cipher suites and groups are a fixed, documented set chosen
  by this package; `zuhttp` can narrow them, never widen them.
- **I/O through callbacks.** The caller supplies send and receive functions over a stream it
  owns. The engine opens no socket, resolves no name and knows nothing of proxies: that is how
  it serves proxied HTTPS without this package touching the network (§5).
- **Policy is `zuhttp`'s; enforcement is the engine's.** `zuhttp` passes the CA bundle, the
  expected host name, the minimum version and any pins. The engine verifies the chain and the
  host name against exactly those, fails closed, and reports why through a status code. It
  never reads a system trust store, a key file or an environment variable.
- **Randomness** is the tranche 1 entropy source feeding the backend's DRBG, never R's RNG.
- **No R surface.** There is no `crypt_tls_*()` function. The table is C only, for `zuhttp`.

**Stability.** The TLS table is *experimental* until `zuhttp` ships a release that uses it,
then additions-only under §8.6's rules, with its own version field. It shares nothing with
`zucrypt.h`, so its changes never touch ABI 1.

**Security obligation.** TLS carries more upstream advisories than the crypto core. An advisory
affecting the enabled TLS configuration is a patch release of this package, prepared from the
existing `vendor-upstream.yaml` watcher, and the vendored-backend vignette says so. This is the
cost of hosting the engine, accepted with it.

`zuhttp` still owns CA discovery, trust configuration, protocol policy, client certificates,
sockets, proxies and network errors. None of those move here.

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
- Keys, passwords, IV-derived secret state and plaintext are never attached to a condition —
  not in the message, and not in the **call** either. A condition's call is the caller's
  expression, arguments and all (and, under `do.call()`, their values), and R prints it before
  the message. `zucrypt_abort()` therefore reduces every call to the bare function name,
  `crypt_hmac()`, whatever a helper passes (#51).

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
| openssl compatibility (§7.1, from Stage 13) | Every mirrored function byte-identical to `openssl` (bytes, classes, attributes, defaults, errors), cross-verified, or a documented difference; an export in none of the three lists fails; one CI leg requires `openssl` present so the gate cannot pass by skipping; the `openssl` version recorded in NEWS |
| Authenticated encryption (§6, from Stage 14) | Tampered ciphertext, tag and associated data, a truncated tag and a wrong key each fail with `zucrypt_auth_error` and release no plaintext, one-shot and incremental, in C and R. A release gate, not a unit test among others |

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
3. **Settle and prove the core** (roadmap Stages 7–9): revision 3's surface changes, gates
   that execute, independent vectors, and documentation that matches the code.
4. **First consumer, freeze and CRAN** (roadmap Stages 10–12, v0.1.0, the first CRAN
   release):
   - the archive fixture package;
   - the CBC rename (#56);
   - `zuxlsx`'s decryption core in C against the archive (zuxlsx#22 step 3);
   - the ABI 1 freeze.

   The family's first end-to-end success criterion is reading a password-encrypted workbook
   without Java, Python or a system OpenSSL. It is met by `zuxlsx` 0.1.0, which follows
   `zucrypt` 0.1.0 onto CRAN.
5. **HTTP evaluation**, owned by `zuhttp`: its Mbed TLS spike, on the shared manifest row, with
   native OS TLS retained.
6. **Tranche 1** (roadmap Stage 13, v0.2.0): randomness, the remaining digests, Base64, and
   the openssl-shaped layer with its gate and migration article over what already exists.
7. **Tranche 2** (Stage 14, v0.3.0): AEAD, CTR, padding, PBKDF2 and HKDF.
8. **Tranches 3 and 4** (Stages 15–16, v0.4.0 and v0.5.0, candidates): key objects, PEM and
   DER and RSA, then the curves. Ordered by measured use among `openssl`'s importers
   (`tools/openssl-usage.R`, roadmap Stage 13).
9. **Tranche 5** (Stage 17, v0.6.0, candidate): X.509 certificate data on a second manifest
   row.

Each release after v0.1.0 is additions only, to the R surface and to the archive, and each is
a CRAN release. The `zuhttp` TLS engine, if taken, is Stage 18 in this repository and
starts from step 9's manifest row (§10).

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

- **When the table leaves the experimental tier.** When a non-fixture package uses it.
  Removal is no longer an option (revision 4, item 6).
- **Whether ECB returns.** It is admissible under §6 and in no tranche; it returns as an
  addition when a mirrored function or a consumer needs it.
- **Whether `zuhttp` ever takes the bundled TLS engine** (§10). It is built here, as Stage 18,
  on `zuhttp`'s trigger; not before `zuhttp` 1.0 unless that trigger comes first.
- **When calls may leave the main thread.** Only when a consumer asks, and only after locking and
  shutdown are verified (§8.4). A long-lived `openssl` replacement in a server process is the
  likeliest asker.
- **Ed25519**, when upstream ships EdDSA on the LTS line (§6, gaps).
- **Post-quantum signatures.** ML-DSA is in the pinned tree; it enters, if at all, on the
  admission rule and with a named standard (FIPS 204), after tranche 4.
- **Bignum arithmetic**, if an importer ever calls it (§6).
- **Which `openssl` version the gate tracks** when the two packages' semantics diverge.
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

These choices do not move the boundary. `zucrypt` owns reusable cryptography and, from
Stage 18, the TLS protocol engine; document readers own document formats; and `zuhttp` owns
connections, trust and TLS policy.
