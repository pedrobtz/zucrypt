# zucrypt: design

Status: implemented in v0.1.0 for §3–§8 and §11–§12. §9 and §13 steps 3–6 remain plans, owned
by `zuxlsx` and `zuhttp`. Reviewed 2026-09-22; the review at the end of [roadmap.md](roadmap.md)
records what the evidence changed.
Date: 2026-09-19. Revised 2026-09-20 after review against the `zu*` packages as shipped.
Initial application: cryptographic support for password-encrypted Excel input.
Related packages: `zuxlsx`, `zukomp`, `zuxml`, and `zuhttp`.

## Revision note (2026-09-20)

The first draft was written from the design documents of the sibling packages. This revision
was checked against the packages themselves — `zukomp` v0.1.0, `zuxml`, the `zuxlsx` build slice
and `zuhttp` — and the changes are all in one direction: making `zucrypt` consumable by those
packages exactly the way they already consume each other. The material differences:

1. **Two consumer shapes, not one.** `zuxlsx` links its siblings as static archives
   (`lib<pkg>.a` under the installed package's `lib/` or `lib${R_ARCH}/`, resolved by `configure`, `LinkingTo` only, no `Imports:`). The draft
   supported only the registered function table. Both are now required; see §8.
2. **A C-symbol prefix, chosen for non-collision.** `zu_` is `zukomp`'s public ABI namespace
   (`zu_status`, `zu_buffer`, `ZU_OK`, `ZU_ERR_MEMORY`…) and `zuhttp`'s internal one. A
   `zucrypt.h` that declared `zu_status` could not be included beside `zukomp.h`. (This note
   first said `zuxlsx` includes both. It does not: it includes `miniz.h`, from zukomp's archive,
   not `zukomp.h`. The rule stands on the two namespaces, not on any one consumer.) The C ABI is
   `zuc_`/`ZUC_`; see §3.
3. **What goes in the archive.** `zukomp` and `zuxml` ship raw upstream in their archives and
   install upstream headers. `zucrypt`'s archive ships the adapter, and no upstream header is
   installed. This is the one deliberate departure from precedent, and §8 says why.
4. **R names, condition classes, vendoring layout, build rules and test conventions** now follow
   the family's, which several `zukomp` and `zuxlsx` tests enforce mechanically. Where the draft
   invented its own (`hash_raw()`, `zucrypt_<code>_error`, `tools/update-vendor.R`), it is
   replaced; see §3, §7, §11.

## 1. Purpose

`zucrypt` provides a small, predictable cryptographic foundation for R packages, backed by vendored code from the Mbed TLS ecosystem. It exposes a narrow R interface and a versioned C interface, with no requirement for an installed OpenSSL library, Java, or Python at runtime.

The first integration is reading password-encrypted `.xlsx` files through `zuxlsx`. A second consumer is `zuhttp`, which may use the same upstream cryptography ecosystem for a vendored TLS backend while retaining its existing native OS TLS implementation. `zuhttp` needs no digest from this package today: `pinned_public_key = "sha256//…"` is implemented only on its OpenSSL backend, but the Schannel and Secure Transport backends *refuse* a pin with `zu_tls_pin_error` rather than ignoring it, and what blocks them is extracting the SubjectPublicKeyInfo from the platform's certificate objects, not hashing it — both platforms have a native SHA-256. `zuhttp` imports nothing by policy, and nothing here changes that.

The package's value is straightforward installation, controlled algorithm support, and reusable native interfaces. It does not claim that R lacks cryptography: `openssl` already provides broad cryptographic functionality, `sodium` provides modern encryption interfaces, and encrypted Excel can already be read through Java or Python integrations. The opportunity is a focused native foundation that fits the `zu*` package family. See the [openssl manual](https://jeroen.r-universe.dev/openssl/doc/manual.html), [sodium documentation](https://docs.ropensci.org/sodium/), [xlsx manual](https://cran.r-project.org/web/packages/xlsx/refman/xlsx.html), and [rpxl](https://github.com/epicentre-msf/rpxl).

## 2. Main decisions

| Decision | Rationale |
| --- | --- |
| Use the Mbed TLS ecosystem rather than BearSSL | Align document cryptography with the potential TLS backend for `zuhttp` |
| Build only the crypto components in `zucrypt` | Excel cryptography does not need TLS or certificate processing |
| Keep Office parsing and decryption orchestration in `zuxlsx` initially | Avoid making HTTP or other crypto consumers depend on Office, XML or ZIP code |
| Expose a small wrapper API, not upstream types | Isolate consumers from upstream configuration and ABI changes |
| **Ship both consumer shapes: a registered function table and a static archive** | `zuxlsx` consumes siblings by archive with no runtime dependency; `zuhttp` was expected to consume the table. Supporting one would force the other consumer to change its own design. *Review 2026-09-22: no table consumer exists or is planned — `zuhttp` has no `Imports:` and uses backend-native digests (#14); whether the table is frozen with the archive is #28* |
| **The archive contains the adapter, never raw upstream** | Unlike `miniz.h`/`expat.h`, PSA headers are configuration-dependent and expose key identifiers; a consumer that saw them would have to replicate the build configuration. With only `zucrypt.h` visible there is no define to match |
| **C ABI prefix `zuc_`/`ZUC_`, never `zu_`** | `zu_` is `zukomp`'s public namespace and `zuhttp`'s internal one; a `zucrypt.h` using it could not be included beside `zukomp.h` |
| Support raw bytes explicitly | Avoid implicit text encoding, serialization or path interpretation |
| Treat cipher operations as low-level interfaces | They do not by themselves define a secure encrypted-file format |
| Share upstream provenance with `zuhttp` first | A single shared compiled backend is a separate, deferred engineering decision |

If Office support later serves several readers, extract it from `zuxlsx` into a dedicated document package. Do not introduce that extra package before there is a second consumer.

## 3. Conventions inherited from the `zu*` family

These are established in `zukomp` and `zuxml`, restated in `zuxlsx`'s CLAUDE.md, and in several cases enforced by tests that a new package is expected to carry too. They are listed here so nothing below has to re-derive them.

**Naming by layer.**

| Layer | Prefix | Examples |
| --- | --- | --- |
| R exports | `crypt_` | `crypt_hash()`, `crypt_info()` |
| C ABI (installed headers) | `zuc_` / `ZUC_` | `zuc_status`, `ZUC_OK`, `zuc_hash_new()` |
| Entry points and registration | `zucrypt_` | `R_init_zucrypt`, `zucrypt_get_api`, `zucrypt_api_v1` |
| Internal only, never installed | `zuc_int_` | `zuc_int_backend_init()` |
| Test-only `.Call` symbols | `zucrypt_test_` | `zucrypt_test_hash_split()` |
| R condition classes | `zucrypt_` | `zucrypt_invalid_argument`, `zucrypt_error` |

`zuc_` and `ZUC_` are used by no other package in the family (checked 2026-09-20 across `zukomp`, `zuxml`, `zuhttp`, `zucsv`, `zujson`, `zuyaml`, `zuxlsx`). `zu_` is `zukomp`'s public namespace and `zuhttp`'s internal one; `zux_` is `zuxml`'s. Nothing that reads as another library's ABI may be exported: no `mbedtls_*` or `psa_*`, and — because `zuhttp` links system `libcrypto` on Linux — no OpenSSL-ABI name either (`SHA256_Init`, `SHA256_Update`, `AES_encrypt`, `HMAC`, `EVP_*`). `test-abi.R` audits the shared object for all of these, the way `zukomp`'s bans zlib names.

**Headers.** `inst/include/zucrypt.h` compiles standalone as C99 against only `<stddef.h>` and `<stdint.h>`: no `R.h`, no `SEXP`, no upstream type or vocabulary in a declaration (a comment may say "PSA"; a declaration may not). R-specific resolution lives in `inst/include/zucrypt-r.h`. Both rules are enforced twice with the same comment-stripped check: an `abi.yaml` job compiles the header standalone under `-Werror` in C99 and C++, and `test-abi.R` greps the *installed* copy.

**Build.** `src/Makevars` is portable make only: `OBJECTS` listed explicitly (R compiles only `src/*.c` by itself, and vendored code lives in a subdirectory), no `$(wildcard)`, no GNU-make conditionals (either forces `SystemRequirements: GNU make`), no `-W*` or optimisation overrides (CRAN policy). Project code is C99 — no C11 atomics, intrinsics, assembly or thread APIs; vendored sources may use whatever upstream requires.

**Errors.** C layers return a status enum and never call `Rf_error()` below the outermost `.Call`; R constructs conditions. Anything holding heap state across a possible `longjmp` — `Rf_error()` *and* `R_CheckUserInterrupt()` both jump past every `free()` beneath them — is owned by an external pointer with `R_RegisterCFinalizerEx(..., TRUE)`, freed eagerly on the success path with the pointer cleared first. Condition classes are `c(<specific>, "zucrypt_error", "error", "condition")`; the status-to-class map is keyed by C enumerator *name*, fetched from C at runtime, so renumbering the enum cannot silently remap a condition.

**Tests.** Self-sufficient (inputs built inside each `test_that()`), self-contained (`withr::local_*()`), assert on condition classes never message text, pass under `devtools::test(shuffle = TRUE)`, and finish under 60 seconds. Fixtures are committed with provenance in a `MANIFEST.tsv` and a `tools/` generator supporting `--check`; nothing is generated at test time. An always-compiled `.Call` harness (`zukomp`'s `zu_test_stream()`) drives the native layer at caller-chosen chunk sizes — for this package, the incremental hash/HMAC/CBC paths at every split point.

**Vendoring.** Third-party code under `src/vendor/<source>/`, never edited in place. Patches in `tools/patches/<source>/NNNN-*.patch`. `tools/vendor/manifest.tsv` (columns `source repo tag commit version_string archive archive_sha256 license defines patches`), `tools/vendor/checksums.sha256`, and the three scripts `fetch` (network, maintainer only), `record` and `verify` (offline; checks tree, both manifests, the `Makevars` define set and `inst/COPYRIGHTS` all agree). These are also the defaults `r-actions`' `vendor.yml` expects. Provenance is *reported from the compiled library* (`crypt_info()$vendored`), never read from the manifest, which is not installed.

**DESCRIPTION.** `Copyright: See inst/COPYRIGHTS and tools/vendor/manifest.tsv.`; upstream authors as `cph` in `Authors@R` with a `comment` naming what they hold; `Imports:` limited to base-priority packages (`utils` for `packageVersion()`); everything test-only in `Suggests`, and nothing in `Suggests` referenced from `R/`.

**Definition of done for a stage** (from `zukomp`): `document()` and `check()` clean 0/0/0; shuffled tests green; CI green on every leg including the CRAN-like containers; new public surface has roxygen docs with runnable examples; `tools/vendor/verify` clean if `src/vendor/` moved.

## 4. Backend and vendoring

Use a supported Mbed TLS release family, with Mbed TLS 4.1 LTS as the initial candidate. Pin an exact release and its corresponding TF-PSA-Crypto dependency during implementation; never build from a moving development branch. The upstream branch policy currently lists 4.1 support through March 2029. [Mbed TLS support policy](https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md).

In the 4.x architecture, TF-PSA-Crypto supplies cryptography, while Mbed TLS supplies separate X.509 and TLS libraries. `zucrypt` vendors and builds the required crypto subset. `zuhttp` may additionally build X.509 and TLS. Prefer supported PSA interfaces where they cover the required operations; keep any necessary release-specific calls behind the private adapter. [Mbed TLS architecture and build documentation](https://github.com/Mbed-TLS/mbedtls), [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto).

Vendoring requirements:

- One manifest row, `tf-psa-crypto`, with release, source URL, checksum, licence, define set and patch list, in the §3 layout. The draft allowed a second `mbedtls` row "if any file of it is needed"; none is ([stage-1-spike.md](stage-1-spike.md) §1). `zuhttp`'s eventual TLS spike should pin the *same* rows so the two packages track one upstream release and one patch set.
- Use official source archives containing generated files. Installation must not download dependencies or generate sources using Python or Perl.
- `tools/vendor/fetch` re-derives the tree from the archive: keep only the files the trim needs (`tools/vendor/keep/tf-psa-crypto.txt` is the list, a two-column keep list rather than the family's `keep_files()` case arm), drop examples, build systems and test suites so the tarball stays small and the surface reviewable.
- Use upstream configuration to disable features; avoid rewriting cryptographic internals. The define set is recorded in the manifest and in `src/Makevars`, and `verify` fails if they disagree.
- Preserve upstream license and notice files. Select the Apache-2.0 option where offered and document the licenses of all included files in `inst/COPYRIGHTS`.
- Hide upstream symbols. The archive objects and the shared object are compiled with hidden visibility so `mbedtls_*` and `psa_*` never appear in a dynamic symbol table; R loads packages `RTLD_LOCAL` by default and Windows DLLs have per-module namespaces, so two independently vendored copies (`zucrypt` inside `zuxlsx.so`, a TLS build inside `zuhttp.so`) cannot bind to one another. `test-abi.R` asserts it on the shared object; `test-linking.R` asserts the archive defines `zuc_*` and nothing from R.
- Keep the enabled feature set consistent across supported platforms. Hardware acceleration may vary; observable results must not.
- Ship security updates promptly. Vendored code does not receive fixes merely because the operating system is updated. **For a static-archive consumer the fix reaches it only when that consumer is reinstalled** — `zuxlsx` already accepts this for Expat, and it is why §9 asks `zuxlsx` to report the linked `zucrypt` and backend versions the way `zuxlsx_native()` reports Expat's. Detecting a stale link is tracked as [pedrobtz/zuxlsx#15](https://github.com/pedrobtz/zuxlsx/issues/15); whatever pattern lands there applies to `libzucrypt.a` unchanged.

**Build tooling is decided: `src/Makevars`, not CMake.** The first draft left this to the spike. The family rule in §3 and CRAN policy settle it: a CMake step at install time would add a `SystemRequirements` the siblings do not carry, and the archive shape in §8 needs the objects built by R's own flags (`$(ALL_CFLAGS)` carries `$(CPICFLAGS)`, which is what makes the archive linkable into a consumer's shared object). What the spike measures instead is the length of the explicit `OBJECTS` list a TF-PSA-Crypto trim produces, how the configuration header is supplied without generation, and whether the release archive's pre-generated driver-wrapper sources suffice. Do not claim an ordinary compiler is the only build requirement until this is demonstrated on all target platforms.

**Entropy and initialisation are a spike question, not a default.** Whether `psa_crypto_init()` in the pinned release requires an entropy source even when only hashes, MACs and unauthenticated ciphers are enabled decides between two configurations: external-RNG mode with no entropy module at all, or an OS entropy backend. If an OS backend is required, select it the way `zuxml` selects Expat's (`src/zux_expat_random.c`): one translation unit, one backend chosen by preprocessor macros — `rand_s` on Windows, `arc4random_buf`, `getrandom`, `getentropy`, `/dev/urandom` — because a portable `Makevars` has no conditional to pick a source file. Either way, no randomness is exposed in 0.1 (§6).

## 5. Dependency boundaries

| Package | Owns | Does not acquire through `zucrypt` | How it consumes `zucrypt` |
| --- | --- | --- | --- |
| `zucrypt` | Crypto primitives, state and native API | XML, ZIP, Office, sockets, TLS or trust stores | — |
| `zuxlsx` | Workbook interpretation; initially the Office encryption adapter and CFB reader | TLS | `LinkingTo` + `configure` + the installed `lib/libzucrypt.a`; no `Imports:` (its design §3) |
| `zuxml` | XML parsing, reused for Agile encryption metadata | Cryptographic policy | does not |
| `zukomp` | ZIP entry access and decompression after decryption | Office password handling | does not |
| `zuhttp` | HTTP, sockets, TLS backend selection and certificate trust | Office processing | not at all today; a future engine would vendor its own build, aligned on the same manifest rows (§10); a digest for SPKI pinning could come through the table — *but `zuhttp` hashes with each backend's native SHA-256 and has recorded no use for it (#14, 2026-09-22)* |

The Office adapter may use `zuxml` and `zucrypt`; it must not create a reverse dependency from either package to `zuxlsx`.

## 6. Algorithm scope

The following is the required capability profile to validate against the pinned backend build, not a claim that every capability is enabled by its default configuration.

| Capability | Initial use | Exposure |
| --- | --- | --- |
| SHA-1 | Office compatibility | Explicit compatibility option |
| SHA-256, SHA-384, SHA-512 | Hashing, HMAC and Office derivation | R and C |
| HMAC with the supported hashes | Integrity checks and package integrations | R and C |
| AES-128/192/256-CBC without padding | Common Office Agile profiles | Advanced R interface and C |
| AES-128/192/256-ECB without padding | Office Standard AES support — no consumer since zuxlsx §21c put Standard encryption out of scope (2026-09-20); removal proposed in #29 | C compatibility interface initially |
| Constant-time comparison for equal-length byte strings | Verifiers and authentication tags | R and C |
| Secure cleanup of native buffers | Keys and intermediate state | Internal |

SHA-1 and ECB are compatibility facilities. They are not defaults for new data formats. Their availability for document handling must not weaken `zuhttp`'s TLS policy.

Defer public authenticated-encryption, random-byte generation, PBKDF2, HKDF, signatures and key serialization until required by a concrete consumer. Add them through the same backend where supported. PBKDF2 is not a substitute for Office's specified password derivation.

There is no general `encrypt_file(password = ...)` in version 0.1. Such an interface requires a separately specified authenticated format, password KDF, nonce policy and reliable entropy source. Argon2 support is a separate decision.

## 7. Proposed R interface

```r
crypt_info()

crypt_hash(data, algorithm = "sha256")
crypt_hmac(data, key, algorithm = "sha256")
crypt_equal(x, y)

# Advanced interoperability functions; no padding or authentication is added.
crypt_aes_cbc_encrypt(data, key, iv)
crypt_aes_cbc_decrypt(data, key, iv)
```

The names follow the family's short package prefix (`komp_`, `xml_`, `json_`, `yaml_`, `zu_` in `zuhttp`). The first draft's `hash_raw()` and `constant_time_equal()` were unprefixed and would sit beside `openssl::sha256()` and `digest::digest()` in a user's search path with nothing to say which package they belong to. The `_raw` suffix is dropped because raw-only is the whole contract, not a variant; `komp_compress()` takes raw without saying so.

Contract:

- Binary arguments are raw vectors. A character value is never silently interpreted as a filename, password or byte sequence.
- A scalar algorithm name selects one documented algorithm. No partial matching (`match.arg()` is not used) or fallback to another algorithm.
- Hashes and HMACs are returned as raw vectors. Hex formatting belongs in an explicit conversion at the call site.
- AES keys must be exactly 16, 24 or 32 bytes; CBC IVs exactly 16 bytes; data length a multiple of 16 bytes.
- CBC functions return raw data of the same length and do not mutate R input objects. They do not add or strip PKCS#7 padding.
- Empty hash and HMAC inputs are valid. Empty CBC input produces an empty result after parameter validation.
- Equal-length comparison uses a timing-resistant native operation. Unequal lengths return `FALSE`; length is not hidden.
- `crypt_info()` follows `komp_info()`: a list with `version` (character), `abi_version`, `algorithms` (those enabled in this build), `vendored` (a data frame of `source`, `version`, reported from the compiled library) and `build_flags`. Never keys or internal addresses.

These functions operate on supplied keys. They do not turn a password into an encryption key automatically. CBC provides confidentiality only; its documentation and examples must make authentication the caller's explicit responsibility.

File hashing and R connection wrappers are later conveniences. The C API supplies incremental processing from the outset so native consumers need not concatenate large inputs.

## 8. Native interface and R package integration

There are two consumer shapes in the family, and both are supported from 0.1.

### 8.1 The public header

`inst/include/zucrypt.h` declares plain C functions, standalone per §3. Its vocabulary:

- `zuc_status`: `ZUC_OK = 0`, then errors — `ZUC_ERR_INVALID_ARGUMENT`, `ZUC_ERR_UNSUPPORTED`, `ZUC_ERR_BAD_LENGTH`, `ZUC_ERR_OVERLAP`, `ZUC_ERR_MEMORY`, `ZUC_ERR_BACKEND`, `ZUC_ERR_ABI`, `ZUC_ERR_INTERNAL`. No negative value is ever returned, so `if (st)` reliably means "not success". `zuc_status_string()` covers every enumerator and never returns `NULL`; a test asserts this.
- `zuc_alg`: fixed-width identifiers for SHA-1, SHA-256/384/512 and AES-128/192/256. Values are permanent; an algorithm compiled out keeps its number and reports unavailable.
- Opaque handles: `zuc_hash`, `zuc_hmac`, `zuc_aes`. Provider-allocated, destroyed only by provider functions.
- One-shot and incremental hash and HMAC (`new`, `update`, `finish`, `reset`, `free`); AES key context creation validating 16/24/32-byte keys; block-aligned CBC with an explicit, resettable chaining state; ECB for compatibility; constant-time compare; secure zero; backend information.
- Every options or information struct carries a leading `uint32_t struct_size` with a `ZUC_*_REQUIRED_SIZE` macro giving the prefix the core dereferences — never the full current `sizeof`, or every appended field is a breaking change for a consumer built against an older header.
- Functions return status codes and do not raise R errors, allocate R objects or invoke R callbacks. Overlap: exact in-place operation is permitted where the backend supports it and rejected with `ZUC_ERR_OVERLAP` otherwise; partial overlap is always rejected.
- For CBC streaming, the mutable chaining state is documented separately from the R wrapper's immutable input IV. Office callers reset it at the segment boundaries the file format requires.

### 8.2 Shape one: the registered function table (`zuhttp`-style)

`inst/include/zucrypt-r.h` includes `zucrypt.h`, then adds the one thing that must know about R: how to reach the table. It defines `zucrypt_api_v1` — leading `uint32_t abi_version` and `uint32_t struct_size`, then function pointers mirroring §8.1 — and a `static inline const zucrypt_api_v1 *zucrypt_api(void)` that resolves `R_GetCCallable("zucrypt", "zucrypt_get_api")` once, through a union rather than a function-pointer cast (`-Wcast-function-type-mismatch` under `-Werror` is a build failure *for the consumer*), passes `ZUCRYPT_ABI_VERSION`, and caches the result. `static inline`, not `static`: a header-defined plain `static` is an unused-function error in every consumer translation unit that includes the header without calling it.

Resolution is lazy, on first use. `Imports: zucrypt` does not load the namespace unless the consumer's `NAMESPACE` also carries a real `importFrom()`; resolving inside the consumer's `R_init_` can therefore fail because the DLL is not loaded yet.

`zucrypt_get_api(requested)` returns `NULL` for an unsupported major version, so a mismatch is a clean error at the call site rather than a call through a garbage pointer. Two discriminators, as in `zuxml.h`: `struct_size` versions the *table*, and fields are only ever appended; the registered callable *name* versions every other type in the header, because `struct_size` cannot see a layout change in an options struct and R does not rebuild `LinkingTo` dependents on upgrade. Any such change renames the callable so an old consumer fails loudly at `R_GetCCallable()` instead of smashing its stack.

"Fails loudly" is literal: `R_GetCCallable()` does not return `NULL` for a callable that is not registered, it raises an R error, which longjmps out of the consumer's C code. So `zucrypt_api()` returns `NULL` only for a version mismatch; a missing or too-old `zucrypt` never reaches the `NULL` check. A consumer should therefore resolve the table before it acquires anything a longjmp would strand. `zucrypt-r.h` and `?zucrypt_c_api` currently say otherwise (#36).

The consumer's `DESCRIPTION` needs `Imports: zucrypt` and `LinkingTo: zucrypt`; `LinkingTo` alone supplies headers and links nothing. The accessor is registered from `R_init_zucrypt` with `R_RegisterCCallable("zucrypt", "zucrypt_get_api", …)` after the backend is initialised, so a consumer that reaches the table can rely on it.

### 8.3 Shape two: the static archive (`zuxlsx`-style)

`src/Makevars` builds `libzucrypt.a` beside the shared object — the `all: $(SHLIB) libzucrypt.a` pattern, with `all` as the first target — and `src/install.libs.R` installs it to the installed package's `lib/` (there is no `inst/lib/` in the sources). `zuxml` does the same; `zukomp` installs under `lib${R_ARCH}/`, the family's convergence target (#33). `install.libs.R` also has to install the shared object itself: defining that file stops R doing it. The archive installs to a single arch-neutral path, which every current platform needs; it would have to move under `R_ARCH` before a multi-arch installation could be supported.

The archive holds the R-free core: the adapter objects and the vendored crypto objects, compiled with `$(ALL_CFLAGS)` so they are position-independent. **No R glue is in it** — `test-linking.R` greps the archive for `R_init_`, `zucrypt_` and any R symbol and expects none — and no upstream header is installed. That is the departure from `zukomp`/`zuxml`, whose archives are raw miniz and Expat with `miniz.h`/`expat.h` installed beside them. It is deliberate: a consumer of those must reproduce the provider's define set (`XML_STATIC`, `MINIZ_NO_ZLIB_COMPATIBLE_NAMES`) or its declarations describe a different library. PSA headers are worse — sizes and key-identifier types are generated from the configuration — so a consumer of `libzucrypt.a` sees `zucrypt.h` only and there is no define to match.

The consumer recipe is `zuxlsx`'s: `LinkingTo: zucrypt` for the header; a `configure`/`configure.win` that resolves `system.file("lib", package = "zucrypt")` and substitutes it into `src/Makevars.in` as a **single-quoted** `PKG_LIBS` entry (a library path with a space, the norm on Windows, otherwise reaches the linker as two arguments); a failure message naming `pak::pak("pedrobtz/zucrypt")` when the archive is absent; no `Imports:`, no GNU make. `zucrypt` itself needs no `configure`.

Consequences this shape has and the table does not:

- The consumer's shared object contains its own copy of the backend. Symbol hiding (§4) is what keeps that copy private.
- A `zucrypt` upgrade does nothing to an installed consumer until the consumer is rebuilt. The consumer should report the versions it actually linked (`zuxlsx_native()` does this for Expat and miniz by calling a version function, not reading a macro, so a header on the path without the archive behind it fails at link time).
- Backend initialisation is the consumer's: `zuc_init()`/`zuc_shutdown()` are in the archive and reference-counted, and the archive never touches R, so the consumer decides when to call them (its `R_init_`, or lazily on first use).

### 8.4 Threads

API resolution and backend initialisation happen on the R main thread. In 0.1 all calls are main-thread only. This is stricter than `zukomp` §19 ("distinct streams usable concurrently on distinct threads; one object, one thread at a time"), and stated so a consumer designed against `zukomp`'s promise does not assume it here: PSA's global key store needs upstream's threading option, which needs pthreads, and that is not a 0.1 build. Relax it only after initialisation, locking and shutdown are verified. R wrappers clean up on both errors and interrupts. Do not globally tear down crypto state while consumer contexts remain alive.

### 8.5 Enforced by tests

`test-abi.R` (against the shared object): no `mbedtls_`/`psa_`/OpenSSL-ABI name exported; the installed header leaks no upstream or R vocabulary, carries its guard and C++ wrapper; the backend is compiled in at the pinned version. `test-linking.R` (against the installed package; skipped under `load_all()`): `lib/libzucrypt.a` and both headers exist in the installed package after the install-step merge; the archive defines every `zuc_*` entry point a consumer needs and no R symbol. `tests/consumer/zucrypttest` is a package consuming shape one, `.Rbuildignore`d and built only by `consumer.yaml`; a C program linking the archive covers shape two (`tools/check-linking.sh`). [Writing R Extensions: native routines in other packages](https://cran.r-project.org/doc/manuals/r-release/R-exts.html#Linking-to-native-routines-in-other-packages).

## 9. Excel integration contract

The user-facing goal is a proposed call such as:

```r
zuxlsx::read_xlsx("risk.xlsx", password = password)
```

This is a target integration, not an existing function guarantee. `zucrypt` itself does not initially export `office_decrypt()` or `office_info()`.

`zuxlsx` links `zucrypt` as the §8.3 archive — it has no `Imports:` and its design forbids adding one — so the adapter in `zuxlsx` calls `zuc_*` directly. Today `zuxlsx` opens workbooks by path (`xlsxioread_open()`); the decrypted package is handed over with `xlsxioread_open_memory()`, which the vendored xlsxio already provides, so no plaintext temporary file is needed for the bounded case. `zuxlsx_native()` should grow a `zucrypt` row reporting the linked adapter and backend versions, for the reason §8.3 gives.

For supported encrypted OOXML, the Office adapter performs this sequence:

1. Inspect file signatures rather than trusting the extension.
2. Read the outer OLE Compound File Binary container.
3. Locate and validate `EncryptionInfo` and `EncryptedPackage`.
4. Parse the declared encryption profile and reject unsupported combinations.
5. Convert the password to the required UTF-16LE representation without normalization or truncation; reject invalid input explicitly.
6. Derive keys and verify the password according to that profile.
7. Validate Agile payload integrity before exposing successful plaintext to the workbook reader.
8. Recover the package bytes and pass them to ZIP and workbook processing.

The crypto package provides the primitives; the Office adapter owns iteration counts, salts, block-key constants, key expansion, password verifiers, segment IV derivation and payload-length rules. Keep the iterative derivation loop in native code, using one reusable incremental hash context to avoid an R call or allocation for every iteration — which is why §8.1 has `reset` on every context.

Common Agile AES-CBC profiles are the first target. Standard AES support was planned to follow, using ECB with the scheme's SHA-1 derivation; it has no consumer since zuxlsx §21c (2026-09-20) made agile the only scope, and ECB's removal is proposed in #29. Standard password verification must not be described as full payload authentication. The detailed algorithms are illustrated by the independent [Agile implementation](https://msoffcrypto-tool.readthedocs.io/en/latest/_modules/msoffcrypto/method/ecma376_agile.html) and [Standard implementation](https://msoffcrypto-tool.readthedocs.io/en/latest/_modules/msoffcrypto/method/ecma376_standard.html); Microsoft's MS-OFFCRYPTO specification remains the implementation authority.

Start with a bounded in-memory decrypted package and an explicit maximum output size. Larger-file support can use a seekable backing store, but any plaintext temporary file must be an explicit policy choice with restrictive permissions and cleanup on failure. Decryption does not automatically provide a streaming ZIP reader.

The CFB reader must validate sector bounds, allocation-chain cycles, mini-stream handling, stream sizes and integer arithmetic. Limit password iteration counts, metadata size and output size before doing expensive work. ZIP decompression limits remain necessary after decryption.

Worksheet protection, passwords to modify a workbook, legacy `.xls` RC4/XOR encryption, rights-managed documents, certificate-based decryption and Office encryption writing are outside the first integration. Decrypting `.xlsb`, `.docx` or `.pptx` containers would not imply that `zuxlsx` can interpret their contents.

## 10. Relationship with zuhttp

Retain the existing native OS TLS backend. Add Mbed TLS as a separately tested build option or backend where it solves a concrete portability requirement. Backend selection must not occur as an automatic retry after certificate verification fails.

`zuhttp`'s roadmap already records the spike and frames it correctly: it is mitigation for the risk that Apple removes Secure Transport (its R-15), not a TLS 1.3 feature, and its exit criteria are a trimmed source size against a ≤ 2 MB tarball budget, composition over a caller-owned socket, and handing the peer chain to `SecTrustEvaluateWithError` so trust stays native. `zucrypt`'s Stage 1 measurements — trimmed source size, installed object size — are direct inputs to that first criterion and should be recorded in a form `zuhttp` can cite.

Initially, align `zuhttp` and `zucrypt` on compatible upstream releases, patch policy and update tooling: the same `manifest.tsv` rows and `tools/patches/` files, so one upstream advisory is one change in each repository. Each may privately compile its required components. This duplicates some crypto code, but avoids prematurely exposing a broad upstream ABI.

The small `zucrypt` C interface is not sufficient to link an unmodified Mbed TLS engine against it: TLS requires additional crypto operations, initialization and compatible configuration. Do not describe the initial architecture as a single shared compiled crypto provider.

If duplication becomes material, evaluate a dedicated backend package with a deliberately designed TLS/crypto interface and one initialization owner. Measure source archive size, installed binary size, update burden and loading behaviour before making that change. Keep upstream symbols private in either design.

`zuhttp` owns CA discovery, corporate trust configuration, hostname verification, client certificates, protocol policy, sockets and network error handling. Vendoring Mbed TLS does not automatically inherit native OS trust policy. Its application must supply trusted authorities. [Mbed TLS server authentication](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/mbedtls-tutorial/#server-authentication).

## 11. Errors and resource handling

R conditions follow the family shape: class `c(<specific>, "zucrypt_error", "error", "condition")`, constructed in R by a `zucrypt_abort()` helper from a status the C layer returned. Specific classes, keyed by C enumerator name:

| `zuc_status` | Condition class |
| --- | --- |
| `ZUC_ERR_INVALID_ARGUMENT` | `zucrypt_invalid_argument` |
| `ZUC_ERR_UNSUPPORTED` | `zucrypt_unsupported_algorithm` |
| `ZUC_ERR_BAD_LENGTH` | `zucrypt_bad_length` |
| `ZUC_ERR_MEMORY` | `zucrypt_memory_error` |
| `ZUC_ERR_BACKEND` | `zucrypt_backend_error` |
| `ZUC_ERR_ABI` | `zucrypt_abi_mismatch` |
| `ZUC_ERR_INTERNAL` | `zucrypt_internal_error` |

The mapping is keyed by name and the names are fetched from C (`.Call(zucrypt_status_codes)`) so renumbering cannot remap a condition. Every condition carries `algorithm` and `native_status` fields even when a failure knows only one of them, so the shape never has to be retrofitted. Messages are one line, phrased for the person who hit them, and are allowed to be reworded — tests assert on class. Never attach keys, passwords, IV-derived secret state or plaintext to conditions.

Incorrect passwords, malformed Office containers and integrity failures are conditions owned by the Office adapter (`zuxlsx_*`). Where the format cannot distinguish causes reliably, report authentication failure without inventing a precise diagnosis.

In C: validate lengths and arithmetic before allocation, through checked helpers — never a bare `size *= 2`. Destroy partial contexts after any failed initialization. Wipe owned native key buffers and backend state through suitable cleanup primitives. A context that must survive `R_CheckUserInterrupt()` inside a long hash or derivation loop is owned by an external pointer with a finalizer for the duration, not a bare local — `zukomp` leaked one stream per interrupted decompression before it learned this. R may retain copies of raw vectors and strings; do not promise complete erasure from process memory, swap or crash dumps.

Use backend primitives rather than reimplementing ciphers or hashes. Any future cryptographic randomness must use properly initialized platform entropy or a securely seeded backend generator, never R's statistical RNG.

## 12. Testing and release gates

| Layer | Required evidence |
| --- | --- |
| Primitives | Published known-answer vectors for every enabled hash, HMAC, key size and cipher mode, committed as fixtures with provenance in a `MANIFEST.tsv` |
| Stateful operations | One-shot versus incremental equivalence at every split point via an always-compiled `zucrypt_test_*` harness, reset behaviour, boundary lengths and context cleanup |
| R interface | Raw-type validation, key/IV lengths, empty input, input immutability and structured conditions asserted by class |
| C interface | `tests/consumer/zucrypttest` for the table; a C program linking `libzucrypt.a` for the archive; ABI rejection; ownership rules; package loading |
| Installed layout | `test-abi.R` and `test-linking.R` as in §8.5 |
| Backend isolation | Load beside `openssl`, other Mbed consumers and `zuhttp` in both orders without symbol interference |
| Office integration | Fixtures from Excel and an independent implementation, with recorded provenance and expected package bytes |
| Negative Office cases | Wrong password, altered ciphertext/HMAC, unsupported profiles, Unicode passwords, truncation and malformed CFB chains |
| Platforms | R package build/check on Windows, macOS and Linux, including ARM64 where supported, plus the CRAN-like containers |

Fuzz the Office parser separately from the primitive wrappers and run native code under address/undefined-behaviour sanitizers. Include files spanning the Agile segment boundary and partial final segments. Bound performance tests for intentionally large spin counts.

An encrypt/decrypt round trip alone is insufficient: the same implementation can contain matching mistakes. Run independent compatibility checks. Tests must work offline using synthetic fixtures with known passwords and appropriate redistribution permission.

## 13. Implementation sequence

1. **Backend spike:** pin the release pair, validate the required algorithm profile, settle the `Makevars` object list and configuration header, decide the entropy/initialisation policy (§4), build on target platforms, measure source/binary size and establish symbol isolation.
2. **Core package:** implement the R-free adapter and the archive, the R functions, the versioned table, status mapping and lifecycle management; pass primitive, layout and consumer tests for both shapes.
3. **Agile Excel integration:** implement the bounded CFB/Office adapter in `zuxlsx` against the archive, including password and integrity checks; feed decrypted bytes into xlsxio through `xlsxioread_open_memory()`.
4. **Standard Excel integration:** add the AES-ECB compatibility path and document its integrity limitations. *No consumer since zuxlsx §21c (2026-09-20), which scoped decryption to agile only; removal of ECB is proposed in #29.*
5. **HTTP evaluation:** prototype the Mbed TLS backend in `zuhttp` on the shared manifest rows, including trust integration, while retaining native OS TLS.
6. **Measured expansion:** decide whether authenticated encryption, KDF utilities, larger-file handling or a shared compiled backend justify additional API surface.

`roadmap.md` breaks steps 1–2 into stages with exit criteria. The core can be released independently, but the package family's first end-to-end success criterion is reading a supported password-encrypted Excel workbook without Java, Python or a system OpenSSL dependency.

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

## 14. Decisions left for implementation

- Exact Mbed/TF-PSA release pair and minimal build configuration.
- The `OBJECTS` list and configuration-header mechanism that a portable `Makevars` needs for that trim, and the resulting supported R/compiler versions.
- Whether the pinned release's `psa_crypto_init()` needs an entropy source for this profile, and therefore which of §4's two configurations applies.
- Default Office resource limits, informed by representative workbooks — in `zuxlsx`.
- Suitable CFB parser reuse versus a narrowly scoped implementation, assessed for license, robustness and size — in `zuxlsx`.
- Whether a shared compiled backend produces enough measured benefit to justify its additional coupling.

Resolved since the first draft: build tooling (`Makevars`, §4); the byte-source question for handing decrypted bytes to xlsxio (`xlsxioread_open_memory()`, §9); the consumer linkage model (both shapes, §8).

These are implementation choices to resolve with evidence. They do not change the core boundary: `zucrypt` owns reusable cryptography; document readers own document formats; `zuhttp` owns TLS and trust integration.
