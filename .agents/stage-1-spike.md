# Stage 1 backend spike: what was measured, and what it decided

Date: 2026-09-20.
Answers the four open backend decisions in [design.md](design.md) §14 and the
work items of [roadmap.md](roadmap.md) Stage 1.

Everything below is evidence, not intent. Where a number is given it was
measured on the platform named; where a decision is given, the alternative it
beat is named too.

## 1. The pinned release pair

| | |
|---|---|
| Source | TF-PSA-Crypto `tf-psa-crypto-1.1.1`, commit `a0632be9` |
| Archive | `tf-psa-crypto-1.1.1.tar.bz2`, sha256 `3236f70e…a480e` |
| Licence | Apache-2.0 (upstream is dual Apache-2.0 OR GPL-2.0-or-later) |
| Support | 1.1 is an LTS branch, supported until at least March 2029 |

**Mbed TLS is not vendored at all.** The design allowed for a second manifest
row "if any file of it is needed", and none is: in the 4.x architecture
TF-PSA-Crypto is the whole cryptography library, and Mbed TLS supplies only
X.509 and TLS, which this package does not build. The `mbedtls/` headers in
the tree are TF-PSA-Crypto's own compatibility headers, shipped in its
archive.

The design named "Mbed TLS 4.1 LTS" as the candidate; the matching crypto
release is TF-PSA-Crypto 1.1, and 1.1.1 is its current patch release. The
version pairing is why `vendor-upstream.yaml` watches TF-PSA-Crypto only, not
both repositories: a new Mbed TLS 4.1.x with no TF-PSA-Crypto change is not a
reason to move.

## 2. The minimal configuration

`src/zuc_crypto_config.h` replaces upstream's `psa/crypto_config.h` entirely,
through `-DTF_PSA_CRYPTO_CONFIG_FILE` in `src/Makevars`. Eleven defines, all
listed in the manifest's `defines` column and cross-checked by
`tools/vendor/verify`:

    SHA-1, SHA-256, SHA-384, SHA-512
    HMAC (algorithm and key type)
    AES with CBC-no-padding and ECB-no-padding
    MBEDTLS_PSA_CRYPTO_C, MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

Nothing else. No public-key cryptography, no AEAD, no key derivation, no
ChaCha20, no SHA-3, no SHA-224, no PKCS#7 padding, no X.509, no TLS, no
persistent key storage. Everything is disabled through upstream's own
configuration mechanism, and no upstream file is edited in place. When this
section was written `tools/patches/` was empty; later in the same stage
(515df48) it gained `0001-avoid-zero-size-pubkey-array.patch`, which removes a
zero-size array upstream declares when no public-key algorithm is enabled — a
GNU extension that `-Wpedantic` reports.

The probe asserted the negative side too: `PSA_ALG_MD5` and `PSA_ALG_SHA_224`
both return `PSA_ERROR_NOT_SUPPORTED` rather than working by accident.

## 3. The object list, and how it was derived

Upstream's own build compiles every file in `core/`, `drivers/builtin/src/`,
`platform/`, `utilities/`, `extras/` and `dispatch/` and lets the
configuration guard the unused ones down to empty translation units. Under the
configuration above that is **77 files, of which 18 define a single symbol**.

The method, which is also how to redo it after a release bump:

1. Compile all 77 sources with the config header.
2. Keep those whose object defines anything (`nm -g`, count the `[TDBSR]`
   lines). 18 do.
3. Take the header closure of those 18 with `cc -MM`. 108 files.
4. Add upstream's `LICENSE`. 109 files, 2.6 MB.

The result is `tools/vendor/keep/tf-psa-crypto.txt`, the object list is
`VENDOR_OBJECTS` in `src/Makevars`, and `tools/vendor/verify` fails if the two
disagree — a vendored `.c` that no object names is dead weight in the tarball,
and an object with no source is a build failure on a fresh clone.

`psa_crypto_rsa.c` is in the list and looks wrong, since no public-key
algorithm is enabled. It compiles to two key-management helpers that
`psa_crypto.c` calls unconditionally. Dropping it is a link error, not a
smaller build.

**No CMake, no Python, no Perl, no network.** The release archive ships the
generated files (`psa_crypto_driver_wrappers_no_static.c`,
`psa_crypto_driver_wrappers.h`, `tf_psa_crypto_config_check_*.h`), which is
what upstream's `crypto-library.make` would otherwise invoke
`generate_driver_wrappers.py` to produce. `SystemRequirements` therefore names
a C99 compiler and nothing else.

## 4. The layout is flattened, and that is not tidiness

`R CMD check` rejects a tarball path over 100 bytes, and Windows has the same
practical limit. Upstream's own

    drivers/builtin/include/mbedtls/private/crypto_adjust_config_enable_builtins.h

is over it before `zucrypt/src/vendor/…` is prefixed, and the first build of
this stage produced exactly that NOTE. The vendored tree is therefore two
directories — `inc/` for the header hierarchies and `lib/` for sources and
their neighbouring private headers — which brings the longest path to 96
bytes. `tools/vendor/verify` measures every path, so a release that adds a
longer name fails with the reason attached instead of as a check NOTE someone
has to trace back.

Within `inc/` the `mbedtls/`, `psa/` and `tf-psa-crypto/` prefixes are
upstream's own `#include` paths and are untouched.

## 5. Entropy and initialisation

**Decision: external RNG, no entropy module.**

`MBEDTLS_PSA_CRYPTO_C` requires one of CTR-DRBG, HMAC-DRBG or an external RNG
(`core/tf_psa_crypto_check_config.h`). External is the smallest: it pulls in
no entropy module, no DRBG and no NV-seed storage.

The question the design left open was whether `psa_crypto_init()` needs an
entropy source for a hash/MAC/cipher-only profile. **It does not.** The probe
wired `mbedtls_psa_external_get_random()` to return
`PSA_ERROR_INSUFFICIENT_ENTROPY` unconditionally, and `psa_crypto_init()`
still returned `PSA_SUCCESS` and every algorithm still produced the right
answer. No operation in the profile consumes randomness: CBC takes its IV from
the caller.

The symbol is still *referenced* by `psa_cipher_encrypt()` and
`psa_generate_key()` inside `psa_crypto.c`, so it has to link. `src/zuc_random.c`
supplies it from the operating system rather than as a failing stub — a stub
would be an accurate description of today and a trap the first time anything
needs a random byte. Backend selection is in the preprocessor, the way `zuxml`
selects Expat's, because a portable `Makevars` has no conditional to choose a
source file with and there is no `configure` to probe with:

| Platform | Source |
|---|---|
| Windows | `rand_s` |
| macOS, *BSD | `arc4random_buf` |
| glibc ≥ 2.25 | `getrandom` |
| anything else (musl, older glibc, Solaris) | `/dev/urandom` |

`crypt_info()$build_flags$random_backend` reports which one was compiled in,
and `tests/testthat/test-interface.R` asserts it is one of those four — a
preprocessor chain that fell through would report an empty string.

## 6. Hardware acceleration: off, uniformly

`MBEDTLS_HAVE_ASM`, `MBEDTLS_AESNI_C`, `MBEDTLS_AESCE_C` and the
`SHA*_USE_*_CRYPTO_IF_PRESENT` options are set only by upstream's default
`crypto_config.h`, which `src/zuc_crypto_config.h` replaces. None is
auto-enabled by the `crypto_adjust_config_*` headers — checked, not assumed.
Every platform runs the same C and produces the same bytes, which is the
stronger half of design §4's "results must not vary".

This is the conservative choice and it is revisitable: the alternative is
measurably faster AES on x86-64 and aarch64, and it costs a per-platform
result comparison that Stage 2's KAT suite would be the right place to run.

## 7. Symbol isolation

`PKG_CFLAGS = $(C_VISIBILITY)` — R's own substitution for
`-fvisibility=hidden`, empty on a compiler without it.

Measured on the installed shared object (macOS x86-64, `nm -gU`):

    exported symbols: 1
    _R_init_zucrypt

No `mbedtls_*`, no `psa_*`, no OpenSSL-ABI name. `tests/testthat/test-abi.R`
asserts all three permanently, reading the *dynamic* symbol table — `nm -D` on
ELF, `nm -gU` on Mach-O. Plain `nm` on ELF reads `.symtab`, which still holds
every hidden symbol, and auditing that would report a leak where there is
none.

Windows is skipped rather than approximated: a PE DLL exports only what its
export table names and each module has its own namespace, so the property is a
property of the format there.

## 8. Measurements

macOS 26.2, x86-64, Apple clang 17:

| | |
|---|---|
| Vendored tree | 2.6 MB, 109 files |
| Source tarball | 632 KB |
| Installed `zucrypt.so` | 118 KB |
| `R CMD INSTALL`, cold | 4.4 s |

For comparison, the upstream archive is 55 MB unpacked, of which `tests/` is
31 MB and `drivers/` 9.4 MB.

The other platforms' numbers come from CI, which is where this stage is
actually finished.

## 9. Known check NOTE

`checking pragmas in C/C++ headers and code` reports
`lib/constant_time_impl.h` and `lib/platform_util.c`. Both are upstream's, and
both are narrow: `-Wvla`, `-Wredundant-decls`, and MSVC's C4146 for unary
minus on an unsigned type — the last of which is the *point* of a
constant-time implementation. They are not ours to remove, removing them by
patch would mean carrying a patch forever for a diagnostic we do not see, and
CI runs with `error_on = "warning"`, so a NOTE does not fail the check. Revisit
only if CRAN objects at submission time.

## 10. Verification of the profile

A standalone C probe (not shipped; it becomes `test-kat.R` in Stage 2) linked
the 18 objects and checked published vectors:

    SHA-1("abc")             FIPS 180-2          OK
    SHA-256("abc")           FIPS 180-2          OK
    SHA-384("abc")           FIPS 180-2          OK
    SHA-512("abc")           FIPS 180-2          OK
    SHA-256 incremental      split "a" + "bc"    OK, equals one-shot
    HMAC-SHA-256             RFC 4231 case 1     OK
    AES-128-CBC              SP 800-38A F.2.1    OK
    AES-128-ECB              SP 800-38A F.1.1    OK
    AES-256 key import                           OK
    MD5, SHA-224                                 NOT_SUPPORTED, as intended

Stage 2 owns the real KAT suite with committed fixtures and provenance. This
was enough to decide the configuration.

---

## 11. Addendum: the security-update rehearsal (Stage 5)

Roadmap Stage 5 asks for the upstream-update procedure to be proved before it
is needed under time pressure. Run on 2026-09-20, against the same pinned
release:

    sh tools/vendor/fetch      # downloads, verifies sha256, trims, patches
    sh tools/vendor/verify     # offline, checks everything against everything

`git status --porcelain src/vendor tools/vendor` was empty afterwards: the
tree, including the applied patch and the recorded checksums, is reproduced
byte for byte from the upstream archive. `verify` was clean.

So the procedure for acting on a `vendor-upstream.yaml` notification is:

1. Edit the `tag`, `commit`, `version_string`, `archive` and `archive_sha256`
   columns of `tools/vendor/manifest.tsv`.
2. `sh tools/vendor/fetch`, which re-derives the tree and re-records the
   checksums.
3. Re-derive the trim if upstream's file list moved — §3 above has the method,
   and `verify` fails if the keep list and the `OBJECTS` list disagree.
4. Update the version literal in `tests/testthat/test-abi.R`; `verify` fails
   until it matches.
5. Re-check each patch in `tools/patches/` still applies and is still needed.
   The one that exists today should be dropped as soon as a release carries
   the fix.
6. `sh tools/vendor/verify`, then the full CI run.

## 12. Addendum: the R floor is now measured (Stage 5)

`Depends: R (>= 4.1)` was inherited from the family and never checked: the
`release` and `oldrel-1` legs prove the package works on two recent versions
and say nothing about the floor. `R-CMD-check.yaml` now carries an explicit
`ubuntu-latest / 4.1` leg, so the declared minimum is a measurement.

The compiler requirement is C99 and nothing else. No CMake, no Python, no
Perl, no GNU make, and no system cryptographic library — `SystemRequirements`
says so, and every element of that claim is exercised by an ordinary source
install on each CI platform.
