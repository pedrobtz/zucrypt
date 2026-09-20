# zucrypt: design

Status: proposed design, not an implemented API.  
Date: 2026-09-19.  
Initial application: cryptographic support for password-encrypted Excel input.  
Related packages: `zuxlsx`, `zukomp`, `zuxml`, and `zuhttp`.

## 1. Purpose

`zucrypt` provides a small, predictable cryptographic foundation for R packages, backed by vendored code from the Mbed TLS ecosystem. It exposes a narrow R interface and a versioned C interface, with no requirement for an installed OpenSSL library, Java, or Python at runtime.

The first integration is reading password-encrypted `.xlsx` files through `zuxlsx`. A second consumer is `zuhttp`, which may use the same upstream cryptography ecosystem for a vendored TLS backend while retaining its existing native OS TLS implementation.

The package's value is straightforward installation, controlled algorithm support, and reusable native interfaces. It does not claim that R lacks cryptography: `openssl` already provides broad cryptographic functionality, `sodium` provides modern encryption interfaces, and encrypted Excel can already be read through Java or Python integrations. The opportunity is a focused native foundation that fits the `zu*` package family. See the [openssl manual](https://jeroen.r-universe.dev/openssl/doc/manual.html), [sodium documentation](https://docs.ropensci.org/sodium/), [xlsx manual](https://cran.r-project.org/web/packages/xlsx/refman/xlsx.html), and [rpxl](https://github.com/epicentre-msf/rpxl).

## 2. Main decisions

| Decision | Rationale |
| --- | --- |
| Use the Mbed TLS ecosystem rather than BearSSL | Align document cryptography with the potential TLS backend for `zuhttp` |
| Build only the crypto components in `zucrypt` | Excel cryptography does not need TLS or certificate processing |
| Keep Office parsing and decryption orchestration in `zuxlsx` initially | Avoid making HTTP or other crypto consumers depend on Office, XML or ZIP code |
| Expose a small wrapper API, not upstream types | Isolate consumers from upstream configuration and ABI changes |
| Support raw bytes explicitly | Avoid implicit text encoding, serialization or path interpretation |
| Treat cipher operations as low-level interfaces | They do not by themselves define a secure encrypted-file format |
| Share upstream provenance with `zuhttp` first | A single shared compiled backend is a separate, deferred engineering decision |

If Office support later serves several readers, extract it from `zuxlsx` into a dedicated document package. Do not introduce that extra package before there is a second consumer.

## 3. Backend and vendoring

Use a supported Mbed TLS release family, with Mbed TLS 4.1 LTS as the initial candidate. Pin an exact release and its corresponding TF-PSA-Crypto dependency during implementation; never build from a moving development branch. The upstream branch policy currently lists 4.1 support through March 2029. [Mbed TLS support policy](https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md).

In the 4.x architecture, TF-PSA-Crypto supplies cryptography, while Mbed TLS supplies separate X.509 and TLS libraries. `zucrypt` vendors and builds the required crypto subset. `zuhttp` may additionally build X.509 and TLS. Prefer supported PSA interfaces where they cover the required operations; keep any necessary release-specific calls behind the private adapter. [Mbed TLS architecture and build documentation](https://github.com/Mbed-TLS/mbedtls), [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto).

Vendoring requirements:

- Record release, source URL, checksum, dependency versions, configuration and local patches in a manifest.
- Use official source archives containing generated files. Installation must not download dependencies or generate sources using Python or Perl.
- Maintain a reproducible source-selection and update procedure. Use upstream configuration to disable features; avoid rewriting cryptographic internals.
- Preserve upstream license and notice files. Select the Apache-2.0 option where offered and document the licenses of all included files.
- Hide or namespace upstream symbols so independent vendored copies cannot accidentally bind to one another.
- Keep the enabled feature set consistent across supported platforms. Hardware acceleration may vary; observable results must not.
- Ship security updates promptly. Vendored code does not receive fixes merely because the operating system is updated.

The build spike must establish whether the supported upstream CMake build or a maintained R `Makevars` integration gives the more reliable source installation. Do not claim an ordinary compiler is the only build requirement until this is demonstrated on all target platforms.

## 4. Dependency boundaries

| Package | Owns | Does not acquire through `zucrypt` |
| --- | --- | --- |
| `zucrypt` | Crypto primitives, state and native API | XML, ZIP, Office, sockets, TLS or trust stores |
| `zuxlsx` | Workbook interpretation; initially the Office encryption adapter and CFB reader | TLS |
| `zuxml` | XML parsing, reused for Agile encryption metadata | Cryptographic policy |
| `zukomp` | ZIP entry access and decompression after decryption | Office password handling |
| `zuhttp` | HTTP, sockets, TLS backend selection and certificate trust | Office processing |

The Office adapter may use `zuxml` and `zucrypt`; it must not create a reverse dependency from either package to `zuxlsx`.

## 5. Algorithm scope

The following is the required capability profile to validate against the pinned backend build, not a claim that every capability is enabled by its default configuration.

| Capability | Initial use | Exposure |
| --- | --- | --- |
| SHA-1 | Office compatibility | Explicit compatibility option |
| SHA-256, SHA-384, SHA-512 | Hashing, HMAC and Office derivation | R and C |
| HMAC with the supported hashes | Integrity checks and package integrations | R and C |
| AES-128/192/256-CBC without padding | Common Office Agile profiles | Advanced R interface and C |
| AES-128/192/256-ECB without padding | Office Standard AES support | C compatibility interface initially |
| Constant-time comparison for equal-length byte strings | Verifiers and authentication tags | R and C |
| Secure cleanup of native buffers | Keys and intermediate state | Internal |

SHA-1 and ECB are compatibility facilities. They are not defaults for new data formats. Their availability for document handling must not weaken `zuhttp`'s TLS policy.

Defer public authenticated-encryption, random-byte generation, PBKDF2, HKDF, signatures and key serialization until required by a concrete consumer. Add them through the same backend where supported. PBKDF2 is not a substitute for Office's specified password derivation.

There is no general `encrypt_file(password = ...)` in version 0.1. Such an interface requires a separately specified authenticated format, password KDF, nonce policy and reliable entropy source. Argon2 support is a separate decision.

## 6. Proposed R interface

```r
crypto_info()

hash_raw(data, algorithm = "sha256")
hmac_raw(data, key, algorithm = "sha256")
constant_time_equal(x, y)

# Advanced interoperability functions; no padding or authentication is added.
aes_cbc_encrypt_raw(data, key, iv)
aes_cbc_decrypt_raw(data, key, iv)
```

Contract:

- Binary arguments are raw vectors. A character value is never silently interpreted as a filename, password or byte sequence.
- A scalar algorithm name selects one documented algorithm. No partial matching or fallback to another algorithm.
- Hashes and HMACs are returned as raw vectors. Hex formatting belongs in an explicit conversion at the call site.
- AES keys must be exactly 16, 24 or 32 bytes; CBC IVs exactly 16 bytes; data length a multiple of 16 bytes.
- CBC functions return raw data of the same length and do not mutate R input objects. They do not add or strip PKCS#7 padding.
- Empty hash and HMAC inputs are valid. Empty CBC input produces an empty result after parameter validation.
- Equal-length comparison uses a timing-resistant native operation. Unequal lengths return `FALSE`; length is not hidden.
- `crypto_info()` reports backend versions, API version and enabled capabilities, never keys or internal addresses.

These functions operate on supplied keys. They do not turn a password into an encryption key automatically. CBC provides confidentiality only; its documentation and examples must make authentication the caller's explicit responsibility.

File hashing and R connection wrappers are later conveniences. The C API supplies incremental processing from the outset so native consumers need not concatenate large inputs.

## 7. Native interface and R package integration

Install a public header under `inst/include/zucrypt.h`. Export one registered API accessor returning a versioned table of function pointers. Consumers request a supported ABI version and check capability flags before use.

The table provides:

- One-shot and incremental hash/HMAC operations.
- AES key-context creation, block-aligned CBC operations and ECB compatibility operations.
- Constant-time comparison and cleanup functions.
- Explicit context destruction, status codes and backend information.

Use opaque context handles, fixed-width identifiers and `size_t` lengths. Do not expose PSA key identifiers, Mbed structures or upstream headers. Provider-allocated objects must be destroyed by provider functions. Functions return status codes and do not raise R errors, allocate R objects or invoke R callbacks. State whether overlapping buffers are supported; initially allow exact in-place native operation where implemented, and reject partial overlap.

For CBC streaming, document the mutable chaining state separately from the R wrapper's immutable input IV. Office callers must reset it at the segment boundaries required by the file format.

Register the accessor with `R_RegisterCCallable`; consumers resolve it with `R_GetCCallable`. A compiled consumer uses `LinkingTo: zucrypt` for the header and a runtime dependency such as `Imports: zucrypt`, with namespace loading arranged before resolution. `LinkingTo` alone supplies headers; it does not load another package or link its shared object. Avoid hard-coded links to an installed `zucrypt.so` or DLL. [Writing R Extensions: native routines in other packages](https://cran.r-project.org/doc/manuals/r-release/R-exts.html#Linking-to-native-routines-in-other-packages).

Resolve the API on the R main thread. Version 0.1 supports calls from that thread only; worker-thread use is deferred until backend initialization, locking and shutdown behaviour are verified. R wrappers clean up on both errors and interrupts. Do not globally tear down crypto state while consumer contexts remain alive.

## 8. Excel integration contract

The user-facing goal is a proposed call such as:

```r
zuxlsx::read_xlsx("risk.xlsx", password = password)
```

This is a target integration, not an existing function guarantee. `zucrypt` itself does not initially export `office_decrypt()` or `office_info()`.

For supported encrypted OOXML, the Office adapter performs this sequence:

1. Inspect file signatures rather than trusting the extension.
2. Read the outer OLE Compound File Binary container.
3. Locate and validate `EncryptionInfo` and `EncryptedPackage`.
4. Parse the declared encryption profile and reject unsupported combinations.
5. Convert the password to the required UTF-16LE representation without normalization or truncation; reject invalid input explicitly.
6. Derive keys and verify the password according to that profile.
7. Validate Agile payload integrity before exposing successful plaintext to the workbook reader.
8. Recover the package bytes and pass them to ZIP and workbook processing.

The crypto package provides the primitives; the Office adapter owns iteration counts, salts, block-key constants, key expansion, password verifiers, segment IV derivation and payload-length rules. Keep the iterative derivation loop in native code, using reusable hash contexts to avoid an R call or allocation for every iteration.

Common Agile AES-CBC profiles are the first target. Standard AES support follows and uses ECB with the scheme's SHA-1 derivation. Standard password verification must not be described as full payload authentication. The detailed algorithms are illustrated by the independent [Agile implementation](https://msoffcrypto-tool.readthedocs.io/en/latest/_modules/msoffcrypto/method/ecma376_agile.html) and [Standard implementation](https://msoffcrypto-tool.readthedocs.io/en/latest/_modules/msoffcrypto/method/ecma376_standard.html); Microsoft's MS-OFFCRYPTO specification remains the implementation authority.

Start with a bounded in-memory decrypted package and an explicit maximum output size. Larger-file support can use a seekable backing store, but any plaintext temporary file must be an explicit policy choice with restrictive permissions and cleanup on failure. Decryption does not automatically provide a streaming ZIP reader.

The CFB reader must validate sector bounds, allocation-chain cycles, mini-stream handling, stream sizes and integer arithmetic. Limit password iteration counts, metadata size and output size before doing expensive work. ZIP decompression limits remain necessary after decryption.

Worksheet protection, passwords to modify a workbook, legacy `.xls` RC4/XOR encryption, rights-managed documents, certificate-based decryption and Office encryption writing are outside the first integration. Decrypting `.xlsb`, `.docx` or `.pptx` containers would not imply that `zuxlsx` can interpret their contents.

## 9. Relationship with zuhttp

Retain the existing native OS TLS backend. Add Mbed TLS as a separately tested build option or backend where it solves a concrete portability requirement. Backend selection must not occur as an automatic retry after certificate verification fails.

Initially, align `zuhttp` and `zucrypt` on compatible upstream releases, patch policy and update tooling. Each may privately compile its required components. This duplicates some crypto code, but avoids prematurely exposing a broad upstream ABI.

The small `zucrypt` C interface is not sufficient to link an unmodified Mbed TLS engine against it: TLS requires additional crypto operations, initialization and compatible configuration. Do not describe the initial architecture as a single shared compiled crypto provider.

If duplication becomes material, evaluate a dedicated backend package with a deliberately designed TLS/crypto interface and one initialization owner. Measure source archive size, installed binary size, update burden and loading behaviour before making that change. Keep upstream symbols private in either design.

`zuhttp` owns CA discovery, corporate trust configuration, hostname verification, client certificates, protocol policy, sockets and network error handling. Vendoring Mbed TLS does not automatically inherit native OS trust policy. Its application must supply trusted authorities. [Mbed TLS server authentication](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/mbedtls-tutorial/#server-authentication).

## 10. Errors and resource handling

R conditions inherit from `zucrypt_error` and include a stable error code plus a concise message. Initial codes cover invalid arguments, unsupported algorithms, allocation failure, backend failure and API-version mismatch. Never attach keys, passwords, IV-derived secret state or plaintext to conditions.

Incorrect passwords, malformed Office containers and integrity failures are conditions owned by the Office adapter. Where the format cannot distinguish causes reliably, report authentication failure without inventing a precise diagnosis.

Validate lengths and arithmetic before allocation. Destroy partial contexts after any failed initialization. Wipe owned native key buffers and backend state through suitable cleanup primitives. R may retain copies of raw vectors and strings; do not promise complete erasure from process memory, swap or crash dumps.

Use backend primitives rather than reimplementing ciphers or hashes. Any future cryptographic randomness must use properly initialized platform entropy or a securely seeded backend generator, never R's statistical RNG.

## 11. Testing and release gates

| Layer | Required evidence |
| --- | --- |
| Primitives | Published known-answer vectors for every enabled hash, HMAC, key size and cipher mode |
| Stateful operations | One-shot versus incremental equivalence, reset behaviour, boundary lengths and context cleanup |
| R interface | Raw-type validation, key/IV lengths, empty input, input immutability and structured conditions |
| C interface | A compiled consumer fixture, ABI rejection, ownership rules and package loading |
| Backend isolation | Load beside `openssl`, other Mbed consumers and `zuhttp` in both orders without symbol interference |
| Office integration | Fixtures from Excel and an independent implementation, with recorded provenance and expected package bytes |
| Negative Office cases | Wrong password, altered ciphertext/HMAC, unsupported profiles, Unicode passwords, truncation and malformed CFB chains |
| Platforms | R package build/check on Windows, macOS and Linux, including ARM64 where supported |

Fuzz the Office parser separately from the primitive wrappers and run native code under address/undefined-behaviour sanitizers. Include files spanning the Agile segment boundary and partial final segments. Bound performance tests for intentionally large spin counts.

An encrypt/decrypt round trip alone is insufficient: the same implementation can contain matching mistakes. Run independent compatibility checks. Tests must work offline using synthetic fixtures with known passwords and appropriate redistribution permission.

## 12. Implementation sequence

1. **Backend spike:** pin the release, validate the required algorithm profile, build on target platforms, measure source/binary size and establish symbol isolation.
2. **Core package:** implement the R functions, versioned C interface, status mapping and lifecycle management; pass primitive and consumer tests.
3. **Agile Excel integration:** implement the bounded CFB/Office adapter in `zuxlsx`, including password and integrity checks; feed decrypted bytes into its ZIP reader.
4. **Standard Excel integration:** add the AES-ECB compatibility path and document its integrity limitations.
5. **HTTP evaluation:** prototype the Mbed TLS backend in `zuhttp`, including trust integration, while retaining native OS TLS.
6. **Measured expansion:** decide whether authenticated encryption, KDF utilities, larger-file handling or a shared compiled backend justify additional API surface.

The core can be released independently, but the package family's first end-to-end success criterion is reading a supported password-encrypted Excel workbook without Java, Python or a system OpenSSL dependency.

## 13. Decisions left for implementation

- Exact Mbed/TF-PSA release pair and minimal build configuration.
- Source-install build tooling and resulting supported R/compiler versions.
- Default Office resource limits, informed by representative workbooks.
- Suitable CFB parser reuse versus a narrowly scoped implementation, assessed for license, robustness and size.
- Whether the initial `zuxlsx` ZIP interface accepts raw memory or needs a new seekable byte-source abstraction.
- Whether a shared compiled backend produces enough measured benefit to justify its additional coupling.

These are implementation choices to resolve with evidence. They do not change the core boundary: `zucrypt` owns reusable cryptography; document readers own document formats; `zuhttp` owns TLS and trust integration.
