#!/usr/bin/env bash
# The static-archive shape, proved the way a consumer uses it.
#
#   tools/check-linking.sh
#
# Builds tools/zucryptlink -- a LinkingTo-only package whose configure
# resolves libzucrypt.a exactly as zuxlsx's does -- against a freshly
# installed zucrypt, and checks what a plain C main() never could (#32):
#
#   1. zucrypt installs the archive, both headers and the backend's licence;
#   2. the fixture declares no run-time dependency on zucrypt;
#   3. configure resolves the archive and the link succeeds, through a
#      library path that contains a space (the norm on Windows, and the case
#      the single-quoted PKG_LIBS exists for);
#   4. the backend is linked *into* the consumer's shared object, and none of
#      it -- no zuc_, psa_ or mbedtls_ symbol -- is exported from it;
#   5. the fixture's tests pass: published vectors, and msoffcrypto-tool's
#      answer for the derivation loop zuxlsx will run;
#   6. the archive and zucrypt.so report the same backend release;
#   7. zucrypt.so and the fixture coexist in one process, loaded in either
#      order: two backend copies, two key stores, no crosstalk;
#   8. the fixture still works with zucrypt removed from the library path.
#
# zukomp's tools/check-linking.sh, with tools/zukomplink, is the model. Its
# CLAUDE.md records why a hand-compiled main() was retired: it "exercised
# none of what actually breaks".
#
# Run from anywhere; needs R, a compiler toolchain and testthat. Runs on
# Linux, macOS and Windows (Rtools' bash); step 4 is skipped on Windows, where
# a DLL exports only what its export table names and two independently linked
# copies cannot bind to each other at all (design.md section 4).
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

WORK="$ROOT/.check-linking"
LIB="$WORK/r lib"              # the space is deliberate; see step 3
rm -rf "$WORK"
mkdir -p "$LIB"
trap 'rm -rf "$WORK"' EXIT

rscript() { R_LIBS="$LIB" Rscript --vanilla "$@"; }

echo "==> 1. installing zucrypt into a library whose path has a space"
R CMD INSTALL --preclean --no-multiarch --library="$LIB" . >"$WORK/install-zucrypt.log" 2>&1 \
  || { cat "$WORK/install-zucrypt.log" >&2; exit 1; }

ZUCRYPT_LIB=$(rscript -e 'arch <- .Platform$r_arch; d <- if (nzchar(arch)) system.file("lib", arch, package = "zucrypt") else ""; if (!nzchar(d)) d <- system.file("lib", package = "zucrypt"); cat(d)')
[ -n "$ZUCRYPT_LIB" ] || { echo "FAIL: zucrypt installed no lib directory" >&2; exit 1; }
[ -f "$ZUCRYPT_LIB/libzucrypt.a" ] || { echo "FAIL: libzucrypt.a is missing from the installation" >&2; exit 1; }
for f in include/zucrypt.h include/zucrypt-r.h licenses/tf-psa-crypto-LICENSE; do
  [ -f "$LIB/zucrypt/$f" ] || { echo "FAIL: $f is missing from the installation" >&2; exit 1; }
done
echo "    archive: $ZUCRYPT_LIB/libzucrypt.a"

echo "==> 2. the fixture must link zucrypt, not load it"
if grep -qE '^(Imports|Depends):' tools/zucryptlink/DESCRIPTION; then
  echo "FAIL: zucryptlink declares Imports/Depends" >&2; exit 1
fi
if grep -qE '^[[:space:]]*(import|importFrom)\(' tools/zucryptlink/NAMESPACE; then
  echo "FAIL: zucryptlink imports a namespace" >&2; exit 1
fi

echo "==> 3. installing the archive consumer (configure resolves the archive)"
R_LIBS="$LIB" R CMD INSTALL --preclean --no-multiarch --library="$LIB" \
  tools/zucryptlink >"$WORK/install-link.log" 2>&1 \
  || { cat "$WORK/install-link.log" >&2; exit 1; }
grep 'configure: linking' "$WORK/install-link.log" | sed 's/^/    /'

echo "==> 4. the backend is linked in, and none of it is exported"
so=$(find "$LIB/zucryptlink/libs" -name 'zucryptlink.*' | head -1)
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "    skipped on Windows: a DLL exports only what its export table names" ;;
  *)
    if ! command -v nm >/dev/null 2>&1; then
      echo "FAIL: nm is required for the symbol audit on this platform" >&2; exit 1
    fi
    undefined=$(nm -u "$so" 2>/dev/null | grep -cE '_?(zuc|psa|mbedtls)_' || true)
    [ "$undefined" = "0" ] || {
      echo "FAIL: $undefined zuc_/psa_/mbedtls_ symbols are undefined in $so;" >&2
      echo "  libzucrypt.a was not linked in. Check PKG_LIBS and ./configure." >&2
      exit 1
    }
    defined=$(nm "$so" 2>/dev/null | grep -cE ' [TtDdSsBb] _?zuc_' || true)
    [ "$defined" -gt 0 ] || { echo "FAIL: no zuc_ symbol is defined in $so" >&2; exit 1; }
    if [ "$(uname -s)" = "Darwin" ]; then
      exported=$(nm -gU "$so" | awk '{print $NF}')
    else
      exported=$(nm -D --defined-only "$so" | awk '{print $NF}')
    fi
    leaked=$(printf '%s\n' "$exported" | grep -E '^_?(zuc|psa|mbedtls)_' || true)
    [ -z "$leaked" ] || {
      echo "FAIL: the consumer exports backend symbols:" >&2
      printf '  %s\n' $leaked >&2
      echo "  An independently vendored copy elsewhere in the process could bind to them." >&2
      exit 1
    }
    echo "    $defined zuc_ symbols linked in; exported: $(printf '%s ' $exported)" ;;
esac

echo "==> 5. running the archive consumer's tests"
cat > "$WORK/run-tests.R" <<'RUN'
results <- as.data.frame(testthat::test_local("tools/zucryptlink", reporter = "summary"))
if (nrow(results) == 0L || sum(results$passed) == 0L) stop("no archive-consumer tests ran")
cat(sprintf("    %d expectations passed\n", sum(results$passed)))
quit(status = as.integer(any(results$failed > 0 | results$error)))
RUN
R_LIBS="$LIB" Rscript "$WORK/run-tests.R"

echo "==> 6. the archive and zucrypt.so report the same backend"
rscript -e '
  a <- zucryptlink::linked_backend()
  s <- zucrypt::crypt_info()
  if (!identical(a$version, s$vendored$version) || !identical(a$abi_version, s$abi_version)) {
    stop("archive reports ", a$version, " / ABI ", a$abi_version,
         "; zucrypt.so reports ", s$vendored$version, " / ABI ", s$abi_version)
  }
  cat("    both report", a$name, a$version, "and ABI", a$abi_version, "\n")'

echo "==> 7. zucrypt.so and the archive coexist, loaded in either order"
cat > "$WORK/coexist.R" <<'COEXIST'
first <- commandArgs(trailingOnly = TRUE)[[1]]
second <- setdiff(c("zucrypt", "zucryptlink"), first)
for (p in c(first, second)) loadNamespace(p)
data <- as.raw(seq_len(4096L) %% 251L)
key <- as.raw(seq_len(32L))
iv <- as.raw(seq_len(16L))
# Interleaved, so each copy runs while the other holds live state in its own
# key store; an HMAC key and an AES key are imported on each side.
for (alg in c("sha1", "sha256", "sha512")) {
  stopifnot(identical(zucrypt::crypt_hash(data, alg), zucryptlink::archive_hash(data, alg)))
  stopifnot(identical(zucrypt::crypt_hmac(data, key, alg), zucryptlink::archive_hmac(data, key, alg)))
}
ct <- zucrypt::crypt_aes_cbc_encrypt(data, key, iv)
stopifnot(identical(zucryptlink::archive_segments(data, key, iv, 4096L, encrypt = TRUE), ct))
stopifnot(identical(zucryptlink::archive_segments(ct, key, iv, 4096L), data))
cat("    ", first, " then ", second, ": identical answers\n", sep = "")
COEXIST
rscript "$WORK/coexist.R" zucrypt
rscript "$WORK/coexist.R" zucryptlink

echo "==> 8. the fixture works with zucrypt absent from the library path"
mv "$LIB/zucrypt" "$LIB/.zucrypt-hidden"
# No testthat here: with the user library off the path it may not be
# reachable either, and this step is about zucrypt, not testthat. Published
# vectors and the msoffcrypto-derived one, checked directly.
cat > "$WORK/without.R" <<'WITHOUT'
found <- system.file(package = "zucrypt")
if (nzchar(found)) {
  stop("zucrypt is still reachable at ", found, "; this step proves nothing while it is")
}
library(zucryptlink)
hex <- function(x) paste(format(x, width = 2), collapse = "")
unhex <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
stopifnot(identical(hex(archive_hash(charToRaw("abc"), "sha256")),
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
kat <- utils::read.delim(file.path("tools", "zucryptlink", "tests", "testthat",
                                   "fixtures", "derivation.tsv"),
                         colClasses = "character")
stopifnot(identical(hex(archive_derive(unhex(kat$seed[1]), as.integer(kat$spin_count[1]),
                                       kat$algorithm[1])), kat$output[1]))
stopifnot(!"zucrypt" %in% loadedNamespaces())
cat("    SHA-256 and the 100,000-spin derivation are right with zucrypt uninstalled\n")
WITHOUT
# R_LIBS_USER='-' keeps the user library -- where a developer's own zucrypt
# probably is -- off the path, so "absent" means absent.
R_LIBS="$LIB" R_LIBS_USER='-' Rscript "$WORK/without.R"
mv "$LIB/.zucrypt-hidden" "$LIB/zucrypt"

echo "all checks passed"
