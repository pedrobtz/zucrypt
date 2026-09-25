#!/bin/sh
# The layering rule, checked mechanically.
#
# design.md sections 8.1 and 8.3 put a hard boundary through src/: the
# adapter is R-free and the R glue is backend-free. It matters because
# src/zuc_*.c and src/vendor/ are what go into libzucrypt.a, which a
# consumer links into its own shared object. R glue in that archive is a
# duplicate symbol; a backend header reaching the R layer is the start of PSA
# types appearing in an installed header.
#
# Neither direction is visible to R CMD check, and neither breaks loudly:
# including R.h in the adapter compiles fine and only fails much later, in a
# consumer's build, with an error that does not name this cause.
#
# Run from the repository root. Offline, no compiler.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

status=0

# The R-free half: the adapter and the public header.
for f in src/zuc_*.c src/zuc_internal.h src/zuc_live.h inst/include/zucrypt.h; do
    [ -e "$f" ] || continue
    if grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"](R\.h|Rinternals\.h|Rdefines\.h|R_ext/|Rmath\.h)' "$f" >/dev/null; then
        printf 'FAIL %s includes an R header; it belongs to the archive\n' "$f" >&2
        grep -nE '^[[:space:]]*#[[:space:]]*include.*R' "$f" >&2
        status=1
    fi
    if grep -nE '\bSEXP\b|\bRf_[A-Za-z_]+' "$f" >/dev/null; then
        printf 'FAIL %s mentions an R type or function\n' "$f" >&2
        status=1
    fi
done

# The backend-free half: the R glue. zucrypt_r.c and zucrypt_test.c speak
# zuc_* only, so that swapping the backend never touches them.
for f in src/zucrypt_*.c; do
    [ -e "$f" ] || continue
    if grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"](psa/|mbedtls/|tf-psa-crypto/)' "$f" >/dev/null; then
        printf 'FAIL %s includes a backend header; it must go through zucrypt.h\n' "$f" >&2
        status=1
    fi
    if grep -nE '\bpsa_[a-z_]+|\bmbedtls_[a-z_]+|\bPSA_[A-Z_]+' "$f" >/dev/null; then
        printf 'FAIL %s mentions backend vocabulary\n' "$f" >&2
        grep -nE '\bpsa_[a-z_]+|\bmbedtls_[a-z_]+|\bPSA_[A-Z_]+' "$f" >&2
        status=1
    fi
done

# The public header is stricter still: two system includes, nothing else.
# Checked here as well as in test-linking.R, because that test reads the
# *installed* copy and this reads the source -- a difference between the two
# is itself worth knowing about.
includes=$(grep -E '^[[:space:]]*#[[:space:]]*include' inst/include/zucrypt.h \
             | sed 's/[[:space:]]*//g' | LC_ALL=C sort)
expected='#include<stddef.h>
#include<stdint.h>'
if [ "$includes" != "$expected" ]; then
    printf 'FAIL inst/include/zucrypt.h includes more than <stddef.h> and <stdint.h>:\n%s\n' \
        "$includes" >&2
    status=1
fi

# Every zuc_* entry point the header declares must be defined somewhere in
# the adapter. A declaration with no definition is a link error for a
# consumer of the archive and nothing at all for this package, which never
# calls most of them.
declared=$(sed 's|/\*.*\*/||' inst/include/zucrypt.h \
             | grep -oE '\bzuc_[a-z_]+\(' | sed 's/($//; s/(//' \
             | LC_ALL=C sort -u)
for fn in $declared; do
    if ! grep -qE "^(zuc_status|const char \*|void|int|size_t|zuc_alg) ?\*?$fn\(" src/zuc_*.c; then
        printf 'FAIL %s is declared in zucrypt.h but defined in no src/zuc_*.c\n' "$fn" >&2
        status=1
    fi
done

# The shape #18 fixed, which rchk, gctorture and the sanitizers had all
# passed:
#
#     UNPROTECT(2);
#     return result(st, out);
#
# result() allocates, and `out` is no longer protected, so a collection
# inside it can take `out` and store a dangling pointer -- a wrong answer
# returned successfully. The rule for the R glue is simple enough to check
# textually: after UNPROTECT, return a variable or a constant, never a call.
# Compute the value while everything it needs is protected, then unprotect.
unprotect_then_call() {
    awk '
        /^[[:space:]]*UNPROTECT[[:space:]]*\(/ { pending = FNR; next }
        pending && /^[[:space:]]*$/ { next }
        pending && /^[[:space:]]*return[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(/ {
            printf "%s:%d: return of a call after UNPROTECT (line %d)\n", FILENAME, FNR, pending
            found = 1
        }
        { pending = 0 }
        END { exit found ? 1 : 0 }
    ' "$@"
}

if ! unprotect_then_call src/zucrypt_*.c >&2; then
    printf 'FAIL a call is returned after UNPROTECT; compute it while protected\n' >&2
    status=1
fi

# And the canary: the lint above is only worth its line if it fires on the
# shape it names. A regex that silently stopped matching would pass every
# file forever.
canary=$(mktemp)
printf 'SEXP f(void)\n{\n    UNPROTECT(2);\n    return result(st, out);\n}\n' > "$canary"
if unprotect_then_call "$canary" >/dev/null 2>&1; then
    printf 'FAIL the UNPROTECT/return lint did not fire on its canary\n' >&2
    status=1
fi
printf 'SEXP f(void)\n{\n    res = result(st, out);\n    UNPROTECT(2);\n    return res;\n}\n' > "$canary"
if ! unprotect_then_call "$canary" >/dev/null 2>&1; then
    printf 'FAIL the UNPROTECT/return lint fired on the safe shape\n' >&2
    status=1
fi
rm -f "$canary"

if [ "$status" -eq 0 ]; then
    printf 'ok  src/ layering holds: the adapter is R-free, the glue is backend-free\n'
    printf 'ok  no call is returned after UNPROTECT, and the lint fires on its canary\n'
fi
exit "$status"
