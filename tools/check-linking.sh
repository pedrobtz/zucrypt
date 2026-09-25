#!/bin/sh
# The second consumer shape, proved: a plain C program that links
# libzucrypt.a and calls the library directly.
#
# This is how zuxlsx consumes its siblings -- LinkingTo for the header, a
# configure script resolving system.file("lib"), and no Imports: at all, so
# nothing of R is involved at run time. Nothing in R CMD check exercises it,
# and it breaks silently: an archive that stopped being installed, an entry
# point that stopped being defined, or a header that drifted from the
# implementation all look fine until someone tries to link.
#
#   tools/check-linking.sh [library]
#
# `library` is an R library containing an installed zucrypt; the default is
# whatever the R on PATH finds. Run after installing the package.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

LIBARG=${1:-}
RSCRIPT=${RSCRIPT:-Rscript}

# Resolved exactly the way zuxlsx's configure resolves it: lib/<r_arch>
# first, then plain lib. Both layouts exist in the family and a consumer has
# to cope with either.
lookup() {
    "$RSCRIPT" --vanilla -e "
      if (nzchar('$LIBARG')) .libPaths(c('$LIBARG', .libPaths()))
      arch <- .Platform\$r_arch
      d <- if (nzchar(arch)) system.file('lib', arch, package = 'zucrypt') else ''
      if (!nzchar(d)) d <- system.file('lib', package = 'zucrypt')
      cat(d)"
}

INCDIR=$("$RSCRIPT" --vanilla -e "
  if (nzchar('$LIBARG')) .libPaths(c('$LIBARG', .libPaths()))
  cat(system.file('include', package = 'zucrypt'))")
LIBDIR=$(lookup)

if [ -z "$INCDIR" ] || [ -z "$LIBDIR" ]; then
    echo "FAIL zucrypt is not installed, or has no include/ and lib/" >&2
    echo "     install it first: R CMD INSTALL ." >&2
    exit 1
fi
if [ ! -f "$LIBDIR/libzucrypt.a" ]; then
    echo "FAIL $LIBDIR/libzucrypt.a does not exist" >&2
    exit 1
fi
if [ ! -f "$INCDIR/zucrypt.h" ]; then
    echo "FAIL $INCDIR/zucrypt.h does not exist" >&2
    exit 1
fi

printf 'include: %s\nlib:     %s\n' "$INCDIR" "$LIBDIR"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/consumer.c" <<'C'
/* A consumer of the static archive. No R anywhere: this program does not
 * link libR, is not loaded by R, and includes only <zucrypt.h>.
 *
 * It owns the backend's lifetime, which is the part that differs from the
 * table shape -- there is no zucrypt namespace here to have started it.
 */
#include <stdio.h>
#include <string.h>

#include <zucrypt.h>

/* FIPS 180-2 B.1 */
static const unsigned char SHA256_ABC[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};
/* NIST SP 800-38A F.2.1 */
static const unsigned char KEY[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const unsigned char IV[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const unsigned char PT[32] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
};
static const unsigned char CT[32] = {
    0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
    0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2
};

static int failures = 0;
static void check(int ok, const char *what)
{
    printf("  %-40s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) failures++;
}

int main(void)
{
    unsigned char out[ZUC_MAX_DIGEST_SIZE];
    unsigned char buf[32];
    size_t n = 0;
    zuc_info info;
    zuc_hash *h = NULL;
    zuc_aes *aes = NULL;

    /* The archive consumer starts the backend itself. */
    check(zuc_init() == ZUC_OK, "zuc_init");

    info.struct_size = (unsigned int) sizeof info;
    check(zuc_get_info(&info) == ZUC_OK, "zuc_get_info");
    printf("  backend: %s %s (random: %s), ABI %u\n",
           info.backend_name, info.backend_version, info.random_backend,
           (unsigned) info.abi_version);

    check(zuc_hash_compute(ZUC_ALG_SHA256, (const unsigned char *) "abc", 3,
                           out, sizeof out, &n) == ZUC_OK, "zuc_hash_compute");
    check(n == 32 && memcmp(out, SHA256_ABC, 32) == 0, "sha256(\"abc\")");

    check(zuc_hash_new(ZUC_ALG_SHA256, &h) == ZUC_OK, "zuc_hash_new");
    check(zuc_hash_update(h, (const unsigned char *) "a", 1) == ZUC_OK,
          "zuc_hash_update");
    check(zuc_hash_update(h, (const unsigned char *) "bc", 2) == ZUC_OK,
          "zuc_hash_update (2)");
    check(zuc_hash_finish(h, out, sizeof out, &n) == ZUC_OK, "zuc_hash_finish");
    check(memcmp(out, SHA256_ABC, 32) == 0, "incremental equals one-shot");
    zuc_hash_free(h);

    check(zuc_aes_new(KEY, sizeof KEY, &aes) == ZUC_OK, "zuc_aes_new");
    check(zuc_aes_cbc_set_state(aes, IV) == ZUC_OK, "zuc_aes_cbc_set_state");
    check(zuc_aes_cbc_encrypt(aes, PT, 32, buf) == ZUC_OK, "zuc_aes_cbc_encrypt");
    check(memcmp(buf, CT, 32) == 0, "AES-128-CBC SP 800-38A F.2.1");
    check(zuc_aes_cbc_set_state(aes, IV) == ZUC_OK, "reset chaining state");
    check(zuc_aes_cbc_decrypt(aes, CT, 32, buf) == ZUC_OK, "zuc_aes_cbc_decrypt");
    check(memcmp(buf, PT, 32) == 0, "round trip");
    zuc_aes_free(aes);

    check(zuc_equal(SHA256_ABC, SHA256_ABC, 32) == 1, "zuc_equal");
    check(zuc_shutdown() == ZUC_OK, "zuc_shutdown");

    if (failures) {
        printf("\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
C

CC=${CC:-cc}
echo "compiling and linking with $CC"
"$CC" -std=c99 -Wall -Wextra -Wpedantic -Werror \
      -I"$INCDIR" "$tmp/consumer.c" "$LIBDIR/libzucrypt.a" -o "$tmp/consumer"

echo "running"
"$tmp/consumer"
