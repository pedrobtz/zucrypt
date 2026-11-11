#!/usr/bin/env bash
# An incremental R CMD INSTALL rebuilds what a changed header affects (#109).
# Run from the repository root; needs R. aes-paths.yaml runs it on Linux.
#
# R CMD INSTALL on a checkout keeps the objects in src/ between runs, and make
# rebuilds only what is older than its prerequisites. Before #109 no object
# had a header as a prerequisite, so a change to src/zuc_crypto_config.h, an
# installed header or a vendored one reused objects compiled before it: the
# AES path stayed hardware after ZUC_AES_SOFTWARE_ONLY was defined, and a
# stale zucrypt_api.o filled the function table in an old layout. Each step
# below changes one input and checks the build that follows it.
set -eu

lib=$(mktemp -d)
cfg=src/zuc_crypto_config.h
backup=$(mktemp)
cp -p "$cfg" "$backup"
restore() {
  cp "$backup" "$cfg"
  rm -rf "$lib" "$backup"
}
trap restore EXIT

install() {
  R CMD INSTALL --no-test-load -l "$lib" . > "$lib/install.log" 2>&1 ||
    { cat "$lib/install.log" >&2; exit 1; }
}
aes_path() {
  R_LIBS="$lib" Rscript -e \
    'cat(zucrypt::crypt_info()$build_flags$aes_implementation)'
}
compiled() {
  grep -cE "(^|[ /])$1\.c( |$)" "$lib/install.log" || true
}

echo "== a full build"
R CMD INSTALL --preclean --no-test-load -l "$lib" . > "$lib/install.log" 2>&1 ||
  { cat "$lib/install.log" >&2; exit 1; }
hardware=$(aes_path)
echo "   aes_implementation: $hardware"

echo "== ZUC_AES_SOFTWARE_ONLY defined in $cfg, no --preclean"
{ printf '#define ZUC_AES_SOFTWARE_ONLY 1\n'; cat "$backup"; } > "$cfg"
install
got=$(aes_path)
if [ "$got" != "software" ]; then
  echo "FAIL the rebuild kept the $got objects: aes_implementation is $got" >&2
  exit 1
fi
echo "ok  aes_implementation: software"

echo "== and back"
cp "$backup" "$cfg"
install
got=$(aes_path)
if [ "$got" != "$hardware" ]; then
  echo "FAIL aes_implementation is $got after restoring $cfg, not $hardware" >&2
  exit 1
fi
echo "ok  aes_implementation: $got"

echo "== an installed header and a vendored one rebuild their users"
for step in "inst/include/zucrypt-r.h zucrypt_api" \
            "src/vendor/tf-psa-crypto/inc/psa/crypto.h psa_crypto"; do
  set -- $step
  touch "$1"
  install
  if [ "$(compiled "$2")" -eq 0 ]; then
    echo "FAIL touching $1 did not recompile $2.c" >&2
    exit 1
  fi
  echo "ok  $1 -> $2.c recompiled"
done

echo "== nothing changed, nothing recompiled"
install
n=$(grep -cE '\.c -o ' "$lib/install.log" || true)
if [ "$n" -ne 0 ]; then
  echo "FAIL an unchanged tree recompiled $n file(s)" >&2
  exit 1
fi
echo "ok  0 files recompiled"
