#!/usr/bin/env bash
# ABI 1 against the frozen v0.1.0 headers (#139). Run from the repository
# root; needs cc, python3 and R. abi.yaml runs it on Linux and
# tools/ci/platform.sh on macOS.
#
# Every other consumer in CI compiles against the header of the same
# checkout, so a change made on both sides agrees with itself and passes.
# These two checks hold the current headers and archive to what v0.1.0
# published instead:
#
# 1. tools/abi/probe.c, generated from tools/abi/v0.1.0/, prints the value
#    of every enumerator and macro v0.1.0 published and the offset and size
#    of every field of zuc_info and zucrypt_api_v1. Compiled against the
#    frozen headers and against inst/include, every line of the first output
#    must be in the second.
# 2. tools/abi/old-consumer.c, compiled against the frozen zucrypt.h and
#    linked to the current libzucrypt.a, calls every v0.1.0 function and
#    checks each answer against a published vector.
#
# ZUCRYPT_LIB may name a directory holding libzucrypt.a; otherwise the
# checkout is installed into a temporary library first.
set -eu

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
old="$(pwd)/tools/abi/v0.1.0"
new="$(pwd)/inst/include"
rinc="$(R RHOME)/include"

echo "== the probe matches its generator"
python3 tools/abi/make-probe.py --check

echo "== every v0.1.0 value, offset and size is unchanged"
cc -std=c99 -Wall -Werror -I"$old" -I"$rinc" tools/abi/probe.c -o "$dir/probe-old"
cc -std=c99 -Wall -Werror -I"$new" -I"$rinc" tools/abi/probe.c -o "$dir/probe-new"
"$dir/probe-old" > "$dir/old.txt"
"$dir/probe-new" > "$dir/new.txt"
n=$(wc -l < "$dir/old.txt")
if [ "$n" -lt 60 ]; then
  echo "FAIL the probe printed only $n lines" >&2
  exit 1
fi
missing=$(grep -vxF -f "$dir/new.txt" "$dir/old.txt" || true)
if [ -n "$missing" ]; then
  echo "FAIL ABI 1 broken: v0.1.0 published these, the current headers differ:" >&2
  echo "$missing" | while read -r line; do
    name=$(echo "$line" | awk '{print $2}')
    echo "  v0.1.0:  $line" >&2
    echo "  current: $(grep -E "^[a-z]+ +$name " "$dir/new.txt" || echo '(absent)')" >&2
  done
  exit 1
fi
echo "ok  $n published values unchanged"

echo "== a v0.1.0 consumer runs against the current archive"
lib=${ZUCRYPT_LIB:-}
if [ -z "$lib" ]; then
  R CMD INSTALL --preclean --no-test-load -l "$dir" . > "$dir/install.log" 2>&1 ||
    { cat "$dir/install.log" >&2; exit 1; }
  for cand in "$dir/zucrypt/lib${R_ARCH:-}" "$dir/zucrypt/lib"; do
    if [ -f "$cand/libzucrypt.a" ]; then lib=$cand; break; fi
  done
fi
[ -f "$lib/libzucrypt.a" ] || { echo "FAIL no libzucrypt.a in '$lib'" >&2; exit 1; }
cc -std=c99 -Wall -Werror -I"$old" tools/abi/old-consumer.c \
   "$lib/libzucrypt.a" -o "$dir/old-consumer"
"$dir/old-consumer"
