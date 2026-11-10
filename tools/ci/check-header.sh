#!/usr/bin/env bash
# The public headers' standalone checks, run from the repository root: what
# abi.yaml's standalone-header job did on each OS. abi.yaml runs it on Linux
# and tools/ci/platform.sh on macOS, so the two cannot drift. Needs cc, c++,
# python3 and an R installation (for R's headers).
set -eu

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
inc="$(pwd)/inst/include"
rinc="$(R RHOME)/include"

echo "== zucrypt.h compiles as C99 with no R and no backend headers"
printf '#include <zucrypt.h>\nint main(void){return 0;}\n' > "$dir/probe.c"
cc -std=c99 -Wall -Wextra -Wpedantic -Werror \
   -I"$inc" -c "$dir/probe.c" -o /dev/null
echo "ok  C99"

echo "== zucrypt.h compiles as C++ through the extern \"C\" wrapper"
printf '#include <zucrypt.h>\nint main(){return 0;}\n' > "$dir/probe.cpp"
c++ -std=c++11 -Wall -Wextra -Werror \
    -I"$inc" -c "$dir/probe.cpp" -o /dev/null
echo "ok  C++"

echo "== a consumer compiles against zucrypt-r.h with -Werror"
cat > "$dir/probe_consumer.c" <<'C'
#include <zucrypt-r.h>
SEXP probe(void) {
    const zucrypt_api_v1 *api = zucrypt_api();
    if (api == NULL) return Rf_ScalarLogical(0);
    /* ZUCRYPT_API_HAS expands offsetof/sizeof arithmetic in the
     * consumer's translation unit, under the consumer's flags. */
    if (!ZUCRYPT_API_HAS(api, secure_zero)) return Rf_ScalarLogical(0);
    return Rf_ScalarLogical(api->alg_by_name("sha256") == ZUC_ALG_SHA256);
}
C
cc -std=c99 -Wall -Wextra -Werror \
   -I"$inc" -I"$rinc" \
   -c "$dir/probe_consumer.c" -o /dev/null
echo "ok  consumer build"

echo "== including zucrypt-r.h without using it is warning-free"
printf '#include <zucrypt-r.h>\nSEXP other(void){ return R_NilValue; }\n' \
  > "$dir/probe_unused.c"
cc -std=c99 -Wall -Wextra -Werror \
   -I"$inc" -I"$rinc" \
   -c "$dir/probe_unused.c" -o /dev/null
echo "ok  header is inert when unused"

echo "== zucrypt.h declares nothing from R or the backend"
python3 - <<'PY'
import re, sys
src = open("inst/include/zucrypt.h", encoding="utf-8").read()
code = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
code = re.sub(r"//[^\n]*", " ", code)
banned = ("mbedtls", "psa_", "PSA_", "MBEDTLS_", "tf-psa", "TF_PSA",
          "SEXP", "Rf_", "Rinternals", "R_xlen_t",
          "SHA256_Init", "SHA256_Update", "AES_encrypt", "EVP_")
bad = [p for p in banned if p in code]
for p in bad:
    print(f"FAIL inst/include/zucrypt.h declares '{p}'")
sys.exit(1 if bad else print("ok  no leaked vocabulary") or 0)
PY

echo "== zucrypt.h uses the zuc_ prefix and never zu_"
python3 - <<'PY'
import re, sys
src = open("inst/include/zucrypt.h", encoding="utf-8").read()
code = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
bad = sorted(set(re.findall(r"\bzu_[a-z_]+", code)) |
             set(re.findall(r"\bZU_[A-Z0-9_]+", code)))
for name in bad:
    print(f"FAIL inst/include/zucrypt.h declares '{name}', "
          f"which belongs to zukomp")
sys.exit(1 if bad else print("ok  prefix is zuc_/ZUC_") or 0)
PY
