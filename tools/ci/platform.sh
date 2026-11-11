#!/usr/bin/env bash
# zucrypt's own per-OS checks, one job per OS (platforms.yaml, through
# r-actions' platforms.yml). Run from the repository root with the OS:
#
#   tools/ci/platform.sh macos | windows | ubuntu
#
# Before this, each check was its own macOS and Windows job in abi.yaml,
# aes-paths.yaml, consumer.yaml, revdep.yaml and fuzz.yaml: up to five
# macOS and four Windows jobs per pull request, against an account that
# runs about five macOS jobs at once. The Linux legs stay in those files.
# The commands here are theirs; each check is its own command under
# `set -e`, so the log says which one failed, and every R check runs from
# a file in tools/ci/.
#
# R_ACTIONS_PROFILE is `quick` on a pull request and `full` on a schedule,
# a dispatch or a `full-ci` pull request. The slow, secondary checks -- the
# fuzz corpus replay on a second OS and zuxlsx built against this checkout
# -- run on `full` only; their Linux legs run on every pull request.
set -eu
os=${1:?usage: tools/ci/platform.sh macos|windows|ubuntu}
profile=${R_ACTIONS_PROFILE:-full}
full() { [ "$profile" = full ]; }
step() { echo "::endgroup::"; echo "::group::$*"; }
echo "::group::platform.sh $os (profile: $profile)"

export NOT_CRAN=true R_KEEP_PKG_SOURCE=yes

case "$os" in
  macos|windows|ubuntu) ;;
  *) echo "unknown OS: $os" >&2; exit 2 ;;
esac
# The hardware AES this CPU has: the Arm Cryptography Extension on Arm
# (macos-latest is Apple silicon), AES-NI on x86-64. aes-paths.yaml tied it
# to the runner label; the architecture is what decides it.
case "$(uname -m)" in
  arm64|aarch64) expect_aes=aesce ;;
  *)             expect_aes=aesni ;;
esac

# abi.yaml: the public headers compile standalone (it ran on macOS and
# Linux; Linux stays there).
if [ "$os" = macos ]; then
  step "abi: zucrypt.h and zucrypt-r.h standalone"
  bash tools/ci/check-header.sh
fi

# One install serves every check below: aes-paths.yaml, consumer.yaml and
# revdep.yaml each installed the same checkout with --preclean and no
# ZUCRYPT_TEST_CPPFLAGS on these runners.
step "Install zucrypt"
ZUCRYPT_TEST_CPPFLAGS="" R CMD INSTALL --preclean .

# abi.yaml: ABI 1 against the frozen v0.1.0 headers, with the archive just
# installed (its Linux leg runs in abi.yaml).
if [ "$os" = macos ]; then
  step "abi: ABI 1 against the v0.1.0 headers"
  ZUCRYPT_LIB=$(Rscript -e 'cat(system.file("lib", package = "zucrypt"))') \
    bash tools/ci/check-abi.sh
fi

# aes-paths.yaml: the runner selects its hardware AES, and the whole suite
# passes against the installed package on that path.
step "aes-paths: the runner selects $expect_aes"
ZUCRYPT_EXPECT_AES=$expect_aes Rscript tools/ci/aes-check.R
# With every NIST CAVP vector (#67) and every Wycheproof case (#70),
# relative to tests/testthat.
step "aes-paths: the test suite against the installed package ($expect_aes, full CAVP and Wycheproof)"
ZUCRYPT_EXPECT_AES=$expect_aes ZUCRYPT_CAVP=../../tools/cavp/cavp.tsv.gz \
  ZUCRYPT_WYCHEPROOF=../../tools/wycheproof/wycheproof.tsv.gz \
  Rscript tools/ci/test-installed.R

# consumer.yaml: both consumer shapes.
step "consumer: install the table fixture"
R CMD INSTALL tools/zucrypttest
step "consumer: the table fixture's tests"
Rscript tools/ci/consumer-tests.R
step "consumer: link the static archive into a LinkingTo-only package"
bash tools/check-linking.sh

if full; then
  # fuzz.yaml: the committed corpus through every oracle (its Linux leg,
  # and the ASan replay, run on every pull request).
  step "fuzz: replay the corpus"
  if [ "$os" = windows ]; then
    make -C fuzz -j4 replay-run CC="$(R CMD config CC)"
  else
    make -C fuzz -j4 replay-run
  fi
  if [ "$os" = macos ]; then
    step "fuzz: replay the corpus under ASan + UBSan"
    make -C fuzz -j4 replay-asan FUZZ_CC=clang
  fi

  # revdep.yaml: zuxlsx built against this checkout's libzucrypt.a, and its
  # decryption tests (its Linux leg runs on every pull request).
  step "revdep: fetch zuxlsx (${ZUXLSX_REF:-main})"
  git clone --depth 1 --branch "${ZUXLSX_REF:-main}" \
    https://github.com/pedrobtz/zuxlsx .revdep/zuxlsx
  step "revdep: zuxlsx's dependencies"
  Rscript tools/ci/revdep-deps.R .revdep/zuxlsx
  step "revdep: the installed zucrypt is this checkout"
  Rscript tools/ci/revdep-installed.R
  step "revdep: install zuxlsx (configure links this checkout's libzucrypt.a)"
  R CMD INSTALL .revdep/zuxlsx
  step "revdep: zuxlsx's decryption tests"
  Rscript tools/ci/revdep-tests.R
fi
echo "::endgroup::"
echo "platform.sh $os: every check passed (profile: $profile)"
