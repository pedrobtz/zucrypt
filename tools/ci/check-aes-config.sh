#!/usr/bin/env bash
# Hardware AES is enabled only where it can be relied on (#144). Run from the
# repository root; needs cc. aes-paths.yaml runs it.
#
# Upstream's aesce.h detects the Arm Cryptography Extension at run time on
# Linux only; on any other OS MBEDTLS_AESCE_HAS_SUPPORT() is 1, so an Arm
# CPU without the extension (FreeBSD on a Raspberry Pi 4, Windows on some
# Arm boards) would execute AES instructions it lacks: SIGILL on the first
# AES call. src/zuc_crypto_config.h enables MBEDTLS_AESCE_C on Linux and
# Apple platforms only (every Apple Arm CPU has the extension), and AES-NI,
# which upstream detects with CPUID everywhere, on every OS. This
# preprocesses the configuration as each platform's compiler would see it,
# so the rule is checked without the hardware.
set -eu
cfg=src/zuc_crypto_config.h
fail=0

defines() {  # $@: the platform's predefined macros, as -U/-D flags
  cc -E -dM -undef -I src "$@" -include "$cfg" -x c /dev/null 2>/dev/null |
    awk '$1 == "#define" { print $2 }'
}
expect() {  # name, define, want (yes/no), flags...
  name=$1 def=$2 want=$3
  shift 3
  if defines "$@" | grep -qx "$def"; then got=yes; else got=no; fi
  if [ "$got" = "$want" ]; then
    echo "ok  $name: $def $([ "$want" = yes ] && echo on || echo off)"
  else
    echo "FAIL $name: $def is $([ "$got" = yes ] && echo on || echo off)" >&2
    fail=1
  fi
}

expect "Linux on arm64"     MBEDTLS_AESCE_C yes -D__linux__ -D__aarch64__
expect "macOS on arm64"     MBEDTLS_AESCE_C yes -D__APPLE__ -D__aarch64__
expect "Android on arm64"   MBEDTLS_AESCE_C yes -D__linux__ -D__ANDROID__ -D__aarch64__
expect "FreeBSD on arm64"   MBEDTLS_AESCE_C no  -D__FreeBSD__ -D__aarch64__
expect "Windows on arm64"   MBEDTLS_AESCE_C no  -D_WIN32 -D_M_ARM64
expect "Linux on x86-64"    MBEDTLS_AESNI_C yes -D__linux__ -D__x86_64__
expect "Windows on x86-64"  MBEDTLS_AESNI_C yes -D_WIN32 -D__x86_64__
expect "FreeBSD on x86-64"  MBEDTLS_AESNI_C yes -D__FreeBSD__ -D__x86_64__
expect "the software-only test build" MBEDTLS_AESCE_C no \
  -D__linux__ -D__aarch64__ -DZUC_AES_SOFTWARE_ONLY
exit $fail
