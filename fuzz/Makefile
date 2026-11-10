# Fuzz targets for the adapter (#94), each carrying an oracle (fuzz_*.c).
#
# Three builds of the same harnesses:
#
#   make fuzz          libFuzzer + ASan + UBSan; needs clang. Finds bugs.
#   make replay-run    a plain driver over the committed corpus; any C
#                      compiler, Rtools included. The cross-platform
#                      regression suite.
#   make replay-asan   the same under ASan + UBSan, so an over-read in a
#                      replayed seed fails rather than passing silently.
#
#   make fuzz-run SECS=60    each libFuzzer target for SECS seconds
#
# GNU make. fuzz/ is in .Rbuildignore: none of this reaches CRAN.

CC       ?= cc
FUZZ_CC  ?= clang
SRC      := ../src
VENDOR   := $(SRC)/vendor/tf-psa-crypto
CORPUS   := corpus
TARGETS  := pkey gcm verify
SECS     ?= 60

CPPFLAGS := -I. -I$(SRC) -I../inst/include -I$(VENDOR)/inc -I$(VENDOR)/lib \
            -DTF_PSA_CRYPTO_CONFIG_FILE='"zuc_crypto_config.h"'
BASE     := -g -O1 -fno-omit-frame-pointer
SAN      := -fsanitize=address,undefined -fno-sanitize-recover=undefined

VNAMES   := $(shell sed -n 's|^  \$$(VENDOR)/lib/\([a-z0-9_]*\)\.o.*|\1|p' $(SRC)/Makevars)
OWN      := $(notdir $(basename $(wildcard $(SRC)/zuc_*.c)))
NAMES    := $(OWN) $(addprefix v_,$(VNAMES))

# One library build per flavour: plain, asan, fuzz.
objs = $(patsubst %,build-$(1)/%.o,$(NAMES))

define flavour
build-$(1)/v_%.o: $(VENDOR)/lib/%.c
	@mkdir -p build-$(1)
	$(2) $(CPPFLAGS) $(BASE) $(3) -w -c $$< -o $$@
build-$(1)/%.o: $(SRC)/%.c
	@mkdir -p build-$(1)
	$(2) $(CPPFLAGS) $(BASE) $(3) -c $$< -o $$@
endef

$(eval $(call flavour,plain,$(CC),$(REPLAY_FLAGS)))
$(eval $(call flavour,asan,$(FUZZ_CC),$(SAN)))
$(eval $(call flavour,fuzz,$(FUZZ_CC),$(SAN) -fsanitize=fuzzer-no-link))

HDRS := fuzz_common.h fuzz_keys.h

# REPLAY_FLAGS is for tools/coverage/fuzz-lcov.sh, which builds the plain
# flavour with coverage instrumentation; clean-bin before and after keeps
# instrumented and plain objects apart.
replay_%: fuzz_%.c replay_main.c $(HDRS) $(call objs,plain)
	$(CC) $(CPPFLAGS) $(BASE) $(REPLAY_FLAGS) -o $@ fuzz_$*.c replay_main.c \
	  $(call objs,plain)

asan_%: fuzz_%.c replay_main.c $(HDRS) $(call objs,asan)
	$(FUZZ_CC) $(CPPFLAGS) $(BASE) $(SAN) -o $@ fuzz_$*.c replay_main.c \
	  $(call objs,asan)

fuzz_%: fuzz_%.c $(HDRS) $(call objs,fuzz)
	$(FUZZ_CC) $(CPPFLAGS) $(BASE) $(SAN) -fsanitize=fuzzer -o $@ fuzz_$*.c \
	  $(call objs,fuzz)

replay: $(addprefix replay_,$(TARGETS))
fuzz: $(addprefix fuzz_,$(TARGETS))

replay-run: replay
	@for t in $(TARGETS); do ./replay_$$t $(CORPUS)/$$t/* || exit 1; done

replay-asan: $(addprefix asan_,$(TARGETS))
	@for t in $(TARGETS); do ./asan_$$t $(CORPUS)/$$t/* || exit 1; done

fuzz-run: fuzz
	@for t in $(TARGETS); do \
	  mkdir -p work/$$t && \
	  ./fuzz_$$t work/$$t $(CORPUS)/$$t -max_total_time=$(SECS) \
	    -print_final_stats=1 -artifact_prefix=./crash-$$t- || exit 1; \
	done

# The binaries only; the library objects stay. fuzz-lcov.sh calls it before
# and after an instrumented build, so neither is mixed with the other.
clean-bin:
	rm -f $(addprefix replay_,$(TARGETS)) $(addprefix asan_,$(TARGETS)) \
	  $(addprefix fuzz_,$(TARGETS))
	rm -f build-plain/*.o

.PHONY: replay fuzz replay-run replay-asan fuzz-run clean-bin
.SECONDARY:
