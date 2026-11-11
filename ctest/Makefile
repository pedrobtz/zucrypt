# A standalone C driver for the R-free adapter (#96), and what mutation.yaml
# runs under Mull.
#
# It links src/zuc_*.c and the vendored backend into a bare binary, with no
# R header anywhere: if this stops building, the adapter has stopped being
# R-free (tools/check-layering.sh checks the same thing from the other
# side). Every object is one `-c` compilation of one source, which is what
# Mull's compiler plugin needs. GNU make, unlike src/Makevars: this is a
# development tool, never part of the package build (.Rbuildignore).
#
#   make -C ctest                            # build, and run on the fixtures
#   make -C ctest zuc_ctest CC="$MULL_CC"    # what mutation.yaml builds

CC      ?= cc
SRC     := ../src
VENDOR  := $(SRC)/vendor/tf-psa-crypto
BUILD   := build$(BUILD_SUFFIX)

CPPFLAGS += -I$(SRC) -I../inst/include -I$(VENDOR)/inc -I$(VENDOR)/lib \
            -DTF_PSA_CRYPTO_CONFIG_FILE='"zuc_crypto_config.h"'
CFLAGS  ?= -O1 -g
OWNWARN := -std=c99 -Wall -Wextra

# The vendored objects src/Makevars links, read from it so the two cannot
# drift; compiled with warnings off, as upstream's code is not ours to fix.
VNAMES  := $(shell sed -n 's|^  \$$(VENDOR)/lib/\([a-z0-9_]*\)\.o.*|\1|p' $(SRC)/Makevars)
VOBJ    := $(patsubst %,$(BUILD)/v_%.o,$(VNAMES))
OWN     := $(notdir $(basename $(wildcard $(SRC)/zuc_*.c)))
OOBJ    := $(patsubst %,$(BUILD)/%.o,$(OWN))
# Every object depends on every header and on src/Makevars (#109): a
# coarse rule that rebuilds everything on any change and never too little.
HEADERS := $(SRC)/Makevars $(wildcard $(SRC)/*.h) \
           $(wildcard ../inst/include/*.h) \
           $(wildcard $(VENDOR)/inc/*/*.h $(VENDOR)/inc/*/*/*.h $(VENDOR)/lib/*.h)

all: run

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/v_%.o: $(VENDOR)/lib/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -w -c $< -o $@

$(BUILD)/%.o: $(SRC)/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OWNWARN) -c $< -o $@

$(BUILD)/test_main.o: test_main.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OWNWARN) -c $< -o $@

zuc_ctest: $(BUILD)/test_main.o $(OOBJ) $(VOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

run: zuc_ctest
	./zuc_ctest ../tests/testthat/fixtures

clean:
	rm -rf zuc_ctest zuc_ctest.dSYM build build-*

.PHONY: all run clean
