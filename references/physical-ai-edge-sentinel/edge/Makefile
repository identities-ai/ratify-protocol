# Ratify Edge Sentinel, Protocol v2 edge receiver
#
#   make              build edge, edge-checkpoint, and controller (production)
#   make test-bins    build edge-test and edge-checkpoint-test (fixture clock)
#   make check        build everything and run the deterministic scenario matrix
#
# RATIFY_SDK points at a Ratify C SDK 2.0.0-alpha.1 tree with include/ratify.h
# and lib/libratify_c.a. The static library is linked, so the binaries carry
# no runtime library path. Only the *-test binaries are compiled with
# -DSENTINEL_TEST_BUILD; the edge and edge-checkpoint binaries cannot read the
# fixture clock or skip the quarantine however they are invoked.

RATIFY_SDK ?= ../sdk

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -std=c99
INCLUDES := -Iinclude -Isrc -Iactuator -I$(RATIFY_SDK)/include
# The Rust standard library inside the static archive unwinds through
# libgcc_s on Linux; the Pi provides it.
LDLIBS   ?= -lpthread -ldl -lm
UNAME_S  ?= $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
PLATFORM_LIBS := -framework Security -framework CoreFoundation
else
PLATFORM_LIBS := -lgcc_s
endif
RATIFY_LIB := $(RATIFY_SDK)/lib/libratify_c.a
LINK       := $(RATIFY_LIB) $(LDLIBS) $(PLATFORM_LIBS)

COMMON := src/util.c src/clock.c src/actx.c
EDGE   := src/main.c src/http.c src/verifier.c src/store.c src/trust.c src/ckpt_client.c actuator/actuator.c $(COMMON)
CKPT   := checkpoint/checkpoint.c $(COMMON)
CTRL   := ../controller/controller.c $(COMMON)
HDRS   := $(wildcard include/*.h src/*.h actuator/*.h)

.PHONY: all test-bins check clean

all: edge edge-checkpoint controller

edge: $(EDGE) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(EDGE) $(LINK)

edge-checkpoint: $(CKPT) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(CKPT) $(LINK)

# The only builds with the fixture clock and quarantine override compiled
# in. Named differently on purpose so they cannot be mistaken for production.
edge-test: $(EDGE) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -DSENTINEL_TEST_BUILD -o $@ $(EDGE) $(LINK)

edge-checkpoint-test: $(CKPT) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -DSENTINEL_TEST_BUILD -o $@ $(CKPT) $(LINK)

controller: $(CTRL) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(CTRL) $(LINK)

test-bins: edge-test edge-checkpoint-test controller

check: all test-bins
	./tests/scenarios.sh

clean:
	rm -rf edge edge-checkpoint edge-test edge-checkpoint-test controller *.dSYM
