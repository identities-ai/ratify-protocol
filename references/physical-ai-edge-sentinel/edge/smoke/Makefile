# Ratify Edge Sentinel — Pi 2 smoke test
#
#   make            build against ./vendor/ratify-c (shared library)
#   make STATIC=1   link libratify_c.a instead
#   make vendor     fetch and extract the alpha.18 armv7 artifact
#   make run        build and run with the default iteration count

RATIFY_VERSION ?= v1.0.0-alpha.18
RATIFY_ARCHIVE ?= ratify-c-$(RATIFY_VERSION)-linux-armv7.tar.gz
RATIFY_URL     ?= https://github.com/identities-ai/ratify-protocol/releases/download/$(RATIFY_VERSION)/$(RATIFY_ARCHIVE)
RATIFY_SDK     ?= vendor/ratify-c

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
CFLAGS  += -I$(RATIFY_SDK)/include
LDLIBS  := -lpthread -ldl -lm

ifdef STATIC
LDFLAGS :=
RATIFY_LIB := $(RATIFY_SDK)/lib/libratify_c.a
else
LDFLAGS := -L$(RATIFY_SDK)/lib -Wl,-rpath,$(abspath $(RATIFY_SDK)/lib)
RATIFY_LIB := -lratify_c
endif

.PHONY: all run vendor footprint clean

all: smoke

smoke: smoke.c $(RATIFY_SDK)/include/ratify.h
	$(CC) $(CFLAGS) -o $@ smoke.c $(LDFLAGS) $(RATIFY_LIB) $(LDLIBS)

run: smoke
	./smoke

# Fetch the published artifact. The Pi builds no Rust and needs no Docker.
# Offline devices: scp the archive across and run "make vendor" with
# RATIFY_URL unset, or extract it into $(RATIFY_SDK) by hand.
vendor:
	mkdir -p vendor
	test -f $(RATIFY_ARCHIVE) || curl -fSL -o $(RATIFY_ARCHIVE) $(RATIFY_URL)
	tar xzf $(RATIFY_ARCHIVE) -C vendor
	rm -rf $(RATIFY_SDK)
	mv vendor/ratify-c-$(RATIFY_VERSION)-linux-armv7 $(RATIFY_SDK)
	file $(RATIFY_SDK)/lib/libratify_c.so

# Library footprint for the evidence record.
footprint:
	@ls -l $(RATIFY_SDK)/lib
	@size smoke 2>/dev/null || true

clean:
	rm -f smoke
