# Ratify Edge Physical AI — Linux edge receiver
#
#   make test     build and run the fixture harness (test build, override available)
#   make          build the edge library objects only (no override compiled in)
#
# The test binary is the ONLY artifact compiled with -DSENTINEL_TEST_BUILD, so
# the edge binary cannot enable the quarantine override however it is invoked.

RATIFY_SDK ?= smoke/vendor/ratify-c

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
CFLAGS  += -Iinclude -Isrc -Iactuator -I$(RATIFY_SDK)/include
LDFLAGS := -L$(RATIFY_SDK)/lib -Wl,-rpath,$(abspath $(RATIFY_SDK)/lib)
LDLIBS  := -lratify_c -lpthread -ldl -lm

CORE := src/verifier.c src/trust.c actuator/actuator.c

.PHONY: all edge test clean

all: edge

edge: src/main.c src/http.c $(CORE)
	$(CC) $(CFLAGS) -o $@ src/main.c src/http.c $(CORE) $(LDFLAGS) $(LDLIBS)

core_test: tests/core_test.c $(CORE)
	$(CC) $(CFLAGS) -DSENTINEL_TEST_BUILD -o $@ tests/core_test.c $(CORE) $(LDFLAGS) $(LDLIBS)

# The ONLY daemon build with the quarantine override compiled in. Named
# differently on purpose so it cannot be mistaken for the edge binary.
edge-test: src/main.c src/http.c $(CORE)
	$(CC) $(CFLAGS) -DSENTINEL_TEST_BUILD -o $@ src/main.c src/http.c $(CORE) $(LDFLAGS) $(LDLIBS)

controller: ../controller/controller.c
	$(CC) $(CFLAGS) -o $@ ../controller/controller.c $(LDFLAGS) $(LDLIBS)

test: core_test
	./core_test

clean:
	rm -f core_test edge edge-test controller
