.DEFAULT_GOAL := all
CC ?= cc
PYTHON ?= python3
CFLAGS ?= -O3 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Wno-deprecated-declarations -MMD -MP -fPIC
SODIUM_LIBS ?= $(shell pkg-config --libs libsodium 2>/dev/null || echo -l:libsodium.so.23)
# Point BLST_DIR at a built blst release for the Quicknet receipt mode.
ifneq ($(strip $(BLST_DIR)),)
DRAND_CPPFLAGS := -DSTENCIL_HAVE_BLST=1 -I$(BLST_DIR)/bindings
drand.o: CPPFLAGS += $(DRAND_CPPFLAGS)
drand.o: $(BLST_DIR)/bindings/blst.h
BLST_LIB := $(BLST_DIR)/libblst.a
endif
LDLIBS += $(SODIUM_LIBS) -lcrypto -lm
receipt_objects = receipt.o beacon.o drand.o rfc3161.o
library_objects = three_band.o three_band_rng.o library.o witness.o commit.o matrix.o $(receipt_objects)
objects = scratch.o three_band_cli.o protocol.o fold.o mask.o operator.o solve.o $(library_objects)

all: stencil libstencil.so
stencil: $(objects) $(BLST_LIB)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
libstencil.so: $(library_objects) $(BLST_LIB)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)
# Recompile the backend on either change of configuration, including when a
# previous build used blst and the next invocation explicitly omits it.
.stencil-blst-config: FORCE
	@printf '%s\n' '$(BLST_DIR)' | cmp -s - $@ || printf '%s\n' '$(BLST_DIR)' > $@
drand.o: .stencil-blst-config
$(objects): Makefile

# NumPy rounds the individual arithmetic operations in its Gumbel scores.
three_band.o: CFLAGS += -ffp-contract=off
tests/check-three-band-rng: tests/three_band_rng.c three_band_rng.o
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) $(LDFLAGS) $^ -lm -o $@
tests/check-three-band-c: tests/three_band_c.c three_band.o three_band_rng.o
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) $(LDFLAGS) $^ -lm -o $@
check-three-band: stencil tests/check-three-band-rng tests/check-three-band-c
	./tests/check-three-band-rng
	./tests/check-three-band-c
	$(PYTHON) tests/check_three_band_cli.py
check-three-band-reference: check-three-band
	$(PYTHON) tests/three_band_reference.py
	$(PYTHON) tests/check_three_band_cli.py --interoperability

tests/check-commit: tests/commit.c commit.c witness.c commit.h witness.h
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) -DSTENCIL_CHECK_LIMBS $(LDFLAGS) tests/commit.c commit.c witness.c $(LDLIBS) -o $@
tests/check-generator: tests/generator.c operator.o witness.o scratch.o
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) -I. $(LDFLAGS) $^ $(LDLIBS) -o $@
tests/check-drand: tests/drand.c drand.o $(BLST_LIB)
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) $(DRAND_CPPFLAGS) $(LDFLAGS) $^ -lcrypto -o $@
tests/check-tsa-clock: tests/tsa_clock.c
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) $(LDFLAGS) $< -lcrypto -o $@

check: all check-three-band tests/check-commit tests/check-generator tests/check-drand check-signed3d
	./tests/check-commit
	./tests/check-generator
	./tests/check-drand
	python3 tests/check.py ./stencil
	python3 tests/check_rfc3161.py ./stencil
	python3 tests/check_public_tsa.py
	python3 tests/library.py
	python3 tests/check_interop.py
ifneq ($(strip $(BLST_DIR)),)
check: check-beacon
check-beacon: all tests/check-tsa-clock
	python3 tests/check_beacon.py ./stencil ./tests/check-tsa-clock
else
check-beacon:
	@echo 'check-beacon requires BLST_DIR pointing at a built blst checkout' >&2
	@false
endif
check-signed3d: stencil
	python3 tests/signed_spectrum.py
	python3 benchmarks/signed3d.py --sides 32 --regression --no-save
clean:
	$(RM) tests/check-three-band-rng tests/check-three-band-c stencil libstencil.so stencil-direct3d direct3d.o direct3d.d tests/check-commit tests/check-generator tests/check-drand tests/check-tsa-clock $(objects) $(objects:.o=.d) .stencil-blst-config
-include $(objects:.o=.d)
.PHONY: all FORCE check check-three-band check-three-band-reference check-beacon check-signed3d clean

include direct3d.mk
