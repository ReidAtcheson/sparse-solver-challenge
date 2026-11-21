# Only the standalone VM solver links oneMKL. On Ubuntu 24.04 use libmkl-dev.
MKL_CPPFLAGS ?= $(shell pkg-config --cflags mkl-dynamic-lp64-iomp 2>/dev/null || echo -I/usr/include/mkl)
# MKL loads its GNU threading backend dynamically. Retain libgomp even when
# no OpenMP symbol is referenced by this executable's main object.
MKL_LIBS ?= -lmkl_rt -Wl,--no-as-needed -lgomp -Wl,--as-needed -lpthread -ldl
direct3d: stencil-direct3d
direct3d.o: CPPFLAGS += $(MKL_CPPFLAGS)
stencil-direct3d: direct3d.o matrix.o three_band.o three_band_rng.o $(receipt_objects) $(BLST_LIB) direct3d.mk
	$(CC) $(LDFLAGS) -o $@ $(filter %.o %.a,$^) $(MKL_LIBS) -lcrypto -lm
-include direct3d.d
.PHONY: direct3d
