SRCS  := $(shell cd src ; ls *.c)
SCS := $(subst .c,,$(notdir $(SRCS)))
PYTHON3?=python3
HAVE_PYTHON=$(shell $(PYTHON3) --version && echo 1)

all: out

out:
ifeq ($(HAVE_PYTHON),1)
	$(PYTHON3) scmangle.py --out-dir out/ src/*
else
	rm -rf out
	mkdir -p out
	cp -rf src/*.c out
	echo 'static inline ut8 *sc_decrypt(const ut8 *buf, size_t len) { return r_mem_dup (buf, len); }' > out/decrypt.inc.c
endif

clean:
	rm -rf out
	rm -f *.c

.PHONY: all clean
