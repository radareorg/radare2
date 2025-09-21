SRCS  := $(shell cd src ; ls *.c)
SCS := $(subst .c,,$(notdir $(SRCS)))
PYTHON?=python3

all: out

out:
	$(PYTHON) scmangle.py --out-dir out/ src/*

clean:
	rm -rf out
	rm -f *.c

.PHONY: all clean
