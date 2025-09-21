SRCS  := $(shell cd src ; ls *.c)
SCS := $(subst .c,,$(notdir $(SRCS)))

all: out

out:
	python scmangle.py --out-dir out/ src/*

clean:
	rm -rf out
	rm -f *.c

.PHONY: all clean
