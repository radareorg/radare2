SRCS  := $(shell cd src ; ls *.c)
SCS := $(subst .c,,$(notdir $(SRCS)))

all: out

out:
	python scmangle.py --out-dir out/ src/*
	#for a in $(SCS) ; do cp -f src/$$a.c $$a.inc.c ; done

clean:
	rm -rf out
	rm -f *.c

.PHONY: all clean
