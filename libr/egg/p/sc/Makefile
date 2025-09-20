SRCS  := $(shell cd src ; ls *.c)
SCS := $(subst .c,,$(notdir $(SRCS)))

all: clean
	# TODO: encode rather than copying
	for a in $(SCS) ; do cp -f src/$$a.c $$a.inc.c ; done

clean:
	rm -f *.c

.PHONY: all clean
