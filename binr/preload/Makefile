include ../../libr/config.mk

all: libr2.$(EXT_SO)

libr2.$(EXT_SO): libr2.c
	$(CC) -shared -fPIC libr2.c -o libr2.$(EXT_SO) \
		`pkg-config --cflags --libs r_core`

test:
	rarun2 preload=libr2.$(EXT_SO) program=/bin/cat

.PHONY: alloc
alloc:
	$(CC) -o alloc alloc.c -D__MAIN__
	./alloc

traps:
	@for a in *.asm ; do \
		printf "$$a\t" ; \
		rasm2 -f $$a ; \
	done ; true

clean:
	rm -f libr2.dylib alloc

