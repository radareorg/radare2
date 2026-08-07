TESTS=lowerdash test test-enum a c b invalid j macho
TESTS+=union crash vararg align books dotfun sizes
TESTS+=typestr fcnptr anonworld pre 12272 colons
TESTS+=typedef typedef2 fcnptr2 funsig static typedef_union_enum unionstruct last

all: build
	@ret=0; for a in $(TESTS); do \
		echo "Testing $$a " \
		&& ./a.out t/$${a}.h 2> t/$${a}.h.tmperr > t/$${a}.h.tmp \
		&& if [ -f t/$${a}.h.err ]; then diff -u t/$${a}.h.err t/$${a}.h.tmperr || ret=1; fi \
		&& diff -u t/$${a}.h.txt t/$${a}.h.tmp || \
			{ ret=1; echo '# ------------' ; echo "$$ cat t/$${a}.h" ; cat t/$${a}.h ; echo '# -------' ; } ; \
		echo "$$a" | grep -q invalid || cat t/$${a}.h.tmperr ; \
	done; rm -f t/*.tmp*; exit $$ret

regen: build
	@for a in $(TESTS); do \
		./a.out t/$${a}.h 2> t/$${a}.h.tmperr > t/$${a}.h.txt ; \
		if [ -f t/$${a}.h.err ]; then mv t/$${a}.h.tmperr t/$${a}.h.err ; fi ; \
	done; rm -f t/*.tmp*

build:
	rm -f a.out
	$(CC) -DMAIN=1 -g kv.c $(shell pkg-config --cflags --libs r_anal) \
		-Wl,-rpath,$(shell pkg-config --variable=libdir r_anal) -I ../../shlr/

td:
	./a.out typedef.h
	r2 -qc 'to typedef.h;t*~foo,bar' --

.PHONY: all regen build td
