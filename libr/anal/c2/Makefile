TESTS=lowerdash test test-enum a c b invalid j macho union crash vararg typedef align

all:
	rm -f a.out
	$(CC) -DMAIN=1 -g kv.c $(shell pkg-config --cflags --libs r_util) -I ../../shlr/
	for a in $(TESTS); do \
		echo "Testing $$a " \
		&& ./a.out t/$${a}.h 2> t/$${a}.h.tmperr > t/$${a}.h.tmp \
		&& if [ -f t/$${a}.h.err ]; then diff -u t/$${a}.h.err t/$${a}.h.tmperr; fi \
		&& diff -u t/$${a}.h.txt t/$${a}.h.tmp || cat t/$${a}.h ; \
	done
	rm -f t/*.tmp*

td:
	./a.out typedef.h
	r2 -qc 'to typedef.h;t*~foo,bar' --
