TESTS=lowerdash test test-enum a c b invalid j macho
TESTS+=union crash vararg align books dotfun sizes
TESTS+=typestr fcnptr anonworld pre 12272 colons
TESTS+=typedef typedef2 fcnptr2

all:
	rm -f a.out
	$(CC) -DMAIN=1 -g kv.c $(shell pkg-config --cflags --libs r_util) -I ../../shlr/
	for a in $(TESTS); do \
		echo "Testing $$a " \
		&& ./a.out t/$${a}.h 2> t/$${a}.h.tmperr > t/$${a}.h.tmp \
		&& if [ -f t/$${a}.h.err ]; then diff -u t/$${a}.h.err t/$${a}.h.tmperr; fi \
		&& diff -u t/$${a}.h.txt t/$${a}.h.tmp || \
			(echo '# ------------' ; echo '$$ cat t/$${a}.h' ; cat t/$${a}.h ; echo '# -------' ); \
		[ -z "`echo $${a}| grep invalid`" ] && cat t/$${a}.h.tmperr ; \
	done
	rm -f t/*.tmp*

td:
	./a.out typedef.h
	r2 -qc 'to typedef.h;t*~foo,bar' --
