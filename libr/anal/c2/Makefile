TESTS=a b c invalid

all:
	rm -f a.out
	$(CC) -g kv.c $(shell pkg-config --cflags --libs r_util) -I ../../shlr/
	for a in $(TESTS); do \
		echo "Testing $$a " \
		&& ./a.out t/$${a}.h 2> t/$${a}.h.tmperr > t/$${a}.h.tmp \
		&& if [ -f t/$${a}.h.err ]; then diff -u t/$${a}.h.err t/$${a}.h.tmperr; fi \
		&& diff -u t/$${a}.h.txt t/$${a}.h.tmp ; \
	done
	rm -f t/*.tmp*
