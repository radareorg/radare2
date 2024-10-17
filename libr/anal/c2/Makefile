TESTS=a b c

all:
	rm -f a.out
	$(CC) -g kv.c $(shell pkg-config --cflags --libs r_util) -I ../../shlr/
	for a in $(TESTS); do \
		echo "Testing $$a " && \
		./a.out t/$${a}.h > t/$${a}.h.tmp && \
		diff -u t/$${a}.h.txt t/$${a}.h.tmp ; done
