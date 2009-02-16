BINDEPS=r_util r_search

include ../../rules.mk

all: test test-str test-regexp

test:
	${CC} -g -I ../../include test.c ${LDFLAGS} -o test

test-regexp:
	${CC} -g -I ../../include test-regexp.c ${LDFLAGS} -o test-regexp

test-str:
	${CC} -g -I ../../include test-str.c ${LDFLAGS} -o test-str

clean:
	rm -f test test.o test-str test-str.o test-regexp

