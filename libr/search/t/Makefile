BINDEPS=r_util r_search r_print r_io r_cons r_line

include ../../rules.mk

all: test test-str test-regexp rafind2

rafind2: rafind2.o
	${CC} -g -I ../../include rafind2.o ${LDFLAGS} -o rafind2

test:
	${CC} -g -I ../../include test.c ${LDFLAGS} -o test

test-regexp:
	${CC} -g -I ../../include test-regexp.c ${LDFLAGS} -o test-regexp

test-str:
	${CC} -g -I ../../include test-str.c ${LDFLAGS} -o test-str

myclean:
	rm -f test test.o test-str test-str.o test-regexp rafind2 *.o
