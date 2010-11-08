BINDEPS=r_util r_search

include ../../config.mk

all: test${EXT_EXE} test-str${EXT_EXE} test-regexp${EXT_EXE}

include ../../rules.mk

test${EXT_EXE}:
	${CC} ${CFLAGS} -g -I ../../include test.c ${LDFLAGS} -o test${EXT_EXE}

test-regexp${EXT_EXE}:
	${CC} ${CFLAGS} -g -I ../../include test-regexp.c ${LDFLAGS} -o test-regexp${EXT_EXE}

test-str${EXT_EXE}:
	${CC} ${CFLAGS} -g -I ../../include test-str.c ${LDFLAGS} -o test-str${EXT_EXE}

myclean:
	rm -f test${EXT_EXE} test.o test-str${EXT_EXE} test-str.o test-regexp${EXT_EXE} test-regexp.o
