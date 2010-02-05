include ../../config.mk

BINDEPS=r_diff r_util

CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-g -I../../include

all: test${EXT_EXE} radiff2${EXT_EXE}

test${EXT_EXE}: test.o
	${CC} ${CFLAGS} test.o ${LDFLAGS} -o test${EXT_EXE}

radiff2${EXT_EXE}: radiff2.o
	${CC} ${CFLAGS} radiff2.c ${LDFLAGS} -o radiff2${EXT_EXE}

myclean:
	rm -f test${EXT_EXE} test.o radiff2${EXT_EXE} radiff2.o

include ../../rules.mk
