BINDEPS=r_diff r_util

include ../../rules.mk

CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-g -I../../include

all: test radiff2

test: test.o
	${CC} ${CFLAGS} test.o ${LDFLAGS} -o test

radiff2: radiff2.o
	${CC} ${CFLAGS} radiff2.c ${LDFLAGS} -o radiff2

myclean:
	rm -f test test.o radiff2 radiff2.o

