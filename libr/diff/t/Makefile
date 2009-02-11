BINDEPS=r_diff r_util

include ../../rules.mk

all: test radiff2

test:
	${CC} -g -I ../../include test.c ${LDFLAGS} -o test

radiff2:
	${CC} -g -I ../../include radiff2.c ${LDFLAGS} -o radiff2

clean:
	rm -f test test.o radiff2

