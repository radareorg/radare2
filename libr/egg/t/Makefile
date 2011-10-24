TESTS=exit1 hello loop loop2 fun fun2 fun3 fun4
TESTS+=nest nest2 nest3

#ARG PASSING ERR
TESTS+=fun5 fun6

#INVALID SYNTAX
#TESTS+=looptail

include ../../config.mk

BINDEPS=r_egg r_util r_asm r_syscall r_db

CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-g -I../../include

all: test${EXT_EXE}

test${EXT_EXE}: test.o
	${CC} ${CFLAGS} test.o ${LDFLAGS} -o test${EXT_EXE}

.PHONY: t

t tests:
	@for a in ${TESTS} ; do sh t-$$a.sh ; done

myclean:
	rm -f test${EXT_EXE} test.o

include ../../rules.mk
