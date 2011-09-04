include ../../config.mk

BINDEPS=r_egg r_util r_asm r_syscall r_db

CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-g -I../../include

all: test${EXT_EXE}

test${EXT_EXE}: test.o
	${CC} ${CFLAGS} test.o ${LDFLAGS} -o test${EXT_EXE}

myclean:
	rm -f test${EXT_EXE} test.o

include ../../rules.mk
