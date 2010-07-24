include ../../config.mk

CFLAGS+=-I ../arch -I../../include -D__UNIX__=1
LDFLAGS=-L../../util -lr_util

all: test_x86im${EXT_EXE}

test_x86im${EXT_EXE}: test_x86im.o ../arch/x86/x86im/x86im.o
	${CC} ${CFLAGS} ${LDFLAGS} -o test_x86im${EXT_EXE} \
		../arch/x86/x86im/x86im.o test_x86im.o

clean:
	rm -f test_x86im${EXT_EXE} test_x86im.o
