BINDEPS=bla
include ../../config.mk
#include ../../../mk/${COMPILER}.mk

all: test${EXT_EXE}

test.o: test.c
	@true

test${EXT_EXE}: test.o
	${CC} -g -I ../../include test.c -L.. -lr_db -lr_util -L../../util -o test${EXT_EXE}

clean:
	rm -f test
