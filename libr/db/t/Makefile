include ../../config.mk
include ../../../mk/${COMPILER}.mk

all: test${EXT_EXE}

test${EXT_EXE}:
	${CC} -g -I ../../include test.c ../*.o -lr_util -L../../util -o tes${EXT_EXE}

clean:
	rm -f test
