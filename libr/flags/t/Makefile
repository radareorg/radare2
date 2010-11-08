include ../../config.mk

all: test${EXT_EXE}

test${EXT_EXE}:
	${CC} ${CFLAGS} -g -I ../../include test.c ../*.o -lr_util -L../../util -L../../cons -lr_cons -o test${EXT_EXE}

clean:
	rm -f test${EXT_EXE}
