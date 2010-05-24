include ../../config.mk

all: test${EXT_EXE}

test${EXT_EXE}:
	${CC} -g -I ../../include test.c ../*.o \
	../../util/*.o -o test${EXT_EXE}

clean:
	rm -f test *.exe
