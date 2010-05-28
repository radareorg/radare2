include ../../config.mk

all: test${EXT_EXE}

test${EXT_EXE}:
	${CC} -g -I ../../include test.c -lr_config -lr_util -L.. -L../../util \
	-o test${EXT_EXE}

clean:
	rm -f test *.exe
