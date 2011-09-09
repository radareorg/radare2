BINDEPS=bla
include ../../config.mk
BIN=test${EXT_EXE}

all: ${BIN}

${BIN}: test.c
	${CC} -g -I ../../include test.c -L.. -lr_db -lr_util -L../../util -o ${BIN}

clean:
	rm -f ${BIN}
