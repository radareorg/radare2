BINDEPS=bla
include ../../config.mk
BIN=test${EXT_EXE}

all: ${BIN}

${BIN}:
ifeq (${WITHPIC},1)
	${CC} -g -I ../../include test.c -L.. -lr_db -lr_util -L../../util -o ${BIN}
else
	${CC} -g -I ../../include test.c ../libr_db.a ../sdb/src/libsdb.a -lr_util -L../../util -o ${BIN}
endif

clean:
	rm -f ${BIN}
