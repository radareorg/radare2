include ../../config.mk

OBJ=rahash2.o
BIN=rahash2
# already appended in rules.mk ${EXT_EXE}
BINDEPS=r_io r_hash r_util
LIBS=-lm

all: ${BIN} hello${EXT_EXE}

hello${EXT_EXE}: hello.o
	@#${CC} -I../../include hello.o -Wl,-R.. -L.. -L../../io -L../../util -L../../lib -lr_util -lr_lib -lr_hash -lr_io -o hello
	${CC} hello.o ${CFLAGS} ${LDFLAGS} -o hello${EXT_EXE}

${BIN}: rahash2.o
	${CC} ${CFLAGS} rahash2.c ${LDFLAGS} -o ${BIN}

myclean:
	rm -f hello${EXT_EXE} hello.o ${BIN}

include ../../rules.mk
