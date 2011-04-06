include ../../libr/config.mk

.PHONY: all clean

CFLAGS+=-I../../libr/include
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"

LIBS=$(subst r_,-lr_,$(BINDEPS))
LIBS+=$(subst r_,-L../../libr/,$(BINDEPS))
LDFLAGS=${LIBS}

all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${BIN}.o ${OBJS}
	${CC} -o ${BIN}${EXT_EXE} ${OBJS} ${BIN}.o ${LIBS} ${LDFLAGS}

clean:
	-rm -f ${BIN} ${BIN}.o ${OBJS}

mrproper: clean
	-rm -f ${BIN}.d
