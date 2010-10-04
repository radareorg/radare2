include ../../libr/config.mk

.PHONY: all clean

CFLAGS+=-I../../libr/include
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"

#LIBS=$(subst r_,-lr_,$(DEPS))
LIBS+=$(subst r_,-L../../libr/,$(DEPS))

all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${BIN}.o ${OBJS}
	${CC} -o ${BIN}${EXT_EXE} ${LIBS} ${LDFLAGS} ${OBJS} ${BIN}.o

clean:
	-rm -f ${BIN} ${BIN}.o ${OBJS}

mrproper: clean
	-rm -f ${BIN}.d
