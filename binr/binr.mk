include ../../libr/config.mk

.PHONY: all clean

CFLAGS+=-I../../libr/include
CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"

#LIBS=$(subst r_,-lr_,$(DEPS))
LIBS+=$(subst r_,-L../../libr/,$(DEPS))

all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${BIN}.o
	${CC} -o ${BIN}${EXT_EXE} ${LIBS} ${LDFLAGS} ${BIN}.o

clean:
	-rm -f ${BIN} ${BIN}.o

mrproper: clean
	-rm -f ${BIN}.d
