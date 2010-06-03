include ../../libr/config.mk

.PHONY: all clean

CFLAGS+=-I../../libr/include
CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"

#LIBS=$(subst r_,-lr_,$(DEPS))
LIBS+=$(subst r_,-L../../libr/,$(DEPS))

all: ${BIN}

${BIN}: ${BIN}.o
	${CC} -o ${BIN} ${LIBS} ${LDFLAGS} ${BIN}.o

clean:
	rm -f ${BIN} ${BIN}.o ${BIN}.d
