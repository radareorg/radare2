include ../../libr/config.mk

#.PHONY: all clean

CFLAGS+=-DLIBDIR=\"${LIBDIR}\"

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

#all: ${BEXE}

#${BEXE}: ${OBJ}
#	${CC} -o ${BEXE} ${OBJ} ${LIBS} ${LDFLAGS}

include ../../libr/rules.mk
