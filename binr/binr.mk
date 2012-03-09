include ../../libr/rules.mk

.PHONY: all clean

CFLAGS+=-DLIBDIR=\"${LIBDIR}\"

OBJS+=${BIN}.o

all: ${BIN}${EXT_EXE}

${BIN}${EXT_EXE}: ${OBJS}
