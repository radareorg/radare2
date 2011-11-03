include ../../libr/rules.mk

.PHONY: all clean

CFLAGS+=-DLIBDIR=\"${LIBDIR}\"

OBJS+=${BIN}.o

${BIN}${EXT_EXE}: ${OBJS}
