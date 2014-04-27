include ../../global.mk
include $(LTOP)/config.mk

NAME=r_magic
DEPS=r_util
CFLAGS+=-I.
CFLAGS+=-DHAVE_CONFIG_H
ifeq (${USE_LIB_MAGIC},1)
LDFLAGS+=-lmagic
endif
OBJS=apprentice.o ascmagic.o fsmagic.o funcs.o is_tar.o magic.o print.o softmagic.o

include $(LTOP)/rules.mk

libfile.a:
	${CC} -c ${CFLAGS} ${SRC}
	ar q libfile.a *.o
	ranlib libfile.a

BIN=file${EXT_EXE}
${BIN}:
	${CC} -I../include ${CFLAGS} ${SRC} file.c -o ${BIN}
