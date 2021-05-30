include ../../global.mk
include $(LTOP)/config.mk

NAME=r_magic
R2DEPS=r_util
CFLAGS+=-I.
OBJS=apprentice.o ascmagic.o fsmagic.o funcs.o is_tar.o magic.o softmagic.o
PCLIBS=@LIBMAGIC@

alle: all

include deps.mk
include ../rules.mk

libfile.a:
	${CC} -c ${CFLAGS} ${SRC}
	${AR} q libfile.a *.o
	${RANLIB} libfile.a


BIN=file${EXT_EXE}
${BIN}:
	${CC} -I../include ${CFLAGS} ${SRC} file.c -o ${BIN}
