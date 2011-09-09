include ../config.mk

NAME=r_magic
CFLAGS+=-I.
CFLAGS+=-DHAVE_CONFIG_H
OBJ=apprentice.o ascmagic.o compress.o fsmagic.o funcs.o is_tar.o magic.o print.o softmagic.o

include ../rules.mk

libfile.a:
	${CC} -c ${CFLAGS} ${SRC}
	ar q libfile.a *.o
	ranlib libfile.a

BIN=file${EXT_EXE}
${BIN}:
	${CC} -I../include ${CFLAGS} ${SRC} file.c -o ${BIN}
