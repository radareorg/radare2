include ../config.mk

NAME=r_magic
DEPS=r_util
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

install-data: ${F_SDB}
	mkdir -p ${DESTDIR}${LIBDIR}/radare2/${VERSION}/magic
	cp -f d/* ${DESTDIR}${LIBDIR}/radare2/${VERSION}/magic

CWD=$(shell pwd)
symstall-data install-symlink-data: ${F_SDB}
	mkdir -p ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/magic
	cd d ; for a in * ; do ln -fs ${CWD}/d/$$a ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/magic/$$a ; done
