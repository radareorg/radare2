include ../../../config.mk
#CC?=gcc
KERNFILES=kern/file.c 
KERNFILES+=kern/term.c kern/device.c
KERNFILES+=kern/err.c
KERNFILES+=kern/env.c kern/disk.c
KERNFILES+=kern/fs.c kern/misc.c
KERNFILES+=kern/time.c
KERNFILES+=kern/list.c kern/partition.c
KERNFILES+=fs/fshelp.c fs/ext2.c
#KERNFILES+=main.c
KERNFILES+=grubfs.c

KERNOBJS=$(subst .c,.o,${KERNFILES})
CFLAGS=-Iinclude -g
CFLAGS+=-I../../../include
BIN=test${EXT_EXE}

all: ${KERNOBJS} main.o ${BIN}

${BIN}:
	${CC} -o ${BIN} main.o ${CFLAGS} ${KERNOBJS}

lib: all libgrubfs.a
	

libgrubfs.a:
	rm -f libgrubfs.a
	ar -q libgrubfs.a ${KERNOBJS}

clean:
	rm -f ${KERNOBJS} ${BIN} main.o
	rm -f libgrubfs.a
