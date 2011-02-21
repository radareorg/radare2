include ../../../config.mk
#CC?=gcc

RFSARCH=$(shell uname -m)
RFSOS=$(shell uname -s)

KERNFILES=kern/file.c 
KERNFILES+=kern/term.c kern/device.c
KERNFILES+=kern/err.c
KERNFILES+=kern/env.c kern/disk.c
KERNFILES+=kern/fs.c kern/misc.c
KERNFILES+=kern/time.c
KERNFILES+=kern/list.c kern/partition.c
KERNFILES+=kern/mm.c
#KERNFILES+=kern/dl.c
KERNFILES+=fs/fshelp.c
KERNFILES+=fs/reiserfs.c
KERNFILES+=fs/ext2.c
KERNFILES+=fs/fat.c
KERNFILES+=fs/ntfs.c
KERNFILES+=fs/cpio.c
KERNFILES+=fs/tar.c
KERNFILES+=fs/xfs.c 
# All nested functions are removed from the following .c with a lot of tobacco :-)
KERNFILES+=fs/hfs.c 
KERNFILES+=fs/hfsplus.c 
KERNFILES+=fs/udf.c 
KERNFILES+=fs/iso9660.c
KERNFILES+=fs/jfs.c
KERNFILES+=grubfs.c

KERNFILES+=partmap/msdos.c
#KERNFILES+=partmap/acorn.c
KERNFILES+=partmap/gpt.c
KERNFILES+=partmap/apple.c
KERNFILES+=partmap/amiga.c
KERNFILES+=partmap/sun.c
KERNFILES+=partmap/bsdlabel.c
KERNFILES+=partmap/sunpc.c

KERNOBJS=$(subst .c,.o,${KERNFILES})
CFLAGS=-Iinclude -g -fPIC 
CFLAGS+=-I../../../include -DGRUB_TARGET_NO_MODULES

ifeq ($(RFSOS),Darwin)
CFLAGS+=-DAPPLE_CC
endif

BIN=test${EXT_EXE}

all: ${BIN}

${BIN}: ${KERNOBJS} main.o
	${CC} -o ${BIN} main.o ${CFLAGS} ${KERNOBJS}

lib: all libgrubfs.a

libgrubfs.a:
	rm -f libgrubfs.a
	ar -q libgrubfs.a ${KERNOBJS}

clean:
	rm -f ${KERNOBJS} ${BIN} main.o
	rm -f libgrubfs.a

sync:
	echo "XXX: Implement syncing with burg project"
