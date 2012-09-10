BINR_PROGRAM=1
include ../../libr/config.mk

#.PHONY: all clean

CFLAGS+=-DLIBDIR=\"${LIBDIR}\"

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

#all: ${BEXE}

#${BEXE}: ${OBJ}
#	${CC} -o ${BEXE} ${OBJ} ${LIBS} ${LDFLAGS}

include ../../libr/rules.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=../../libr/db/sdb/src/libsdb.a
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
LDFLAGS+=-lm
endif
