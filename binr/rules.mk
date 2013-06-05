BINR_PROGRAM=1
include ../../libr/config.mk

CFLAGS+=-DLIBDIR=\"${LIBDIR}\" -I$(LTOP)/include
CFLAGS+=-DR2_BIRTH=\"`date +%Y-%m-%d`\" 
CFLAGS+=-DR2_GITTIP=\"$(GIT_TIP)\"
CFLAGS+=-DR2_GITTAP=\"$(GIT_TAP)\"


ifeq ($(USE_RPATH),1)
LDFLAGS+=-Wl,-R${PREFIX}/lib
endif

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

ifeq ($(WITHNONPIC),1)
LDFLAGS+=../../libr/libr.a
LDFLAGS+=../../libr/db/sdb/src/libsdb.a
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
LDFLAGS+=-lm
endif
LDFLAGS+=${DL_LIBS}

#--------------------#
# Rules for programs #
#--------------------#

ifneq ($(BIN)$(BINS),)

all: ${BEXE} ${BINS}

${BINS}: ${OBJS}
ifneq ($(SILENT),)
	@echo CC $@
endif
	${CC} ${CFLAGS} $@.c ${OBJS} ${LDFLAGS} -o $@

${BEXE}: ${OBJ} ${SHARED_OBJ}
ifneq ($(SILENT),)
	@echo LD $@
endif
	${CC} $+ -L.. -o $@ ${LDFLAGS}
endif

# Dummy myclean rule that can be overriden by the t/ Makefile
# TODO: move to config.mk ? it must be a precondition
myclean:

clean:: myclean
	-rm -f ${OBJS} ${OBJ} ${BIN}

mrproper: clean
	-rm -f *.d

install:
	cd ../.. && ${MAKE} install

.PHONY: all clean myclean mrproper install
